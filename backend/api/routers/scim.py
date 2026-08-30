"""SCIM 2.0 (RFC 7643 / RFC 7644) user and group provisioning.

JumpCloud and other IdPs call `/scim/v2` with a bearer token
(`SEG_SCIM_BEARER_TOKEN`) or an admin JWT. Groups map to the local RBAC
roles admin / analyst / viewer.
"""
from __future__ import annotations

import json
import logging
import re
import secrets
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from backend.config import get_settings

from .. import activity_log
from ..auth_store import ROLES, User, get_default_store
from ..deps import get_auth_store, get_current_user_optional, presented_token

_log = logging.getLogger("backend.api.scim")

SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_SP = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"

_FILTER_EQ = re.compile(
    r'^\s*(\w+)\s+eq\s+"(.*?)"\s*$',
    re.I,
)
_USERNAME_OK = re.compile(r"^[a-zA-Z0-9._@\-]+$")

router = APIRouter(prefix="/scim/v2", tags=["scim"])
_store = get_default_store()


class ScimJSONResponse(JSONResponse):
    media_type = "application/scim+json"


def _scim_error(status: int, detail: str, scim_type: str = "") -> JSONResponse:
    body: dict[str, Any] = {
        "schemas": [SCIM_ERROR],
        "status": str(status),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type
    return ScimJSONResponse(content=body, status_code=status)


def _base_url(request: Request) -> str:
    origin = (get_settings().public_origin or "").strip().rstrip("/")
    if origin:
        return origin + "/scim/v2"
    proto = (
        (request.headers.get("cloudfront-forwarded-proto") or "")
        or (request.headers.get("x-forwarded-proto") or "")
        or request.url.scheme
        or "https"
    ).split(",")[0].strip()
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc)
    host = host.split(",")[0].strip()
    return f"{proto}://{host}/scim/v2"


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(float(ts or 0), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scim_bearer_ok(token: str) -> bool:
    expected = (get_settings().scim_bearer_token or "").strip()
    if not expected or not token:
        return False
    return secrets.compare_digest(token, expected)


def require_scim_admin(request: Request) -> User:
    token = presented_token(request)
    if _scim_bearer_ok(token):
        return User(id=0, username="scim-client", role="admin")
    user = get_current_user_optional(request)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="not authenticated",
            headers={"WWW-Authenticate": 'Bearer realm="SEGS", error="invalid_token"'},
        )
    if not user.has_role("admin"):
        raise HTTPException(status_code=403, detail="insufficient role")
    return user


def _user_resource(request: Request, row: dict) -> dict[str, Any]:
    base = _base_url(request)
    uid = str(row["id"])
    username = row["username"]
    display = (row.get("display_name") or "").strip() or username
    email = (row.get("email") or "").strip()
    ext = (row.get("external_id") or "").strip()
    created = _iso(row.get("created_at") or 0)
    emails = [{"value": email, "type": "work", "primary": True}] if email else []
    body: dict[str, Any] = {
        "schemas": [SCIM_USER],
        "id": uid,
        "userName": username,
        "displayName": display,
        "name": {"formatted": display},
        "active": not bool(row.get("disabled")),
        "emails": emails,
        "roles": [{"value": row["role"], "display": row["role"], "primary": True, "type": "rbac"}],
        "groups": [
            {
                "value": row["role"],
                "display": row["role"],
                "$ref": f"{base}/Groups/{quote(row['role'], safe='')}",
            }
        ],
        "meta": {
            "resourceType": "User",
            "created": created,
            "lastModified": created,
            "location": f"{base}/Users/{quote(uid, safe='')}",
        },
    }
    if ext:
        body["externalId"] = ext
    return body


def _group_resource(request: Request, role: str, members: list[dict]) -> dict[str, Any]:
    base = _base_url(request)
    return {
        "schemas": [SCIM_GROUP],
        "id": role,
        "displayName": role,
        "members": [
            {
                "value": str(m["id"]),
                "display": m["username"],
                "$ref": f"{base}/Users/{m['id']}",
            }
            for m in members
        ],
        "meta": {
            "resourceType": "Group",
            "location": f"{base}/Groups/{quote(role, safe='')}",
        },
    }


def _parse_filter(flt: str) -> tuple[str, str] | None:
    raw = (flt or "").strip()
    if not raw:
        return None
    m = _FILTER_EQ.match(raw)
    if not m:
        raise ValueError("unsupported filter")
    return m.group(1), m.group(2)


def _role_from_scim(payload: dict) -> str:
    roles = payload.get("roles") or []
    if isinstance(roles, list) and roles:
        first = roles[0]
        value = first.get("value") if isinstance(first, dict) else str(first)
        value = str(value or "").strip().lower()
        if value in ROLES:
            return value
    groups = payload.get("groups") or []
    if isinstance(groups, list) and groups:
        first = groups[0]
        value = first.get("value") if isinstance(first, dict) else str(first)
        value = str(value or "").strip().lower()
        if value in ROLES:
            return value
    return "viewer"


def _email_from_scim(payload: dict) -> str:
    emails = payload.get("emails") or []
    if isinstance(emails, list):
        for item in emails:
            if isinstance(item, dict) and item.get("value"):
                return str(item["value"]).strip()
            if isinstance(item, str) and item.strip():
                return item.strip()
    return ""


def _display_from_scim(payload: dict, username: str) -> str:
    name = payload.get("name") or {}
    if isinstance(name, dict):
        formatted = (name.get("formatted") or "").strip()
        given = (name.get("givenName") or "").strip()
        family = (name.get("familyName") or "").strip()
        if formatted:
            return formatted
        joined = " ".join(p for p in (given, family) if p).strip()
        if joined:
            return joined
    return str(payload.get("displayName") or username).strip()


def _provision_password() -> str:
    return secrets.token_urlsafe(18) + "Aa1!"


async def _json_body(request: Request) -> dict:
    raw = await request.body()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid JSON") from exc
    return data if isinstance(data, dict) else {}


@router.get("/ServiceProviderConfig")
def service_provider_config(_: User = Depends(require_scim_admin)):
    return ScimJSONResponse({
        "schemas": [SCIM_SP],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "RFC 6750 bearer token (SEG_SCIM_BEARER_TOKEN or admin JWT)",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                "primary": True,
            }
        ],
    })


@router.get("/ResourceTypes")
def resource_types(request: Request, _: User = Depends(require_scim_admin)):
    base = _base_url(request)
    return ScimJSONResponse({
        "schemas": [SCIM_LIST],
        "totalResults": 2,
        "Resources": [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "schema": SCIM_USER,
                "meta": {"location": f"{base}/ResourceTypes/User", "resourceType": "ResourceType"},
            },
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "schema": SCIM_GROUP,
                "meta": {"location": f"{base}/ResourceTypes/Group", "resourceType": "ResourceType"},
            },
        ],
    })


@router.get("/Schemas")
def schemas(_: User = Depends(require_scim_admin)):
    return ScimJSONResponse({
        "schemas": [SCIM_LIST],
        "totalResults": 2,
        "Resources": [
            {"id": SCIM_USER, "name": "User", "description": "User Account"},
            {"id": SCIM_GROUP, "name": "Group", "description": "Group"},
        ],
    })


@router.get("/Users")
def list_users(
    request: Request,
    filter: str = Query(default=""),
    startIndex: int = Query(default=1, ge=1),
    count: int = Query(default=100, ge=1, le=200),
    _: User = Depends(require_scim_admin),
):
    store = get_auth_store()
    rows = store.list_users()
    try:
        parsed = _parse_filter(filter) if filter else None
    except ValueError:
        return _scim_error(400, "unsupported filter", "invalidFilter")
    if parsed:
        attr, value = parsed
        key = attr.lower()
        if key == "username":
            rows = [r for r in rows if r["username"].lower() == value.lower()]
        elif key == "externalid":
            rows = [r for r in rows if (r.get("external_id") or "") == value]
        elif key == "emails":
            rows = [r for r in rows if (r.get("email") or "").lower() == value.lower()]
        else:
            return _scim_error(400, f"unsupported filter attribute {attr}", "invalidFilter")
    total = len(rows)
    start = startIndex - 1
    page = rows[start:start + count]
    resources = [_user_resource(request, r) for r in page]
    return ScimJSONResponse({
        "schemas": [SCIM_LIST],
        "totalResults": total,
        "startIndex": startIndex,
        "itemsPerPage": len(resources),
        "Resources": resources,
    })


@router.get("/Users/{user_id}")
def get_user(user_id: str, request: Request, _: User = Depends(require_scim_admin)):
    store = get_auth_store()
    row = store.get_user_row(int(user_id)) if user_id.isdigit() else None
    if row is None:
        return _scim_error(404, "user not found")
    return ScimJSONResponse(_user_resource(request, row))


@router.post("/Users", status_code=201)
async def create_user(request: Request, admin: User = Depends(require_scim_admin)):
    payload = await _json_body(request)
    username = str(payload.get("userName") or "").strip()
    if not username or not _USERNAME_OK.match(username):
        return _scim_error(400, "userName is required", "invalidValue")
    store = get_auth_store()
    if store.get_user_by_username(username):
        return _scim_error(409, "userName already exists", "uniqueness")
    role = _role_from_scim(payload)
    email = _email_from_scim(payload)
    display = _display_from_scim(payload, username)
    external_id = str(payload.get("externalId") or "").strip()
    active = payload.get("active", True)
    try:
        user = store.create_user(
            username, _provision_password(), role,
            email=email, display_name=display, external_id=external_id,
        )
    except Exception as exc:
        _log.warning("scim create user failed: %s", exc)
        return _scim_error(400, "could not create user")
    if active is False:
        store.set_user_disabled(user.id, True)
    row = store.get_user_row(user.id)
    activity_log.record(
        "scim_user_create", actor=admin.username, actor_role=admin.role,
        detail=f"SCIM created {username} role={role}",
        meta={"target_user": username, "role": role},
    )
    body = _user_resource(request, row or {
        "id": user.id, "username": username, "role": role, "disabled": not active,
        "created_at": 0, "email": email, "display_name": display, "external_id": external_id,
    })
    return ScimJSONResponse(body, status_code=201, headers={"Location": body["meta"]["location"]})


@router.put("/Users/{user_id}")
async def replace_user(user_id: str, request: Request, admin: User = Depends(require_scim_admin)):
    store = get_auth_store()
    if not user_id.isdigit():
        return _scim_error(404, "user not found")
    row = store.get_user_row(int(user_id))
    if row is None:
        return _scim_error(404, "user not found")
    payload = await _json_body(request)
    username = str(payload.get("userName") or row["username"]).strip()
    if not _USERNAME_OK.match(username):
        return _scim_error(400, "invalid userName", "invalidValue")
    store.update_user_profile(
        int(user_id),
        username=username,
        role=_role_from_scim(payload) if (payload.get("roles") or payload.get("groups")) else row["role"],
        email=_email_from_scim(payload),
        display_name=_display_from_scim(payload, username),
        external_id=str(payload.get("externalId") or "").strip(),
        disabled=not bool(payload.get("active", not row["disabled"])),
    )
    activity_log.record(
        "scim_user_replace", actor=admin.username, actor_role=admin.role,
        detail=f"SCIM replaced {username}",
        meta={"target_user": username},
    )
    updated = store.get_user_row(int(user_id))
    return ScimJSONResponse(_user_resource(request, updated or row))


@router.patch("/Users/{user_id}")
async def patch_user(user_id: str, request: Request, admin: User = Depends(require_scim_admin)):
    store = get_auth_store()
    if not user_id.isdigit():
        return _scim_error(404, "user not found")
    row = store.get_user_row(int(user_id))
    if row is None:
        return _scim_error(404, "user not found")
    payload = await _json_body(request)
    fields: dict[str, Any] = {}
    for op in payload.get("Operations") or []:
        if not isinstance(op, dict):
            continue
        name = str(op.get("op") or "").lower()
        path = str(op.get("path") or "").strip().lstrip("/")
        value = op.get("value")
        attr = path.split("[")[0] if path else ""
        if not attr and isinstance(value, dict):
            if "active" in value:
                fields["disabled"] = not bool(value["active"])
            if "userName" in value:
                fields["username"] = str(value["userName"]).strip()
            if "displayName" in value:
                fields["display_name"] = str(value["displayName"]).strip()
            if "externalId" in value:
                fields["external_id"] = str(value["externalId"]).strip()
            continue
        if attr.lower() == "active":
            fields["disabled"] = not bool(value) if name != "remove" else False
        elif attr.lower() == "username":
            fields["username"] = str(value or "").strip()
        elif attr.lower() == "displayname":
            fields["display_name"] = str(value or "").strip()
        elif attr.lower() == "externalid":
            fields["external_id"] = str(value or "").strip()
        elif attr.lower() == "emails" and isinstance(value, list) and value:
            item = value[0]
            fields["email"] = str(item.get("value") if isinstance(item, dict) else item).strip()
        elif attr.lower() == "roles" and isinstance(value, list) and value:
            item = value[0]
            role = str(item.get("value") if isinstance(item, dict) else item).strip().lower()
            if role in ROLES:
                fields["role"] = role
    if fields:
        store.update_user_profile(int(user_id), **fields)
    activity_log.record(
        "scim_user_patch", actor=admin.username, actor_role=admin.role,
        detail=f"SCIM patched user {row['username']}",
        meta={"target_user": row["username"]},
    )
    updated = store.get_user_row(int(user_id))
    return ScimJSONResponse(_user_resource(request, updated or row))


@router.delete("/Users/{user_id}", status_code=204)
def delete_user(user_id: str, admin: User = Depends(require_scim_admin)):
    store = get_auth_store()
    if not user_id.isdigit():
        return Response(status_code=404)
    row = store.get_user_row(int(user_id))
    if row is None:
        return _scim_error(404, "user not found")
    if admin.id and int(user_id) == admin.id:
        return _scim_error(400, "cannot delete your own account")
    store.delete_user(int(user_id))
    activity_log.record(
        "scim_user_delete", actor=admin.username, actor_role=admin.role,
        detail=f"SCIM deleted {row['username']}",
        meta={"target_user": row["username"]},
    )
    return Response(status_code=204)


@router.get("/Groups")
def list_groups(
    request: Request,
    filter: str = Query(default=""),
    startIndex: int = Query(default=1, ge=1),
    count: int = Query(default=100, ge=1, le=200),
    _: User = Depends(require_scim_admin),
):
    store = get_auth_store()
    users = store.list_users()
    groups = [_group_resource(request, role, [u for u in users if u["role"] == role]) for role in ROLES]
    try:
        parsed = _parse_filter(filter) if filter else None
    except ValueError:
        return _scim_error(400, "unsupported filter", "invalidFilter")
    if parsed:
        attr, value = parsed
        if attr.lower() == "displayname":
            groups = [g for g in groups if g["displayName"].lower() == value.lower()]
        else:
            return _scim_error(400, f"unsupported filter attribute {attr}", "invalidFilter")
    total = len(groups)
    start = startIndex - 1
    page = groups[start:start + count]
    return ScimJSONResponse({
        "schemas": [SCIM_LIST],
        "totalResults": total,
        "startIndex": startIndex,
        "itemsPerPage": len(page),
        "Resources": page,
    })


@router.get("/Groups/{group_id}")
def get_group(group_id: str, request: Request, _: User = Depends(require_scim_admin)):
    role = group_id.strip().lower()
    if role not in ROLES:
        return _scim_error(404, "group not found")
    store = get_auth_store()
    members = [u for u in store.list_users() if u["role"] == role]
    return ScimJSONResponse(_group_resource(request, role, members))


@router.patch("/Groups/{group_id}")
async def patch_group(group_id: str, request: Request, admin: User = Depends(require_scim_admin)):
    role = group_id.strip().lower()
    if role not in ROLES:
        return _scim_error(404, "group not found")
    store = get_auth_store()
    payload = await _json_body(request)
    for op in payload.get("Operations") or []:
        if not isinstance(op, dict):
            continue
        name = str(op.get("op") or "").lower()
        path = str(op.get("path") or "").strip().lower()
        value = op.get("value")
        member_ids: list[int] = []
        if isinstance(value, list):
            for item in value:
                raw = item.get("value") if isinstance(item, dict) else item
                if str(raw).isdigit():
                    member_ids.append(int(raw))
        if path.startswith("members") or path == "":
            if name in ("add", "replace"):
                for uid in member_ids:
                    store.update_user_profile(uid, role=role)
            elif name == "remove":
                for uid in member_ids:
                    row = store.get_user_row(uid)
                    if row and row["role"] == role:
                        store.update_user_profile(uid, role="viewer")
    activity_log.record(
        "scim_group_patch", actor=admin.username, actor_role=admin.role,
        detail=f"SCIM patched group {role}",
        meta={"group": role},
    )
    members = [u for u in store.list_users() if u["role"] == role]
    return ScimJSONResponse(_group_resource(request, role, members))
