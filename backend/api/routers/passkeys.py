"""WebAuthn passkeys — step-up auth for viewing original email content.

Login still uses username/password, then a WebAuthn passkey on every sign-in.
A registered passkey is also required to download/render the EML. AI assessment
on the feed is not gated here.
"""
from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from backend.config import get_settings

from .. import activity_log
from ..auth_store import User
from ..deps import get_auth_store, get_current_user, presented_token
from ..tokens import session_key
from .. import feed_builder

router = APIRouter(prefix="/api")
_log = logging.getLogger("backend.api.passkeys")

_RP_NAME = "SEGS"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_UNUSABLE_RP_MARKERS = (
    ".elb.amazonaws.com",
    ".elb.amazonaws.com.cn",
    ".execute-api.",
)


def _session_token(request: Request) -> str:
    token = presented_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="not authenticated")
    key = session_key(token)
    if not key:
        raise HTTPException(status_code=401, detail="not authenticated")
    return key


def _origin(scheme: str, host: str, port: int | None) -> str:
    origin = f"{scheme}://{host}"
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        origin = f"{origin}:{port}"
    return origin


def _parse_origin(value: str) -> tuple[str, str] | None:
    raw = (value or "").strip()
    if not raw or raw.lower() == "null":
        return None
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    host = parsed.hostname.lower().strip("[]")
    return host, f"{parsed.scheme}://{parsed.netloc}"


def _usable_rp_host(host: str) -> bool:
    h = (host or "").lower().strip("[]")
    if not h or h in _LOOPBACK_HOSTS:
        return False
    if ":" in h:
        return False
    if all(part.isdigit() for part in h.split(".")):
        return False
    return not any(marker in h for marker in _UNUSABLE_RP_MARKERS)


def _rp_origin(request: Request) -> tuple[str, list[str]]:
    """WebAuthn rpId must be a DNS name — never an IP or an ALB hostname.

    The browser origin is https://<cloudfront>. CloudFront talks to the API
    over HTTP on the ALB, so request.url is http://<alb> unless we read the
    viewer Origin / forwarded proto. Using that ALB URL as rpId/origin makes
    Chrome reject create() and py_webauthn reject the attestation.
    """
    host = (request.url.hostname or "localhost").lower().strip("[]")
    port = request.url.port
    scheme = request.url.scheme or "http"
    proto = (
        (request.headers.get("cloudfront-forwarded-proto") or "")
        or (request.headers.get("x-forwarded-proto") or "")
    ).split(",")[0].strip().lower()
    if proto in ("http", "https"):
        scheme = proto
    elif get_settings().cookie_secure and host not in _LOOPBACK_HOSTS:
        scheme = "https"

    if host in _LOOPBACK_HOSTS:
        return "localhost", [
            _origin(scheme, "localhost", port),
            _origin(scheme, "127.0.0.1", port),
        ]

    page = _parse_origin(request.headers.get("origin") or "")
    public = _parse_origin((get_settings().public_origin or "").strip())
    xf_host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip().lower()
    if xf_host:
        xf_host = xf_host.split("/")[0].split(":")[0].strip("[]")

    rp_id = ""
    origins: list[str] = []
    if page and _usable_rp_host(page[0]):
        rp_id = page[0]
        origins.append(page[1])
    elif public and _usable_rp_host(public[0]):
        rp_id = public[0]
        origins.append(public[1])
    elif _usable_rp_host(xf_host):
        rp_id = xf_host
        origins.append(_origin(scheme if scheme == "https" else "https", rp_id, None))
    elif _usable_rp_host(host):
        rp_id = host
        origins.append(_origin(scheme, host, port if scheme == "http" else None))
    elif public:
        rp_id = public[0]
        origins.append(public[1])

    if not rp_id:
        raise HTTPException(
            status_code=400,
            detail="passkeys need the console HTTPS hostname (set SEG_PUBLIC_ORIGIN)",
        )

    if public:
        origins.append(public[1])
    https_twin = f"https://{rp_id}"
    if https_twin not in origins:
        origins.append(https_twin)
    return rp_id, list(dict.fromkeys(origins))


def login_webauthn_begin(request: Request, user: User, pending_token: str) -> dict:
    """Password-verified login: assertion if a passkey exists, else enrollment."""
    store = get_auth_store()
    rp_id, _origins = _rp_origin(request)
    if store.passkey_count(user.id) == 0:
        opts = generate_registration_options(
            rp_id=rp_id,
            rp_name=_RP_NAME,
            user_name=user.username,
            user_id=f"user:{user.id}".encode("utf-8"),
            user_display_name=user.username,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
        store.create_pending_login(pending_token, user.id, "enroll")
        store.save_challenge(pending_token, bytes_to_base64url(opts.challenge), "login_enroll")
        return {"mode": "enroll", "options": json.loads(options_to_json(opts))}
    allow = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
        for cid in store.list_passkey_credential_ids(user.id)
    ]
    opts = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    store.create_pending_login(pending_token, user.id, "assert")
    store.save_challenge(pending_token, bytes_to_base64url(opts.challenge), "login_assert")
    return {"mode": "assert", "options": json.loads(options_to_json(opts))}


def login_webauthn_finish(request: Request, user: User, pending_token: str,
                          credential: dict, purpose: str, name: str = "Passkey") -> None:
    store = get_auth_store()
    expected_purpose = "login_enroll" if purpose == "enroll" else "login_assert"
    challenge_b64 = store.pop_challenge(pending_token, expected_purpose)
    if not challenge_b64:
        raise HTTPException(status_code=400, detail="passkey challenge expired — try again")
    rp_id, origins = _rp_origin(request)
    if purpose == "enroll":
        try:
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge_b64),
                expected_rp_id=rp_id,
                expected_origin=origins,
            )
        except Exception as exc:
            _log.warning("login passkey registration verify failed: %s", exc)
            raise HTTPException(status_code=400, detail="passkey registration failed")
        cred_id = bytes_to_base64url(verified.credential_id)
        if store.get_passkey_by_credential_id(cred_id):
            raise HTTPException(status_code=409, detail="this passkey is already registered")
        label = (name or "Passkey").strip() or "Passkey"
        store.add_passkey(
            user.id, cred_id, bytes_to_base64url(verified.credential_public_key),
            verified.sign_count, label,
        )
        return
    cred_id = credential.get("id") or credential.get("rawId")
    if not isinstance(cred_id, str) or not cred_id:
        raise HTTPException(status_code=400, detail="passkey assertion failed")
    record = store.get_passkey_by_credential_id(cred_id)
    if record is None or record["user_id"] != user.id:
        raise HTTPException(status_code=400, detail="unknown passkey")
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=origins,
            credential_public_key=base64url_to_bytes(record["public_key"]),
            credential_current_sign_count=int(record["sign_count"]),
        )
    except Exception as exc:
        _log.warning("login passkey assertion verify failed: %s", exc)
        raise HTTPException(status_code=400, detail="passkey assertion failed")
    store.update_passkey_sign_count(record["id"], verified.new_sign_count)


def _unlock_for_queue(store, token: str, queue_id: str) -> str:
    thread_key = feed_builder.preferred_unlock_key(queue_id) if queue_id else "*"
    store.unlock_content(token, thread_key)
    return thread_key


class CredentialBody(BaseModel):
    credential: dict = Field(min_length=1)
    name: str = Field(default="Passkey", max_length=64)
    unlock: bool = False
    queue_id: str = Field(default="", max_length=256)


@router.get("/auth/passkeys")
def list_passkeys(user: User = Depends(get_current_user)):
    store = get_auth_store()
    return {"passkeys": store.list_passkeys(user.id)}


@router.post("/auth/passkeys/register/options")
def register_options(request: Request, user: User = Depends(get_current_user)):
    store = get_auth_store()
    rp_id, _origins = _rp_origin(request)
    exclude = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
        for cid in store.list_passkey_credential_ids(user.id)
    ]
    opts = generate_registration_options(
        rp_id=rp_id,
        rp_name=_RP_NAME,
        user_name=user.username,
        user_id=f"user:{user.id}".encode("utf-8"),
        user_display_name=user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=exclude or None,
    )
    store.save_challenge(_session_token(request), bytes_to_base64url(opts.challenge), "register")
    return json.loads(options_to_json(opts))


@router.post("/auth/passkeys/register")
def register(body: CredentialBody, request: Request, user: User = Depends(get_current_user)):
    store = get_auth_store()
    token = _session_token(request)
    challenge_b64 = store.pop_challenge(token, "register")
    if not challenge_b64:
        raise HTTPException(status_code=400, detail="registration challenge expired — try again")
    rp_id, origins = _rp_origin(request)
    try:
        verified = verify_registration_response(
            credential=body.credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=origins,
        )
    except Exception as exc:
        _log.warning("passkey registration verify failed: %s", exc)
        raise HTTPException(status_code=400, detail="passkey registration failed")
    cred_id = bytes_to_base64url(verified.credential_id)
    if store.get_passkey_by_credential_id(cred_id):
        raise HTTPException(status_code=409, detail="this passkey is already registered")
    name = (body.name or "Passkey").strip() or "Passkey"
    pk_id = store.add_passkey(
        user.id, cred_id, bytes_to_base64url(verified.credential_public_key),
        verified.sign_count, name,
    )
    unlocked = False
    thread_key = ""
    if body.unlock:
        thread_key = _unlock_for_queue(store, token, body.queue_id)
        unlocked = True
    activity_log.record(
        "passkey_register", actor=user.username, actor_role=user.role,
        detail=f"Registered passkey {name}",
        meta={"passkey_id": pk_id},
    )
    return {"ok": True, "id": pk_id, "content_unlocked": unlocked, "thread_key": thread_key}


@router.post("/auth/passkeys/assert/options")
def assert_options(request: Request, user: User = Depends(get_current_user)):
    store = get_auth_store()
    if store.passkey_count(user.id) == 0:
        raise HTTPException(status_code=400, detail="no passkey registered")
    rp_id, _origins = _rp_origin(request)
    allow = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
        for cid in store.list_passkey_credential_ids(user.id)
    ]
    opts = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    store.save_challenge(_session_token(request), bytes_to_base64url(opts.challenge), "assert")
    return json.loads(options_to_json(opts))


@router.post("/auth/passkeys/assert")
def assert_passkey(body: CredentialBody, request: Request, user: User = Depends(get_current_user)):
    store = get_auth_store()
    token = _session_token(request)
    challenge_b64 = store.pop_challenge(token, "assert")
    if not challenge_b64:
        raise HTTPException(status_code=400, detail="unlock challenge expired — try again")
    cred_id = body.credential.get("id") or body.credential.get("rawId")
    if not isinstance(cred_id, str) or not cred_id:
        raise HTTPException(status_code=400, detail="passkey assertion failed")
    record = store.get_passkey_by_credential_id(cred_id)
    if record is None or record["user_id"] != user.id:
        raise HTTPException(status_code=400, detail="unknown passkey")
    rp_id, origins = _rp_origin(request)
    try:
        verified = verify_authentication_response(
            credential=body.credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=origins,
            credential_public_key=base64url_to_bytes(record["public_key"]),
            credential_current_sign_count=int(record["sign_count"]),
        )
    except Exception as exc:
        _log.warning("passkey assertion verify failed: %s", exc)
        raise HTTPException(status_code=400, detail="passkey assertion failed")
    store.update_passkey_sign_count(record["id"], verified.new_sign_count)
    thread_key = _unlock_for_queue(store, token, body.queue_id)
    meta = activity_log.resolve_email(body.queue_id or "")
    phrase = activity_log.email_phrase(meta)
    activity_log.record(
        "passkey_unlock", actor=user.username, actor_role=user.role,
        detail=f"Unlocked original of {phrase} with passkey",
        meta={**meta, "thread_key": thread_key},
    )
    return {"ok": True, "content_unlocked": True, "thread_key": thread_key}


@router.post("/auth/passkeys/lock")
def lock_content(request: Request, user: User = Depends(get_current_user)):
    store = get_auth_store()
    store.lock_content(_session_token(request))
    return {"ok": True, "content_unlocked": False}


@router.delete("/auth/passkeys/{passkey_id}")
def delete_passkey(passkey_id: int, user: User = Depends(get_current_user)):
    store = get_auth_store()
    if not store.delete_passkey(user.id, passkey_id):
        raise HTTPException(status_code=404, detail="passkey not found")
    activity_log.record(
        "passkey_delete", actor=user.username, actor_role=user.role,
        detail=f"Removed passkey {passkey_id}",
        meta={"passkey_id": passkey_id},
    )
    return {"ok": True}
