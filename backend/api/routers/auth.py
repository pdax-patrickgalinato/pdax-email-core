"""Auth endpoints: first-run setup wizard, login/logout, current-user info,
and Admin-only user management.

Login is password then WebAuthn (every sign-in). Sessions are stateful JWTs
(RFC 7519 / RFC 9068) presented as an HttpOnly cookie or RFC 6750 Bearer.
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import activity_log
from ..auth_store import ROLES, User, get_default_store
from ..deps import SESSION_COOKIE_NAME, get_auth_store, get_current_user, presented_token, require_role
from ..security import ip_login_limiter, username_lockout
from ..tokens import SESSION_TTL_SECONDS, session_key
from backend.config import get_settings
from .passkeys import login_webauthn_begin, login_webauthn_finish

# Set SEG_COOKIE_SECURE=1 when the app is served over HTTPS (behind a TLS
# reverse proxy). Keeps the flag off for plain HTTP localhost development.
_COOKIE_SECURE = get_settings().cookie_secure

router = APIRouter(prefix="/api")
_store = get_default_store()


# Safe username pattern: alphanumeric, dots, underscores, hyphens, and @ only.
# This prevents YAML injection when the username is written into config files
# (enforcement.yaml, slack_config.yaml, notify_config.yaml) as the "updated_by"
# field, and prevents shell/path special characters from reaching log entries.
_USERNAME_PATTERN = r'^[a-zA-Z0-9._@\-]+$'


class SetupRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=_USERNAME_PATTERN)
    password: str = Field(min_length=8, max_length=256)


class LoginRequest(BaseModel):
    # Length limits prevent DoS via oversized PBKDF2 computation.
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)


class LoginWebauthnRequest(BaseModel):
    login_token: str = Field(min_length=8, max_length=256)
    credential: dict = Field(min_length=1)
    name: str = Field(default="Passkey", max_length=64)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=_USERNAME_PATTERN)
    password: str = Field(min_length=8, max_length=256)
    role: str


class ResetPasswordRequest(BaseModel):
    password: str = Field(min_length=8, max_length=256)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=8, max_length=256)


def _user_out(user: User) -> dict:
    return {"username": user.username, "role": user.role}


def _issue_session(response: Response, user: User) -> dict:
    token = _store.create_session(user.id)
    response.set_cookie(
        SESSION_COOKIE_NAME, token,
        httponly=True, samesite="strict", secure=_COOKIE_SECURE, path="/",
    )
    return {
        **_user_out(user),
        "token_type": "Bearer",
        "access_token": token,
        "expires_in": SESSION_TTL_SECONDS,
    }


@router.get("/setup/status")
def setup_status(request: Request):
    ip = request.client.host if request.client else "unknown"
    if ip_login_limiter.is_limited(ip):
        raise HTTPException(status_code=429, detail="too many requests")
    return {"needs_setup": _store.user_count() == 0}


@router.post("/setup")
def setup(body: SetupRequest, request: Request, response: Response):
    # 404s once any user exists — the wizard is a one-time, first-run-only
    # path, not a general "create admin" endpoint (that's POST /api/users,
    # admin-gated, below).
    if _store.user_count() > 0:
        raise HTTPException(status_code=404, detail="not found")
    ip = request.client.host if request.client else "unknown"
    if ip_login_limiter.is_limited(ip):
        raise HTTPException(status_code=429, detail="too many requests")
    try:
        user = _store.create_user(body.username, body.password, role="admin")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    activity_log.record(
        "setup", actor=user.username, actor_role=user.role,
        detail="Created initial admin account",
    )
    return _issue_session(response, user)


@router.post("/auth/login")
def login(body: LoginRequest, request: Request):
    ip = request.client.host if request.client else "unknown"

    # IP-level throttle — catches credential spray from one source.
    if ip_login_limiter.is_limited(ip):
        activity_log.record(
            "login_failed", actor=body.username.strip() or "(blank)",
            detail=f"Rate-limited (IP {ip})",
        )
        raise HTTPException(status_code=429, detail="too many requests")

    # Per-username lockout — protects individual accounts from distributed spray.
    username_key = body.username.lower().strip()
    if username_lockout.is_limited(username_key):
        activity_log.record(
            "login_failed", actor=body.username.strip() or "(blank)",
            detail="Account temporarily locked after repeated failures",
        )
        raise HTTPException(status_code=429, detail="too many requests")

    user = _store.verify_password(body.username, body.password)
    if user is None:
        activity_log.record(
            "login_failed", actor=body.username.strip() or "(blank)",
            detail="Invalid username or password",
        )
        raise HTTPException(status_code=401, detail="invalid username or password")

    # Successful password step — clear lockout counters; session waits on WebAuthn.
    ip_login_limiter.clear(ip)
    username_lockout.clear(username_key)

    pending = secrets.token_urlsafe(24)
    mfa = login_webauthn_begin(request, user, pending)
    activity_log.record(
        "login_mfa", actor=user.username, actor_role=user.role,
        detail=f"Password accepted; WebAuthn {mfa.get('mode')} required",
    )
    return {"mfa": "webauthn", "login_token": pending, **mfa}


@router.post("/auth/login/webauthn")
def login_webauthn(body: LoginWebauthnRequest, request: Request, response: Response):
    pending = _store.get_pending_login(body.login_token)
    if pending is None:
        raise HTTPException(status_code=400, detail="passkey challenge expired — sign in again")
    user = _store.get_user_by_id(pending["user_id"])
    if user is None or user.disabled:
        _store.delete_pending_login(body.login_token)
        raise HTTPException(status_code=401, detail="invalid username or password")
    login_webauthn_finish(
        request, user, body.login_token, body.credential, pending["purpose"], body.name,
    )
    _store.delete_pending_login(body.login_token)
    activity_log.record(
        "login", actor=user.username, actor_role=user.role,
        detail="Session started after passkey",
    )
    return _issue_session(response, user)


@router.post("/auth/logout")
def logout(request: Request, response: Response, user: User = Depends(get_current_user)):
    token = presented_token(request)
    if token:
        _store.delete_session(token)
    else:
        _store.delete_all_sessions_for_user(user.id)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    activity_log.record(
        "logout", actor=user.username, actor_role=user.role,
        detail="Session revoked",
    )
    return {"ok": True}


@router.get("/auth/me")
def me(request: Request, user: User = Depends(get_current_user)):
    store = get_auth_store()
    key = session_key(presented_token(request))
    return {
        "id": str(user.id),
        "username": user.username,
        "role": user.role,
        "passkey_count": store.passkey_count(user.id),
        "content_unlocked": store.is_content_unlocked(key),
        "content_unlocked_thread": store.unlocked_thread(key),
    }


@router.post("/auth/password")
def change_own_password(
    body: ChangePasswordRequest,
    request: Request,
    user: User = Depends(get_current_user),
):
    """Self-service password change. Requires the current password; keeps this session."""
    if _store.verify_password(user.username, body.current_password) is None:
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if body.current_password == body.new_password:
        raise HTTPException(status_code=422, detail="New password must be different from the current password")
    try:
        _store.set_password(user.id, body.new_password, keep_token=presented_token(request))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    activity_log.record(
        "password_change", actor=user.username, actor_role=user.role,
        detail="Changed own password",
    )
    return {"ok": True}


# --- Admin-only user management ---------------------------------------------

@router.get("/users")
def list_users(_: User = Depends(require_role("admin"))):
    return _store.list_users()


@router.post("/users")
def create_user(body: CreateUserRequest, admin: User = Depends(require_role("admin"))):
    if body.role not in ROLES:
        raise HTTPException(status_code=422, detail=f"role must be one of {ROLES}")
    try:
        user = _store.create_user(body.username, body.password, body.role)
    except Exception as e:
        # Return a safe message; don't leak raw SQLite exception strings (schema details).
        msg = "Username already exists" if "UNIQUE" in str(e) else "Could not create user"
        raise HTTPException(status_code=409, detail=msg)
    activity_log.record(
        "user_create", actor=admin.username, actor_role=admin.role,
        detail=f"Created {user.username} with role {user.role}",
        meta={"target_user": user.username, "role": user.role},
    )
    return _user_out(user)


@router.delete("/users/{user_id}")
def delete_user(user_id: int, current: User = Depends(require_role("admin"))):
    if user_id == current.id:
        raise HTTPException(status_code=400, detail="cannot delete your own account")
    target = _store.get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="user not found")
    _store.delete_user(user_id)
    activity_log.record(
        "user_delete", actor=current.username, actor_role=current.role,
        detail=f"Deleted user {target.username} (was {target.role})",
        meta={"target_user": target.username},
    )
    return {"ok": True}


@router.post("/users/{user_id}/password")
def reset_password(
    user_id: int,
    body: ResetPasswordRequest,
    admin: User = Depends(require_role("admin")),
):
    """Admin-only: set any user's password and revoke their sessions."""
    target = _store.get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="user not found")
    try:
        _store.set_password(user_id, body.password)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    activity_log.record(
        "password_reset", actor=admin.username, actor_role=admin.role,
        detail=f"Reset password for {target.username}",
        meta={"target_user": target.username},
    )
    return {"ok": True, "username": target.username}
