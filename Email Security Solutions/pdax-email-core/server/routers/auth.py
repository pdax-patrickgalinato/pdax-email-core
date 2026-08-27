"""Auth endpoints: first-run setup wizard, login/logout, current-user info,
and Admin-only user management. See server/auth_store.py for the storage
layer and server/deps.py for the require_role gating pattern reused by
every other router from here on.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import activity_log
from ..auth_store import ROLES, User, get_default_store
from ..deps import SESSION_COOKIE_NAME, get_current_user, require_role
from ..security import ip_login_limiter, username_lockout

# Set SEG_COOKIE_SECURE=1 when the app is served over HTTPS (behind a TLS
# reverse proxy). Keeps the flag off for plain HTTP localhost development.
_COOKIE_SECURE = os.getenv("SEG_COOKIE_SECURE", "").strip() in ("1", "true", "yes")

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


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=_USERNAME_PATTERN)
    password: str = Field(min_length=8, max_length=256)
    role: str


class ResetPasswordRequest(BaseModel):
    password: str = Field(min_length=8, max_length=256)


def _user_out(user: User) -> dict:
    return {"username": user.username, "role": user.role}


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
    user = _store.create_user(body.username, body.password, role="admin")
    token = _store.create_session(user.id)
    response.set_cookie(
        SESSION_COOKIE_NAME, token,
        httponly=True, samesite="strict", secure=_COOKIE_SECURE,
    )
    activity_log.record(
        "setup", actor=user.username, actor_role=user.role,
        detail="Created initial admin account",
    )
    return _user_out(user)


@router.post("/auth/login")
def login(body: LoginRequest, request: Request, response: Response):
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

    # Successful login — clear lockout counters.
    ip_login_limiter.clear(ip)
    username_lockout.clear(username_key)

    token = _store.create_session(user.id)
    response.set_cookie(
        SESSION_COOKIE_NAME, token,
        httponly=True, samesite="strict", secure=_COOKIE_SECURE,
    )
    activity_log.record(
        "login", actor=user.username, actor_role=user.role,
        detail="Session started",
    )
    return _user_out(user)


@router.post("/auth/logout")
def logout(response: Response, user: User = Depends(get_current_user)):
    # Session token isn't available here directly (only the resolved user
    # is) — deleting all of this user's sessions is a safe, simple logout;
    # a single-session-only logout would need the raw cookie value threaded
    # through instead, not worth the extra plumbing for a local admin tool.
    _store.delete_all_sessions_for_user(user.id)
    response.delete_cookie(SESSION_COOKIE_NAME)
    activity_log.record(
        "logout", actor=user.username, actor_role=user.role,
        detail="All sessions revoked",
    )
    return {"ok": True}


@router.get("/auth/me")
def me(user: User = Depends(get_current_user)):
    return _user_out(user)


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
