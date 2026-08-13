"""Auth endpoints: first-run setup wizard, login/logout, current-user info,
and Admin-only user management. See server/auth_store.py for the storage
layer and server/deps.py for the require_role gating pattern reused by
every other router from here on.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from ..auth_store import ROLES, User, get_default_store
from ..deps import SESSION_COOKIE_NAME, get_current_user, require_role

router = APIRouter(prefix="/api")
_store = get_default_store()


class SetupRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    role: str


def _user_out(user: User) -> dict:
    return {"username": user.username, "role": user.role}


@router.get("/setup/status")
def setup_status():
    return {"needs_setup": _store.user_count() == 0}


@router.post("/setup")
def setup(body: SetupRequest, response: Response):
    # 404s once any user exists — the wizard is a one-time, first-run-only
    # path, not a general "create admin" endpoint (that's POST /api/users,
    # admin-gated, below).
    if _store.user_count() > 0:
        raise HTTPException(status_code=404, detail="setup already completed")
    user = _store.create_user(body.username, body.password, role="admin")
    token = _store.create_session(user.id)
    response.set_cookie(SESSION_COOKIE_NAME, token, httponly=True, samesite="lax")
    return _user_out(user)


@router.post("/auth/login")
def login(body: LoginRequest, response: Response):
    user = _store.verify_password(body.username, body.password)
    if user is None:
        raise HTTPException(status_code=401, detail="invalid username or password")
    token = _store.create_session(user.id)
    response.set_cookie(SESSION_COOKIE_NAME, token, httponly=True, samesite="lax")
    return _user_out(user)


@router.post("/auth/logout")
def logout(response: Response, user: User = Depends(get_current_user)):
    # Session token isn't available here directly (only the resolved user
    # is) — deleting all of this user's sessions is a safe, simple logout;
    # a single-session-only logout would need the raw cookie value threaded
    # through instead, not worth the extra plumbing for a local admin tool.
    _store.delete_all_sessions_for_user(user.id)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"ok": True}


@router.get("/auth/me")
def me(user: User = Depends(get_current_user)):
    return _user_out(user)


# --- Admin-only user management ---------------------------------------------

@router.get("/users")
def list_users(_: User = Depends(require_role("admin"))):
    return _store.list_users()


@router.post("/users")
def create_user(body: CreateUserRequest, _: User = Depends(require_role("admin"))):
    if body.role not in ROLES:
        raise HTTPException(status_code=422, detail=f"role must be one of {ROLES}")
    try:
        user = _store.create_user(body.username, body.password, body.role)
    except Exception as e:
        # UNIQUE constraint on username is the realistic failure here.
        raise HTTPException(status_code=409, detail=f"could not create user: {e}")
    return _user_out(user)


@router.delete("/users/{user_id}")
def delete_user(user_id: int, current: User = Depends(require_role("admin"))):
    if user_id == current.id:
        raise HTTPException(status_code=400, detail="cannot delete your own account")
    _store.delete_user(user_id)
    return {"ok": True}
