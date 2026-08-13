"""Shared FastAPI dependencies — current-user extraction and role gating.

get_current_user resolves the session cookie via server/auth_store.py.
require_role(*roles) is a dependency factory: 401s if unauthenticated, 403s
if the current user's role isn't in `roles`. Applied per-route by every
router from Phase 11 onward (policy write = admin only; quarantine actions
= admin/analyst; read-only endpoints = any logged-in role).
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from .auth_store import User, get_default_store

SESSION_COOKIE_NAME = "seg_session"

_store = get_default_store()


def get_auth_store():
    return _store


def get_current_user(request: Request) -> User:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    user = _store.resolve_session(token) if token else None
    if user is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user


def get_current_user_optional(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    return _store.resolve_session(token) if token else None


def require_role(*roles: str):
    """FastAPI dependency factory. Usage: Depends(require_role("admin"))."""
    def _dependency(user: User = Depends(get_current_user)) -> User:
        if not user.has_role(*roles):
            raise HTTPException(status_code=403, detail="insufficient role")
        return user
    return _dependency
