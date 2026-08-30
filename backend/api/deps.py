"""Shared FastAPI dependencies — current-user extraction and role gating.

get_current_user resolves a stateful JWT (RFC 6750 Bearer or session cookie)
via auth_store. require_role(*roles) is a dependency factory: 401s if
unauthenticated, 403s if the current user's role isn't in `roles`.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from .auth_store import User, get_default_store
from .tokens import session_key

SESSION_COOKIE_NAME = "seg_session"
WWW_AUTHENTICATE = 'Bearer realm="SEGS", error="invalid_token"'

_store = get_default_store()
_correlation_store = None


def get_auth_store():
    return _store


def set_correlation_store(store) -> None:
    global _correlation_store
    _correlation_store = store


def get_correlation_store():
    return _correlation_store


def presented_token(request: Request) -> str:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return request.cookies.get(SESSION_COOKIE_NAME) or ""


def session_lookup_key(request: Request) -> str:
    return session_key(presented_token(request))


def get_current_user(request: Request) -> User:
    token = presented_token(request)
    user = _store.resolve_session(token) if token else None
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="not authenticated",
            headers={"WWW-Authenticate": WWW_AUTHENTICATE},
        )
    return user


def get_current_user_optional(request: Request):
    token = presented_token(request)
    return _store.resolve_session(token) if token else None


def require_role(*roles: str):
    """FastAPI dependency factory. Usage: Depends(require_role("admin"))."""
    def _dependency(user: User = Depends(get_current_user)) -> User:
        if not user.has_role(*roles):
            raise HTTPException(status_code=403, detail="insufficient role")
        return user
    return _dependency
