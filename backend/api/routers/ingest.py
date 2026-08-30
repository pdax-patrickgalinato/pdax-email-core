"""Admin toggle for inbound Gmail fetch — GET/PUT /api/ingest.

When fetch is off the poll worker skips Gmail API history, but static and
content-AI workers keep processing copies already in the spool.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import activity_log
from ..auth_store import User
from ..deps import require_role
from ..security import admin_write_limiter
from backend.stores import ingest_control

router = APIRouter(prefix="/api")


class IngestUpdate(BaseModel):
    gmail_fetch: bool


@router.get("/ingest")
def get_ingest(_: User = Depends(require_role("admin", "analyst", "viewer"))):
    return ingest_control.gmail_fetch_snapshot()


@router.put("/ingest")
def set_ingest(body: IngestUpdate, user: User = Depends(require_role("admin"))):
    if admin_write_limiter.is_limited(user.username):
        raise HTTPException(status_code=429, detail="Too many settings writes — wait one minute")
    snap = ingest_control.set_gmail_fetch(body.gmail_fetch, actor=user.username)
    activity_log.record(
        "gmail_fetch_resume" if snap["gmail_fetch"] else "gmail_fetch_pause",
        actor=user.username,
        actor_role=user.role,
        detail=("Gmail fetch on" if snap["gmail_fetch"]
                else "Gmail fetch paused — pipeline keeps assessing existing mail"),
        meta={"gmail_fetch": snap["gmail_fetch"]},
    )
    return snap
