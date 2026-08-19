"""Real-data feed + quarantine action endpoints — Phase 12 of the
dashboard-overhaul plan. Analyst actions wrap app/disposition.py's existing
functions directly (list_spool_entries/release_from_quarantine/keep_blocked/
reevaluate_spool_entry) rather than reimplementing spool-management logic.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from .. import activity_log, feed_builder
from ..auth_store import User
from ..deps import get_correlation_store, require_role
from app import disposition

router = APIRouter(prefix="/api")

_SPOOL_ROOT = Path(__file__).resolve().parents[2] / "gateway" / "spool"


@router.get("/feed")
def get_feed(_: User = Depends(require_role("admin", "analyst", "viewer"))):
    return {"entries": feed_builder.build_feed()}


@router.post("/feed/refresh")
def refresh_feed(_: User = Depends(require_role("admin", "analyst", "viewer"))):
    return {"entries": feed_builder.build_feed(force=True, correlation_store=get_correlation_store())}


@router.get("/audit")
def get_audit(_: User = Depends(require_role("admin", "analyst", "viewer"))):
    """Gateway shadow decisions + console activity (logins, user admin, triage)."""
    return {"entries": feed_builder.combined_audit_entries()}


@router.post("/quarantine/{queue_id}/release")
def release(queue_id: str, user: User = Depends(require_role("admin", "analyst"))):
    try:
        dest = disposition.release_from_quarantine(_SPOOL_ROOT, queue_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    feed_builder.build_feed(force=True, correlation_store=get_correlation_store())
    activity_log.record(
        "quarantine_release", actor=user.username, actor_role=user.role,
        detail=f"Released queue {queue_id} → {dest.parent.name}/{dest.name}",
        meta={"queue_id": queue_id, "bucket": dest.parent.name},
    )
    return {"queue_id": dest.name, "bucket": dest.parent.name}


@router.post("/quarantine/{queue_id}/keep-blocked")
def keep_blocked(queue_id: str, user: User = Depends(require_role("admin", "analyst"))):
    try:
        dest = disposition.keep_blocked(_SPOOL_ROOT, queue_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    feed_builder.build_feed(force=True, correlation_store=get_correlation_store())
    activity_log.record(
        "quarantine_keep_blocked", actor=user.username, actor_role=user.role,
        detail=f"Kept blocked queue {queue_id} → {dest.parent.name}/{dest.name}",
        meta={"queue_id": queue_id, "bucket": dest.parent.name},
    )
    return {"queue_id": dest.name, "bucket": dest.parent.name}


@router.post("/quarantine/{queue_id}/reevaluate")
def reevaluate(queue_id: str, user: User = Depends(require_role("admin", "analyst"))):
    try:
        # Uses dashboard_content_provider() (GLM when credentials exist).
        result = disposition.reevaluate_spool_entry(
            _SPOOL_ROOT, queue_id, content_provider=feed_builder.dashboard_content_provider())
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    feed_builder.build_feed(force=True, correlation_store=get_correlation_store())
    verdict = (result or {}).get("verdict") if isinstance(result, dict) else None
    activity_log.record(
        "quarantine_reevaluate", actor=user.username, actor_role=user.role,
        detail=f"Re-evaluated queue {queue_id}" + (f" → {verdict}" if verdict else ""),
        meta={"queue_id": queue_id, "verdict": verdict},
    )
    return result


@router.get("/quarantine/{queue_id}/download")
def download(queue_id: str, user: User = Depends(require_role("admin", "analyst"))):
    try:
        entries = [e for e in disposition.list_spool_entries(_SPOOL_ROOT) if e["queue_id"] == queue_id]
        if not entries:
            raise FileNotFoundError(queue_id)
        entry = entries[0]
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    eml_path = Path(entry["path"]) / "message.eml"
    if not eml_path.is_file():
        raise HTTPException(status_code=404, detail="message.eml not found for this entry")
    activity_log.record(
        "quarantine_download", actor=user.username, actor_role=user.role,
        detail=f"Downloaded {queue_id}.eml",
        meta={"queue_id": queue_id},
    )
    return FileResponse(str(eml_path), media_type="message/rfc822",
                        filename=f"{queue_id}.eml")
