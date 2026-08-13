"""Real-data feed + quarantine action endpoints — Phase 12 of the
dashboard-overhaul plan. Analyst actions wrap app/disposition.py's existing
functions directly (list_spool_entries/release_from_quarantine/keep_blocked/
reevaluate_spool_entry) rather than reimplementing spool-management logic.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from .. import feed_builder
from ..auth_store import User
from ..deps import require_role
from app import disposition

router = APIRouter(prefix="/api")

_SPOOL_ROOT = Path(__file__).resolve().parents[2] / "gateway" / "spool"


@router.get("/feed")
def get_feed(_: User = Depends(require_role("admin", "analyst", "viewer"))):
    return {"entries": feed_builder.build_feed()}


@router.post("/feed/refresh")
def refresh_feed(_: User = Depends(require_role("admin", "analyst", "viewer"))):
    return {"entries": feed_builder.build_feed(force=True)}


@router.get("/audit")
def get_audit(_: User = Depends(require_role("admin", "analyst", "viewer"))):
    return {"entries": feed_builder.shadow_log_entries()}


@router.post("/quarantine/{queue_id}/release")
def release(queue_id: str, _: User = Depends(require_role("admin", "analyst"))):
    try:
        dest = disposition.release_from_quarantine(_SPOOL_ROOT, queue_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    feed_builder.build_feed(force=True)
    return {"queue_id": dest.name, "bucket": dest.parent.name}


@router.post("/quarantine/{queue_id}/keep-blocked")
def keep_blocked(queue_id: str, _: User = Depends(require_role("admin", "analyst"))):
    try:
        dest = disposition.keep_blocked(_SPOOL_ROOT, queue_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    feed_builder.build_feed(force=True)
    return {"queue_id": dest.name, "bucket": dest.parent.name}


@router.post("/quarantine/{queue_id}/reevaluate")
def reevaluate(queue_id: str, _: User = Depends(require_role("admin", "analyst"))):
    try:
        # Forced HeuristicProvider — same dashboard cost-guard as
        # feed_builder.run_samples(); clicking "re-evaluate" must never
        # trigger a surprise paid LLM call.
        result = disposition.reevaluate_spool_entry(
            _SPOOL_ROOT, queue_id, content_provider=feed_builder.dashboard_content_provider())
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    feed_builder.build_feed(force=True)
    return result


@router.get("/quarantine/{queue_id}/download")
def download(queue_id: str, _: User = Depends(require_role("admin", "analyst"))):
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
    return FileResponse(str(eml_path), media_type="message/rfc822",
                        filename=f"{queue_id}.eml")
