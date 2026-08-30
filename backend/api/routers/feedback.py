"""Analyst feedback: mark mail benign, export/import the good-indicator pack."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from backend.stores import feedback as feedback_mod
from backend.paths import SPOOL_DIR
from backend.api import activity_log, feed_builder
from backend.api.auth_store import User
from backend.api.deps import require_role
from backend.api.security import assert_within_root, validate_queue_id

router = APIRouter(prefix="/api/feedback", tags=["feedback"])

_SPOOL_ROOT = SPOOL_DIR
_BUCKETS = ("gmail", "quarantine", "released", "rejected")


class BenignBody(BaseModel):
    queue_id: str = Field(min_length=1, max_length=128)
    note: Optional[str] = ""


class ImportBody(BaseModel):
    pack: dict


def _find_entry(queue_id: str) -> Path:
    validate_queue_id(queue_id)
    root = Path(_SPOOL_ROOT)
    for bucket in _BUCKETS:
        dest = root / bucket / queue_id
        if dest.is_dir() and (dest / "meta.json").is_file():
            assert_within_root(dest, root)
            return dest
    raise HTTPException(status_code=404, detail="entry not found")


def _read_meta(dest: Path) -> dict:
    try:
        return json.loads((dest / "meta.json").read_text(encoding="utf-8"))
    except Exception:
        return {}


def _patch_meta(dest: Path, updates: dict) -> dict:
    meta = _read_meta(dest)
    meta.update(updates)
    (dest / "meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return meta


@router.post("/benign")
def mark_benign(body: BenignBody, user: User = Depends(require_role("admin", "analyst"))):
    dest = _find_entry(body.queue_id)
    meta = _read_meta(dest)
    raw = None
    eml = dest / "message.eml"
    if eml.is_file():
        raw = eml.read_bytes()
    recorded = feedback_mod.record_benign(
        queue_id=body.queue_id,
        meta=meta,
        raw=raw,
        actor=user.username,
        note=body.note or "",
    )
    _patch_meta(dest, {
        "analyst_label": "benign",
        "analyst_label_by": user.username,
        "analyst_label_ts": recorded["ts"],
        "analyst_label_note": (body.note or "")[:500],
    })
    feed_builder.build_feed()
    meta = activity_log.resolve_email(
        body.queue_id,
        subject=str(meta.get("subject") or ""),
        from_addr=str(meta.get("from") or ""),
    )
    phrase = activity_log.email_phrase(meta)
    activity_log.record(
        "feedback_benign",
        actor=user.username,
        actor_role=user.role,
        detail=f"Marked {phrase} as not malicious",
        meta=meta,
    )
    return recorded


@router.delete("/benign/{queue_id}")
def unmark_benign(queue_id: str, user: User = Depends(require_role("admin", "analyst"))):
    dest = _find_entry(queue_id)
    feedback_mod.remove_label(queue_id)
    _patch_meta(dest, {
        "analyst_label": "",
        "analyst_label_by": "",
        "analyst_label_ts": "",
        "analyst_label_note": "",
    })
    feed_builder.build_feed()
    meta = activity_log.resolve_email(queue_id)
    phrase = activity_log.email_phrase(meta)
    activity_log.record(
        "feedback_benign_undo",
        actor=user.username,
        actor_role=user.role,
        detail=f"Removed benign label from {phrase}",
        meta=meta,
    )
    return {"queue_id": queue_id, "label": None}


@router.get("/indicators")
def get_indicators(_: User = Depends(require_role("admin", "analyst", "viewer"))):
    pack = feedback_mod.load_pack()
    return {
        "updated_at": pack.get("updated_at"),
        "count": len(pack.get("indicators") or []),
        "indicators": pack.get("indicators") or [],
    }


@router.get("/export")
def export_pack(_: User = Depends(require_role("admin", "analyst"))):
    pack = feedback_mod.load_pack()
    return JSONResponse(
        content=pack,
        headers={"Content-Disposition": 'attachment; filename="good_indicators.json"'},
    )


@router.post("/import")
def import_pack(body: ImportBody, user: User = Depends(require_role("admin"))):
    try:
        pack = feedback_mod.import_pack(body.pack, actor=user.username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    activity_log.record(
        "feedback_import",
        actor=user.username,
        actor_role=user.role,
        detail=f"Imported good-mail pack ({len(pack.get('indicators') or [])} indicators)",
    )
    return pack
