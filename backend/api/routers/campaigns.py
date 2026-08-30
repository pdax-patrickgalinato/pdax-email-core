"""Read-only phishing-campaign clusters for the console.

Built by the campaign worker from spool copies. Any authenticated role can
read — same bar as the live feed and sender profiles.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.stores.campaign import get_default_store
from ..auth_store import User
from ..deps import require_role

router = APIRouter(prefix="/api")


@router.get("/campaigns")
def list_campaigns(
    _: User = Depends(require_role("admin", "analyst", "viewer")),
    limit: int = Query(100, ge=1, le=200),
):
    try:
        items = get_default_store().list_campaigns(limit=limit)
    except Exception:
        items = []
    flagged = sum(1 for c in items if int(c.get("flagged") or 0) > 0)
    return {
        "campaigns": items,
        "total": len(items),
        "flagged": flagged,
    }


@router.get("/campaigns/by-id")
def get_campaign(
    id: str = Query(..., min_length=4, max_length=40),
    _: User = Depends(require_role("admin", "analyst", "viewer")),
):
    try:
        item = get_default_store().get_campaign(id)
    except Exception:
        item = None
    if not item:
        raise HTTPException(status_code=404, detail="campaign not found")
    return item
