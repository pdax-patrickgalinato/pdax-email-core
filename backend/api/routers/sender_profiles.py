"""Read-only sender behavior profiles for the console.

Baselines are CLEAN/LOW only (see workers/pipeline/correlation.py). Any
authenticated role can read — same bar as the live feed.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from workers.pipeline.correlation import PROFILE_MIN_N, profile_summary_line
from ..auth_store import User
from ..deps import get_correlation_store, require_role

router = APIRouter(prefix="/api")
_log = logging.getLogger("backend.api.sender_profiles")


def _empty_payload() -> dict:
    return {
        "senders": [], "total": 0, "min_n": PROFILE_MIN_N,
        "assessment": {"CLEAN": 0, "SUSPICIOUS": 0, "MALICIOUS": 0},
        "ai_risk": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
    }


def _ai_risk_totals(items: list) -> dict:
    totals = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for p in items:
        key = str(p.get("ai_risk") or "").upper()
        if key in totals:
            totals[key] += 1
    return totals


def _assessment_totals(items: list) -> dict:
    totals = {"CLEAN": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}
    for p in items:
        key = str(p.get("assessment") or "CLEAN").upper()
        if key in totals:
            totals[key] += 1
    return totals


@router.get("/sender-profiles")
def list_sender_profiles(
    q: str = Query("", max_length=200),
    ready: bool = False,
    _: User = Depends(require_role("admin", "analyst", "viewer")),
):
    store = get_correlation_store()
    if store is None or not hasattr(store, "list_profiles"):
        return _empty_payload()
    try:
        items = store.list_profiles(query=q, limit=500)
    except Exception:
        _log.exception("GET /api/sender-profiles failed")
        return _empty_payload()
    if ready:
        items = [p for p in items if p.get("ready")]
    return {
        "senders": items,
        "total": len(items),
        "min_n": PROFILE_MIN_N,
        "assessment": _assessment_totals(items),
        "ai_risk": _ai_risk_totals(items),
    }


@router.get("/sender-profiles/by-address")
def get_sender_profile(
    sender: str = Query(..., min_length=1, max_length=320),
    _: User = Depends(require_role("admin", "analyst", "viewer")),
):
    addr = sender.strip().lower()
    if "@" not in addr:
        raise HTTPException(status_code=400, detail="sender must be an email address")
    store = get_correlation_store()
    if store is None or not hasattr(store, "profile_for"):
        return {
            "sender": addr,
            "profile": {},
            "observations": [],
            "summary": "",
            "min_n": PROFILE_MIN_N,
            "ready": False,
        }
    try:
        prof = store.profile_for(addr)
        obs = store.profile_observations(addr) if hasattr(store, "profile_observations") else []
    except Exception:
        prof, obs = {}, []
    n = int((prof or {}).get("n") or 0)
    listed = []
    try:
        listed = store.list_profiles(query=addr, limit=50) if hasattr(store, "list_profiles") else []
    except Exception:
        _log.exception("GET /api/sender-profiles/by-address list failed for %s", addr)
        listed = []
    match = next((p for p in listed if p.get("sender") == addr), None) or {}
    behavior: dict = {}
    if hasattr(store, "behavior_for"):
        try:
            behavior = store.behavior_for(addr) or {}
        except Exception:
            behavior = {}
    vol = (behavior.get("volume") or {}) if behavior else {}
    if not match.get("sent_count") and (vol or hasattr(store, "volume_for")):
        try:
            if not vol and hasattr(store, "volume_for"):
                vol = store.volume_for(addr)
            match = dict(match)
            match["sent_count"] = int(vol.get("sent_count") or match.get("copies") or n)
            match["received_count"] = int(vol.get("received_count") or 0)
            match["mailbox_targets"] = int(vol.get("mailbox_targets") or 0)
            match["outbound_count"] = int(vol.get("outbound_count") or 0)
        except Exception:
            pass
    if behavior:
        prof = dict(prof or {})
        if not prof.get("hours"):
            prof["hours"] = behavior.get("hours") or []
        prof["request_mix"] = behavior.get("request_mix") or []
        prof["sent_to"] = behavior.get("sent_to") or []
        prof["received_from"] = behavior.get("received_from") or []
        prof["receive_mix"] = behavior.get("receive_mix") or []
    risk: dict = {}
    try:
        from backend.stores.sender_risk import ensure_assessed
        risk = ensure_assessed(store, addr, match, use_llm=False) or {}
    except Exception:
        risk = {}
    return {
        "sender": addr,
        "profile": prof,
        "observations": obs,
        "summary": profile_summary_line(prof, []),
        "min_n": PROFILE_MIN_N,
        "ready": n >= PROFILE_MIN_N,
        "assessment": match.get("assessment") or ("CLEAN" if n else "CLEAN"),
        "assessment_note": match.get("assessment_note") or "",
        "lane": match.get("lane") or "",
        "verdicts": match.get("verdicts") or {
            "CLEAN": n, "LOW": 0, "SUSPICIOUS": 0, "MALICIOUS": 0,
        },
        "copies": match.get("copies") if match.get("copies") is not None else n,
        "hostile_rate": float(match.get("hostile_rate") or 0),
        "sent_count": int(match.get("sent_count") or 0),
        "received_count": int(match.get("received_count") or 0),
        "mailbox_targets": int(match.get("mailbox_targets") or 0),
        "outbound_count": int(match.get("outbound_count") or 0),
        "ai_risk": risk.get("risk") or match.get("ai_risk") or "",
        "ai_score": float(risk.get("score") or match.get("ai_score") or 0),
        "ai_posture": risk.get("posture") or match.get("ai_posture") or "",
        "ai_confidence": risk.get("confidence") or "",
        "ai_summary": risk.get("summary") or "",
        "ai_factors": risk.get("factors") or [],
        "ai_provider": risk.get("provider") or match.get("ai_provider") or "",
        "ai_model": risk.get("model_id") or "",
        "ai_assessed_at": float(risk.get("assessed_at") or 0),
        "reciprocity": float(risk.get("reciprocity") or 0),
        "request_mix": (prof or {}).get("request_mix") or behavior.get("request_mix") or [],
        "receive_mix": behavior.get("receive_mix") or [],
        "sent_to": behavior.get("sent_to") or [],
        "received_from": behavior.get("received_from") or [],
        "hours": (prof or {}).get("hours") or behavior.get("hours") or [],
        "attachment_rate": float(behavior.get("attachment_rate") or 0),
        "reply_rate": float(behavior.get("reply_rate") or 0),
        "burst": behavior.get("burst") or {},
    }
