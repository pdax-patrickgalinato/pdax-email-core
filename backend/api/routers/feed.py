"""Real-data feed + quarantine action endpoints — Phase 12 of the
dashboard-overhaul plan. Analyst actions wrap backend/disposition.py's existing
functions directly (list_spool_entries/release_from_quarantine/keep_blocked/
reevaluate_spool_entry) rather than reimplementing spool-management logic.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from .. import activity_log, feed_builder
from ..auth_store import User
from ..deps import SESSION_COOKIE_NAME, get_auth_store, get_correlation_store, require_role
from ..security import reevaluate_limiter, retry_ai_limiter, search_limiter
from ..security import assert_within_root, validate_queue_id
from backend import disposition

from backend.paths import SPOOL_DIR
from backend.stores import ai_assess
from workers.gmail_llm import retry_gmail_llm

router = APIRouter(prefix="/api")
_log = logging.getLogger("backend.api.feed")

_SPOOL_ROOT = SPOOL_DIR


class RetryAiBody(BaseModel):
    queue_ids: list[str] | None = Field(default=None, max_length=100)


class SpotlightSearchBody(BaseModel):
    q: str = Field(min_length=1, max_length=500)
    verdict: str = Field(default="", max_length=32)


class EmailViewBody(BaseModel):
    queue_id: str = Field(min_length=1, max_length=200)
    event: Literal["open", "leave", "download"] = "leave"
    dwell_ms: int = Field(default=0, ge=0, le=86_400_000)
    subject: str = Field(default="", max_length=500)
    from_addr: str = Field(default="", max_length=320)


_view_dedupe: dict[tuple[str, str, str], float] = {}


def _email_meta(queue_id: str, subject: str = "", from_addr: str = "") -> dict:
    return activity_log.resolve_email(queue_id, subject, from_addr)


def _log_email(
    action: str,
    user: User,
    queue_id: str,
    *,
    subject: str = "",
    from_addr: str = "",
    detail: str = "",
    extra: dict | None = None,
    dwell_ms: int | None = None,
) -> dict:
    meta = _email_meta(queue_id, subject, from_addr)
    if dwell_ms is not None:
        meta["dwell_ms"] = int(dwell_ms)
    if extra:
        meta.update(extra)
    phrase = activity_log.email_phrase(meta)
    activity_log.record(
        action,
        actor=user.username,
        actor_role=user.role,
        detail=detail or phrase,
        meta=meta,
    )
    return meta


def _feed_payload(entries: list) -> dict:
    from backend.stores import assessments as store
    try:
        stats = store.overview_stats()
    except Exception:
        _log.exception("overview_stats failed; returning feed rows without tiles")
        stats = store.empty_overview_stats()
    stats.setdefault("inboxesMonitored", int(stats.get("mailboxes") or 0))
    stats.setdefault("inboxesPolling", 0)
    stats.setdefault("inboxesConfigured", 0)
    stats.setdefault("inboxesDiscovered", 0)
    stats.setdefault("inboxesSkipped", 0)
    stats.setdefault("origin", {"located": 0, "countries": [], "points": []})
    pending_in_page = sum(1 for e in entries if e.get("aiPending"))
    timed_in_page = sum(1 for e in entries if e.get("aiTimedOut"))
    return {
        "entries": entries,
        "llmConfigured": feed_builder.llm_configured(),
        "aiPendingCount": max(int(stats.get("aiPendingTotal") or 0), pending_in_page),
        "aiTimedOutCount": max(int(stats.get("aiTimedOutTotal") or 0), timed_in_page),
        "llmAssessTimeoutSeconds": ai_assess.timeout_seconds(),
        "stats": stats,
    }


@router.get("/feed")
def get_feed(
    verdict: str = Query("", description="Overview tile: safe, suspicious, or malicious."),
    origin: str = Query("", description="ISO country from the Overview origin map."),
    _: User = Depends(require_role("admin", "analyst", "viewer")),
):
    from backend.stores import assessments as store
    filt = (verdict or "").strip().lower()
    cc = (origin or "").strip().upper()
    if store.verdicts_for_filter(filt) or cc:
        entries = feed_builder.build_filtered_feed(filt, origin=cc)
    else:
        entries = feed_builder.build_feed()
    return _feed_payload(entries)


@router.post("/feed/search")
def spotlight_search(
    body: SpotlightSearchBody,
    user: User = Depends(require_role("admin", "analyst", "viewer")),
):
    """Natural-language spotlight search: LLM → validated SQL → mail rows."""
    if search_limiter.is_limited(user.username):
        raise HTTPException(status_code=429, detail="too many search requests")
    from .. import nl_search
    from backend.stores import assessments as store

    q = (body.q or "").strip()
    try:
        plan = nl_search.compile_search(q)
        sql = nl_search.apply_verdict_filter(plan["sql"], body.verdict)
    except nl_search.SearchSqlError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        ids = store.search_queue_ids(sql)
        rows = store.list_copies_by_ids(ids)
        entries = feed_builder.entries_from_copy_rows(rows)
    except Exception:
        _log.exception("spotlight search execute failed")
        raise HTTPException(status_code=400, detail="search query could not be executed")
    return {
        "entries": entries,
        "labels": plan.get("labels") or [],
        "source": plan.get("source") or "fallback",
        "q": q,
        "total": len(entries),
    }


@router.get("/feed/item/{queue_id}")
def get_feed_item(queue_id: str, _: User = Depends(require_role("admin", "analyst", "viewer"))):
    """One copy (and its thread) even when it has aged off the 500-row feed page."""
    validate_queue_id(queue_id)
    entries = feed_builder.entries_for_queue_id(queue_id)
    if not entries:
        raise HTTPException(status_code=404, detail="entry not found")
    return {"id": queue_id, "entries": entries}


@router.post("/feed/refresh")
def refresh_feed(_: User = Depends(require_role("admin", "analyst", "viewer"))):
    return _feed_payload(feed_builder.build_feed(force=True, correlation_store=get_correlation_store()))


@router.post("/feed/retry-ai")
def retry_ai(body: RetryAiBody | None = None, user: User = Depends(require_role("admin", "analyst"))):
    if retry_ai_limiter.is_limited(user.username):
        raise HTTPException(status_code=429, detail="Too many AI retries — wait one minute")
    if not feed_builder.llm_configured():
        raise HTTPException(status_code=409, detail="LLM is not configured")
    payload = body or RetryAiBody()
    ids = [q for q in (payload.queue_ids or []) if q]
    for qid in ids:
        validate_queue_id(qid)
    all_missing = not ids
    queued = retry_gmail_llm(
        queue_ids=ids or None,
        spool_root=_SPOOL_ROOT,
        all_missing=all_missing,
        limit=100,
    )
    feed_builder.build_feed(force=True, correlation_store=get_correlation_store())
    activity_log.record(
        "ai_retry", actor=user.username, actor_role=user.role,
        detail=("Retried AI assessment for all waiting emails"
                if all_missing else f"Retried AI assessment for {len(queued)} message(s)"),
        meta={"queue_ids": queued, "all": all_missing},
    )
    return {"queued": len(queued), "queue_ids": queued}


@router.get("/audit")
def get_audit(_: User = Depends(require_role("admin", "analyst", "viewer"))):
    """Gateway shadow decisions + console activity (logins, user admin, triage)."""
    return {"entries": feed_builder.combined_audit_entries()}


@router.get("/audit/me")
def get_my_audit(user: User = Depends(require_role("admin", "analyst", "viewer"))):
    """The signed-in user's own console activity (no gateway shadow decisions)."""
    raw = activity_log.list_entries(actor=user.username)
    return {"entries": [activity_log.to_audit_ui(e) for e in raw]}


@router.post("/activity/email-view")
def record_email_view(
    body: EmailViewBody,
    user: User = Depends(require_role("admin", "analyst", "viewer")),
):
    """Analyst opened or left an email details page, or saved the original file."""
    validate_queue_id(body.queue_id)
    event = body.event
    key = (user.username, body.queue_id, event)
    now = time.time()
    prev = _view_dedupe.get(key, 0.0)
    if now - prev < 2:
        return {"ok": True, "deduped": True}
    _view_dedupe[key] = now
    if len(_view_dedupe) > 4000:
        cutoff = now - 60
        stale = [k for k, ts in _view_dedupe.items() if ts < cutoff]
        for k in stale:
            _view_dedupe.pop(k, None)
    if event == "open":
        meta = _log_email(
            "email_open", user, body.queue_id,
            subject=body.subject, from_addr=body.from_addr,
            detail=f"Opened {activity_log.email_phrase(_email_meta(body.queue_id, body.subject, body.from_addr))}",
        )
    elif event == "download":
        meta = _log_email(
            "quarantine_download", user, body.queue_id,
            subject=body.subject, from_addr=body.from_addr,
            detail="Saved the original .eml file",
        )
    else:
        dwell = int(body.dwell_ms or 0)
        phrase = activity_log.email_phrase(_email_meta(body.queue_id, body.subject, body.from_addr))
        meta = _log_email(
            "email_view", user, body.queue_id,
            subject=body.subject, from_addr=body.from_addr,
            detail=f"Looked at {phrase} for {activity_log.format_dwell(dwell)}",
            dwell_ms=dwell,
        )
    return {"ok": True, "queue_id": meta.get("queue_id")}


@router.post("/quarantine/{queue_id}/release")
def release(queue_id: str, user: User = Depends(require_role("admin", "analyst"))):
    validate_queue_id(queue_id)
    try:
        dest = disposition.release_from_quarantine(_SPOOL_ROOT, queue_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="entry not found")
    feed_builder.build_feed(force=True, correlation_store=get_correlation_store())
    meta = _email_meta(queue_id)
    phrase = activity_log.email_phrase(meta)
    activity_log.record(
        "quarantine_release", actor=user.username, actor_role=user.role,
        detail=f"Released {phrase} from quarantine",
        meta={**meta, "bucket": dest.parent.name},
    )
    return {"queue_id": dest.name, "bucket": dest.parent.name}


@router.post("/quarantine/{queue_id}/keep-blocked")
def keep_blocked(queue_id: str, user: User = Depends(require_role("admin", "analyst"))):
    validate_queue_id(queue_id)
    try:
        dest = disposition.keep_blocked(_SPOOL_ROOT, queue_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="entry not found")
    feed_builder.build_feed(force=True, correlation_store=get_correlation_store())
    meta = _email_meta(queue_id)
    phrase = activity_log.email_phrase(meta)
    activity_log.record(
        "quarantine_keep_blocked", actor=user.username, actor_role=user.role,
        detail=f"Kept {phrase} blocked",
        meta={**meta, "bucket": dest.parent.name},
    )
    return {"queue_id": dest.name, "bucket": dest.parent.name}


@router.post("/quarantine/{queue_id}/reevaluate", status_code=202)
def reevaluate(queue_id: str, user: User = Depends(require_role("admin", "analyst"))):
    if reevaluate_limiter.is_limited(user.username):
        raise HTTPException(status_code=429, detail="Too many re-evaluations — wait one minute and retry")
    validate_queue_id(queue_id)
    from backend.stores import assessments as store
    from backend.stores import spool as spoolmod
    from workers.copy_jobs import enqueue_static
    row = store.get_copy(queue_id)
    if not row:
        raise HTTPException(status_code=404, detail="entry not found")
    dest = row.get("dest")
    if isinstance(dest, str):
        text = dest.strip()
        if text.startswith("{"):
            try:
                dest = json.loads(text)
            except json.JSONDecodeError:
                dest = text
        else:
            dest = text
    try:
        payload = spoolmod.as_payload(dest) if dest else spoolmod.payload(queue_id)
        enqueue_static(payload)
    except Exception:
        _log.exception("reevaluate enqueue failed for %s", queue_id)
        raise HTTPException(status_code=404, detail="entry not found")
    feed_builder.build_feed(force=True)
    meta = _email_meta(queue_id)
    phrase = activity_log.email_phrase(meta)
    activity_log.record(
        "quarantine_reevaluate", actor=user.username, actor_role=user.role,
        detail=f"Queued re-evaluation of {phrase}",
        meta={**meta, "queued": True},
    )
    return {
        "queued": True,
        "queue_id": queue_id,
        "status": store.status_of(row),
        "verdict": row.get("verdict") or "",
    }


@router.get("/quarantine/{queue_id}/download")
def download(
    queue_id: str,
    request: Request,
    user: User = Depends(require_role("admin", "analyst")),
    intent: str = Query("", description="view = load into the console; omit to log a file download"),
):
    validate_queue_id(queue_id)
    token = request.cookies.get(SESSION_COOKIE_NAME) or ""
    thread_key = feed_builder.thread_key_for_queue_id(queue_id)
    if not get_auth_store().is_content_unlocked(token, thread_key, queue_id=queue_id):
        raise HTTPException(status_code=403, detail="passkey_required")
    raw = b""
    from backend.stores import spool as spoolmod
    try:
        raw = spoolmod.read_message(queue_id)
    except FileNotFoundError:
        raw = b""
    if not raw:
        try:
            entries = [e for e in disposition.list_spool_entries(_SPOOL_ROOT) if e["queue_id"] == queue_id]
            if not entries:
                raise FileNotFoundError(queue_id)
            eml_path = Path(entries[0]["path"]) / "message.eml"
            assert_within_root(eml_path, _SPOOL_ROOT)
            if not eml_path.is_file():
                raise FileNotFoundError(queue_id)
            raw = eml_path.read_bytes()
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="entry not found")
    if (intent or "").strip().lower() != "view":
        meta = _email_meta(queue_id)
        phrase = activity_log.email_phrase(meta)
        activity_log.record(
            "quarantine_download", actor=user.username, actor_role=user.role,
            detail=f"Saved the original .eml of {phrase}",
            meta=meta,
        )
    return Response(
        content=raw,
        media_type="message/rfc822",
        headers={"Content-Disposition": f'attachment; filename="{queue_id}.eml"'},
    )
