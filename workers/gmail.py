"""Gmail API I/O — cursors, persist, history poll.

Owned by the workers package. `workers.gmail_poll` drives the cycle.
Gmail labels are never written.
"""
from __future__ import annotations

import base64
import json
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from backend.report import send_slack_alert
from backend.config import get_settings
from backend.paths import CREDENTIALS_PATH, DATA_DIR, RULES_RUNTIME, SPOOL_DIR
from backend.db import connect as db_connect, is_postgres

_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
_CURSOR_DB = DATA_DIR / "gmail_cursors.sqlite3"
CURSOR_DB = _CURSOR_DB
# First poll copies this many recent INBOX messages into the console. After
# that, only history.list deltas are scanned (no full-mailbox backfill).
_SEED_INBOX_LIMIT = 20
_LLM_PROVIDERS = frozenset({"glm", "gemini", "bedrock", "ollama"})
_POLL_WORKERS = 8
_poll_gate = threading.Lock()
_sa_creds = None
_sa_creds_lock = threading.Lock()
_label_cache: dict[str, tuple[float, dict]] = {}
_label_cache_lock = threading.Lock()
_LABEL_TTL = 300.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS history_cursor (
    user_email TEXT PRIMARY KEY,
    history_id TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS processed_message (
    user_email TEXT NOT NULL,
    message_id TEXT NOT NULL,
    seen_at REAL NOT NULL,
    PRIMARY KEY (user_email, message_id)
);
"""


def _creds_path() -> str:
    return get_settings().gmail_credentials or str(CREDENTIALS_PATH)


def _monitored_users() -> list[str]:
    from backend.stores.gmail_coverage import monitored_users
    return monitored_users()


def _scan_timeout() -> float:
    return float(get_settings().email_scan_timeout_seconds)


# ── cursor / idempotency store ────────────────────────────────────────────────

def _connect(db_path: Path = _CURSOR_DB):
    conn = db_connect(db_path, schema=_SCHEMA)
    return conn


def get_cursor(user_email: str, db_path: Path = _CURSOR_DB) -> Optional[str]:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT history_id FROM history_cursor WHERE user_email = ?",
            (user_email,),
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def set_cursor(user_email: str, history_id: str, db_path: Path = _CURSOR_DB) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO history_cursor (user_email, history_id, updated_at) "
            "VALUES (?, ?, ?) ON CONFLICT(user_email) DO UPDATE SET "
            "history_id = excluded.history_id, updated_at = excluded.updated_at",
            (user_email, str(history_id), time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def already_processed(user_email: str, message_id: str, db_path: Path = _CURSOR_DB) -> bool:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT 1 FROM processed_message WHERE user_email = ? AND message_id = ?",
            (user_email, message_id),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def mark_processed(user_email: str, message_id: str, db_path: Path = _CURSOR_DB) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO processed_message (user_email, message_id, seen_at) "
            "VALUES (?, ?, ?)",
            (user_email, message_id, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def _gmail_queue_id(message_id: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_." else "_" for c in (message_id or "unknown"))
    return ("gmail-" + (cleaned[:100] or "unknown"))[:128]


def _content_ai_meta(result) -> dict:
    summary, provider, model_id = "", "", ""
    structure = {
        "is_forwarded": False,
        "is_reply": False,
        "primary_content": "",
        "quoted_or_forwarded_content": "",
        "footer_content": "",
        "footer_worth_assessing": False,
        "footer_assessment": "",
        "thread_summary": "",
        "thread_verdict": "",
    }
    for st in getattr(result, "stages", None) or []:
        if getattr(st, "stage", None) != "content_ai":
            continue
        facts = getattr(st, "facts", None) or {}
        summary = facts.get("summary") or ""
        provider = facts.get("provider") or ""
        model_id = facts.get("model_id") or ""
        structure = {
            "is_forwarded": bool(facts.get("is_forwarded")),
            "is_reply": bool(facts.get("is_reply")),
            "primary_content": facts.get("primary_content") or "",
            "quoted_or_forwarded_content": facts.get("quoted_or_forwarded_content") or "",
            "footer_content": facts.get("footer_content") or "",
            "footer_worth_assessing": bool(facts.get("footer_worth_assessing")),
            "footer_assessment": facts.get("footer_assessment") or "",
            "thread_summary": facts.get("thread_summary") or "",
            "thread_verdict": facts.get("thread_verdict") or "",
        }
        break
    return {
        "ai_summary": summary,
        "ai_provider": provider,
        "ai_model": model_id,
        "threat_class": getattr(result, "threat_class", None) or "none",
        "threat_confidence": float(getattr(result, "threat_confidence", None) or 0.0),
        **structure,
    }


def _iocs_dict(result) -> dict:
    iocs = getattr(result, "iocs", None)
    if iocs is None:
        return {}
    if hasattr(iocs, "model_dump"):
        try:
            return iocs.model_dump()
        except Exception:
            return {}
    return dict(iocs) if isinstance(iocs, dict) else {}


def persist_gmail_scan(
    user_email: str,
    message_id: str,
    raw: bytes,
    result,
    gmail_labels: list[str],
    spool_root: Optional[Path] = None,
    llm_attempted: bool = False,
    ts: Optional[str] = None,
    gmail_thread_id: str = "",
) -> str:
    """Write a local copy for the SOC console. Does not change Gmail."""
    from backend.stores.mail_thread import headers_from_raw
    from workers.pipeline.stage_summary import compact_stages

    root = Path(spool_root) if spool_root else Path(
        get_settings().quarantine_root or str(SPOOL_DIR)
    )
    qid = _gmail_queue_id(message_id)
    from backend.stores import spool as spoolmod
    s3 = spool_root is None and spoolmod.use_s3()
    if s3:
        dest = spoolmod.local_dir(qid, "gmail")
    else:
        root = Path(spool_root) if spool_root else Path(
            get_settings().quarantine_root or str(SPOOL_DIR)
        )
        dest = root / "gmail" / qid
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "message.eml").write_bytes(raw)
    ai = _content_ai_meta(result)
    provider = (ai.get("ai_provider") or "").strip().lower()
    rfc = headers_from_raw(raw)
    meta = {
        "ts": ts or datetime.now(timezone.utc).isoformat(),
        "queue_id": qid,
        "mailbox": user_email,
        "gmail_message_id": message_id,
        "gmail_thread_id": (gmail_thread_id or "").strip(),
        "gmail_labels": list(gmail_labels or []),
        "source": "gmail_api",
        "verdict": result.verdict.value,
        "disposition": getattr(getattr(result, "disposition", None), "value", None) or "LOG",
        "score": result.composite_score,
        "hard_override": result.hard_override,
        "reasons": list(result.reasons or []),
        "subject": result.subject,
        "from": result.from_header,
        "to": getattr(result, "to_header", "") or rfc.get("to") or "",
        "cc": rfc.get("cc") or "",
        "message_id": result.message_id or rfc.get("message_id") or "",
        "in_reply_to": rfc.get("in_reply_to") or "",
        "references": rfc.get("references") or "",
        "ai_summary": ai["ai_summary"],
        "ai_provider": ai["ai_provider"],
        "ai_model": ai.get("ai_model") or "",
        "threat_class": ai["threat_class"],
        "threat_confidence": ai["threat_confidence"],
        "is_forwarded": bool(ai.get("is_forwarded")),
        "is_reply": bool(ai.get("is_reply")),
        "primary_content": ai.get("primary_content") or "",
        "quoted_or_forwarded_content": ai.get("quoted_or_forwarded_content") or "",
        "footer_content": ai.get("footer_content") or "",
        "footer_worth_assessing": bool(ai.get("footer_worth_assessing")),
        "footer_assessment": ai.get("footer_assessment") or "",
        "thread_summary": ai.get("thread_summary") or "",
        "thread_verdict": ai.get("thread_verdict") or "",
        "ai_llm_attempted": bool(llm_attempted) or provider in _LLM_PROVIDERS,
        "iocs": _iocs_dict(result),
        "stages": compact_stages(result),
    }
    from backend.stores.mail_fanout import fanout_prompt_context, merge_fanout_stage
    fanout_ctx = fanout_prompt_context(dest, meta)
    if fanout_ctx:
        meta["fanout_count"] = int(fanout_ctx.get("inbox_count") or 0)
        meta["fanout_mailboxes"] = list(fanout_ctx.get("mailboxes") or [])
        meta["fanout_recipients"] = list(fanout_ctx.get("recipients") or [])
        meta["fanout_match"] = fanout_ctx.get("match") or ""
        meta["stages"] = merge_fanout_stage(meta["stages"], fanout_ctx)
    existing_path = dest / "meta.json"
    prev: dict = {}
    if s3:
        prev = spoolmod.get_meta(qid, "gmail")
        for key in (
            "analyst_label", "analyst_label_by", "analyst_label_ts", "analyst_label_note",
            "gmail_thread_id",
        ):
            if prev.get(key) and not meta.get(key):
                meta[key] = prev[key]
    elif existing_path.is_file():
        try:
            prev = json.loads(existing_path.read_text(encoding="utf-8"))
            for key in (
                "analyst_label", "analyst_label_by", "analyst_label_ts", "analyst_label_note",
                "gmail_thread_id",
            ):
                if prev.get(key) and not meta.get(key):
                    meta[key] = prev[key]
        except Exception:
            prev = {}
    if not (meta.get("thread_summary") or "").strip():
        meta["thread_summary"] = prev.get("thread_summary") or ""
    if not (meta.get("thread_verdict") or "").strip():
        meta["thread_verdict"] = prev.get("thread_verdict") or ""
    llm_done = provider in _LLM_PROVIDERS and bool((ai.get("ai_summary") or "").strip())
    if llm_done:
        meta["ai_timed_out"] = False
        meta["ai_retry_requested"] = False
        meta["ai_queued_at"] = prev.get("ai_queued_at") or datetime.now(timezone.utc).isoformat()
    else:
        meta["ai_queued_at"] = prev.get("ai_queued_at") or datetime.now(timezone.utc).isoformat()
        if prev.get("ai_timed_out"):
            meta["ai_timed_out"] = True
            meta["ai_timed_out_at"] = prev.get("ai_timed_out_at") or ""
    if s3:
        spoolmod.put_eml(qid, raw, "gmail")
        spoolmod.put_meta(qid, meta, "gmail")
    else:
        (dest / "meta.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    _after_gmail_meta_write(dest, meta, fanout_ctx, llm_done=llm_done)
    _record_copy(dest, meta, ai_done=llm_done)
    return qid


def persist_gmail_pending(
    user_email: str,
    message_id: str,
    raw: bytes,
    gmail_labels: list[str],
    spool_root: Optional[Path] = None,
    gmail_thread_id: str = "",
) -> str:
    """Store the raw copy for the LLM worker. Does not run the pipeline."""
    from backend.stores.mail_thread import extract_message_ids, headers_from_raw
    from backend.stores import ai_assess

    root = Path(spool_root) if spool_root else Path(
        get_settings().quarantine_root or str(SPOOL_DIR)
    )
    qid = _gmail_queue_id(message_id)
    from backend.stores import spool as spoolmod
    s3 = spool_root is None and spoolmod.use_s3()
    if s3:
        dest = spoolmod.local_dir(qid, "gmail")
        prev = {}
        try:
            from backend.stores import assessments as store
            row = store.get_copy(qid) or {}
            blob = row.get("meta_json") or ""
            if blob:
                prev = json.loads(blob)
        except Exception:
            prev = {}
    else:
        dest = root / "gmail" / qid
        dest.mkdir(parents=True, exist_ok=True)
        existing_path = dest / "meta.json"
        prev = {}
        if existing_path.is_file():
            try:
                prev = json.loads(existing_path.read_text(encoding="utf-8"))
            except Exception:
                prev = {}
        if ai_assess.has_llm_assessment(prev.get("ai_provider") or "", prev.get("ai_summary") or ""):
            return qid
    if prev and ai_assess.has_llm_assessment(prev.get("ai_provider") or "", prev.get("ai_summary") or ""):
        return qid
    if not s3:
        (dest / "message.eml").write_bytes(raw)
    rfc = headers_from_raw(raw)
    now = datetime.now(timezone.utc).isoformat()
    mids = extract_message_ids(rfc.get("message_id") or "")
    meta = {
        "ts": prev.get("ts") or now,
        "queue_id": qid,
        "mailbox": user_email,
        "gmail_message_id": message_id,
        "gmail_thread_id": (gmail_thread_id or prev.get("gmail_thread_id") or "").strip(),
        "gmail_labels": list(gmail_labels or prev.get("gmail_labels") or []),
        "source": "gmail_api",
        "verdict": prev.get("verdict") or "",
        "disposition": prev.get("disposition") or "LOG",
        "score": prev.get("score"),
        "hard_override": prev.get("hard_override"),
        "reasons": list(prev.get("reasons") or []),
        "subject": rfc.get("subject") or prev.get("subject") or "",
        "from": rfc.get("from") or prev.get("from") or "",
        "to": rfc.get("to") or prev.get("to") or "",
        "cc": rfc.get("cc") or prev.get("cc") or "",
        "message_id": rfc.get("message_id") or prev.get("message_id") or "",
        "in_reply_to": rfc.get("in_reply_to") or prev.get("in_reply_to") or "",
        "references": rfc.get("references") or prev.get("references") or "",
        "ai_summary": prev.get("ai_summary") or "",
        "ai_provider": prev.get("ai_provider") or "",
        "ai_model": prev.get("ai_model") or "",
        "threat_class": prev.get("threat_class") or "none",
        "threat_confidence": prev.get("threat_confidence") or 0.0,
        "is_forwarded": bool(prev.get("is_forwarded")),
        "is_reply": bool(prev.get("is_reply")),
        "primary_content": prev.get("primary_content") or "",
        "quoted_or_forwarded_content": prev.get("quoted_or_forwarded_content") or "",
        "footer_content": prev.get("footer_content") or "",
        "footer_worth_assessing": bool(prev.get("footer_worth_assessing")),
        "footer_assessment": prev.get("footer_assessment") or "",
        "thread_summary": prev.get("thread_summary") or "",
        "thread_verdict": prev.get("thread_verdict") or "",
        "ai_llm_attempted": bool(prev.get("ai_llm_attempted")),
        "ai_queued_at": prev.get("ai_queued_at") or now,
        "ai_timed_out": bool(prev.get("ai_timed_out")),
        "ai_timed_out_at": prev.get("ai_timed_out_at") or "",
        "ai_retry_requested": bool(prev.get("ai_retry_requested")),
        "ai_auto_retry_count": int(prev.get("ai_auto_retry_count") or 0),
        "ai_auto_retry_at": prev.get("ai_auto_retry_at") or "",
        "iocs": prev.get("iocs") if isinstance(prev.get("iocs"), dict) else {},
        "stages": prev.get("stages") if isinstance(prev.get("stages"), dict) else {},
        "rfc_message_id": (mids[0] if mids else "") or prev.get("rfc_message_id") or "",
    }
    from backend.stores.mail_fanout import fanout_prompt_context, merge_fanout_stage
    fanout_ctx = fanout_prompt_context(dest, meta)
    if fanout_ctx:
        meta["fanout_count"] = int(fanout_ctx.get("inbox_count") or 0)
        meta["fanout_mailboxes"] = list(fanout_ctx.get("mailboxes") or [])
        meta["fanout_recipients"] = list(fanout_ctx.get("recipients") or [])
        meta["fanout_match"] = fanout_ctx.get("match") or ""
        meta["stages"] = merge_fanout_stage(meta["stages"], fanout_ctx)
    if s3:
        spoolmod.put_eml(qid, raw, "gmail")
        spoolmod.put_meta(qid, meta, "gmail")
    else:
        (dest / "meta.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    _after_gmail_meta_write(dest, meta, fanout_ctx, llm_done=False)
    _record_copy(dest, meta)
    return qid


def _after_gmail_meta_write(dest: Path, meta: dict, fanout_ctx, *, llm_done: bool) -> None:
    if meta.get("fanout_count"):
        from backend.stores.mail_fanout import propagate_fanout
        propagate_fanout(dest, meta)
    try:
        from backend.stores.gmail_coverage import offer_from_scan
        added = offer_from_scan(dest, meta, fanout_ctx or {})
        if added:
            shown = ", ".join(added[:8])
            extra = f" (+{len(added) - 8} more)" if len(added) > 8 else ""
            print(f"[gmail_receiver] fanout coverage +{len(added)}: {shown}{extra}",
                  file=sys.stderr)
    except Exception as exc:
        print(f"[gmail_receiver] coverage offer failed: {exc}", file=sys.stderr)
    if llm_done and (meta.get("thread_summary") or meta.get("thread_verdict")):
        from backend.stores.mail_thread import propagate_thread_assessment
        propagate_thread_assessment(
            dest,
            meta.get("thread_summary") or "",
            meta.get("thread_verdict") or "",
            meta,
        )


def _record_copy(dest: Path, meta: dict, *, ai_done: bool = False) -> None:
    try:
        from backend.stores.assessments import upsert_copy
        from backend.stores.mail_thread import extract_message_ids
        from backend.stores.spool import dest_name
        mids = extract_message_ids(str(meta.get("message_id") or meta.get("rfc_message_id") or ""))
        rfc_id = (mids[0] if mids else "") or str(meta.get("rfc_message_id") or "")
        upsert_copy(
            str(meta.get("queue_id") or dest_name(dest)),
            dest=json.dumps(dest) if isinstance(dest, dict) else str(dest),
            mailbox=str(meta.get("mailbox") or ""),
            gmail_message_id=str(meta.get("gmail_message_id") or ""),
            gmail_thread_id=str(meta.get("gmail_thread_id") or ""),
            rfc_message_id=rfc_id,
            from_addr=str(meta.get("from") or ""),
            subject=str(meta.get("subject") or ""),
            to_addr=str(meta.get("to") or ""),
            verdict=str(meta.get("verdict") or ""),
            score=meta.get("score"),
            disposition=str(meta.get("disposition") or "LOG"),
            ai_provider=str(meta.get("ai_provider") or ""),
            ai_summary=str(meta.get("ai_summary") or ""),
            ai_model=str(meta.get("ai_model") or ""),
            ai_done=1 if ai_done else 0,
            status="complete" if ai_done else "queued",
            meta_json=json.dumps(meta, default=str),
        )
    except Exception:
        pass


def _spool_root() -> Path:
    return Path(get_settings().quarantine_root or str(SPOOL_DIR))


def _service_account_creds():
    """Load the DWD key once; each mailbox only needs with_subject()."""
    global _sa_creds
    with _sa_creds_lock:
        if _sa_creds is None:
            from google.oauth2 import service_account
            _sa_creds = service_account.Credentials.from_service_account_file(
                _creds_path(), scopes=_SCOPES
            )
        return _sa_creds


def build_gmail_service(user_email: str):
    """Return an authorized Gmail API client impersonating *user_email* via DWD."""
    from googleapiclient.discovery import build

    creds = _service_account_creds().with_subject(user_email)
    return build("gmail", "v1", credentials=creds, cache_discovery=True, static_discovery=True)


def _label_map(service, user_email: str) -> dict:
    now = time.time()
    with _label_cache_lock:
        hit = _label_cache.get(user_email)
        if hit and (now - hit[0]) < _LABEL_TTL:
            return hit[1]
    listed = service.users().labels().list(userId=user_email).execute()
    by_id = {lbl["id"]: lbl.get("name") or lbl["id"] for lbl in listed.get("labels") or []}
    with _label_cache_lock:
        _label_cache[user_email] = (now, by_id)
    return by_id


def _label_names(service, user_email: str, label_ids: list) -> list[str]:
    """Resolve Gmail label IDs to names (read-only). System ids like INBOX stay as-is if missing."""
    ids = [i for i in (label_ids or []) if i]
    if not ids:
        return []
    by_id = _label_map(service, user_email)
    return [by_id.get(i, i) for i in ids]


def scan_message(user_email: str, message_id: str) -> dict:
    """Fetch raw EML, persist a pending copy, enqueue the static worker. Does not write to Gmail."""
    service = build_gmail_service(user_email)

    msg = service.users().messages().get(
        userId=user_email, id=message_id, format="raw"
    ).execute()

    raw = base64.urlsafe_b64decode(msg["raw"] + "==")
    gmail_labels = _label_names(service, user_email, msg.get("labelIds") or [])
    gmail_thread_id = str(msg.get("threadId") or "")
    queue_id = persist_gmail_pending(
        user_email, message_id, raw, gmail_labels,
        gmail_thread_id=gmail_thread_id,
    )
    dest = _spool_root() / "gmail" / queue_id
    from workers.copy_jobs import enqueue_static
    from backend.stores import assessments as store
    from backend.stores import spool as spoolmod
    row = store.get_copy(queue_id) or {}
    status = store.status_of(row)
    if status != store.DEAD_LETTER and not store.static_complete(row):
        enqueue_static(spoolmod.payload(queue_id) if spoolmod.use_s3() else dest)
    return {
        "message_id": message_id,
        "user": user_email,
        "verdict": "",
        "score": None,
        "action": "queued",
        "gmail_labels": gmail_labels,
        "hard_override": None,
        "queue_id": queue_id,
    }


def _maybe_slack_alert(result) -> None:
    import yaml
    path = RULES_RUNTIME / "slack_config.yaml"
    try:
        cfg = yaml.safe_load(path.read_text()) or {} if path.is_file() else {}
    except Exception:
        cfg = {}
    if not cfg.get("enabled"):
        return
    url = cfg.get("webhook_url", "").strip()
    if url:
        send_slack_alert(result, url, cfg.get("threshold", "SUSPICIOUS"))


def _current_history_id(service, user_email: str) -> str:
    profile = service.users().getProfile(userId=user_email).execute()
    return str(profile["historyId"])


def _recent_inbox_ids(service, user_email: str, limit: int = _SEED_INBOX_LIMIT) -> list[str]:
    resp = service.users().messages().list(
        userId=user_email,
        labelIds=["INBOX"],
        maxResults=max(1, int(limit)),
    ).execute()
    return [m["id"] for m in (resp.get("messages") or []) if m.get("id")]


def _added_message_ids(history_resp: dict) -> list[str]:
    ids = []
    for record in history_resp.get("history") or []:
        for added in record.get("messagesAdded") or []:
            msg_id = (added.get("message") or {}).get("id")
            if msg_id:
                ids.append(msg_id)
    return ids


def _fetch_workers() -> int:
    try:
        n = int(get_settings().gmail_fetch_workers)
        return max(1, min(n, 8))
    except Exception:
        return 4


def _scan_ids(
    user_email: str,
    msg_ids: list[str],
    scan: Callable[[str, str], dict],
    db_path: Path,
) -> list[dict]:
    pending = [m for m in msg_ids if m and not already_processed(user_email, m, db_path=db_path)]
    if not pending:
        return []

    def _one(msg_id: str) -> dict | None:
        try:
            summary = scan(user_email, msg_id)
            mark_processed(user_email, msg_id, db_path=db_path)
            print(
                f"[gmail_receiver] {user_email} {msg_id} → "
                f"{summary.get('verdict')} ({summary.get('action')})",
                file=sys.stderr,
            )
            return summary
        except Exception as exc:
            print(f"[gmail_receiver] scan_message failed {msg_id}: {exc}", file=sys.stderr)
            return None

    workers = min(_fetch_workers(), len(pending))
    if workers <= 1:
        return [s for s in (_one(m) for m in pending) if s]
    by_id: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_one, mid): mid for mid in pending}
        for fut in as_completed(futs):
            summary = fut.result()
            if summary:
                by_id[futs[fut]] = summary
    return [by_id[m] for m in pending if m in by_id]


def _is_history_gone(exc: BaseException) -> bool:
    status = getattr(getattr(exc, "resp", None), "status", None)
    try:
        code = int(status)
    except (TypeError, ValueError):
        code = 0
    if code == 404:
        return True
    msg = str(exc).lower()
    return "404" in msg or "not found" in msg or "history id" in msg


def _list_history(svc, user_email: str, start: str) -> tuple[list[str], str]:
    """All messageAdded ids since start, following nextPageToken."""
    page_token = None
    ids: list[str] = []
    latest = start
    while True:
        kwargs = {
            "userId": user_email,
            "startHistoryId": str(start),
            "historyTypes": ["messageAdded"],
            "labelId": "INBOX",
        }
        if page_token:
            kwargs["pageToken"] = page_token
        resp = svc.users().history().list(**kwargs).execute()
        ids.extend(_added_message_ids(resp))
        if resp.get("historyId"):
            latest = str(resp["historyId"])
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    # Preserve first-seen order, drop dupes from overlapping history records.
    return list(dict.fromkeys(ids)), latest


def poll_mailbox(
    user_email: str,
    *,
    service=None,
    scan: Callable[[str, str], dict] = scan_message,
    db_path: Path = _CURSOR_DB,
) -> dict[str, Any]:
    """Process INBOX messages for one mailbox.

    First run seeds the console with recent INBOX mail, then records historyId.
    Later runs only scan history.list deltas. Gmail labels are never changed.
    """
    svc = service or build_gmail_service(user_email)
    start = get_cursor(user_email, db_path=db_path)
    if start is None:
        hid = _current_history_id(svc, user_email)
        try:
            seed_ids = _recent_inbox_ids(svc, user_email)
        except Exception as exc:
            print(f"[gmail_receiver] inbox seed failed for {user_email}: {exc}",
                  file=sys.stderr)
            seed_ids = []
        processed = _scan_ids(user_email, seed_ids, scan, db_path)
        set_cursor(user_email, hid, db_path=db_path)
        print(
            f"[gmail_receiver] {user_email}: initialized cursor {hid} "
            f"(seeded {len(processed)} recent INBOX)",
            file=sys.stderr,
        )
        return {
            "user": user_email,
            "initialized": True,
            "processed": len(processed),
            "results": processed,
        }

    try:
        msg_ids, new_id = _list_history(svc, user_email, start)
    except Exception as exc:
        if not _is_history_gone(exc):
            print(f"[gmail_receiver] history.list failed for {user_email}: {exc} "
                  "— keeping cursor", file=sys.stderr)
            return {"user": user_email, "error": str(exc), "processed": 0}
        print(f"[gmail_receiver] historyId expired for {user_email}: {exc} "
              "— reseeding recent INBOX", file=sys.stderr)
        try:
            seed_ids = _recent_inbox_ids(svc, user_email)
        except Exception as seed_exc:
            print(f"[gmail_receiver] inbox reseed failed for {user_email}: {seed_exc}",
                  file=sys.stderr)
            seed_ids = []
        processed = _scan_ids(user_email, seed_ids, scan, db_path)
        hid = _current_history_id(svc, user_email)
        set_cursor(user_email, hid, db_path=db_path)
        return {
            "user": user_email,
            "reset": True,
            "reseeded": True,
            "processed": len(processed),
            "results": processed,
        }

    processed = _scan_ids(user_email, msg_ids, scan, db_path)
    set_cursor(user_email, str(new_id or start), db_path=db_path)
    return {"user": user_email, "processed": len(processed), "results": processed}


def _poll_one_mailbox(user: str, db_path: Path) -> dict:
    try:
        return poll_mailbox(user, db_path=db_path)
    except Exception as exc:
        print(f"[gmail_receiver] poll failed for {user}: {exc}", file=sys.stderr)
        try:
            from backend.stores.gmail_coverage import note_failure
            note_failure(user, str(exc))
        except Exception:
            pass
        return {"user": user, "error": str(exc)}


def acquire_poll() -> bool:
    return _poll_gate.acquire(blocking=False)


def release_poll() -> None:
    _poll_gate.release()


def poll_unlocked(db_path: Path = _CURSOR_DB) -> list[dict]:
    """History pass with no overlap lock, no worker slot, no LLM enqueue."""
    from backend.stores.gmail_coverage import coverage_domains, is_org_mailbox

    domains = coverage_domains()
    users = [
        u for u in _monitored_users()
        if not domains or is_org_mailbox(u, domains)
    ]
    if not users:
        want = ", ".join(sorted(domains)) if domains else "SEG_GMAIL_USERS"
        print(f"[gmail_receiver] no {want} mailboxes to poll", file=sys.stderr)
        return []
    workers = max(1, min(_POLL_WORKERS, len(users)))
    if workers == 1:
        return [_poll_one_mailbox(user, db_path) for user in users]
    out = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_poll_one_mailbox, user, db_path) for user in users]
        for fut in as_completed(futs):
            out.append(fut.result())
    return out


def poll_all_mailboxes(db_path: Path = _CURSOR_DB) -> list[dict]:
    """One Gmail history pass across every configured mailbox.

    Overlapping calls are skipped: a second pass over ~100 mailboxes is what
    made cycles blow the watchdog and stick the console on Error.
    """
    if not acquire_poll():
        print("[gmail_receiver] skipping poll — previous cycle still running",
              file=sys.stderr)
        return []
    try:
        return poll_unlocked(db_path)
    finally:
        release_poll()

