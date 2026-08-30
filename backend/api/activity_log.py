"""Append-only activity audit log for dashboard user / admin actions.

Complements email/spool/shadow_logs/shadow_enforcement.jsonl (pipeline
disposition decisions). This file records who did what in the SEGS console:
login/logout, user CRUD, password resets, quarantine actions, Analyze uploads,
policy toggles.

Storage: Postgres ``activity_audit`` when ``SEG_DATABASE_URL`` is set (ECS).
JSONL ``data/activity_audit.jsonl`` otherwise (pytest / local). Dual-write to
JSONL in production so the Wazuh shipper still has a local tail. Never raises
into request handlers — a logging failure must not break the primary action.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from backend.paths import DATA_DIR

_log = logging.getLogger("backend.api.activity_log")

_DEFAULT_PATH = DATA_DIR / "activity_audit.jsonl"
_lock = threading.Lock()
_MAX_READ = 2000  # newest-first cap for API responses

# Field-length caps — bound each stored string so an attacker-influenced value
# (e.g. a crafted email sender name that ends up as `actor`) can't bloat the log
# file or smuggle megabytes of payload into an append-only audit record.
_MAX_ACTOR_LEN = 256
_MAX_DETAIL_LEN = 2048
_MAX_ACTION_LEN = 64


def _clip(value: Any, limit: int) -> str:
    """Coerce to str and truncate to `limit` chars. Strips control characters
    (newlines, etc.) so a value can't forge extra JSONL lines or corrupt the
    single-line-per-record invariant the reader relies on."""
    s = str(value)
    s = s.replace("\r", " ").replace("\n", " ").replace("\x00", "")
    if len(s) > limit:
        s = s[: limit - 1] + "…"  # ellipsis marks truncation
    return s

# action -> (ui type for icon, human title prefix)
_ACTION_META = {
    "setup": ("accent", "First-run setup"),
    "login": ("good", "Signed in"),
    "login_failed": ("warning", "Failed sign-in"),
    "login_mfa": ("accent", "Passkey required"),
    "logout": ("good", "Signed out"),
    "user_create": ("accent", "User created"),
    "user_delete": ("serious", "User deleted"),
    "password_reset": ("accent", "Password reset"),
    "password_change": ("accent", "Password changed"),
    "passkey_register": ("good", "Passkey added"),
    "passkey_delete": ("warning", "Passkey removed"),
    "passkey_unlock": ("good", "Unlocked original email"),
    "quarantine_release": ("good", "Released from quarantine"),
    "quarantine_keep_blocked": ("critical", "Kept blocked"),
    "quarantine_reevaluate": ("warning", "Re-evaluated"),
    "ai_retry": ("warning", "AI assessment retry"),
    "quarantine_download": ("warning", "Downloaded original email file"),
    "email_open": ("accent", "Opened an email"),
    "email_view": ("accent", "Looked at an email"),
    "analyze_eml": ("accent", "Deep analysis"),
    "policy_update": ("accent", "Policy changed"),
    "feedback_benign": ("good", "Marked not malicious"),
    "feedback_benign_undo": ("warning", "Removed benign label"),
    "feedback_import": ("accent", "Imported good-mail pack"),
    "org_context_add": ("accent", "Org context added"),
    "org_context_update": ("accent", "Org context updated"),
    "org_context_remove": ("warning", "Org context removed"),
    "blocklist_add": ("critical", "Sender blocklisted"),
    "blocklist_remove": ("warning", "Sender removed from blocklist"),
    "allowlist_add": ("good", "Sender allowlisted"),
    "allowlist_remove": ("warning", "Sender removed from allowlist"),
    "gmail_fetch_pause": ("warning", "Gmail fetch paused"),
    "gmail_fetch_resume": ("good", "Gmail fetch resumed"),
}


def format_dwell(ms: int) -> str:
    """Human duration for audit copy: '12 seconds', '2 minutes 5 seconds'."""
    try:
        n = int(ms)
    except (TypeError, ValueError):
        n = 0
    if n < 1000:
        return "less than a second"
    total = n // 1000
    hours, rem = divmod(total, 3600)
    minutes, seconds = divmod(rem, 60)
    parts: list[str] = []
    if hours:
        parts.append(f"{hours} hour" + ("" if hours == 1 else "s"))
    if minutes:
        parts.append(f"{minutes} minute" + ("" if minutes == 1 else "s"))
    if seconds and hours == 0:
        parts.append(f"{seconds} second" + ("" if seconds == 1 else "s"))
    return " ".join(parts) if parts else "less than a second"


def resolve_email(
    queue_id: str = "",
    subject: str = "",
    from_addr: str = "",
) -> dict[str, str]:
    """Subject/from for a spool id — client values first, assessments as fallback."""
    qid = (queue_id or "").strip()
    subj = (subject or "").strip()
    frm = (from_addr or "").strip()
    if qid and (not subj or not frm):
        try:
            from backend.stores import assessments as store
            row = store.get_copy(qid) or {}
        except Exception:
            row = {}
        if not subj:
            subj = str(row.get("subject") or "").strip()
        if not frm:
            frm = str(row.get("from_addr") or "").strip()
    return {
        "queue_id": qid[:200],
        "subject": subj[:500],
        "from_addr": frm[:320],
    }


def email_phrase(meta: Optional[dict] = None) -> str:
    """‘Subject’ from sender@x — used in audit titles."""
    info = meta if isinstance(meta, dict) else {}
    subj = str(info.get("subject") or "").strip()
    frm = str(info.get("from_addr") or info.get("from") or "").strip()
    qid = str(info.get("queue_id") or "").strip()
    if subj and frm:
        return f"“{subj}” from {frm}"
    if subj:
        return f"“{subj}”"
    if frm:
        return f"an email from {frm}"
    if qid:
        return f"email {qid}"
    return "an email"


def _path(path: Optional[Path] = None) -> Path:
    return Path(path) if path else _DEFAULT_PATH


def _use_postgres() -> bool:
    try:
        from backend.db import is_postgres
        return is_postgres()
    except Exception:
        return False


def _insert_postgres(entry: dict) -> None:
    from backend.db import connect as db_connect

    conn = db_connect()
    try:
        conn.execute(
            """
            INSERT INTO activity_audit
                (ts, ts_epoch, action, actor, actor_role, detail, meta_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.get("ts") or "",
                float(entry.get("ts_epoch") or 0),
                entry.get("action") or "",
                entry.get("actor") or "",
                entry.get("actor_role") or "",
                entry.get("detail") or "",
                json.dumps(entry.get("meta") or {}, ensure_ascii=False),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _list_postgres(limit: int, actor: Optional[str] = None) -> list[dict]:
    from backend.db import connect as db_connect

    cap = max(1, min(int(limit), _MAX_READ))
    wanted = (actor or "").strip()
    conn = db_connect()
    try:
        if wanted:
            rows = conn.execute(
                """
                SELECT ts, ts_epoch, action, actor, actor_role, detail, meta_json
                FROM activity_audit
                WHERE LOWER(actor) = LOWER(?)
                ORDER BY ts_epoch DESC
                LIMIT ?
                """,
                (wanted, cap),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT ts, ts_epoch, action, actor, actor_role, detail, meta_json
                FROM activity_audit
                ORDER BY ts_epoch DESC
                LIMIT ?
                """,
                (cap,),
            ).fetchall()
    finally:
        conn.close()
    out: list[dict] = []
    for r in rows:
        try:
            meta = json.loads(r.get("meta_json") or "{}")
        except (json.JSONDecodeError, TypeError, ValueError):
            meta = {}
        out.append({
            "ts": r.get("ts") or "",
            "ts_epoch": float(r.get("ts_epoch") or 0),
            "action": r.get("action") or "",
            "actor": r.get("actor") or "",
            "actor_role": r.get("actor_role") or "",
            "detail": r.get("detail") or "",
            "meta": meta if isinstance(meta, dict) else {},
        })
    return out


def _append_jsonl(entry: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    with _lock:
        with path.open("a", encoding="utf-8") as f:
            f.write(line)


def _read_jsonl(path: Path, limit: int) -> list[dict]:
    if not path.is_file():
        return []
    rows: list[dict] = []
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue
    except Exception:
        return []
    rows.sort(key=lambda e: float(e.get("ts_epoch") or 0), reverse=True)
    return rows[: max(1, int(limit))]


def record(
    action: str,
    *,
    actor: str = "",
    actor_role: str = "",
    detail: str = "",
    meta: Optional[dict] = None,
    path: Optional[Path] = None,
) -> None:
    """Append one activity event. Swallows I/O errors."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "ts_epoch": time.time(),
        "action": _clip(action, _MAX_ACTION_LEN),
        "actor": _clip(actor or "(anonymous)", _MAX_ACTOR_LEN),
        "actor_role": _clip(actor_role or "", 32),
        "detail": _clip(detail or "", _MAX_DETAIL_LEN),
        "meta": meta or {},
    }
    if path is None and _use_postgres():
        try:
            _insert_postgres(entry)
        except Exception:
            _log.exception("activity_audit postgres write failed")
    try:
        _append_jsonl(entry, _path(path))
    except Exception:
        _log.exception("activity_audit jsonl write failed")


def _filter_actor(rows: list[dict], actor: str) -> list[dict]:
    wanted = actor.strip().lower()
    if not wanted:
        return rows
    return [e for e in rows if (e.get("actor") or "").strip().lower() == wanted]


def list_entries(
    path: Optional[Path] = None,
    limit: int = _MAX_READ,
    actor: Optional[str] = None,
) -> list[dict]:
    """Newest-first activity events (raw JSONL / Postgres rows)."""
    cap = max(1, min(int(limit), _MAX_READ))
    wanted = (actor or "").strip()
    fetch = _MAX_READ if wanted else cap
    if path is not None:
        rows = _read_jsonl(_path(path), fetch)
        return _filter_actor(rows, wanted)[:cap]
    if _use_postgres():
        try:
            rows = _list_postgres(fetch, actor=wanted or None)
            if rows or wanted:
                return rows[:cap]
        except Exception:
            _log.exception("activity_audit postgres list failed")
    rows = _read_jsonl(_path(), fetch)
    return _filter_actor(rows, wanted)[:cap]


def to_audit_ui(entry: dict) -> dict[str, Any]:
    """Shape an activity row for the dashboard Audit log page."""
    action = entry.get("action") or "activity"
    ui_type, title_base = _ACTION_META.get(action, ("accent", action.replace("_", " ").title()))
    actor = entry.get("actor") or "(anonymous)"
    role = entry.get("actor_role") or ""
    who = f"{actor}" + (f" ({role})" if role else "")
    meta = entry.get("meta") if isinstance(entry.get("meta"), dict) else {}
    phrase = email_phrase(meta)
    has_email = bool(meta.get("subject") or meta.get("from_addr") or meta.get("from") or meta.get("queue_id"))
    if has_email:
        if action == "email_open":
            title_base = f"Opened {phrase}"
        elif action == "email_view":
            title_base = f"Looked at {phrase}"
        elif action == "quarantine_download":
            title_base = f"Downloaded original file of {phrase}"
        elif action == "quarantine_release":
            title_base = f"Released {phrase}"
        elif action == "quarantine_keep_blocked":
            title_base = f"Kept {phrase} blocked"
        elif action == "quarantine_reevaluate":
            title_base = f"Re-evaluated {phrase}"
        elif action == "passkey_unlock":
            title_base = f"Unlocked original of {phrase}"
        elif action == "feedback_benign":
            title_base = f"Marked {phrase} as not malicious"
        elif action == "feedback_benign_undo":
            title_base = f"Removed benign label from {phrase}"
        elif action == "ai_retry" and meta.get("queue_ids"):
            ids = meta.get("queue_ids") or []
            if isinstance(ids, list) and len(ids) == 1:
                title_base = f"Retried AI assessment for {phrase}"
    detail_bits = [who]
    dwell_ms = meta.get("dwell_ms")
    if action == "email_view" and dwell_ms is not None:
        detail_bits.append(f"viewed for {format_dwell(dwell_ms)}")
    elif entry.get("detail"):
        raw_detail = str(entry["detail"])
        if not (has_email and phrase and phrase in raw_detail and action in {
            "email_open", "email_view", "quarantine_download",
            "quarantine_release", "quarantine_keep_blocked", "quarantine_reevaluate",
            "passkey_unlock", "feedback_benign", "feedback_benign_undo",
        }):
            detail_bits.append(raw_detail)
    ts_ms = int(float(entry.get("ts_epoch") or time.time()) * 1000)
    return {
        "ts": ts_ms,
        "type": ui_type,
        "title": title_base,
        "detail": " — ".join(detail_bits),
        "wazuh": False,
        "kind": "activity",
        "action": action,
        "actor": actor,
        "tag": "Activity",
    }
