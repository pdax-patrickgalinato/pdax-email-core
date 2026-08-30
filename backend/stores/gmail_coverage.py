"""Grow Gmail poll coverage from fan-out — org addresses seen in other inboxes.

`SEG_GMAIL_USERS` is the seed. Envelope To/Cc and sibling-mailbox fan-out can
name more people on `SEG_GMAIL_DOMAIN` (pdax.ph) we are not polling yet. Those
addresses are persisted (Postgres when `SEG_DATABASE_URL` is set, otherwise a
JSON file) and merged into the next poll. Other domains — including protected
brands used for lookalike detection — are never impersonated. Mailboxes that
DWD cannot impersonate (groups, no Gmail, bad grants) are skipped so they do
not keep failing every cycle.
"""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from email.utils import getaddresses
from pathlib import Path
from typing import Iterable

from backend.config import get_settings
from backend.domainutils import registrable_domain
from backend.paths import DATA_DIR

_STORE_OVERRIDE: Path | None = None
_lock = threading.Lock()
_SKIP_LOCAL = frozenset({
    "noreply", "no-reply", "mailer-daemon", "postmaster", "bounce",
    "nobody", "donotreply", "do-not-reply",
})
_PERMANENT_FAIL = (
    "unauthorized_client",
    "invalid_grant",
    "mail service not enabled",
    "failedprecondition",
    "user not found",
    "notfound",
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def store_path() -> Path:
    if _STORE_OVERRIDE is not None:
        return _STORE_OVERRIDE
    raw = (os.environ.get("SEG_GMAIL_COVERAGE_PATH") or "").strip()
    return Path(raw) if raw else DATA_DIR / "gmail_discovered_users.json"


def _use_postgres() -> bool:
    if _STORE_OVERRIDE is not None:
        return False
    try:
        from backend.db import is_postgres
        return is_postgres()
    except Exception:
        return False


def coverage_domains() -> set[str]:
    """Workspace domain(s) whose inboxes we may impersonate and poll.

    Lookalike / protected-brand lists are for sender detection, not poll
    coverage — otherwise To/Cc of @google.com or @fireblocks.com would be
    added to the Gmail DWD poll set.
    """
    configured = (get_settings().gmail_domain or "").strip().lower()
    if not configured:
        return set()
    name = registrable_domain(configured) or configured
    return {name} if name else set()


def env_users() -> list[str]:
    return _unique(
        normalize_mailbox(u) for u in get_settings().gmail_users.split(",") if u.strip()
    )


def normalize_mailbox(value: str) -> str:
    raw = (value or "").strip().lower()
    if "@" not in raw:
        return raw
    local, _, domain = raw.partition("@")
    local = local.split("+", 1)[0]
    return f"{local}@{domain}"


def is_org_mailbox(addr: str, domains: set[str] | None = None) -> bool:
    norm = normalize_mailbox(addr)
    if not _EMAIL_RE.match(norm):
        return False
    local, _, domain = norm.partition("@")
    if not local or local in _SKIP_LOCAL:
        return False
    want = domains if domains is not None else coverage_domains()
    if not want:
        return False
    return (registrable_domain(domain) or domain) in want


def _unique(addrs: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in addrs:
        n = normalize_mailbox(raw)
        if not n or n in seen:
            continue
        seen.add(n)
        out.append(n)
    return out


def _empty_store() -> dict:
    return {"users": [], "skipped": []}


def _load() -> dict:
    path = store_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return _empty_store()
    if not isinstance(data, dict):
        return _empty_store()
    users = data.get("users") if isinstance(data.get("users"), list) else []
    skipped = data.get("skipped") if isinstance(data.get("skipped"), list) else []
    return {"users": users, "skipped": skipped}


def _save(data: dict) -> None:
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _pg_connect():
    from backend.db import connect
    return connect()


def _row_email(row) -> str:
    raw = ""
    try:
        raw = row["email"]
    except (KeyError, IndexError, TypeError):
        try:
            raw = row[0]
        except (KeyError, IndexError, TypeError):
            raw = ""
    return normalize_mailbox(str(raw or ""))


def _pg_skipped_set(conn=None) -> set[str]:
    own = conn is None
    if own:
        conn = _pg_connect()
    try:
        rows = conn.execute("SELECT email FROM gmail_coverage_skipped").fetchall()
        return {e for e in (_row_email(r) for r in rows) if e}
    finally:
        if own:
            conn.close()


def _pg_discovered() -> list[str]:
    conn = _pg_connect()
    try:
        skip = _pg_skipped_set(conn)
        rows = conn.execute(
            "SELECT email FROM gmail_coverage ORDER BY first_seen ASC"
        ).fetchall()
        out = []
        for row in rows:
            email = _row_email(row)
            if email and email not in skip:
                out.append(email)
        return _unique(out)
    finally:
        conn.close()


def skipped_users() -> set[str]:
    if _use_postgres():
        try:
            return _pg_skipped_set()
        except Exception:
            return set()
    with _lock:
        data = _load()
    return {
        normalize_mailbox(str(row.get("email") or ""))
        for row in data.get("skipped") or []
        if isinstance(row, dict) and row.get("email")
    }


def discovered_users() -> list[str]:
    if _use_postgres():
        try:
            return _pg_discovered()
        except Exception:
            return []
    with _lock:
        data = _load()
    skip = {
        normalize_mailbox(str(row.get("email") or ""))
        for row in data.get("skipped") or []
        if isinstance(row, dict) and row.get("email")
    }
    out = []
    for row in data.get("users") or []:
        if not isinstance(row, dict):
            continue
        email = normalize_mailbox(str(row.get("email") or ""))
        if email and email not in skip:
            out.append(email)
    return _unique(out)


def monitored_users() -> list[str]:
    """Seed env list plus fan-out discoveries, minus impersonation skips.

    When `SEG_GMAIL_DOMAIN` is set, only that Workspace domain is polled —
    leftover discovered rows on other domains are ignored.
    """
    skip = skipped_users()
    domains = coverage_domains()
    out = []
    for u in _unique(env_users() + discovered_users()):
        if u in skip:
            continue
        if domains and not is_org_mailbox(u, domains):
            continue
        out.append(u)
    return out


def offer(addrs: Iterable[str], *, source: str = "fanout", limit: int | None = None) -> list[str]:
    """Persist new org-domain mailboxes. Returns addresses newly added."""
    domains = coverage_domains()
    skip = skipped_users()
    already = set(env_users()) | set(discovered_users()) | skip
    fresh = []
    for raw in addrs:
        n = normalize_mailbox(raw)
        if n in already or not is_org_mailbox(n, domains):
            continue
        already.add(n)
        fresh.append(n)
    if limit is not None:
        fresh = fresh[: max(0, int(limit))]
    if not fresh:
        return []
    now = datetime.now(timezone.utc).isoformat()
    if _use_postgres():
        conn = _pg_connect()
        try:
            for email in fresh:
                conn.execute(
                    "INSERT OR IGNORE INTO gmail_coverage (email, first_seen, source) "
                    "VALUES (?,?,?)",
                    (email, now, source),
                )
            conn.commit()
        finally:
            conn.close()
        return fresh
    with _lock:
        data = _load()
        have = {
            normalize_mailbox(str(row.get("email") or ""))
            for row in data.get("users") or []
            if isinstance(row, dict)
        }
        for email in fresh:
            if email in have:
                continue
            data["users"].append({
                "email": email,
                "first_seen": now,
                "source": source,
            })
        _save(data)
    return fresh


def offer_from_scan(dest: Path | dict | None, meta: dict | None, ctx: dict | None) -> list[str]:
    """Pull uncapped envelope + fan-out addresses from a stored copy."""
    addrs: list[str] = []
    if dest is not None:
        from backend.stores.mail_fanout import _envelope_addrs
        addrs.extend(_envelope_addrs(dest, meta or {}))
    if ctx:
        for key in ("mailboxes", "recipients", "envelope_recipients"):
            addrs.extend(ctx.get(key) or [])
    if meta:
        mailbox = str(meta.get("mailbox") or "")
        if mailbox:
            addrs.append(mailbox)
        addrs.extend(_split_addr_fields(meta.get("to"), meta.get("cc"), meta.get("from")))
        addrs.extend(meta.get("fanout_recipients") or [])
        addrs.extend(meta.get("fanout_mailboxes") or [])
    return offer(addrs, source="fanout")


def seed_from_spool(root: Path | None = None, limit_new: int = 80) -> list[str]:
    """Catch up coverage from copies already on disk. Caps how many we add per call."""
    from backend.paths import SPOOL_DIR

    base = Path(root) if root is not None else Path(
        (get_settings().quarantine_root or "").strip() or str(SPOOL_DIR)
    )
    gmail = base / "gmail"
    if not gmail.is_dir() or limit_new <= 0:
        return []
    added: list[str] = []
    for p in gmail.iterdir():
        if len(added) >= limit_new:
            break
        if not p.is_dir() or not (p / "meta.json").is_file():
            continue
        try:
            meta = json.loads((p / "meta.json").read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(meta, dict):
            continue
        ctx = {
            "mailboxes": meta.get("fanout_mailboxes") or [],
            "recipients": meta.get("fanout_recipients") or [],
        }
        room = limit_new - len(added)
        fresh = offer_from_scan(p, meta, ctx)
        added.extend(fresh[:room])
    return added


def _split_addr_fields(*values) -> list[str]:
    out: list[str] = []
    for value in values:
        if not value:
            continue
        if isinstance(value, (list, tuple, set)):
            for item in value:
                out.extend(_split_addr_fields(item))
            continue
        text = str(value)
        parsed = [a for _, a in getaddresses([text]) if a]
        out.extend(parsed if parsed else [text])
    return out


def _addrs_from_copy_row(row: dict) -> list[str]:
    addrs = _split_addr_fields(
        row.get("mailbox"),
        row.get("from_addr"),
        row.get("to_addr"),
    )
    raw_meta = row.get("meta_json") or "{}"
    try:
        meta = json.loads(raw_meta) if isinstance(raw_meta, str) else (raw_meta or {})
    except (json.JSONDecodeError, TypeError, ValueError):
        meta = {}
    if isinstance(meta, dict):
        addrs.extend(_split_addr_fields(
            meta.get("mailbox"),
            meta.get("to"),
            meta.get("cc"),
            meta.get("from"),
        ))
        addrs.extend(meta.get("fanout_recipients") or [])
        addrs.extend(meta.get("fanout_mailboxes") or [])
        addrs.extend(meta.get("envelope_recipients") or [])
    return addrs


def seed_from_copies(limit_rows: int = 500, limit_new: int = 80) -> list[str]:
    """Grow coverage from analyzed copies (Postgres/SQLite), not local spool."""
    if limit_new <= 0:
        return []
    from backend.stores import assessments as store
    try:
        rows = store.list_addr_fields(limit_rows)
    except Exception:
        return []
    addrs: list[str] = []
    for row in rows:
        addrs.extend(_addrs_from_copy_row(row))
    return offer(addrs, source="copies", limit=limit_new)


def is_permanent_failure(error: str) -> bool:
    s = (error or "").lower()
    return any(token in s for token in _PERMANENT_FAIL)


def note_failure(user: str, error: str) -> bool:
    """Remember mailboxes DWD cannot impersonate. Returns True if skipped."""
    if not is_permanent_failure(error):
        return False
    email = normalize_mailbox(user)
    if not email:
        return False
    now = datetime.now(timezone.utc).isoformat()
    reason = (error or "error").replace("\n", " ")[:240]
    if _use_postgres():
        conn = _pg_connect()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO gmail_coverage_skipped (email, reason, ts) "
                "VALUES (?,?,?)",
                (email, reason, now),
            )
            conn.commit()
        finally:
            conn.close()
        return True
    with _lock:
        data = _load()
        skipped = data.setdefault("skipped", [])
        have = {
            normalize_mailbox(str(row.get("email") or ""))
            for row in skipped
            if isinstance(row, dict)
        }
        if email not in have:
            skipped.append({"email": email, "reason": reason, "ts": now})
            _save(data)
    return True


def snapshot() -> dict:
    env = env_users()
    discovered = [u for u in discovered_users() if u not in set(env)]
    skip = sorted(skipped_users())
    polling = monitored_users()
    return {
        "configured": len(env),
        "discovered": len(discovered),
        "skipped": len(skip),
        "polling": len(polling),
        "discovered_users": discovered[:40],
        "skipped_users": skip[:40],
    }
