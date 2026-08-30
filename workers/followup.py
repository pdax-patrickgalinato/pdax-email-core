"""Durable queues that fire after a copy's LLM assessment lands.

Gmail poll persists the raw copy and enqueues static workers. When the AI
worker finishes, this module records the
same dest for campaign reclustering and sender-profile ingest, and the
From address for sender-risk AI. Those jobs live in the API process and
drain this sqlite queue (shared data volume) so they see work the
receiver just finished — in-memory queues cannot cross processes.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
from pathlib import Path

from backend.paths import DATA_DIR
from backend.db import connect as db_connect

_log = logging.getLogger("workers.followup")

_lock = threading.Lock()
_db_override: Path | None = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS followup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    dest TEXT NOT NULL DEFAULT '',
    sender TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    UNIQUE(kind, dest, sender)
);
CREATE INDEX IF NOT EXISTS idx_followup_kind ON followup(kind);
"""


def set_db_path(path: Path | None) -> None:
    """Tests point this at a temp file so they do not touch data/."""
    global _db_override
    with _lock:
        _db_override = Path(path) if path is not None else None


def db_path() -> Path:
    return _db_override or (DATA_DIR / "followup_queue.sqlite3")


def _connect():
    return db_connect(db_path(), schema=_SCHEMA)


def _dest_key(dest: Path) -> str:
    try:
        return str(Path(dest).resolve())
    except OSError:
        return str(dest)


def _put(kind: str, *, dest: str = "", sender: str = "") -> None:
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO followup (kind, dest, sender, created_at) "
                "VALUES (?, ?, ?, ?)",
                (kind, dest, sender, time.time()),
            )
            conn.commit()
        finally:
            conn.close()


def after_assessment(dest: Path) -> None:
    """Called by the LLM worker after a successful persist (not on timeout)."""
    from workers import sqs as sqsmod
    from backend.stores import spool
    if sqsmod.use_sqs():
        pl = spool.as_payload(dest)
        sqsmod.send("campaign", pl)
        sqsmod.send("profile", pl)
    dest = Path(dest) if not isinstance(dest, dict) else spool.as_path(dest)
    key = _dest_key(dest) if dest.exists() else spool.dest_key(dest)
    if not sqsmod.use_sqs():
        _put("campaign", dest=key)
        _put("profile", dest=key)
    sender = ""
    try:
        meta = spool.read_meta(dest)
        from backend.stores.sender_profile_ingest import from_addr
        sender = from_addr(meta)
    except Exception:
        sender = ""
    if sender:
        _put("sender_risk", sender=sender)
        _log.debug("followup queued %s sender=%s", spool.dest_name(dest), sender)
    else:
        _log.debug("followup queued %s (no sender)", spool.dest_name(dest))


def take_campaign(limit: int = 40) -> list:
    from workers import sqs as sqsmod
    from backend.stores import spool
    if sqsmod.use_sqs():
        out = []
        for _ in range(max(1, int(limit))):
            payload, receipt = sqsmod.receive("campaign", wait_seconds=0)
            if not payload:
                break
            sqsmod.ack("campaign", receipt)
            out.append(spool.as_path(payload) if not spool.use_s3() else payload)
        return out
    return _take_dests("campaign", limit)


def take_profiles(limit: int = 40) -> list:
    from workers import sqs as sqsmod
    from backend.stores import spool
    if sqsmod.use_sqs():
        out = []
        for _ in range(max(1, int(limit))):
            payload, receipt = sqsmod.receive("profile", wait_seconds=0)
            if not payload:
                break
            sqsmod.ack("profile", receipt)
            out.append(spool.as_path(payload) if not spool.use_s3() else payload)
        return out
    return _take_dests("profile", limit)


def take_senders(limit: int = 8) -> list[str]:
    rows = _take_rows("sender_risk", max(1, int(limit)))
    out: list[str] = []
    seen: set[str] = set()
    for _id, _dest, sender in rows:
        addr = (sender or "").strip().lower()
        if addr and addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


def _take_dests(kind: str, limit: int) -> list[Path]:
    rows = _take_rows(kind, max(1, int(limit)))
    out: list[Path] = []
    seen: set[str] = set()
    for _id, dest, _sender in rows:
        key = dest or ""
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(Path(key))
    return out


def _take_rows(kind: str, limit: int) -> list[tuple]:
    cap = max(1, int(limit))
    with _lock:
        conn = _connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT id, dest, sender FROM followup WHERE kind = ? "
                "ORDER BY id LIMIT ?",
                (kind, cap),
            ).fetchall()
            if rows:
                ids = [r[0] for r in rows]
                conn.execute(
                    f"DELETE FROM followup WHERE id IN ({','.join('?' * len(ids))})",
                    ids,
                )
            conn.commit()
            return rows
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def pending_counts() -> dict:
    from workers import sqs as sqsmod
    out = {"campaign": 0, "profile": 0, "sender_risk": 0}
    if sqsmod.use_sqs():
        sqs_counts = sqsmod.pending_counts()
        out["campaign"] = int(sqs_counts.get("campaign") or 0)
        out["profile"] = int(sqs_counts.get("profile") or 0)
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT kind, COUNT(*) FROM followup GROUP BY kind"
            ).fetchall()
        finally:
            conn.close()
    for kind, n in rows:
        if kind == "sender_risk" or not sqsmod.use_sqs():
            if kind in out:
                out[kind] = int(n or 0)
    return out


def reset() -> None:
    """Drop queued follow-up jobs. Tests only."""
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM followup")
            conn.commit()
        finally:
            conn.close()
