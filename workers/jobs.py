"""Durable work queue on the shared data volume.

Poll, static checks, content AI, intel, and thread AI put/take rows here
(SQLite on EFS in production). ``take()`` claims a row with a lease instead of
deleting it; ``ack()`` removes it after success. A crash mid-job leaves the
row claimed until the lease expires, then another worker can reclaim it.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from pathlib import Path

from backend.paths import DATA_DIR
from backend.db import connect as db_connect, is_postgres

_log = logging.getLogger("workers.jobs")

_lock = threading.Lock()
_db_override: Path | None = None

KINDS = (
    "static",
    "content_ai",
    "thread_ai",
    "intel",
)

_DEFAULT_LEASE = {
    "static": 180.0,
    "content_ai": 240.0,
    "thread_ai": 90.0,
    "intel": 420.0,
}


def set_db_path(path: Path | None) -> None:
    global _db_override
    with _lock:
        _db_override = Path(path) if path is not None else None


def db_path() -> Path:
    return _db_override or (DATA_DIR / "worker_jobs.sqlite3")


def _lease_seconds(kind: str = "") -> float:
    try:
        from backend.config import get_settings
        n = float(get_settings().job_lease_seconds)
        if n > 0:
            return max(30.0, min(n, 1800.0))
    except Exception:
        pass
    return float(_DEFAULT_LEASE.get(kind, 360.0))


def worker_id() -> str:
    return f"{os.getpid()}:{threading.current_thread().name}"


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _claimant_gone(claimed_by: str) -> bool:
    """True when claimed_by is another process that is no longer running."""
    raw = (claimed_by or "").split(":", 1)[0].strip()
    try:
        pid = int(raw)
    except ValueError:
        return False
    if pid == os.getpid():
        return False
    return not _pid_alive(pid)


_JOBS_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    dest TEXT NOT NULL,
    created_at REAL NOT NULL,
    claimed_at REAL,
    claimed_by TEXT NOT NULL DEFAULT '',
    attempts INTEGER NOT NULL DEFAULT 0,
    UNIQUE(kind, dest)
);
CREATE INDEX IF NOT EXISTS idx_jobs_kind ON jobs(kind);
CREATE INDEX IF NOT EXISTS idx_jobs_kind_claimed ON jobs(kind, claimed_at);
"""


def _connect():
    conn = db_connect(db_path(), schema=_JOBS_SCHEMA)
    if is_postgres():
        return conn
    cols = {r[1] for r in conn.execute("PRAGMA table_info(jobs)").fetchall()}
    if "claimed_at" not in cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN claimed_at REAL")
    if "claimed_by" not in cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN claimed_by TEXT NOT NULL DEFAULT ''")
    if "attempts" not in cols:
        conn.execute("ALTER TABLE jobs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
    conn.commit()
    return conn


def _key(dest) -> str:
    try:
        return str(Path(dest).resolve())
    except OSError:
        return str(dest)


def put(kind: str, dest) -> None:
    """Enqueue dest for kind. Duplicate (kind, dest) is ignored."""
    kind = (kind or "").strip()
    if kind not in KINDS:
        return
    key = _key(dest) if kind != "thread_ai" else str(dest or "").strip()
    if not key:
        return
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO jobs (kind, dest, created_at) VALUES (?, ?, ?)",
                (kind, key, time.time()),
            )
            conn.commit()
        finally:
            conn.close()


def take(kind: str, *, claimant: str = "") -> str | None:
    """Claim one row for kind, or None if idle. Does not delete the row."""
    kind = (kind or "").strip()
    if kind not in KINDS:
        return None
    stale_before = time.time() - _lease_seconds(kind)
    who = (claimant or worker_id())[:120]
    now = time.time()
    with _lock:
        conn = _connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT id, dest FROM jobs
                WHERE kind = ?
                  AND (claimed_at IS NULL OR claimed_at = 0 OR claimed_at < ?)
                ORDER BY id
                LIMIT 1
                """,
                (kind, stale_before),
            ).fetchone()
            if not row:
                live = conn.execute(
                    """
                    SELECT id, dest, claimed_by FROM jobs
                    WHERE kind = ?
                      AND claimed_at IS NOT NULL AND claimed_at >= ?
                    ORDER BY id
                    """,
                    (kind, stale_before),
                ).fetchall()
                for cid, dest, claimed_by in live:
                    if _claimant_gone(claimed_by or ""):
                        row = (cid, dest)
                        break
            if not row:
                conn.commit()
                return None
            conn.execute(
                """
                UPDATE jobs
                SET claimed_at = ?, claimed_by = ?, attempts = attempts + 1
                WHERE id = ?
                """,
                (now, who, row[0]),
            )
            conn.commit()
            return str(row[1] or "")
        except sqlite3.Error:
            conn.rollback()
            raise
        finally:
            conn.close()


def ack(kind: str, dest) -> None:
    """Drop a claimed (or waiting) row after success or a terminal failure."""
    kind = (kind or "").strip()
    key = _key(dest) if kind != "thread_ai" else str(dest or "").strip()
    if kind not in KINDS or not key:
        return
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "DELETE FROM jobs WHERE kind = ? AND dest = ?",
                (kind, key),
            )
            conn.commit()
        finally:
            conn.close()


def nack(kind: str, dest) -> None:
    """Unclaim a row so another worker can pick it up immediately."""
    kind = (kind or "").strip()
    key = _key(dest) if kind != "thread_ai" else str(dest or "").strip()
    if kind not in KINDS or not key:
        return
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                UPDATE jobs
                SET claimed_at = NULL, claimed_by = ''
                WHERE kind = ? AND dest = ?
                """,
                (kind, key),
            )
            conn.commit()
        finally:
            conn.close()


def attempts_of(kind: str, dest) -> int:
    kind = (kind or "").strip()
    key = _key(dest) if kind != "thread_ai" else str(dest or "").strip()
    if kind not in KINDS or not key:
        return 0
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT attempts FROM jobs WHERE kind = ? AND dest = ?",
                (kind, key),
            ).fetchone()
            return int(row[0] or 0) if row else 0
        finally:
            conn.close()


def already_queued(kind: str, dest) -> bool:
    from workers import sqs as sqsmod
    if sqsmod.use_sqs():
        return False
    kind = (kind or "").strip()
    key = _key(dest) if kind != "thread_ai" else str(dest or "").strip()
    if kind not in KINDS or not key:
        return False
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM jobs WHERE kind = ? AND dest = ?",
                (kind, key),
            ).fetchone()
            return row is not None
        finally:
            conn.close()


def pending_count(kind: str = "") -> int:
    """Unclaimed (waiting) rows. Claimed work is not counted here."""
    from workers import sqs as sqsmod
    if sqsmod.use_sqs():
        counts = sqsmod.pending_counts()
        if kind:
            return int(counts.get(kind) or 0)
        return sum(int(v or 0) for v in counts.values())
    now = time.time()
    with _lock:
        conn = _connect()
        try:
            if kind:
                stale = now - _lease_seconds(kind)
                row = conn.execute(
                    """
                    SELECT COUNT(*) FROM jobs
                    WHERE kind = ?
                      AND (claimed_at IS NULL OR claimed_at = 0 OR claimed_at < ?)
                    """,
                    (kind, stale),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()
            return int(row[0] or 0) if row else 0
        finally:
            conn.close()


def pending_counts() -> dict:
    from workers import sqs as sqsmod
    if sqsmod.use_sqs():
        out = {k: 0 for k in KINDS}
        out.update(sqsmod.pending_counts())
        out.setdefault("intel", 0)
        return out
    now = time.time()
    out = {k: 0 for k in KINDS}
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT kind, claimed_at FROM jobs"
            ).fetchall()
        finally:
            conn.close()
    for kind, claimed_at in rows:
        if kind not in out:
            continue
        stale = now - _lease_seconds(kind)
        if claimed_at is None or float(claimed_at or 0) < stale:
            out[kind] += 1
    return out


def queue_stats() -> dict:
    """Waiting / claimed / stale counts plus oldest claim age (seconds)."""
    from workers import sqs as sqsmod
    if sqsmod.use_sqs():
        stats = sqsmod.queue_stats()
        stats.setdefault("intel", {"waiting": 0, "claimed": 0, "stale": 0, "oldest_claim_age": 0.0})
        return stats
    now = time.time()
    out = {
        k: {"waiting": 0, "claimed": 0, "stale": 0, "oldest_claim_age": 0.0}
        for k in KINDS
    }
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT kind, claimed_at FROM jobs"
            ).fetchall()
        finally:
            conn.close()
    oldest = {k: 0.0 for k in KINDS}
    for kind, claimed_at in rows:
        if kind not in out:
            continue
        lease = _lease_seconds(kind)
        ts = float(claimed_at or 0)
        if ts <= 0:
            out[kind]["waiting"] += 1
            continue
        age = now - ts
        if age >= lease:
            out[kind]["stale"] += 1
            out[kind]["waiting"] += 1
        else:
            out[kind]["claimed"] += 1
            if age > oldest[kind]:
                oldest[kind] = age
    for kind in KINDS:
        out[kind]["oldest_claim_age"] = round(oldest[kind], 1)
    return out


def reset() -> None:
    """Drop queued jobs. Tests only."""
    from workers import sqs as sqsmod
    sqsmod.reset()
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM jobs")
            conn.commit()
        finally:
            conn.close()
