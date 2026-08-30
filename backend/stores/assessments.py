"""Per-copy analysis rows written by workers, read by the API feed."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

from backend.paths import DATA_DIR
from backend.db import connect as db_connect, is_postgres

_lock = threading.Lock()
_db_override: Path | None = None

STATIC_KINDS = ("static",)

QUEUED = "queued"
STATIC = "static"
AI = "ai"
TIMED_OUT = "timed_out"
ERROR = "error"
DEAD_LETTER = "dead_letter"
COMPLETE = "complete"

# Must outlast SQS content_ai visibility so a redelivered message cannot
# start a second Vertex call while the first task is still running.
AI_CLAIM_SECONDS = 480

# queued → static → ai ⇄ timed_out → complete. error/dead_letter are terminal
# until an explicit retry walks them back to ai.
_STATUS_RANK = {
    QUEUED: 0,
    STATIC: 1,
    ERROR: 1,
    AI: 2,
    TIMED_OUT: 2,
    DEAD_LETTER: 3,
    COMPLETE: 3,
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS copies (
    queue_id TEXT PRIMARY KEY,
    dest TEXT NOT NULL DEFAULT '',
    mailbox TEXT NOT NULL DEFAULT '',
    gmail_message_id TEXT NOT NULL DEFAULT '',
    gmail_thread_id TEXT NOT NULL DEFAULT '',
    from_addr TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    to_addr TEXT NOT NULL DEFAULT '',
    verdict TEXT NOT NULL DEFAULT '',
    score REAL,
    disposition TEXT NOT NULL DEFAULT 'LOG',
    ai_provider TEXT NOT NULL DEFAULT '',
    ai_summary TEXT NOT NULL DEFAULT '',
    ai_model TEXT NOT NULL DEFAULT '',
    identity_done INTEGER NOT NULL DEFAULT 0,
    reputation_done INTEGER NOT NULL DEFAULT 0,
    static_done INTEGER NOT NULL DEFAULT 0,
    sandbox_done INTEGER NOT NULL DEFAULT 0,
    ai_done INTEGER NOT NULL DEFAULT 0,
    thread_ai_done INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'queued',
    stages_json TEXT NOT NULL DEFAULT '{}',
    meta_json TEXT NOT NULL DEFAULT '{}',
    rfc_message_id TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    ai_claimed_at REAL NOT NULL DEFAULT 0,
    ai_claimed_by TEXT NOT NULL DEFAULT '',
    origin_country TEXT NOT NULL DEFAULT '',
    origin_city TEXT NOT NULL DEFAULT '',
    origin_name TEXT NOT NULL DEFAULT '',
    origin_lat REAL,
    origin_lon REAL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_copies_thread ON copies(gmail_thread_id);
CREATE INDEX IF NOT EXISTS idx_copies_updated ON copies(updated_at);
CREATE TABLE IF NOT EXISTS overview_stats (
    key TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL DEFAULT '{}',
    computed_at REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS worker_locks (
    name TEXT PRIMARY KEY,
    holder TEXT NOT NULL DEFAULT '',
    expires_at REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ai_claims (
    queue_id TEXT PRIMARY KEY,
    claimed_at REAL NOT NULL DEFAULT 0,
    claimed_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS runtime_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at REAL NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL DEFAULT ''
);
"""


def set_db_path(path: Path | None) -> None:
    global _db_override
    with _lock:
        _db_override = Path(path) if path is not None else None


def db_path() -> Path:
    return _db_override or (DATA_DIR / "assessments.sqlite3")


def _connect():
    conn = db_connect(db_path(), schema=_SCHEMA)
    if not is_postgres():
        _ensure_columns(conn)
    return conn


def _ensure_columns(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(copies)").fetchall()}
    if "status" not in cols:
        conn.execute(
            "ALTER TABLE copies ADD COLUMN status TEXT NOT NULL DEFAULT 'queued'"
        )
        conn.execute(
            "UPDATE copies SET status = ? WHERE ai_done = 1",
            (COMPLETE,),
        )
        conn.execute(
            "UPDATE copies SET status = ? WHERE static_done = 1 AND ai_done = 0",
            (AI,),
        )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_copies_status ON copies(status)")
    if "rfc_message_id" not in cols:
        conn.execute(
            "ALTER TABLE copies ADD COLUMN rfc_message_id TEXT NOT NULL DEFAULT ''"
        )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_copies_rfc ON copies(rfc_message_id)")
    if "last_error" not in cols:
        conn.execute(
            "ALTER TABLE copies ADD COLUMN last_error TEXT NOT NULL DEFAULT ''"
        )
    if "ai_claimed_at" not in cols:
        conn.execute(
            "ALTER TABLE copies ADD COLUMN ai_claimed_at REAL NOT NULL DEFAULT 0"
        )
    if "ai_claimed_by" not in cols:
        conn.execute(
            "ALTER TABLE copies ADD COLUMN ai_claimed_by TEXT NOT NULL DEFAULT ''"
        )
    if "origin_country" not in cols:
        conn.execute(
            "ALTER TABLE copies ADD COLUMN origin_country TEXT NOT NULL DEFAULT ''"
        )
    if "origin_city" not in cols:
        conn.execute(
            "ALTER TABLE copies ADD COLUMN origin_city TEXT NOT NULL DEFAULT ''"
        )
    if "origin_name" not in cols:
        conn.execute(
            "ALTER TABLE copies ADD COLUMN origin_name TEXT NOT NULL DEFAULT ''"
        )
    if "origin_lat" not in cols:
        conn.execute("ALTER TABLE copies ADD COLUMN origin_lat REAL")
    if "origin_lon" not in cols:
        conn.execute("ALTER TABLE copies ADD COLUMN origin_lon REAL")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_copies_verdict_ai ON copies(ai_done, verdict, updated_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_copies_pending ON copies(ai_done, status)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_copies_origin ON copies(origin_country)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS overview_stats (
            key TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL DEFAULT '{}',
            computed_at REAL NOT NULL DEFAULT 0
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS worker_locks (
            name TEXT PRIMARY KEY,
            holder TEXT NOT NULL DEFAULT '',
            expires_at REAL NOT NULL DEFAULT 0
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_claims (
            queue_id TEXT PRIMARY KEY,
            claimed_at REAL NOT NULL DEFAULT 0,
            claimed_by TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.commit()


def advance_status(current: str, proposed: str) -> str:
    """Move a copy forward through the pipeline; never regress."""
    cur = (current or QUEUED).strip() or QUEUED
    nxt = (proposed or "").strip()
    if not nxt:
        return cur
    if nxt == cur:
        return cur
    if cur == COMPLETE:
        return COMPLETE
    if nxt == TIMED_OUT:
        return TIMED_OUT
    if nxt == ERROR:
        return ERROR
    if nxt == DEAD_LETTER:
        return DEAD_LETTER
    if cur == TIMED_OUT and nxt == AI:
        return AI
    if cur in (DEAD_LETTER, ERROR) and nxt == AI:
        return AI
    if _STATUS_RANK.get(nxt, 0) >= _STATUS_RANK.get(cur, 0):
        return nxt
    return cur


def status_of(row: Optional[dict]) -> str:
    if not row:
        return QUEUED
    stored = str(row.get("status") or "").strip()
    if stored:
        return stored
    if int(row.get("ai_done") or 0):
        return COMPLETE
    if int(row.get("static_done") or 0):
        return AI
    return QUEUED


def set_status(queue_id: str, status: str) -> dict:
    upsert_copy(queue_id, status=status)
    return get_copy(queue_id) or {}


def upsert_copy(queue_id: str, **fields) -> None:
    qid = (queue_id or "").strip()
    if not qid:
        return
    allowed = {
        "dest", "mailbox", "gmail_message_id", "gmail_thread_id",
        "from_addr", "subject", "to_addr", "verdict", "score", "disposition",
        "ai_provider", "ai_summary", "ai_model",
        "identity_done", "reputation_done", "static_done", "sandbox_done",
        "ai_done", "thread_ai_done", "status", "stages_json", "meta_json",
        "rfc_message_id", "last_error",
        "origin_country", "origin_city", "origin_name", "origin_lat", "origin_lon",
    }
    cols = {k: fields[k] for k in allowed if k in fields}
    if "stages_json" in cols and "origin_country" not in cols:
        try:
            stages = json.loads(cols["stages_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            stages = {}
        from backend.stores.overview import origin_fields_from_stages
        cols.update(origin_fields_from_stages(stages))
    cols["updated_at"] = time.time()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM copies WHERE queue_id = ?", (qid,),
            ).fetchone()
            if row is not None and "status" in cols:
                cols["status"] = advance_status(row["status"] or QUEUED, str(cols["status"]))
            elif row is None:
                cols.setdefault("status", QUEUED)
            if row is None:
                cols["queue_id"] = qid
                names = ", ".join(cols)
                placeholders = ", ".join("?" for _ in cols)
                conn.execute(
                    f"INSERT INTO copies ({names}) VALUES ({placeholders})",
                    list(cols.values()),
                )
            elif cols:
                sets = ", ".join(f"{k} = ?" for k in cols)
                conn.execute(
                    f"UPDATE copies SET {sets} WHERE queue_id = ?",
                    list(cols.values()) + [qid],
                )
            conn.commit()
        finally:
            conn.close()


def merge_stage(queue_id: str, stage: str, facts: dict) -> None:
    qid = (queue_id or "").strip()
    if not qid:
        return
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT stages_json FROM copies WHERE queue_id = ?", (qid,),
            ).fetchone()
            stages = {}
            if row:
                try:
                    stages = json.loads(row["stages_json"] or "{}")
                except json.JSONDecodeError:
                    stages = {}
            if not isinstance(stages, dict):
                stages = {}
            stages[stage] = facts or {}
            packed = json.dumps(stages, default=str)
            extra = ""
            extra_vals: list = []
            if stage == "origin_ip":
                from backend.stores.overview import origin_fields_from_stages
                origin = origin_fields_from_stages({"origin_ip": facts or {}})
                if origin:
                    extra = ", " + ", ".join(f"{k} = ?" for k in origin)
                    extra_vals = list(origin.values())
            conn.execute(
                "UPDATE copies SET stages_json = ?, updated_at = ?" + extra
                + " WHERE queue_id = ?",
                [packed, time.time()] + extra_vals + [qid],
            )
            conn.commit()
        finally:
            conn.close()


def mark_stage(queue_id: str, kind: str) -> dict:
    """Mark a static job done. Returns the copy row as a dict."""
    col = {
        "identity": "identity_done",
        "reputation": "reputation_done",
        "static": "static_done",
        "sandbox": "sandbox_done",
        "ai": "ai_done",
        "thread_ai": "thread_ai_done",
    }.get(kind)
    if not col:
        return {}
    upsert_copy(queue_id, **{col: 1})
    return get_copy(queue_id) or {}


def static_complete(row: dict) -> bool:
    return all(int(row.get(f"{k}_done") or 0) for k in STATIC_KINDS)


def _hydrate_copy(row) -> dict:
    d = dict(row)
    if "_claim_at" in d:
        d["ai_claimed_at"] = float(d.pop("_claim_at") or 0)
    if "_claim_by" in d:
        d["ai_claimed_by"] = str(d.pop("_claim_by") or "")
    return d


def get_copy(queue_id: str) -> Optional[dict]:
    qid = (queue_id or "").strip()
    if not qid:
        return None
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                """
                SELECT c.*, COALESCE(cl.claimed_at, 0) AS _claim_at,
                       COALESCE(cl.claimed_by, '') AS _claim_by
                FROM copies c
                LEFT JOIN ai_claims cl ON cl.queue_id = c.queue_id
                WHERE c.queue_id = ?
                """,
                (qid,),
            ).fetchone()
            return _hydrate_copy(row) if row else None
        finally:
            conn.close()


def stages_for(queue_id: str) -> dict:
    row = get_copy(queue_id) or {}
    try:
        data = json.loads(row.get("stages_json") or "{}")
    except json.JSONDecodeError:
        data = {}
    return data if isinstance(data, dict) else {}


def copies_in_thread(gmail_thread_id: str, mailbox: str | None = None) -> list[dict]:
    """Copies in this Gmail thread. Same mailbox when given; one row per message id."""
    tid = (gmail_thread_id or "").strip()
    if not tid:
        return []
    mb = (mailbox or "").strip().lower()
    with _lock:
        conn = _connect()
        try:
            if mb:
                rows = conn.execute(
                    """
                    SELECT * FROM copies
                    WHERE gmail_thread_id = ?
                      AND LOWER(COALESCE(mailbox, '')) = ?
                    """,
                    (tid, mb),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM copies WHERE gmail_thread_id = ?", (tid,),
                ).fetchall()
            return _unique_thread_messages([dict(r) for r in rows])
        finally:
            conn.close()


def _unique_thread_messages(rows: list[dict]) -> list[dict]:
    """Drop re-ingested duplicates. Keep the newest row per Gmail/RFC message."""
    best: dict[str, dict] = {}
    order: list[str] = []
    for r in rows:
        mid = (
            str(r.get("gmail_message_id") or "").strip()
            or str(r.get("rfc_message_id") or "").strip()
            or str(r.get("queue_id") or "").strip()
        )
        if not mid:
            continue
        prev = best.get(mid)
        if prev is None:
            best[mid] = r
            order.append(mid)
            continue
        if float(r.get("updated_at") or 0) >= float(prev.get("updated_at") or 0):
            best[mid] = r
    return [best[k] for k in order]


def thread_ai_ready(gmail_thread_id: str) -> bool:
    rows = copies_in_thread(gmail_thread_id)
    if len(rows) < 2:
        return False
    return all(int(r.get("ai_done") or 0) for r in rows)


def status_counts() -> dict:
    """How many copies sit in each pipeline status."""
    out = {
        QUEUED: 0, STATIC: 0, AI: 0, TIMED_OUT: 0,
        ERROR: 0, DEAD_LETTER: 0, COMPLETE: 0,
    }
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT status, COUNT(*) FROM copies GROUP BY status"
            ).fetchall()
        finally:
            conn.close()
    for status, n in rows:
        key = str(status or QUEUED).strip() or QUEUED
        if key in out:
            out[key] = int(n or 0)
        else:
            out[QUEUED] += int(n or 0)
    return out


def list_awaiting_ai(limit: int = 200) -> list[dict]:
    """Static-complete copies that still need an LLM assessment."""
    cap = max(1, min(int(limit), 2000))
    cutoff = time.time() - AI_CLAIM_SECONDS
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT c.*, COALESCE(cl.claimed_at, 0) AS _claim_at,
                       COALESCE(cl.claimed_by, '') AS _claim_by
                FROM copies c
                LEFT JOIN ai_claims cl ON cl.queue_id = c.queue_id
                WHERE c.static_done = 1
                  AND c.ai_done = 0
                  AND c.status NOT IN (?, ?)
                  AND COALESCE(cl.claimed_at, 0) < ?
                ORDER BY c.updated_at ASC
                LIMIT ?
                """,
                (COMPLETE, DEAD_LETTER, cutoff, cap),
            ).fetchall()
            return [_hydrate_copy(r) for r in rows]
        finally:
            conn.close()


def find_assessed_sibling(rfc_message_id: str, queue_id: str = "") -> dict | None:
    """Another copy of the same RFC Message-ID that already has an LLM row."""
    mid = (rfc_message_id or "").strip().lower()
    if mid and not mid.startswith("<"):
        mid = f"<{mid.rstrip('>')}>"
    if not mid:
        return None
    qid = (queue_id or "").strip()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                """
                SELECT * FROM copies
                WHERE rfc_message_id = ?
                  AND ai_done = 1
                  AND ai_summary != ''
                  AND queue_id != ?
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (mid, qid),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def list_missing_thread_id(limit: int = 80) -> list[dict]:
    """Copies whose Gmail thread id was never written to Postgres.

    Older static/content workers created the row without ``gmail_thread_id``.
    S3 ``meta.json`` still has it; the thread-AI worker hydrates from there so
    ``copies_in_thread`` / ``thread_ai_ready`` can group siblings.
    """
    cap = max(1, min(int(limit), 500))
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT * FROM copies
                WHERE COALESCE(gmail_thread_id, '') = ''
                  AND COALESCE(queue_id, '') != ''
                  AND COALESCE(status, '') NOT IN (?, ?)
                ORDER BY CASE WHEN COALESCE(ai_done, 0) = 1 THEN 0 ELSE 1 END,
                         updated_at DESC
                LIMIT ?
                """,
                (DEAD_LETTER, ERROR, cap),
            ).fetchall()
            return [_hydrate_copy(r) for r in rows]
        finally:
            conn.close()


def list_awaiting_thread_ai(limit: int = 200) -> list[str]:
    """Gmail thread ids where every copy has per-message AI but thread AI is missing."""
    cap = max(1, min(int(limit), 2000))
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT gmail_thread_id FROM copies
                WHERE COALESCE(gmail_thread_id, '') != ''
                  AND COALESCE(status, '') NOT IN (?, ?)
                GROUP BY gmail_thread_id
                HAVING COUNT(*) >= 2
                   AND MIN(COALESCE(ai_done, 0)) = 1
                   AND MIN(COALESCE(thread_ai_done, 0)) = 0
                ORDER BY MAX(updated_at) DESC
                LIMIT ?
                """,
                (DEAD_LETTER, ERROR, cap),
            ).fetchall()
            return [str(r[0] or "").strip() for r in rows if str(r[0] or "").strip()]
        finally:
            conn.close()


def list_incomplete_static(limit: int = 80) -> list[dict]:
    cap = max(1, min(int(limit), 500))
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT * FROM copies
                WHERE static_done = 0
                  AND LOWER(COALESCE(status, '')) IN (?, '')
                ORDER BY updated_at ASC
                LIMIT ?
                """,
                (QUEUED, cap),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def recover_deadlock_copies(limit: int = 40) -> list[dict]:
    """Walk error/dead-letter copies that died on Aurora 40P01 back onto the pipeline.

    ``CREATE INDEX IF NOT EXISTS`` on the hot ``copies`` table deadlocks live
    INSERT/UPDATE. After that DDL is skipped, these rows still need an explicit
    retry — status error/dead_letter is otherwise terminal.
    """
    cap = max(1, min(int(limit), 200))
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT * FROM copies
                WHERE LOWER(COALESCE(status, '')) IN (?, ?)
                  AND LOWER(COALESCE(last_error, '')) LIKE ?
                ORDER BY updated_at ASC
                LIMIT ?
                """,
                (ERROR, DEAD_LETTER, "%deadlock%", cap),
            ).fetchall()
            now = time.time()
            out: list[dict] = []
            for raw in rows:
                row = _hydrate_copy(raw)
                qid = str(row.get("queue_id") or "").strip()
                if not qid:
                    continue
                if int(row.get("ai_done") or 0):
                    nxt = COMPLETE
                elif int(row.get("static_done") or 0):
                    nxt = AI
                else:
                    nxt = QUEUED
                conn.execute(
                    "UPDATE copies SET status = ?, last_error = '', updated_at = ? "
                    "WHERE queue_id = ?",
                    (nxt, now, qid),
                )
                row["status"] = nxt
                row["last_error"] = ""
                out.append(row)
            conn.commit()
            return out
        finally:
            conn.close()


# Live-feed payload stays bounded so GET /api/feed stays small. Overview
# tiles and the AI-waiting badge must use overview_stats(), not this cap.
FEED_LIST_LIMIT = 100
FEED_FILTER_LIMIT = 2000
# 0 = all copies. A positive value still clips overview tiles to that window.
OVERVIEW_WINDOW_SECONDS = 0

# Overview tile clicks: same verdict buckets as overview_stats.
_FEED_FILTER_VERDICTS = {
    "malicious": ("MALICIOUS",),
    "suspicious": ("SUSPICIOUS",),
    "safe": ("CLEAN", "LOW"),
}


def verdicts_for_filter(name: str) -> tuple[str, ...] | None:
    key = (name or "").strip().lower()
    if key in ("", "all"):
        return None
    return _FEED_FILTER_VERDICTS.get(key)


def list_copies_by_ids(ids: list[str]) -> list[dict]:
    """Return copies in the given queue_id order (missing ids skipped)."""
    wanted = [str(i or "").strip() for i in ids if str(i or "").strip()]
    if not wanted:
        return []
    # Cap the IN list to the search page size.
    wanted = wanted[:200]
    placeholders = ",".join("?" * len(wanted))
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM copies WHERE queue_id IN ({placeholders})",
                wanted,
            ).fetchall()
            by_id = {str(r["queue_id"] or ""): dict(r) for r in rows}
            return [by_id[i] for i in wanted if i in by_id]
        finally:
            conn.close()


def search_queue_ids(sql: str) -> list[str]:
    """Run allow-listed spotlight SQL and return queue_id values."""
    from backend.api.nl_search import validate_search_sql

    sql = validate_search_sql(sql)
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(sql).fetchall()
            out: list[str] = []
            for r in rows:
                try:
                    qid = str(r["queue_id"] or "").strip()
                except (KeyError, TypeError, IndexError):
                    qid = str(r[0] or "").strip()
                if qid:
                    out.append(qid)
            return out[:200]
        finally:
            conn.close()


LIST_FEED_COLUMNS = (
    "queue_id", "dest", "mailbox", "gmail_message_id", "gmail_thread_id",
    "from_addr", "subject", "to_addr", "verdict", "score", "disposition",
    "ai_provider", "ai_summary", "ai_model",
    "identity_done", "reputation_done", "static_done", "sandbox_done",
    "ai_done", "thread_ai_done", "status", "rfc_message_id", "last_error",
    "origin_country", "origin_city", "origin_name", "origin_lat", "origin_lon",
    "updated_at",
)
_LIST_COLS_SQL = ", ".join(LIST_FEED_COLUMNS)


def _list_select_sql() -> str:
    """List columns plus the same origin expression the snapshot GROUP BY uses."""
    from backend.stores.overview import origin_country_sql
    return _LIST_COLS_SQL + ", " + origin_country_sql() + " AS origin_cc"


def list_feed(limit: int = FEED_LIST_LIMIT, *, origin: str = "") -> list[dict]:
    return list_feed_page(limit=limit, origin=origin)


def list_feed_page(
    *,
    verdict: str = "",
    origin: str = "",
    limit: int | None = None,
    since_seconds: float | None = OVERVIEW_WINDOW_SECONDS,
) -> list[dict]:
    """Newest copies for the list DTO (no stages_json / meta_json)."""
    wanted = verdicts_for_filter(verdict)
    cc = (origin or "").strip().upper()
    cap = max(1, min(int(FEED_LIST_LIMIT if limit is None else limit), FEED_FILTER_LIMIT))
    where: list[str] = []
    params: list = []
    if wanted:
        placeholders = ",".join("?" * len(wanted))
        where.append("COALESCE(ai_done, 0) = 1")
        where.append(f"UPPER(COALESCE(verdict, '')) IN ({placeholders})")
        params.extend(wanted)
        window = OVERVIEW_WINDOW_SECONDS if since_seconds is None else float(since_seconds)
        if window > 0:
            where.append("updated_at >= ?")
            params.append(time.time() - window)
    if cc:
        from backend.stores.overview import origin_country_sql
        where.append(origin_country_sql() + " = ?")
        params.append(cc)
    sql = "SELECT " + _list_select_sql() + " FROM copies"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY updated_at DESC LIMIT ?"
    params.append(cap)
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def list_ai_done_payloads(limit: int = 150) -> list[dict]:
    """Recent assessed copies as spool payloads for campaign/profile backfill.

    Follow-up SQS messages are acked before ingest. On Fargate the local spool
    is empty, so when the queue is drained we re-read assessed copies from
    Postgres and ingest them into the shared campaign / sender tables.
    """
    from backend.stores import spool
    cap = max(1, min(int(limit), 500))
    try:
        with _lock:
            conn = _connect()
            try:
                rows = conn.execute(
                    "SELECT queue_id, dest FROM copies "
                    "WHERE COALESCE(ai_done, 0) = 1 "
                    "ORDER BY updated_at DESC LIMIT ?",
                    (cap,),
                ).fetchall()
            finally:
                conn.close()
    except Exception:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for r in rows:
        qid = str(r["queue_id"] or "").strip()
        raw = r["dest"]
        if isinstance(raw, str) and raw.strip().startswith("{"):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                pass
        try:
            pl = spool.as_payload(raw) if raw else spool.payload(qid)
        except Exception:
            pl = spool.payload(qid)
        if not pl.get("queue_id"):
            pl["queue_id"] = qid
        key = str(pl.get("queue_id") or qid)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(pl)
    return out


_THREAD_SIBLING_CAP = 40
_THREAD_ID_IN_CHUNK = 200


def list_feed_by_verdict(
    name: str,
    *,
    since_seconds: float | None = OVERVIEW_WINDOW_SECONDS,
    limit: int = FEED_FILTER_LIMIT,
    origin: str = "",
) -> list[dict]:
    """Copies whose stored verdict matches an overview tile (all time)."""
    return list_feed_page(
        verdict=name, origin=origin, limit=limit, since_seconds=since_seconds,
    )


def list_feed_with_thread_siblings(limit: int | None = None, *, origin: str = "") -> list[dict]:
    """Newest copies plus older siblings in the same mailbox Gmail thread."""
    page = list_feed_page(limit=limit, origin=origin)
    return _with_thread_siblings(page)


def list_feed_by_verdict_with_thread_siblings(
    name: str,
    *,
    since_seconds: float | None = OVERVIEW_WINDOW_SECONDS,
    limit: int = FEED_FILTER_LIMIT,
    origin: str = "",
) -> list[dict]:
    """Overview-tile rows plus Gmail-thread siblings so grouping still works."""
    page = list_feed_page(
        verdict=name, origin=origin, limit=limit, since_seconds=since_seconds,
    )
    return _with_thread_siblings(page)


def _with_thread_siblings(page: list[dict]) -> list[dict]:
    keys = {
        (
            str(r.get("mailbox") or "").strip().lower(),
            str(r.get("gmail_thread_id") or "").strip(),
        )
        for r in page
        if str(r.get("gmail_thread_id") or "").strip()
    }
    tids = sorted({tid for _mb, tid in keys})
    if not tids:
        return page
    seen = {str(r.get("queue_id") or "") for r in page}
    per_thread: dict[tuple[str, str], int] = {}
    out = list(page)
    for extra in _copies_with_thread_ids(tids):
        qid = str(extra.get("queue_id") or "")
        if not qid or qid in seen:
            continue
        key = (
            str(extra.get("mailbox") or "").strip().lower(),
            str(extra.get("gmail_thread_id") or "").strip(),
        )
        if key not in keys:
            continue
        n = per_thread.get(key, 0)
        if n >= _THREAD_SIBLING_CAP:
            continue
        per_thread[key] = n + 1
        seen.add(qid)
        out.append(extra)
    return out


def _copies_with_thread_ids(tids: list[str]) -> list[dict]:
    if not tids:
        return []
    found: list[dict] = []
    with _lock:
        conn = _connect()
        try:
            for i in range(0, len(tids), _THREAD_ID_IN_CHUNK):
                chunk = tids[i : i + _THREAD_ID_IN_CHUNK]
                placeholders = ",".join("?" * len(chunk))
                rows = conn.execute(
                    f"SELECT {_list_select_sql()} FROM copies WHERE gmail_thread_id IN ({placeholders})",
                    chunk,
                ).fetchall()
                found.extend(dict(r) for r in rows)
        finally:
            conn.close()
    return found


def list_addr_fields(limit: int = 500) -> list[dict]:
    """Mailbox / From / To / meta for growing Gmail poll coverage."""
    cap = max(1, min(int(limit), 2000))
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT mailbox, from_addr, to_addr, meta_json
                FROM copies
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (cap,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def _n(row, key: str) -> int:
    try:
        return int(row[key] or 0)
    except (TypeError, KeyError, IndexError, ValueError):
        return 0


def empty_overview_stats(*, window: float = 0.0) -> dict:
    """Tile payload when the aggregate scan fails — feed rows still render."""
    w = float(window)
    return {
        "windowSeconds": int(w) if w > 0 else 0,
        "total": 0,
        "pending": 0,
        "inconclusive": 0,
        "clean": 0,
        "low": 0,
        "suspicious": 0,
        "malicious": 0,
        "assessed": 0,
        "threadAssessed": 0,
        "mailboxes": 0,
        "aiPendingTotal": 0,
        "aiTimedOutTotal": 0,
        "hourly": [],
        "feedLimit": FEED_LIST_LIMIT,
        "inboxesMonitored": 0,
        "inboxesPolling": 0,
        "inboxesConfigured": 0,
        "inboxesDiscovered": 0,
        "inboxesSkipped": 0,
        "quarantined": 0,
        "held": 0,
        "computedAt": 0.0,
        "origin": {"located": 0, "countries": [], "points": []},
    }


def _overview_where(window: float) -> tuple[str, tuple]:
    """All-time scans omit the time predicate so NULL/zero timestamps still count."""
    if float(window) <= 0:
        return "", ()
    return "WHERE updated_at >= ?", (time.time() - window,)


def overview_stats(*, since_seconds: float | None = OVERVIEW_WINDOW_SECONDS) -> dict:
    """Unclipped copy counts for the overview tiles (snapshot SELECT)."""
    from backend.stores.overview import overview_stats as _read
    return _read(since_seconds=since_seconds)


def reset() -> None:
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM copies")
            conn.execute("DELETE FROM worker_locks")
            conn.execute("DELETE FROM ai_claims")
            try:
                conn.execute("DELETE FROM runtime_settings")
            except Exception:
                pass
            try:
                conn.execute("DELETE FROM overview_stats")
            except Exception:
                pass
            conn.commit()
        finally:
            conn.close()


def is_ai_claimed(row: Optional[dict], *, now: float | None = None,
                  lease_seconds: float | None = None) -> bool:
    """True while another worker holds the content-AI lease on this copy."""
    if not row:
        return False
    claimed = float(row.get("ai_claimed_at") or 0)
    if claimed <= 0:
        return False
    lease = AI_CLAIM_SECONDS if lease_seconds is None else float(lease_seconds)
    clock = time.time() if now is None else now
    return (clock - claimed) < lease


def try_claim_ai(queue_id: str, holder: str, *,
                 lease_seconds: float | None = None) -> bool:
    """Atomically take the LLM slot for this copy. False = skip (duplicate or done)."""
    qid = (queue_id or "").strip()
    who = (holder or "").strip() or "unknown"
    if not qid:
        return False
    lease = AI_CLAIM_SECONDS if lease_seconds is None else max(1.0, float(lease_seconds))
    now = time.time()
    cutoff = now - lease
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO ai_claims (queue_id, claimed_at, claimed_by)
                VALUES (?, 0, '')
                """,
                (qid,),
            )
            cur = conn.execute(
                """
                UPDATE ai_claims
                SET claimed_at = ?, claimed_by = ?
                WHERE queue_id = ?
                  AND COALESCE(claimed_at, 0) < ?
                  AND NOT EXISTS (
                    SELECT 1 FROM copies
                    WHERE queue_id = ?
                      AND (
                        COALESCE(ai_done, 0) = 1
                        OR COALESCE(status, '') IN (?, ?)
                      )
                  )
                """,
                (now, who, qid, cutoff, qid, COMPLETE, DEAD_LETTER),
            )
            conn.commit()
            return (cur.rowcount or 0) > 0
        finally:
            conn.close()


def release_ai_claim(queue_id: str) -> None:
    qid = (queue_id or "").strip()
    if not qid:
        return
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                UPDATE ai_claims
                SET claimed_at = 0, claimed_by = ''
                WHERE queue_id = ?
                """,
                (qid,),
            )
            conn.commit()
        finally:
            conn.close()


def try_lock(name: str, holder: str, *, ttl_seconds: float = 60) -> bool:
    """Cluster-wide mutex (Postgres or local sqlite). False if another holder is live."""
    key = (name or "").strip()
    who = (holder or "").strip() or "unknown"
    if not key:
        return False
    now = time.time()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "DELETE FROM worker_locks WHERE name = ? AND expires_at < ?",
                (key, now),
            )
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO worker_locks (name, holder, expires_at)
                VALUES (?, ?, ?)
                """,
                (key, who, now + max(1.0, float(ttl_seconds))),
            )
            conn.commit()
            return (cur.rowcount or 0) > 0
        finally:
            conn.close()


def release_lock(name: str, holder: str) -> None:
    key = (name or "").strip()
    who = (holder or "").strip()
    if not key:
        return
    with _lock:
        conn = _connect()
        try:
            if who:
                conn.execute(
                    "DELETE FROM worker_locks WHERE name = ? AND holder = ?",
                    (key, who),
                )
            else:
                conn.execute("DELETE FROM worker_locks WHERE name = ?", (key,))
            conn.commit()
        finally:
            conn.close()
