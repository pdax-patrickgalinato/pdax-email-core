"""SQLite (pytest) or Postgres (Aurora / compose) connections.

Stores keep sqlite files when SEG_DATABASE_URL is unset. Production sets the
URL; SQL uses ``?`` placeholders which are rewritten for psycopg.
"""
from __future__ import annotations

import hashlib
import logging
import random
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from backend.config import get_settings

_log = logging.getLogger("backend.db")
_pg_lock = threading.Lock()
_pg_ensured = False
_pg_conn = None
_pg_applied_schemas: set[str] = set()

_INSERT_IGNORE = re.compile(r"INSERT\s+OR\s+IGNORE\s+INTO", re.I)
_IFNULL = re.compile(r"\bIFNULL\s*\(", re.I)
_PRAGMA = re.compile(r"^\s*PRAGMA\b", re.I)
_AUTOINCREMENT = re.compile(
    r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT", re.I,
)
_CREATE_TABLE = re.compile(
    r"^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"(?:\"?public\"?\.)?\"?([A-Za-z_][\w]*)\"?",
    re.I,
)
_CREATE_INDEX = re.compile(
    r"^\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"(?:\"?public\"?\.)?\"?([A-Za-z_][\w]*)\"?",
    re.I,
)
_PG_RETRY_STATES = frozenset({"40P01", "40001"})
_PG_RETRY_ATTEMPTS = 5


def is_postgres() -> bool:
    return bool((get_settings().database_url or "").strip())


def _pg_retryable(exc: BaseException) -> bool:
    state = getattr(exc, "sqlstate", None)
    if state in _PG_RETRY_STATES:
        return True
    text = f"{type(exc).__name__} {exc}".lower()
    return (
        "deadlock" in text
        or "serialization failure" in text
        or "could not serialize" in text
    )


def _ddl_relation(stmt: str) -> str:
    """Table or index name for IF NOT EXISTS DDL, else empty."""
    if "IF NOT EXISTS" not in stmt.upper():
        return ""
    m = _CREATE_INDEX.match(stmt) or _CREATE_TABLE.match(stmt)
    return m.group(1) if m else ""


def _relation_exists(cur, name: str) -> bool:
    cur.execute("SELECT to_regclass(%s)", (f"public.{name}",))
    row = cur.fetchone()
    return bool(row and row[0])


def adapt_sql(sql: str) -> str:
    if is_postgres():
        text = sql.replace("BEGIN IMMEDIATE", "BEGIN")
        text = _IFNULL.sub("COALESCE(", text)
        text = _INSERT_IGNORE.sub("INSERT INTO", text)
        if _INSERT_IGNORE.search(sql) and "ON CONFLICT" not in text.upper():
            text = text.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        # psycopg treats % as placeholder markup. LIKE '%term%' must become
        # '%%term%%' before sqlite ? is rewritten to %s.
        return text.replace("%", "%%").replace("?", "%s")
    return sql


class _Row:
    def __init__(self, names: list[str], values: tuple):
        self._names = names
        self._values = values
        self._map = {n: v for n, v in zip(names, values)}

    def __getitem__(self, key):
        if isinstance(key, slice):
            return self._values[key]
        if isinstance(key, int):
            return self._values[key]
        return self._map[key]

    def keys(self):
        return self._names

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, IndexError):
            return default


class _Cursor:
    def __init__(self, cur, names: list[str] | None = None, *, postgres: bool = False):
        self._cur = cur
        self._names = names or [d[0] for d in (cur.description or [])]
        self._postgres = postgres

    def __iter__(self):
        while True:
            row = self.fetchone()
            if row is None:
                return
            yield row

    @property
    def lastrowid(self):
        rid = getattr(self._cur, "lastrowid", None)
        if rid:
            return rid
        if self._postgres:
            try:
                row = self._cur.connection.execute("SELECT lastval()").fetchone()
                return row[0] if row else None
            except Exception:
                return None
        return rid

    @property
    def rowcount(self):
        return getattr(self._cur, "rowcount", -1)

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        if isinstance(row, sqlite3.Row):
            return row
        if isinstance(row, dict):
            names = list(row.keys())
            return _Row(names, tuple(row[n] for n in names))
        return _Row(self._names, tuple(row))

    def fetchall(self):
        rows = self._cur.fetchall()
        out = []
        for row in rows:
            if isinstance(row, sqlite3.Row):
                out.append(row)
            elif isinstance(row, dict):
                names = list(row.keys())
                out.append(_Row(names, tuple(row[n] for n in names)))
            else:
                out.append(_Row(self._names, tuple(row)))
        return out


class Connection:
    def __init__(self, raw, *, postgres: bool):
        self._raw = raw
        self.postgres = postgres

    def _pg_with_retry(self, op: Callable[[], _Cursor]) -> _Cursor:
        last: BaseException | None = None
        for attempt in range(_PG_RETRY_ATTEMPTS):
            with _pg_lock:
                try:
                    return op()
                except Exception as exc:
                    last = exc
                    try:
                        self._raw.rollback()
                    except Exception:
                        _log.exception("postgres rollback failed")
                    if not _pg_retryable(exc) or attempt >= _PG_RETRY_ATTEMPTS - 1:
                        raise
            time.sleep(0.025 * (2 ** attempt) + random.uniform(0, 0.04))
        raise last  # pragma: no cover

    def _pg_call(self, fn, sql: str, args):
        def op():
            if _PRAGMA.match(sql or ""):
                return _Cursor(self._raw.cursor(), [], postgres=True)
            q = adapt_sql(sql)
            cur = fn(q, args)
            names = [d[0] for d in (cur.description or [])] if cur.description else []
            return _Cursor(cur, names, postgres=True)

        return self._pg_with_retry(op)

    def execute(self, sql: str, params: Iterable[Any] = ()):
        if self.postgres:
            return self._pg_call(self._raw.execute, sql, tuple(params))
        cur = self._raw.execute(sql, tuple(params))
        names = [d[0] for d in (cur.description or [])] if cur.description else []
        return _Cursor(cur, names)

    def executemany(self, sql: str, seq_of_params):
        if self.postgres:
            seq = list(seq_of_params)

            def op():
                if _PRAGMA.match(sql or ""):
                    return _Cursor(self._raw.cursor(), [], postgres=True)
                q = adapt_sql(sql)
                cur = self._raw.cursor()
                cur.executemany(q, seq)
                names = (
                    [d[0] for d in (cur.description or [])]
                    if cur.description else []
                )
                return _Cursor(cur, names, postgres=True)

            return self._pg_with_retry(op)
        cur = self._raw.executemany(sql, list(seq_of_params))
        names = [d[0] for d in (cur.description or [])] if cur.description else []
        return _Cursor(cur, names)

    def executescript(self, script: str):
        if self.postgres:
            return self
        self._raw.executescript(script)
        return self

    def commit(self):
        if self.postgres:
            with _pg_lock:
                self._raw.commit()
            return
        self._raw.commit()

    def rollback(self):
        if self.postgres:
            with _pg_lock:
                self._raw.rollback()
            return
        self._raw.rollback()

    def close(self):
        if self.postgres:
            return
        self._raw.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if not self.postgres:
            self._raw.close()
        return False


def _ensure_postgres() -> None:
    global _pg_ensured, _pg_conn
    with _pg_lock:
        if _pg_conn is None:
            import psycopg
            from psycopg.rows import tuple_row
            _pg_conn = psycopg.connect(
                get_settings().database_url,
                row_factory=tuple_row,
                autocommit=False,
                connect_timeout=10,
            )
        if not _pg_ensured:
            with _pg_conn.cursor() as cur:
                cur.execute("SELECT to_regclass('public.copies')")
                row = cur.fetchone()
                copies_exists = bool(row and row[0])
            if copies_exists:
                # Never ALTER copies from workers — that lock waits behind
                # live INSERT/UPDATE and stalls every task. Claim state lives
                # on its own table.
                with _pg_conn.cursor() as cur:
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS worker_locks (
                            name TEXT PRIMARY KEY,
                            holder TEXT NOT NULL DEFAULT '',
                            expires_at DOUBLE PRECISION NOT NULL DEFAULT 0
                        )
                        """
                    )
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS ai_claims (
                            queue_id TEXT PRIMARY KEY,
                            claimed_at DOUBLE PRECISION NOT NULL DEFAULT 0,
                            claimed_by TEXT NOT NULL DEFAULT ''
                        )
                        """
                    )
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS activity_audit (
                            id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                            ts TEXT NOT NULL DEFAULT '',
                            ts_epoch DOUBLE PRECISION NOT NULL DEFAULT 0,
                            action TEXT NOT NULL DEFAULT '',
                            actor TEXT NOT NULL DEFAULT '',
                            actor_role TEXT NOT NULL DEFAULT '',
                            detail TEXT NOT NULL DEFAULT '',
                            meta_json TEXT NOT NULL DEFAULT '{}'
                        )
                        """
                    )
                    cur.execute(
                        "SELECT to_regclass(%s)",
                        ("public.idx_activity_audit_ts",),
                    )
                    if not (cur.fetchone() or (None,))[0]:
                        cur.execute(
                            "CREATE INDEX IF NOT EXISTS idx_activity_audit_ts "
                            "ON activity_audit(ts_epoch DESC)"
                        )
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS gmail_coverage (
                            email TEXT PRIMARY KEY,
                            first_seen TEXT NOT NULL DEFAULT '',
                            source TEXT NOT NULL DEFAULT 'fanout'
                        )
                        """
                    )
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS gmail_coverage_skipped (
                            email TEXT PRIMARY KEY,
                            reason TEXT NOT NULL DEFAULT '',
                            ts TEXT NOT NULL DEFAULT ''
                        )
                        """
                    )
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS webauthn_challenges (
                            session_token TEXT PRIMARY KEY,
                            challenge TEXT NOT NULL,
                            purpose TEXT NOT NULL,
                            expires_at DOUBLE PRECISION NOT NULL
                        )
                        """
                    )
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS passkeys (
                            id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            credential_id TEXT UNIQUE NOT NULL,
                            public_key TEXT NOT NULL,
                            sign_count INTEGER NOT NULL DEFAULT 0,
                            name TEXT NOT NULL DEFAULT 'Passkey',
                            created_at DOUBLE PRECISION NOT NULL
                        )
                        """
                    )
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS runtime_settings (
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL DEFAULT '',
                            updated_at DOUBLE PRECISION NOT NULL DEFAULT 0,
                            updated_by TEXT NOT NULL DEFAULT ''
                        )
                        """
                    )
                _pg_conn.commit()
            else:
                schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
                with _pg_conn.cursor() as cur:
                    for stmt in schema.split(";"):
                        stmt = stmt.strip()
                        if stmt:
                            cur.execute(stmt)
                _pg_conn.commit()
            _pg_ensured = True


def apply_schema(schema: str) -> None:
    """Run a sqlite CREATE script against the shared Postgres connection.

    ``CREATE INDEX IF NOT EXISTS`` still takes a SHARE lock on the table even
    when the index is already there. That lock deadlocks with live INSERT/UPDATE
    from other ECS tasks, so skip DDL whose relation already exists.
    """
    if not schema or _pg_conn is None:
        return
    text = _AUTOINCREMENT.sub(
        "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY",
        schema,
    )
    with _pg_lock:
        try:
            with _pg_conn.cursor() as cur:
                for stmt in text.split(";"):
                    stmt = stmt.strip()
                    if not stmt or _PRAGMA.match(stmt):
                        continue
                    name = _ddl_relation(stmt)
                    if name and _relation_exists(cur, name):
                        continue
                    cur.execute(stmt)
            _pg_conn.commit()
        except Exception:
            try:
                _pg_conn.rollback()
            except Exception:
                pass
            _log.exception("postgres apply_schema failed")
            raise


def connect(sqlite_path: Optional[Path] = None, schema: str = "", *, wal: bool = True) -> Connection:
    if is_postgres():
        _ensure_postgres()
        if schema:
            key = hashlib.sha256(schema.encode("utf-8")).hexdigest()
            if key not in _pg_applied_schemas:
                apply_schema(schema)
                _pg_applied_schemas.add(key)
        return Connection(_pg_conn, postgres=True)
    if sqlite_path is None:
        raise ValueError("sqlite_path required when SEG_DATABASE_URL is unset")
    path = Path(sqlite_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
    raw.row_factory = sqlite3.Row
    if wal:
        raw.execute("PRAGMA journal_mode=WAL")
        raw.execute("PRAGMA busy_timeout=10000")
        raw.execute("PRAGMA synchronous=NORMAL")
    if schema:
        raw.executescript(schema)
    return Connection(raw, postgres=False)


def reset_postgres_cache() -> None:
    """Tests only."""
    global _pg_ensured, _pg_conn, _pg_applied_schemas
    with _pg_lock:
        if _pg_conn is not None:
            try:
                _pg_conn.close()
            except Exception:
                pass
        _pg_conn = None
        _pg_ensured = False
        _pg_applied_schemas = set()
