"""SQL adapter used when SEG_DATABASE_URL points at Postgres."""
from __future__ import annotations

import pytest

from backend import db as db_mod


def test_adapt_sql_rewrites_ifnull_for_postgres(monkeypatch):
    monkeypatch.setattr(db_mod, "is_postgres", lambda: True)
    sql = "SELECT CASE WHEN IFNULL(message_id,'')='' THEN 1 ELSE 0 END"
    out = db_mod.adapt_sql(sql)
    assert "IFNULL" not in out.upper()
    assert "COALESCE(" in out
    monkeypatch.undo()


def test_adapt_sql_rewrites_placeholders(monkeypatch):
    monkeypatch.setattr(db_mod, "is_postgres", lambda: True)
    assert db_mod.adapt_sql("SELECT * FROM users WHERE id=?") == "SELECT * FROM users WHERE id=%s"
    monkeypatch.undo()


def test_adapt_sql_escapes_like_percent_for_postgres(monkeypatch):
    monkeypatch.setattr(db_mod, "is_postgres", lambda: True)
    sql = (
        "SELECT queue_id FROM copies WHERE LOWER(subject) LIKE '%wire%' AND queue_id=? "
        "ORDER BY updated_at DESC LIMIT 200"
    )
    out = db_mod.adapt_sql(sql)
    assert out == (
        "SELECT queue_id FROM copies WHERE LOWER(subject) LIKE '%%wire%%' AND queue_id=%s "
        "ORDER BY updated_at DESC LIMIT 200"
    )
    monkeypatch.undo()


def test_adapted_like_sql_survives_psycopg_placeholder_pass(monkeypatch):
    """psycopg turns %% into % and %s into bound args. Unescaped LIKE '%x%' raises."""
    monkeypatch.setattr(db_mod, "is_postgres", lambda: True)
    sql = (
        "SELECT queue_id FROM copies WHERE LOWER(subject) LIKE '%invoice%' "
        "ORDER BY updated_at DESC LIMIT 200"
    )
    adapted = db_mod.adapt_sql(sql)

    def apply(query, params=()):
        out = []
        i = 0
        p = 0
        while i < len(query):
            if query[i] != "%":
                out.append(query[i])
                i += 1
                continue
            if i + 1 >= len(query):
                raise ValueError("trailing percent")
            nxt = query[i + 1]
            if nxt == "%":
                out.append("%")
                i += 2
            elif nxt == "s":
                out.append(str(params[p]))
                p += 1
                i += 2
            else:
                raise ValueError("bad placeholder %" + nxt)
        return "".join(out)

    assert apply(adapted) == sql
    with pytest.raises(ValueError, match="bad placeholder"):
        apply(sql)
    monkeypatch.undo()


def test_adapt_sql_leaves_sqlite_untouched(monkeypatch):
    monkeypatch.setattr(db_mod, "is_postgres", lambda: False)
    sql = "SELECT IFNULL(sender,'') FROM t WHERE id=?"
    assert db_mod.adapt_sql(sql) == sql


def test_pg_row_supports_slicing():
    row = db_mod._Row(["a", "b", "c"], ("x", "y", "z"))
    assert row[0] == "x"
    assert row[1:] == ("y", "z")
    assert row["a"] == "x"


def test_adapt_sql_rewrites_insert_or_ignore_for_postgres(monkeypatch):
    monkeypatch.setattr(db_mod, "is_postgres", lambda: True)
    sql = "INSERT OR IGNORE INTO worker_locks (name, holder, expires_at) VALUES (?, ?, ?)"
    out = db_mod.adapt_sql(sql)
    assert "OR IGNORE" not in out.upper()
    assert "ON CONFLICT DO NOTHING" in out.upper()
    assert "%s" in out
    monkeypatch.undo()


def test_apply_schema_runs_create_on_postgres_connection():
    executed = []

    class Cur:
        def execute(self, sql, params=None):
            executed.append(sql)
            self._row = (None,)

        def fetchone(self):
            return self._row

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Raw:
        def cursor(self):
            return Cur()

        def commit(self):
            pass

        def rollback(self):
            pass

    prev = db_mod._pg_conn
    db_mod._pg_conn = Raw()
    try:
        db_mod.apply_schema("CREATE TABLE IF NOT EXISTS t (id TEXT PRIMARY KEY);")
        assert any("CREATE TABLE IF NOT EXISTS t" in s for s in executed)
    finally:
        db_mod._pg_conn = prev


def test_apply_schema_skips_existing_index():
    executed = []

    class Cur:
        def execute(self, sql, params=None):
            executed.append((sql, params))
            self._row = ("idx_copies_thread",)

        def fetchone(self):
            return self._row

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Raw:
        def cursor(self):
            return Cur()

        def commit(self):
            pass

        def rollback(self):
            pass

    prev = db_mod._pg_conn
    db_mod._pg_conn = Raw()
    try:
        db_mod.apply_schema(
            "CREATE INDEX IF NOT EXISTS idx_copies_thread ON copies(gmail_thread_id);"
        )
        assert any("to_regclass" in s[0].lower() for s in executed)
        assert not any("CREATE INDEX" in s[0].upper() for s in executed)
    finally:
        db_mod._pg_conn = prev


def test_pg_execute_retries_deadlock(monkeypatch):
    monkeypatch.setattr(db_mod.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setattr(db_mod.random, "uniform", lambda *_a, **_k: 0)

    class Deadlock(Exception):
        sqlstate = "40P01"

    class OkCur:
        description = [("id",)]

    class Raw:
        def __init__(self):
            self.calls = 0
            self.rollbacks = 0

        def execute(self, q, args):
            self.calls += 1
            if self.calls < 3:
                raise Deadlock("deadlock detected")
            return OkCur()

        def rollback(self):
            self.rollbacks += 1

    raw = Raw()
    conn = db_mod.Connection(raw, postgres=True)
    cur = conn.execute("SELECT 1")
    assert raw.calls == 3
    assert raw.rollbacks == 2
    assert cur is not None


def test_connect_applies_postgres_schema_once():
    applied = []
    prev_iso = db_mod.is_postgres
    prev_ensure = db_mod._ensure_postgres
    prev_apply = db_mod.apply_schema
    prev_conn = db_mod._pg_conn
    prev_applied = set(db_mod._pg_applied_schemas)
    db_mod.is_postgres = lambda: True  # type: ignore[method-assign]
    db_mod._ensure_postgres = lambda: None
    db_mod.apply_schema = lambda s: applied.append(s)
    db_mod._pg_conn = object()
    db_mod._pg_applied_schemas = set()
    try:
        schema = "CREATE TABLE IF NOT EXISTS t (id TEXT PRIMARY KEY);"
        db_mod.connect(schema=schema)
        db_mod.connect(schema=schema)
        assert applied == [schema]
    finally:
        db_mod.is_postgres = prev_iso
        db_mod._ensure_postgres = prev_ensure
        db_mod.apply_schema = prev_apply
        db_mod._pg_conn = prev_conn
        db_mod._pg_applied_schemas = prev_applied


def test_executemany_uses_cursor_on_postgres(monkeypatch):
    class Cur:
        def __init__(self):
            self.calls = []
            self.description = None

        def executemany(self, q, seq):
            self.calls.append((q, list(seq)))
            return self

    last = {}

    class Raw:
        def cursor(self):
            cur = Cur()
            last["cur"] = cur
            return cur

        def rollback(self):
            pass

        def executemany(self, *a, **k):
            raise AttributeError("psycopg Connection has no executemany")

    monkeypatch.setattr(db_mod, "adapt_sql", lambda s: s.replace("?", "%s"))
    conn = db_mod.Connection(Raw(), postgres=True)
    conn.executemany("INSERT INTO t VALUES (?, ?)", [(1, 2), (3, 4)])
    assert last["cur"].calls == [
        ("INSERT INTO t VALUES (%s, %s)", [(1, 2), (3, 4)]),
    ]
