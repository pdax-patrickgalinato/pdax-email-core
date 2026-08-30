"""Spotlight NL → SQL: validation, fallback compiler, and execution."""
from __future__ import annotations

import json

import pytest

from backend.api import nl_search
from backend.stores import assessments as store


def test_validate_accepts_thread_missing_sql():
    sql = (
        "SELECT queue_id FROM copies WHERE COALESCE(thread_ai_done, 0) = 0 "
        "ORDER BY updated_at DESC LIMIT 200"
    )
    assert nl_search.validate_search_sql(sql) == sql


def test_validate_rejects_other_tables_and_dml():
    with pytest.raises(nl_search.SearchSqlError):
        nl_search.validate_search_sql("SELECT queue_id FROM users WHERE 1=1 ORDER BY updated_at DESC LIMIT 10")
    with pytest.raises(nl_search.SearchSqlError):
        nl_search.validate_search_sql(
            "SELECT queue_id FROM copies WHERE 1=1; DROP TABLE copies "
            "ORDER BY updated_at DESC LIMIT 10"
        )
    with pytest.raises(nl_search.SearchSqlError):
        nl_search.validate_search_sql(
            "SELECT queue_id FROM copies WHERE 1=1 UNION SELECT username FROM users "
            "ORDER BY updated_at DESC LIMIT 10"
        )
    with pytest.raises(nl_search.SearchSqlError):
        nl_search.validate_search_sql(
            "SELECT password FROM copies WHERE 1=1 ORDER BY updated_at DESC LIMIT 10"
        )


def test_fallback_sql_for_missing_thread_assessment():
    sql, labels = nl_search.fallback_sql("i want to see all the emails without thread assessment yet")
    assert "thread_ai_done" in sql
    assert "No thread assessment" in labels
    nl_search.validate_search_sql(sql)


def test_compile_search_uses_llm_sql_when_valid():
    plan = {
        "sql": (
            "SELECT queue_id FROM copies WHERE UPPER(verdict) = 'MALICIOUS' "
            "ORDER BY updated_at DESC LIMIT 50"
        ),
        "labels": ["Malicious"],
    }

    def llm(_system, _user):
        return json.dumps(plan)

    out = nl_search.compile_search("show me malicious mail", llm_complete=llm)
    assert out["source"] == "ai"
    assert out["sql"] == nl_search.validate_search_sql(plan["sql"])
    assert out["labels"] == ["Malicious"]


def test_compile_search_falls_back_on_bad_llm_sql():
    def llm(_system, _user):
        return json.dumps({"sql": "DELETE FROM copies", "labels": ["nope"]})

    out = nl_search.compile_search("malicious emails", llm_complete=llm)
    assert out["source"] == "fallback"
    assert "MALICIOUS" in out["sql"]


def test_search_queue_ids_runs_validated_sql(tmp_path):
    store.set_db_path(tmp_path / "search.sqlite3")
    try:
        store.upsert_copy("gmail-a", subject="Trade confirm", verdict="CLEAN", thread_ai_done=0, ai_done=1)
        store.upsert_copy("gmail-b", subject="Invoice", verdict="MALICIOUS", thread_ai_done=1, ai_done=1)
        sql, _labels = nl_search.fallback_sql("emails without thread assessment yet")
        ids = store.search_queue_ids(sql)
        assert "gmail-a" in ids
        assert "gmail-b" not in ids
        sql2, _ = nl_search.fallback_sql("malicious emails")
        ids2 = store.search_queue_ids(sql2)
        assert ids2 == ["gmail-b"]
        sql3, _ = nl_search.fallback_sql("invoice")
        assert "LIKE" in sql3
        ids3 = store.search_queue_ids(sql3)
        assert ids3 == ["gmail-b"]
    finally:
        store.set_db_path(None)


def test_spotlight_search_like_query_returns_hits(monkeypatch):
    from pathlib import Path
    import tempfile

    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from backend.api.auth_store import AuthStore
    from backend.api.routers import feed as feed_module
    import backend.api.deps as deps_module

    store.upsert_copy("gmail-inv", subject="Wire invoice", verdict="CLEAN", ai_done=1)
    monkeypatch.setattr(nl_search, "default_llm_complete", lambda *_a, **_k: None)

    auth = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = auth
    user = auth.create_user("searcher", "Password123!", "viewer")
    app = FastAPI()
    app.include_router(feed_module.router)
    client = TestClient(app)
    client.cookies.set("seg_session", auth.create_session(user.id))
    r = client.post("/api/feed/search", json={"q": "invoice"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source"] == "fallback"
    assert "sql" not in body
    assert [e.get("id") for e in body["entries"]] == ["gmail-inv"]
