"""Activity audit log: JSONL locally, Postgres in production."""
from __future__ import annotations

from backend.api import activity_log


def test_jsonl_roundtrip(tmp_path):
    path = tmp_path / "audit.jsonl"
    activity_log.record("login", actor="admin", actor_role="admin",
                        detail="Session started", path=path)
    activity_log.record("logout", actor="admin", actor_role="admin", path=path)
    rows = activity_log.list_entries(path=path)
    assert [r["action"] for r in rows] == ["logout", "login"]
    ui = activity_log.to_audit_ui(rows[1])
    assert ui["kind"] == "activity"
    assert ui["tag"] == "Activity"
    assert ui["title"] == "Signed in"


def test_format_dwell():
    assert activity_log.format_dwell(0) == "less than a second"
    assert activity_log.format_dwell(400) == "less than a second"
    assert activity_log.format_dwell(1000) == "1 second"
    assert activity_log.format_dwell(12_000) == "12 seconds"
    assert activity_log.format_dwell(125_000) == "2 minutes 5 seconds"
    assert activity_log.format_dwell(3_600_000) == "1 hour"


def test_email_phrase_and_view_title():
    assert activity_log.email_phrase({"subject": "Q3 invoice", "from_addr": "alice@example.com"}) == (
        "“Q3 invoice” from alice@example.com"
    )
    ui = activity_log.to_audit_ui({
        "action": "email_view",
        "actor": "jan",
        "actor_role": "analyst",
        "ts_epoch": 1,
        "detail": "Looked at “Q3 invoice” from alice@example.com for 2 minutes 5 seconds",
        "meta": {
            "queue_id": "gmail-abc",
            "subject": "Q3 invoice",
            "from_addr": "alice@example.com",
            "dwell_ms": 125_000,
        },
    })
    assert ui["title"] == "Looked at “Q3 invoice” from alice@example.com"
    assert "jan (analyst)" in ui["detail"]
    assert "viewed for 2 minutes 5 seconds" in ui["detail"]
    opened = activity_log.to_audit_ui({
        "action": "email_open",
        "actor": "jan",
        "actor_role": "analyst",
        "ts_epoch": 1,
        "meta": {"queue_id": "gmail-abc", "subject": "Q3 invoice", "from_addr": "alice@example.com"},
    })
    assert opened["title"] == "Opened “Q3 invoice” from alice@example.com"
    dl = activity_log.to_audit_ui({
        "action": "quarantine_download",
        "actor": "jan",
        "actor_role": "analyst",
        "ts_epoch": 1,
        "detail": "Saved the original .eml of “Q3 invoice” from alice@example.com",
        "meta": {"queue_id": "gmail-abc", "subject": "Q3 invoice", "from_addr": "alice@example.com"},
    })
    assert dl["title"] == "Downloaded original file of “Q3 invoice” from alice@example.com"


def test_postgres_is_source_of_truth_when_enabled(monkeypatch, tmp_path):
    stored = []
    monkeypatch.setattr(activity_log, "_use_postgres", lambda: True)
    monkeypatch.setattr(activity_log, "_insert_postgres", stored.append)
    monkeypatch.setattr(
        activity_log, "_list_postgres",
        lambda limit, actor=None: list(reversed(stored))[:limit],
    )
    activity_log._DEFAULT_PATH = tmp_path / "audit.jsonl"
    activity_log.record("login", actor="admin", actor_role="admin", detail="ok")
    assert stored[0]["action"] == "login"
    assert stored[0]["actor"] == "admin"
    rows = activity_log.list_entries()
    assert rows[0]["action"] == "login"
    assert activity_log._DEFAULT_PATH.is_file()


def test_postgres_empty_falls_back_to_jsonl(monkeypatch, tmp_path):
    monkeypatch.setattr(activity_log, "_use_postgres", lambda: True)
    monkeypatch.setattr(activity_log, "_insert_postgres", lambda _e: None)
    monkeypatch.setattr(activity_log, "_list_postgres", lambda _limit, actor=None: [])
    activity_log._DEFAULT_PATH = tmp_path / "audit.jsonl"
    activity_log.record("setup", actor="admin", actor_role="admin")
    rows = activity_log.list_entries()
    assert rows[0]["action"] == "setup"


def test_postgres_write_failure_still_writes_jsonl(monkeypatch, tmp_path):
    def boom(_entry):
        raise RuntimeError("aurora down")

    monkeypatch.setattr(activity_log, "_use_postgres", lambda: True)
    monkeypatch.setattr(activity_log, "_insert_postgres", boom)
    activity_log._DEFAULT_PATH = tmp_path / "audit.jsonl"
    activity_log.record("login_failed", actor="admin")
    rows = activity_log.list_entries(path=activity_log._DEFAULT_PATH)
    assert rows[0]["action"] == "login_failed"


def test_list_entries_filters_by_actor(tmp_path):
    path = tmp_path / "audit.jsonl"
    activity_log.record("login", actor="alice", actor_role="analyst", path=path)
    activity_log.record("logout", actor="bob", actor_role="admin", path=path)
    activity_log.record("password_change", actor="alice", actor_role="analyst", path=path)
    mine = activity_log.list_entries(path=path, actor="alice")
    assert [r["action"] for r in mine] == ["password_change", "login"]
    ui = activity_log.to_audit_ui(mine[0])
    assert ui["title"] == "Password changed"
    mfa = activity_log.to_audit_ui({"action": "login_mfa", "actor": "alice", "ts_epoch": 1})
    assert mfa["title"] == "Passkey required"
