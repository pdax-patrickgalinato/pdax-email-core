"""Unit tests for allowlist/blocklist loaders and pipeline overrides."""
from __future__ import annotations

from backend.stores.lists import load_allowlist, load_blocklist
from backend.models import Disposition
from workers.pipeline.runner import run_pipeline


def _eml(from_addr: str) -> bytes:
    return (
        f"From: {from_addr}\r\n"
        f"To: victim@pdax.ph\r\n"
        f"Subject: hello\r\n"
        f"Message-ID: <list-test@example.com>\r\n"
        f"\r\n"
        f"plain body\r\n"
    ).encode()


def test_empty_committed_lists_load():
    assert load_allowlist() == []
    assert load_blocklist() == []


def test_load_allowlist_from_temp(tmp_path, monkeypatch):
    (tmp_path / "allowlist.yaml").write_text(
        "entries:\n  - address: friend@example.com\n    note: vendor\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("backend.stores.lists._RUNTIME_DIR", tmp_path)
    rows = load_allowlist()
    assert len(rows) == 1
    assert rows[0]["address"] == "friend@example.com"
    assert rows[0]["note"] == "vendor"


def test_blocklist_forces_quarantine(monkeypatch):
    monkeypatch.setattr(
            "workers.pipeline.runner.lists_mod.load_blocklist",
        lambda: [{"address": "evil@example.com", "note": "known bad"}],
    )
    monkeypatch.setattr("workers.pipeline.runner.lists_mod.load_allowlist", lambda: [])
    result = run_pipeline(_eml("evil@example.com"), source="test")
    assert result.hard_override == "blocklist"
    assert result.disposition == Disposition.QUARANTINE


def test_allowlist_forces_deliver(monkeypatch):
    monkeypatch.setattr("workers.pipeline.runner.lists_mod.load_blocklist", lambda: [])
    monkeypatch.setattr(
            "workers.pipeline.runner.lists_mod.load_allowlist",
        lambda: [{"domain": "trusted.example", "note": "partner"}],
    )
    result = run_pipeline(_eml("alerts@mail.trusted.example"), source="test")
    assert result.hard_override == "allowlist"
    assert result.disposition == Disposition.DELIVER
