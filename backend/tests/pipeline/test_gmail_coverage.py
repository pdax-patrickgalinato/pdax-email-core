"""Fan-out grows Gmail poll coverage with newly seen org mailboxes."""
from __future__ import annotations

import json

from backend.stores import gmail_coverage as cov


def test_offer_adds_org_envelope_addrs(tmp_path, monkeypatch):
    monkeypatch.setattr(cov, "_STORE_OVERRIDE", tmp_path / "c.json")
    monkeypatch.setenv("SEG_GMAIL_USERS", "jan@pdax.ph")
    monkeypatch.setenv("SEG_GMAIL_DOMAIN", "pdax.ph")
    added = cov.offer([
        "jan@pdax.ph",
        "Jessica.Sagarbarria@pdax.ph",
        "vendor@evil.example",
        "noreply@pdax.ph",
        "newhire+tag@pdax.ph",
    ])
    assert "jessica.sagarbarria@pdax.ph" in added
    assert "newhire@pdax.ph" in added
    assert "jan@pdax.ph" not in added
    assert "vendor@evil.example" not in added
    assert "noreply@pdax.ph" not in added
    users = cov.monitored_users()
    assert "jan@pdax.ph" in users
    assert "jessica.sagarbarria@pdax.ph" in users
    assert "newhire@pdax.ph" in users
    snap = cov.snapshot()
    assert snap["configured"] == 1
    assert snap["discovered"] == 2
    assert snap["polling"] == 3


def test_offer_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(cov, "_STORE_OVERRIDE", tmp_path / "c.json")
    monkeypatch.setenv("SEG_GMAIL_USERS", "a@pdax.ph")
    monkeypatch.setenv("SEG_GMAIL_DOMAIN", "pdax.ph")
    assert cov.offer(["b@pdax.ph"]) == ["b@pdax.ph"]
    assert cov.offer(["b@pdax.ph"]) == []


def test_permanent_failure_drops_mailbox_from_poll(tmp_path, monkeypatch):
    monkeypatch.setattr(cov, "_STORE_OVERRIDE", tmp_path / "c.json")
    monkeypatch.setenv("SEG_GMAIL_USERS", "good@pdax.ph,cs@pdax.ph")
    monkeypatch.setenv("SEG_GMAIL_DOMAIN", "pdax.ph")
    assert cov.note_failure("cs@pdax.ph", "unauthorized_client: Client is unauthorized")
    assert "cs@pdax.ph" not in cov.monitored_users()
    assert "good@pdax.ph" in cov.monitored_users()
    assert cov.note_failure("good@pdax.ph", "socket timeout") is False
    assert "good@pdax.ph" in cov.monitored_users()


def test_offer_from_scan_uses_full_envelope(tmp_path, monkeypatch):
    monkeypatch.setattr(cov, "_STORE_OVERRIDE", tmp_path / "c.json")
    monkeypatch.setenv("SEG_GMAIL_USERS", "jan@pdax.ph")
    monkeypatch.setenv("SEG_GMAIL_DOMAIN", "pdax.ph")
    dest = tmp_path / "gmail" / "gmail-x"
    dest.mkdir(parents=True)
    meta = {
        "mailbox": "jan@pdax.ph",
        "to": "jan@pdax.ph, new.person@pdax.ph, outside@example.com",
    }
    (dest / "message.eml").write_bytes(
        b"From: alerts@saas.example\n"
        b"To: jan@pdax.ph, new.person@pdax.ph, outside@example.com\n"
        b"Cc: also.new@pdax.ph\n\nbody\n"
    )
    added = cov.offer_from_scan(dest, meta, {"envelope_recipients": ["new.person@pdax.ph"]})
    assert "new.person@pdax.ph" in added
    assert "also.new@pdax.ph" in added
    assert "outside@example.com" not in cov.monitored_users()


def test_seed_from_spool_adds_envelope_org_addrs(tmp_path, monkeypatch):
    monkeypatch.setattr(cov, "_STORE_OVERRIDE", tmp_path / "c.json")
    monkeypatch.setenv("SEG_GMAIL_USERS", "jan@pdax.ph")
    monkeypatch.setenv("SEG_GMAIL_DOMAIN", "pdax.ph")
    dest = tmp_path / "gmail" / "gmail-old"
    dest.mkdir(parents=True)
    meta = {
        "mailbox": "jan@pdax.ph",
        "to": "jan@pdax.ph, unseen.hire@pdax.ph",
        "fanout_recipients": ["unseen.hire@pdax.ph"],
    }
    (dest / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (dest / "message.eml").write_bytes(
        b"From: a@x\nTo: jan@pdax.ph, unseen.hire@pdax.ph\n\nbody\n"
    )
    added = cov.seed_from_spool(tmp_path, limit_new=10)
    assert "unseen.hire@pdax.ph" in added
    assert "unseen.hire@pdax.ph" in cov.monitored_users()


def test_offer_from_scan_accepts_dict_dest(tmp_path, monkeypatch):
    monkeypatch.setattr(cov, "_STORE_OVERRIDE", tmp_path / "c.json")
    monkeypatch.setenv("SEG_GMAIL_USERS", "jan@pdax.ph")
    monkeypatch.setenv("SEG_GMAIL_DOMAIN", "pdax.ph")
    dest = {"queue_id": "gmail-x", "bucket": "gmail"}
    meta = {
        "mailbox": "jan@pdax.ph",
        "to": "jan@pdax.ph, dict.person@pdax.ph",
        "cc": "cc.hire@pdax.ph",
    }
    added = cov.offer_from_scan(dest, meta, {})
    assert "dict.person@pdax.ph" in added
    assert "cc.hire@pdax.ph" in added


def test_seed_from_copies_grows_org_inboxes(monkeypatch):
    from backend.stores import assessments as store

    monkeypatch.setenv("SEG_GMAIL_USERS", "jan@pdax.ph")
    monkeypatch.setenv("SEG_GMAIL_DOMAIN", "pdax.ph")
    store.upsert_copy(
        "gmail-1",
        mailbox="jan@pdax.ph",
        from_addr="vendor@acme.example",
        to_addr="jan@pdax.ph, new.hire@pdax.ph",
        meta_json=json.dumps({
            "mailbox": "jan@pdax.ph",
            "to": "jan@pdax.ph, new.hire@pdax.ph",
            "cc": "also.new@pdax.ph",
            "fanout_recipients": ["also.new@pdax.ph"],
        }),
    )
    added = cov.seed_from_copies(limit_rows=50, limit_new=10)
    assert "new.hire@pdax.ph" in added
    assert "also.new@pdax.ph" in added
    users = cov.monitored_users()
    assert "jan@pdax.ph" in users
    assert "new.hire@pdax.ph" in users
    snap = cov.snapshot()
    assert snap["configured"] == 1
    assert snap["discovered"] == 2
    assert snap["polling"] == 3


def test_seed_from_copies_caps_new_inboxes_per_call(monkeypatch):
    from backend.stores import assessments as store

    monkeypatch.setenv("SEG_GMAIL_USERS", "jan@pdax.ph")
    monkeypatch.setenv("SEG_GMAIL_DOMAIN", "pdax.ph")
    for i in range(5):
        store.upsert_copy(
            f"gmail-{i}",
            mailbox="jan@pdax.ph",
            to_addr=f"jan@pdax.ph, hire{i}@pdax.ph",
        )
    first = cov.seed_from_copies(limit_rows=50, limit_new=2)
    assert len(first) == 2
    second = cov.seed_from_copies(limit_rows=50, limit_new=10)
    assert len(second) == 3
    assert cov.snapshot()["polling"] == 6


def test_offer_does_not_poll_protected_brand_domains(tmp_path, monkeypatch):
    monkeypatch.setattr(cov, "_STORE_OVERRIDE", tmp_path / "c.json")
    monkeypatch.setenv("SEG_GMAIL_USERS", "jan@pdax.ph")
    monkeypatch.setenv("SEG_GMAIL_DOMAIN", "pdax.ph")
    added = cov.offer([
        "jan@pdax.ph",
        "hire@pdax.ph",
        "treasury@fireblocks.com",
        "alerts@circle.com",
        "someone@google.com",
    ])
    assert added == ["hire@pdax.ph"]
    users = cov.monitored_users()
    assert "hire@pdax.ph" in users
    assert "treasury@fireblocks.com" not in users
    assert "alerts@circle.com" not in users
    assert "someone@google.com" not in users


def test_monitored_users_drops_non_workspace_seed_and_discoveries(tmp_path, monkeypatch):
    monkeypatch.setattr(cov, "_STORE_OVERRIDE", tmp_path / "c.json")
    monkeypatch.setenv("SEG_GMAIL_USERS", "jan@pdax.ph,personal@gmail.com")
    monkeypatch.setenv("SEG_GMAIL_DOMAIN", "pdax.ph")
    cov.offer(["ok@pdax.ph", "ops@fireblocks.com"])
    users = cov.monitored_users()
    assert "jan@pdax.ph" in users
    assert "ok@pdax.ph" in users
    assert "personal@gmail.com" not in users
    assert "ops@fireblocks.com" not in users
