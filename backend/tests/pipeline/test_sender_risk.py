"""Sent/received volume and advisory sender-identity risk."""
from __future__ import annotations

import os
import tempfile

from workers.pipeline.correlation import BehavioralCorrelationStore
from backend.stores.sender_profile_ingest import ingest_mail_volume
from backend.stores.sender_risk import assess_heuristic, assess_sender, build_facts, ensure_assessed


def _store():
    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    return BehavioralCorrelationStore(db_path=path), path


def test_sent_and_received_counts():
    store, path = _store()
    try:
        store.record_volume("vendor@acme.com", "jan@pdax.ph", "m1")
        store.record_volume("vendor@acme.com", "pat@pdax.ph", "m1b")
        store.record_volume("jan@pdax.ph", "jan@pdax.ph", "s1", labels=["SENT"])
        store.record_volume("alice@yahoo.com", "jan@pdax.ph", "in1")
        v = store.volume_for("vendor@acme.com")
        assert v["sent_count"] == 2
        assert v["received_count"] == 0
        assert v["mailbox_targets"] == 2
        jan = store.volume_for("jan@pdax.ph")
        assert jan["sent_count"] == 1
        assert jan["received_count"] == 2
        assert jan["outbound_count"] == 1
    finally:
        os.unlink(path)


def test_heuristic_one_way_payment_is_elevated():
    facts = {
        "sender": "billing@not-acme.example",
        "lane": "external",
        "internal": False,
        "role_mailbox": False,
        "sent_count": 4,
        "received_count": 0,
        "outbound_count": 0,
        "mailbox_targets": 1,
        "copies": 4,
        "reciprocity": 0.0,
        "one_way_external": True,
        "monitored_mailbox": False,
        "span_days": 1,
        "days_active": 1,
        "max_day": 4,
        "avg_day": 4.0,
        "night_hour_share": 0.0,
        "verdicts": {"CLEAN": 3, "LOW": 0, "SUSPICIOUS": 1, "MALICIOUS": 0},
        "hostile_rate": 0.25,
        "typical_assessment": "SUSPICIOUS",
        "baseline_n": 3,
        "baseline_ready": False,
        "majority_role": "cloud_hosting",
        "vpn_rate": 0.0,
        "countries": ["NL"],
        "asns": ["AS1"],
        "spf": ["fail"],
        "dkim": ["none"],
        "request_mix": [{"value": "payment_request", "count": 2}],
        "high_risk_requests": 2,
        "coverage_note": "note",
    }
    out = assess_heuristic(facts)
    assert out["risk"] in ("HIGH", "CRITICAL", "MEDIUM")
    assert out["score"] >= 25
    assert out["sent_count"] == 4
    assert "payment" in out["summary"].lower() or any(
        "payment" in (f.get("detail") or "").lower() for f in out["factors"]
    )
    assert "not a message verdict" in out["summary"].lower() or "advisory" in out["summary"].lower()


def test_heuristic_established_esp_is_low():
    facts = {
        "sender": "notify@yahoo.com",
        "lane": "external",
        "internal": False,
        "role_mailbox": False,
        "sent_count": 40,
        "received_count": 0,
        "outbound_count": 0,
        "mailbox_targets": 6,
        "copies": 40,
        "reciprocity": 0.0,
        "one_way_external": True,
        "monitored_mailbox": False,
        "span_days": 60,
        "days_active": 40,
        "max_day": 2,
        "avg_day": 1.0,
        "night_hour_share": 0.1,
        "verdicts": {"CLEAN": 38, "LOW": 2, "SUSPICIOUS": 0, "MALICIOUS": 0},
        "hostile_rate": 0.0,
        "typical_assessment": "CLEAN",
        "baseline_n": 38,
        "baseline_ready": True,
        "majority_role": "esp",
        "vpn_rate": 0.0,
        "countries": ["US"],
        "asns": ["AS26101"],
        "spf": ["pass"],
        "dkim": ["pass"],
        "request_mix": [{"value": "other", "count": 40}],
        "high_risk_requests": 0,
        "coverage_note": "note",
    }
    out = assess_heuristic(facts)
    assert out["risk"] == "LOW"
    assert out["posture"] in ("established_partner", "one_way_external")


def test_malicious_typical_cannot_be_low():
    store, path = _store()
    try:
        store.record_observation("phish@evil.example", ["9.9.9.9"], [], verdict="MALICIOUS", message_id="x1")
        store.record_volume("phish@evil.example", "jan@pdax.ph", "x1")
        listed = store.list_profiles(query="phish@evil.example")[0]
        out = assess_sender(store, "phish@evil.example", listed, use_llm=False)
        assert out["risk"] == "CRITICAL"
        assert "verdict" in out["summary"].lower()
    finally:
        os.unlink(path)


def test_ensure_assessed_persists_heuristic(monkeypatch):
    store, path = _store()
    try:
        monkeypatch.setattr("backend.stores.sender_risk._llm_json", lambda *a, **k: ({}, ""))
        store.record_volume("alice@yahoo.com", "jan@pdax.ph", "a1")
        store.record_observation("alice@yahoo.com", ["1.1.1.1"], [], verdict="CLEAN", message_id="a1")
        out = ensure_assessed(store, "alice@yahoo.com", use_llm=True)
        assert out["provider"] == "heuristic"
        stored = store.get_sender_risk("alice@yahoo.com")
        assert stored and stored["summary"]
        again = ensure_assessed(store, "alice@yahoo.com", use_llm=True)
        assert again["facts_hash"] == stored["facts_hash"]
    finally:
        os.unlink(path)


def test_llm_refines_narrative(monkeypatch):
    store, path = _store()
    try:
        monkeypatch.setattr("backend.stores.sender_risk._llm_json", lambda *a, **k: ({
            "risk": "MEDIUM",
            "score": 41,
            "posture": "one_way_external",
            "confidence": "high",
            "summary": "LLM narrative about send/receive imbalance.",
            "factors": [{"code": "volume", "direction": "context", "detail": "4 sent 0 received"}],
        }, "deepseek-test"))
        store.record_volume("v@x.com", "jan@pdax.ph", "z1")
        out = assess_sender(store, "v@x.com", {"copies": 1, "lane": "external"}, use_llm=True)
        assert out["provider"] == "glm"
        assert out["summary"].startswith("LLM narrative")
        assert out["model_id"] == "deepseek-test"
    finally:
        os.unlink(path)


def test_ingest_mail_volume_from_spool(tmp_path):
    spool = tmp_path / "spool" / "gmail" / "gmail-1"
    spool.mkdir(parents=True)
    (spool / "message.eml").write_bytes(b"From: a@b.com\n\nHi\n")
    (spool / "meta.json").write_text(
        '{"from": "vendor@acme.com", "mailbox": "jan@pdax.ph", '
        '"message_id": "<v@acme>", "verdict": "CLEAN"}',
        encoding="utf-8",
    )
    store, path = _store()
    try:
        out = ingest_mail_volume(store, tmp_path / "spool")
        assert out["volume_recorded"] == 1
        assert store.volume_for("vendor@acme.com")["sent_count"] == 1
        assert store.volume_for("jan@pdax.ph")["received_count"] == 1
    finally:
        os.unlink(path)


def test_build_facts_includes_coverage_note():
    store, path = _store()
    try:
        facts = build_facts(store, "nobody@example.com")
        assert "INBOX" in facts["coverage_note"]
        assert facts["sent_count"] == 0
    finally:
        os.unlink(path)
