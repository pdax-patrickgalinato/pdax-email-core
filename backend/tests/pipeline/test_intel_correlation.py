"""Tests for the behavioral correlation store (workers/pipeline/correlation.py).

Each test uses a temp-file-backed BehavioralCorrelationStore so nothing touches
the production data/ directory.
"""
from __future__ import annotations

import os
import tempfile
import time

import pytest

from workers.pipeline.correlation import BehavioralCorrelationStore
from workers.pipeline import runner

def _make_store():
    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    return BehavioralCorrelationStore(db_path=path), path

# ---------------------------------------------------------------------------
# Rule 1a: same sender, different originating IPs → behavioral_sender_ip_drift
# ---------------------------------------------------------------------------

def test_ip_drift_two_ips_triggers_flag():
    store, path = _make_store()
    try:
        store.record_observation("alice@example.com", ["1.2.3.4"], [])
        store.record_observation("alice@example.com", ["9.8.7.6"], [])
        flags = store.behavioral_lookup("alice@example.com", ["9.8.7.6"], [])
        drift_flags = [f for f in flags if f.startswith("behavioral_sender_ip_drift:")]
        assert drift_flags, f"expected ip_drift flag, got: {flags}"
        count = int(drift_flags[0].split(":")[-1])
        assert count >= 2
    finally:
        os.unlink(path)

def test_no_flag_consistent_sender_ip():
    store, path = _make_store()
    try:
        store.record_observation("bob@example.com", ["5.5.5.5"], [])
        store.record_observation("bob@example.com", ["5.5.5.5"], [])
        flags = store.behavioral_lookup("bob@example.com", ["5.5.5.5"], [])
        drift = [f for f in flags if "sender_ip_drift" in f]
        assert not drift, f"should not flag consistent sender/IP, got: {flags}"
    finally:
        os.unlink(path)

# ---------------------------------------------------------------------------
# Rule 1b: IP used by 5+ distinct senders → behavioral_ip_many_senders
# ---------------------------------------------------------------------------

def test_ip_many_senders_at_threshold():
    store, path = _make_store()
    try:
        ip = "10.20.30.40"
        for i in range(5):
            store.record_observation(f"sender{i}@example.com", [ip], [])
        flags = store.behavioral_lookup("new@example.com", [ip], [])
        many = [f for f in flags if f.startswith("behavioral_ip_many_senders:")]
        assert many, f"expected ip_many_senders flag at threshold 5, got: {flags}"
        count = int(many[0].split(":")[-1])
        assert count >= 5
    finally:
        os.unlink(path)

def test_ip_many_senders_below_threshold():
    store, path = _make_store()
    try:
        ip = "10.20.30.41"
        for i in range(4):
            store.record_observation(f"sender{i}@example.com", [ip], [])
        flags = store.behavioral_lookup("new@example.com", [ip], [])
        many = [f for f in flags if "ip_many_senders" in f]
        assert not many, f"should not flag below threshold (4 senders), got: {flags}"
    finally:
        os.unlink(path)

# ---------------------------------------------------------------------------
# Rule 2: IP sends link shorteners → behavioral_ip_shortener
# ---------------------------------------------------------------------------

def test_ip_shortener_suspicious():
    store, path = _make_store()
    try:
        ip = "11.22.33.44"
        store.record_observation("spammer@evil.com", [ip], ["bit.ly"])
        flags = store.behavioral_lookup("innocent@domain.com", [ip], [])
        short_flags = [f for f in flags if f.startswith("behavioral_ip_shortener:")]
        assert short_flags, f"expected ip_shortener flag, got: {flags}"
        count = int(short_flags[0].split(":")[-1])
        assert count >= 1
    finally:
        os.unlink(path)

# ---------------------------------------------------------------------------
# Rule 3: different senders share same shortener domain → behavioral_shared_shortener
# ---------------------------------------------------------------------------

def test_shared_shortener_malicious():
    store, path = _make_store()
    try:
        store.record_observation("alice@evil.com", ["1.1.1.1"], ["tinyurl.com"])
        flags = store.behavioral_lookup("bob@other.com", ["2.2.2.2"], ["tinyurl.com"])
        shared = [f for f in flags if f.startswith("behavioral_shared_shortener:")]
        assert shared, f"expected shared_shortener flag, got: {flags}"
        count = int(shared[0].split(":")[-1])
        assert count >= 1
    finally:
        os.unlink(path)

def test_same_sender_no_shared_shortener_flag():
    """Same sender using same shortener twice is NOT a cross-sender signal."""
    store, path = _make_store()
    try:
        store.record_observation("alice@evil.com", ["1.1.1.1"], ["bit.ly"])
        flags = store.behavioral_lookup("alice@evil.com", ["1.1.1.1"], ["bit.ly"])
        shared = [f for f in flags if "shared_shortener" in f]
        assert not shared, f"same sender should not self-trigger shared_shortener, got: {flags}"
    finally:
        os.unlink(path)

# ---------------------------------------------------------------------------
# 6-month window
# ---------------------------------------------------------------------------

def test_six_month_window_excludes_old_records():
    """Records older than 180 days must not trigger any flags."""
    store, path = _make_store()
    try:
        import sqlite3
        old_ts = time.time() - (181 * 86400)
        conn = sqlite3.connect(path)
        # Create table with full schema (including verdict column).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sender_ip_log "
            "(sender TEXT NOT NULL, ip TEXT NOT NULL, verdict TEXT DEFAULT '', "
            "message_id TEXT, seen_at REAL NOT NULL)"
        )
        conn.execute(
            "INSERT INTO sender_ip_log (sender, ip, message_id, seen_at) VALUES (?,?,?,?)",
            ("alice@example.com", "1.2.3.4", "", old_ts),
        )
        conn.commit()
        conn.close()
        # Add a second IP now — but the old record is stale, so distinct IPs in window = 1.
        store.record_observation("alice@example.com", ["9.9.9.9"], [])
        flags = store.behavioral_lookup("alice@example.com", ["9.9.9.9"], [])
        drift = [f for f in flags if "sender_ip_drift" in f]
        assert not drift, f"old record outside window should not count, got: {flags}"
    finally:
        os.unlink(path)

# ---------------------------------------------------------------------------
# behavioral_details() returns rich data with flagged email records
# ---------------------------------------------------------------------------

def test_behavioral_details_returns_rich_structure():
    store, path = _make_store()
    try:
        store.record_observation(
            "alice@evil.com", ["1.1.1.1"], ["bit.ly"],
            message_id="<msg1@test>", verdict="MALICIOUS"
        )
        store.record_observation(
            "alice@evil.com", ["9.9.9.9"], [],
            message_id="<msg2@test>", verdict="SUSPICIOUS"
        )
        details = store.behavioral_details("alice@evil.com", ["9.9.9.9"], [])
        drift = [d for d in details if d["rule"] == "behavioral_sender_ip_drift"]
        assert drift, "expected drift finding in details"
        d = drift[0]
        assert d["ioc_value"] == "alice@evil.com"
        assert d["behavioral_count"] >= 2
        assert d["flagged_count"] >= 1
        assert any(e["verdict"] in ("MALICIOUS", "SUSPICIOUS") for e in d["emails"])
    finally:
        os.unlink(path)

def test_behavioral_details_only_returns_flagged_emails():
    """The 'emails' list in each finding must only contain SUSPICIOUS/MALICIOUS records."""
    store, path = _make_store()
    try:
        store.record_observation("bob@evil.com", ["2.2.2.2"], [], verdict="CLEAN")
        store.record_observation("bob@evil.com", ["3.3.3.3"], [], verdict="MALICIOUS")
        details = store.behavioral_details("bob@evil.com", ["3.3.3.3"], [])
        drift = [d for d in details if d["rule"] == "behavioral_sender_ip_drift"]
        assert drift
        emails = drift[0]["emails"]
        verdicts = {e["verdict"] for e in emails}
        assert verdicts <= {"SUSPICIOUS", "MALICIOUS"}, \
            f"emails list should only contain flagged records, got verdicts: {verdicts}"
    finally:
        os.unlink(path)

# ---------------------------------------------------------------------------
# Behavioral results are reference-only — no scoring or red_flags impact
# ---------------------------------------------------------------------------

def test_behavioral_flags_not_in_red_flags():
    """Behavioral findings must NOT appear in intel stage red_flags (reference only)."""
    store, path = _make_store()
    try:
        # Build a drift history.
        store.record_observation("evil@example.com", ["1.2.3.4"], [])
        store.record_observation("evil@example.com", ["5.6.7.8"], [], verdict="MALICIOUS")

        eml = (
            b"From: evil@example.com\r\n"
            b"Received: from mail.example.com ([1.2.3.4]) by mx.example.com\r\n"
            b"To: victim@company.com\r\n"
            b"Subject: test\r\n"
            b"Message-ID: <test2@example.com>\r\n"
            b"\r\n"
            b"Hello.\r\n"
        )
        result = runner.run_pipeline(eml, source="test", correlation_store=store)
        intel_stage = next((s for s in result.stages if s.stage == "intel"), None)
        assert intel_stage is not None
        behavioral_red_flags = [
            f for f in (intel_stage.red_flags or [])
            if f.startswith("behavioral_")
        ]
        assert not behavioral_red_flags, \
            f"behavioral flags must not appear in red_flags, got: {behavioral_red_flags}"
    finally:
        os.unlink(path)

def test_behavioral_details_in_facts():
    """Behavioral findings must appear in intel stage facts['behavioral_details']."""
    store, path = _make_store()
    try:
        store.record_observation("evil@example.com", ["1.2.3.4"], [])
        store.record_observation("evil@example.com", ["5.6.7.8"], [], verdict="SUSPICIOUS")

        eml = (
            b"From: evil@example.com\r\n"
            b"Received: from mail.example.com ([1.2.3.4]) by mx.example.com\r\n"
            b"To: victim@company.com\r\n"
            b"Subject: test\r\n"
            b"Message-ID: <test3@example.com>\r\n"
            b"\r\n"
            b"Hello.\r\n"
        )
        result = runner.run_pipeline(eml, source="test", correlation_store=store)
        intel_stage = next((s for s in result.stages if s.stage == "intel"), None)
        assert intel_stage is not None
        details = (intel_stage.facts or {}).get("behavioral_details", [])
        assert any(d["rule"] == "behavioral_sender_ip_drift" for d in details), \
            f"expected sender_ip_drift in behavioral_details, got: {details}"
    finally:
        os.unlink(path)

# ---------------------------------------------------------------------------
# correlation_store=False disables the feature
# ---------------------------------------------------------------------------

_MINIMAL_EML = (
    b"From: alice@example.com\r\n"
    b"To: bob@example.com\r\n"
    b"Subject: test\r\n"
    b"Message-ID: <test@example.com>\r\n"
    b"\r\n"
    b"Hello world.\r\n"
)

def test_disabled_store_noop():
    """correlation_store=False must produce no behavioral flags and no errors."""
    result = runner.run_pipeline(_MINIMAL_EML, source="test", correlation_store=False)
    intel_stage = next((s for s in result.stages if s.stage == "intel"), None)
    assert intel_stage is not None
    behav = (intel_stage.facts or {}).get("behavioral_hits", [])
    assert behav == [], f"disabled store should produce no behavioral flags, got: {behav}"
    details = (intel_stage.facts or {}).get("behavioral_details", [])
    assert details == [], f"disabled store should produce no behavioral details, got: {details}"
