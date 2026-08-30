"""Per-sender CLEAN/LOW infrastructure profiles (correlation.py)."""
from __future__ import annotations

import os
import tempfile

from backend.parsed_email import ParsedEmail
from workers.pipeline import runner
from workers.pipeline.content_ai import _summarize_context
from workers.pipeline.correlation import BehavioralCorrelationStore, PROFILE_MIN_N
from workers.pipeline.intel import LocalIOCClient, run as intel_run
from workers.pipeline.stage_summary import compact_stages, stages_for_feed


def _make_store():
    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    return BehavioralCorrelationStore(db_path=path), path


def _pe(sender="alice@yahoo.com"):
    raw = (
        f"From: {sender}\r\n"
        "To: victim@pdax.ph\r\n"
        "Subject: test\r\n"
        "Message-ID: <profile-test@example.com>\r\n"
        "\r\n"
        "Hello.\r\n"
    ).encode()
    return ParsedEmail(raw)


def _learn_esp(store, sender, n=5, asn="AS26101", country="US"):
    for _ in range(n):
        store.record_observation(sender, ["74.6.135.41"], [], verdict="CLEAN")
        store.record_profile_observation(
            sender, asn=asn, country=country, network_role="esp",
            vpn=False, spf="pass", dkim="pass", verdict="CLEAN",
        )


def test_disabled_store_no_profile_crash():
    result = runner.run_pipeline(
        b"From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\n\r\nHi\r\n",
        source="test", correlation_store=False,
    )
    intel_stage = next(s for s in result.stages if s.stage == "intel")
    assert (intel_stage.facts or {}).get("behavioral_hits") == []
    assert (intel_stage.facts or {}).get("profile_delta") in ([], None)
    sender_stage = next(s for s in result.stages if s.stage == "sender")
    assert (sender_stage.facts or {}).get("first_contact") is None


def test_malicious_not_learned_into_baseline():
    store, path = _make_store()
    try:
        sender = "alice@yahoo.com"
        store.record_profile_observation(
            sender, asn="AS999", country="NL", network_role="vpn_proxy",
            vpn=True, verdict="MALICIOUS",
        )
        prof = store.profile_for(sender)
        assert prof["n"] == 0
    finally:
        os.unlink(path)


def test_four_clean_vpn_delta_does_not_score():
    store, path = _make_store()
    try:
        sender = "alice@yahoo.com"
        _learn_esp(store, sender, n=4)
        pe = _pe(sender)
        st = intel_run(
            pe, LocalIOCClient(), {}, {}, store,
            origin_facts={"asn": "AS99999", "country": "NL",
                          "network_role": "vpn_proxy", "vpn": True},
            header_facts={"spf": "pass"},
        )
        codes = {d["code"]: d for d in (st.facts or {}).get("profile_delta") or []}
        assert "profile_vpn_new" in codes
        assert codes["profile_vpn_new"]["score"] is False
        assert st.sub_score < 12
        assert "profile_vpn_new" not in (st.red_flags or [])
        assert "profile_vpn_new" in (st.facts or {}).get("behavioral_hits")
    finally:
        os.unlink(path)


def test_five_esp_same_asn_new_ip_not_scored():
    store, path = _make_store()
    try:
        sender = "alice@yahoo.com"
        _learn_esp(store, sender, n=5, asn="AS26101", country="US")
        pe = _pe(sender)
        st = intel_run(
            pe, LocalIOCClient(), {}, {}, store,
            origin_facts={"asn": "AS26101", "country": "US",
                          "network_role": "esp", "vpn": False, "ip": "98.137.11.1"},
            header_facts={"spf": "pass"},
        )
        scored = [d for d in (st.facts or {}).get("profile_delta") or [] if d.get("score")]
        assert not scored
        assert st.sub_score < 12
    finally:
        os.unlink(path)


def test_five_esp_then_vpn_scores_small():
    store, path = _make_store()
    try:
        sender = "alice@yahoo.com"
        _learn_esp(store, sender, n=5)
        pe = _pe(sender)
        st = intel_run(
            pe, LocalIOCClient(), {}, {}, store,
            origin_facts={"asn": "AS99999", "country": "NL",
                          "network_role": "vpn_proxy", "vpn": True},
            header_facts={"spf": "pass"},
        )
        codes = {d["code"]: d for d in (st.facts or {}).get("profile_delta") or []}
        assert codes["profile_vpn_new"]["score"] is True
        assert st.sub_score >= 16
        assert st.sub_score < 45
        assert "profile_vpn_new" not in (st.red_flags or [])
        ui = stages_for_feed(compact_stages(type("R", (), {"stages": [st]})()))
        assert ui["intel"]["profileDelta"]
        assert ui["intel"]["profile"]["n"] == 5
    finally:
        os.unlink(path)


def test_pipeline_learns_clean_not_suspicious():
    store, path = _make_store()
    try:
        sender = "bob@example.com"
        eml = (
            f"From: {sender}\r\nTo: x@pdax.ph\r\nSubject: hi\r\n"
            "\r\nHi\r\n"
        ).encode()
        result = runner.run_pipeline(eml, source="test", correlation_store=store)
        assert result.verdict.value in ("CLEAN", "LOW", "SUSPICIOUS", "MALICIOUS")
        n = store.profile_for(sender)["n"]
        if result.verdict.value in ("CLEAN", "LOW"):
            assert n == 1
        else:
            assert n == 0
        sender_stage = next(s for s in result.stages if s.stage == "sender")
        assert sender_stage.facts.get("first_contact") == 0
    finally:
        os.unlink(path)


def test_summarize_context_includes_sender_profile():
    summary = _summarize_context({
        "intel": {
            "profile_summary": (
                f"Sender profile ({PROFILE_MIN_N} CLEAN/LOW emails): usually esp, "
                "countries US, ASN AS26101, 0% VPN."
            )
        }
    })
    assert "Sender profile (facts only" in summary
    assert "usually esp" in summary
    assert "not a verdict" in summary


def test_list_profiles_orders_by_volume():
    store, path = _make_store()
    try:
        for _ in range(5):
            store.record_profile_observation(
                "alice@yahoo.com", asn="AS26101", country="US",
                network_role="esp", vpn=False, verdict="CLEAN",
            )
        store.record_profile_observation(
            "bob@example.com", asn="AS16509", country="IE",
            network_role="cloud_hosting", vpn=False, verdict="LOW",
        )
        rows = store.list_profiles()
        assert [r["sender"] for r in rows] == ["alice@yahoo.com", "bob@example.com"]
        assert rows[0]["ready"] is True
        assert rows[1]["ready"] is False
        obs = store.profile_observations("alice@yahoo.com")
        assert len(obs) == 5
        assert obs[0]["country"] == "US"
        assert store.list_profiles(query="bob")[0]["sender"] == "bob@example.com"
    finally:
        os.unlink(path)


def test_verdict_counts_subquery_is_aliased_for_postgres():
    import inspect
    src = inspect.getsource(BehavioralCorrelationStore._verdict_counts_by_sender)
    assert "AS hops" in src
    from backend.db import adapt_sql
    sql = (
        "SELECT sender FROM ("
        "  SELECT sender, MAX(seen_at) AS seen_at FROM sender_ip_log GROUP BY sender"
        ") AS hops WHERE seen_at>?"
    )
    out = adapt_sql(sql)
    assert "AS hops" in out


def test_copy_behavior_graph_and_habits():
    store, path = _make_store()
    try:
        store.record_copy_behavior(
            sender="alice@yahoo.com",
            mailbox="jan@pdax.ph",
            message_id="<v1@x>",
            peers=["jan@pdax.ph", "cc@pdax.ph"],
            request_class="payment_request",
            hour_utc=14,
            has_attachment=True,
            is_reply=False,
        )
        store.record_copy_behavior(
            sender="alice@yahoo.com",
            mailbox="jan@pdax.ph",
            message_id="<v2@x>",
            peers=["jan@pdax.ph"],
            request_class="other",
            hour_utc=15,
            has_attachment=False,
            is_reply=True,
        )
        alice = store.behavior_for("alice@yahoo.com")
        assert alice["volume"]["sent_count"] == 2
        assert {p["value"] for p in alice["sent_to"]} == {"jan@pdax.ph", "cc@pdax.ph"}
        mix = {r["value"]: r["count"] for r in alice["request_mix"]}
        assert mix.get("payment_request") == 1
        assert any(h.get("value") == 14 for h in alice["hours"])
        jan = store.behavior_for("jan@pdax.ph")
        assert jan["volume"]["received_count"] >= 1
        assert any(p["value"] == "alice@yahoo.com" for p in jan["received_from"])
        assert 0 < alice["attachment_rate"] < 1
        assert 0 < alice["reply_rate"] < 1
    finally:
        os.unlink(path)


def _learn_isp(store, sender, n=5, hour=14, mailbox="jan@pdax.ph"):
    for i in range(n):
        store.record_profile_observation(
            sender, asn="AS9299", country="PH", network_role="isp",
            vpn=False, spf="pass", dkim="pass", verdict="CLEAN",
            hour_utc=hour, mailbox=mailbox, message_id=f"<learn-{i}@x>",
        )


def _pe_dated(sender, hour, subject="test", mailbox="victim@pdax.ph"):
    raw = (
        f"From: {sender}\r\n"
        f"To: {mailbox}\r\n"
        f"Date: Sat, 29 Aug 2026 {hour:02d}:00:00 +0000\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: <profile-hour@example.com>\r\n"
        "\r\n"
        "Hello.\r\n"
    ).encode()
    return ParsedEmail(raw)


def test_hour_unusual_scores_only_with_high_risk_ask():
    store, path = _make_store()
    try:
        sender = "treasury@vendor.example"
        _learn_isp(store, sender, n=5, hour=14)
        pe = _pe_dated(
            sender, 3,
            subject="PDAX Request for Payment - New Task - RFP 9",
            mailbox="jan@pdax.ph",
        )
        st = intel_run(
            pe, LocalIOCClient(), {}, {}, store,
            origin_facts={"asn": "AS9299", "country": "PH", "network_role": "isp"},
            header_facts={"spf": "pass"},
            mailbox="jan@pdax.ph",
        )
        codes = {d["code"]: d for d in (st.facts or {}).get("profile_delta") or []}
        assert "profile_hour_unusual" in codes
        assert codes["profile_hour_unusual"]["score"] is True
        assert "profile_hour_unusual" in (st.facts or {}).get("behavioral_hits")
        assert st.sub_score >= 10

        pe_ok = _pe_dated(sender, 3, subject="Bird facts", mailbox="jan@pdax.ph")
        st2 = intel_run(
            pe_ok, LocalIOCClient(), {}, {}, store,
            origin_facts={"asn": "AS9299", "country": "PH", "network_role": "isp"},
            header_facts={"spf": "pass"},
            mailbox="jan@pdax.ph",
        )
        codes2 = {d["code"]: d for d in (st2.facts or {}).get("profile_delta") or []}
        assert codes2["profile_hour_unusual"]["score"] is False
        assert st2.sub_score < 10
    finally:
        os.unlink(path)


def test_new_peer_scores_only_with_high_risk_ask():
    store, path = _make_store()
    try:
        sender = "treasury@vendor.example"
        _learn_isp(store, sender, n=5, mailbox="known@pdax.ph")
        store.record_recipient_request(
            "known@pdax.ph", sender, "other", message_id="<old@x>",
        )
        pe = _pe_dated(
            sender, 14,
            subject="PDAX Request for Payment - New Task - RFP 9",
            mailbox="new.hire@pdax.ph",
        )
        st = intel_run(
            pe, LocalIOCClient(), {}, {}, store,
            origin_facts={"asn": "AS9299", "country": "PH", "network_role": "isp"},
            header_facts={"spf": "pass"},
            mailbox="new.hire@pdax.ph",
        )
        codes = {d["code"]: d for d in (st.facts or {}).get("profile_delta") or []}
        assert "profile_peer_new" in codes
        assert codes["profile_peer_new"]["score"] is True
        assert st.sub_score >= 10
    finally:
        os.unlink(path)


def test_pipeline_records_correspondence_for_any_verdict():
    store, path = _make_store()
    try:
        eml = (
            "From: alice@yahoo.com\r\nTo: jan@pdax.ph\r\n"
            "Cc: cc@pdax.ph\r\nSubject: hi\r\nMessage-ID: <pipe-vol@x>\r\n"
            "\r\nHi\r\n"
        ).encode()
        runner.run_pipeline(
            eml, source="test", correlation_store=store,
            extra_context={"mailbox": "jan@pdax.ph"},
        )
        alice = store.behavior_for("alice@yahoo.com")
        assert alice["volume"]["sent_count"] == 1
        assert "jan@pdax.ph" in {p["value"] for p in alice["sent_to"]}
        assert "cc@pdax.ph" in {p["value"] for p in alice["sent_to"]}
    finally:
        os.unlink(path)


def test_sender_assessment_uses_typical_behavior_not_worst_copy():
    store, path = _make_store()
    try:
        store.record_observation("good@example.com", ["1.1.1.1"], [], verdict="CLEAN", message_id="c1")
        store.record_profile_observation(
            "good@example.com", asn="AS1", country="US", network_role="esp",
            vpn=False, verdict="CLEAN",
        )
        store.record_observation("mixed@example.com", ["2.2.2.2"], [], verdict="CLEAN", message_id="m1")
        store.record_observation("mixed@example.com", ["2.2.2.2"], [], verdict="SUSPICIOUS", message_id="m2")
        store.record_observation("bad@example.com", ["3.3.3.3"], [], verdict="MALICIOUS", message_id="b1")
        rows = {r["sender"]: r for r in store.list_profiles()}
        assert rows["good@example.com"]["assessment"] == "CLEAN"
        assert rows["mixed@example.com"]["assessment"] == "SUSPICIOUS"
        assert rows["mixed@example.com"]["verdicts"]["CLEAN"] == 1
        assert rows["mixed@example.com"]["verdicts"]["SUSPICIOUS"] == 1
        assert rows["bad@example.com"]["assessment"] == "MALICIOUS"
        assert rows["bad@example.com"]["n"] == 0
        assert [r["sender"] for r in store.list_profiles()][:3] == [
            "bad@example.com", "mixed@example.com", "good@example.com",
        ]
    finally:
        os.unlink(path)


def test_one_malicious_copy_does_not_paint_a_mostly_clean_sender():
    store, path = _make_store()
    try:
        sender = "alerts@vendor.example"
        for i in range(21):
            store.record_observation(
                sender, ["1.1.1.1"], [], verdict="CLEAN", message_id=f"c{i}",
            )
        store.record_observation(
            sender, ["1.1.1.1"], [], verdict="MALICIOUS", message_id="m1",
        )
        row = next(r for r in store.list_profiles() if r["sender"] == sender)
        assert row["assessment"] == "CLEAN"
        assert row["verdicts"]["MALICIOUS"] == 1
        assert row["copies"] == 22
    finally:
        os.unlink(path)


def test_sent_quoted_lure_excluded_from_identity():
    store, path = _make_store()
    try:
        sender = "support@pdax.ph"
        for i in range(5):
            store.record_observation(
                sender, ["1.1.1.1"], [], verdict="CLEAN", message_id=f"c{i}",
            )
        store.record_observation(
            sender, ["1.1.1.1"], [], verdict="MALICIOUS", message_id="lure-1",
            identity=0, identity_reason="outbound_sent",
        )
        store.record_observation(
            sender, ["1.1.1.1"], [], verdict="MALICIOUS", message_id="lure-2",
            identity=0, identity_reason="quoted_lure",
        )
        row = next(r for r in store.list_profiles() if r["sender"] == sender)
        assert row["assessment"] == "CLEAN"
        assert row["lane"] == "role"
        assert row["verdicts"]["MALICIOUS"] == 2
        assert row["copies"] == 7
        assert "2 hostile" in row["assessment_note"]
    finally:
        os.unlink(path)


def test_real_phish_majority_still_malicious():
    store, path = _make_store()
    try:
        sender = "phish@evil.example"
        for i in range(4):
            store.record_observation(
                sender, ["9.9.9.9"], [], verdict="MALICIOUS", message_id=f"p{i}",
            )
        store.record_observation(
            sender, ["9.9.9.9"], [], verdict="CLEAN", message_id="c1",
        )
        row = next(r for r in store.list_profiles() if r["sender"] == sender)
        assert row["assessment"] == "MALICIOUS"
        assert row["lane"] == "external"
    finally:
        os.unlink(path)
