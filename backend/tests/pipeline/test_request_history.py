"""Request-class × recipient history, trusted-channel VIP skip."""
from __future__ import annotations

import os
import tempfile

from backend.stores.lists import is_trusted_saas_domain
from backend.parsed_email import ParsedEmail
from workers.pipeline import runner
from workers.pipeline.content_ai import _summarize_context
from workers.pipeline.correlation import BehavioralCorrelationStore
from workers.pipeline.intel import LocalIOCClient, run as intel_run
from workers.pipeline.sender import run as sender_run
from workers.pipeline.request_class import classify_request, is_high_risk_request


def _make_store():
    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    return BehavioralCorrelationStore(db_path=path), path


def _pe(from_header: str, subject: str, mailbox_to: str = "benjy@pdax.ph") -> ParsedEmail:
    raw = (
        f"From: {from_header}\r\n"
        f"To: {mailbox_to}\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: <req-test@example.com>\r\n"
        "\r\n"
        "Please review this workflow item.\r\n"
    ).encode()
    return ParsedEmail(raw)


def test_classify_kissflow_payment_and_access():
    assert classify_request("PDAX Request for Payment - New Task - [PDAX] RFP 12") == "payment_request"
    assert is_high_risk_request("payment_request")
    assert classify_request("[Cybersec] Centralized User Access Request - New Task - x") == "access_request"
    assert classify_request("Account Restricting Request - New Task - hold") == "account_control"
    assert classify_request("Settlements - New Task - Manual Cash In") == "settlement_task"
    assert not is_high_risk_request("settlement_task")


def test_kissflow_is_trusted_saas_not_vip_spoof():
    assert is_trusted_saas_domain("pdax.kissflow.com")
    pe = _pe("PDAX <admin@pdax.kissflow.com>", "PDAX Request for Payment - New Task - RFP")
    st = sender_run(pe, ["pdax.ph"], ["PDAX", "CEO"])
    assert st.facts.get("trusted_channel") is True
    assert "vip_name_spoof:PDAX" not in (st.red_flags or [])


def test_unrelated_domain_still_vip_spoofs():
    pe = _pe("PDAX <admin@evil-saas.example>", "hello")
    st = sender_run(pe, ["pdax.ph"], ["PDAX"])
    assert st.facts.get("trusted_channel") is False
    assert "vip_name_spoof:PDAX" in (st.red_flags or [])


def test_first_payment_request_to_recipient_from_trusted_sender():
    store, path = _make_store()
    try:
        pe = _pe("PDAX <admin@pdax.kissflow.com>", "PDAX Request for Payment - New Task - RFP 9")
        st = intel_run(
            pe, LocalIOCClient(), {}, {}, store, mailbox="benjy.concepcion@pdax.ph",
        )
        assert st.facts.get("request_class") == "payment_request"
        assert st.facts.get("trusted_channel") is True
        assert "first_request_class_from_sender" in (st.red_flags or [])
        assert "first_request_class_for_recipient" in (st.red_flags or [])
        assert st.sub_score >= 18.0
        assert "first time this sender has dropped" in (st.facts.get("request_summary") or "")
        store.record_recipient_request(
            "benjy.concepcion@pdax.ph",
            "admin@pdax.kissflow.com",
            "payment_request",
            message_id="<req-test@example.com>",
        )
        st2 = intel_run(
            pe, LocalIOCClient(), {}, {}, store, mailbox="benjy.concepcion@pdax.ph",
        )
        assert "first_request_class_from_sender" not in (st2.red_flags or [])
        assert st2.sub_score < 18.0
    finally:
        os.unlink(path)


def test_settlement_first_request_is_advisory_not_scored():
    store, path = _make_store()
    try:
        pe = _pe("PDAX <admin@pdax.kissflow.com>", "Settlements - New Task - Manual Cash In")
        st = intel_run(
            pe, LocalIOCClient(), {}, {}, store, mailbox="an.payang@pdax.ph",
        )
        assert st.facts.get("request_class") == "settlement_task"
        assert "first_request_class_from_sender" in (st.red_flags or [])
        assert st.sub_score < 18.0
    finally:
        os.unlink(path)


def test_pipeline_still_analyzes_trusted_sender(tmp_path):
    store = BehavioralCorrelationStore(db_path=tmp_path / "beh.sqlite3")
    eml = (
        "From: PDAX <admin@pdax.kissflow.com>\r\n"
        "To: benjy.concepcion@pdax.ph\r\n"
        "Subject: PDAX Request for Payment - New Task - RFP\r\n"
        "Message-ID: <kissflow-rfp@example.com>\r\n"
        "\r\n"
        "Please approve this payment.\r\n"
    ).encode()
    result = runner.run_pipeline(
        eml, source="test", correlation_store=store,
        extra_context={"mailbox": "benjy.concepcion@pdax.ph"},
    )
    intel_stage = next(s for s in result.stages if s.stage == "intel")
    assert intel_stage.facts.get("request_class") == "payment_request"
    assert "first_request_class_from_sender" in (intel_stage.red_flags or [])
    sender_stage = next(s for s in result.stages if s.stage == "sender")
    assert sender_stage.facts.get("trusted_channel") is True
    prior = store.lookup_recipient_request(
        "benjy.concepcion@pdax.ph", "admin@pdax.kissflow.com", "payment_request",
    )
    assert prior["prior_same_class_from_sender"] >= 1


def test_summarize_context_includes_request_history():
    summary = _summarize_context({
        "sender": {"trusted_channel": True},
        "feedback": {"benign_sender": True},
        "intel": {
            "request_summary": (
                "this email is a payment or invoice request from a trusted/known-good "
                "channel. first time this sender has dropped a payment or invoice "
                "request to benjy.concepcion@pdax.ph."
            )
        },
    })
    assert "Recipient request history" in summary
    assert "first time this sender has dropped" in summary
    assert "known channel" in summary
    assert "not a skip of content review" in summary
