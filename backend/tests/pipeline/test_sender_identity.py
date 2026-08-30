"""Sender-identity assessment: rate, SENT/quoted lure, role mailboxes."""
from __future__ import annotations

from email.mime.text import MIMEText

from backend.parsed_email import ParsedEmail
from workers.pipeline import headers
from workers.pipeline.content_ai import _calibrate_content
from backend.stores.sender_identity import (
    assessment_of,
    identity_skip_reason,
    is_role_mailbox,
    sender_lane,
)


def test_assessment_rate_thresholds():
    assert assessment_of({"CLEAN": 21, "MALICIOUS": 1}) == "CLEAN"
    assert assessment_of({"CLEAN": 181, "LOW": 0, "SUSPICIOUS": 0, "MALICIOUS": 2}) == "CLEAN"
    assert assessment_of({"CLEAN": 1, "SUSPICIOUS": 1}) == "SUSPICIOUS"
    assert assessment_of({"MALICIOUS": 1}) == "MALICIOUS"
    assert assessment_of({"CLEAN": 1, "MALICIOUS": 4}) == "MALICIOUS"
    assert assessment_of({"CLEAN": 7, "SUSPICIOUS": 3}) == "SUSPICIOUS"


def test_role_and_internal_lanes():
    assert is_role_mailbox("support@pdax.ph")
    assert is_role_mailbox("security+hunt@pdax.ph")
    assert sender_lane("support@pdax.ph") == "role"
    assert sender_lane("jan@pdax.ph") == "internal"
    assert sender_lane("phish@evil.example") == "external"


def test_skip_sent_quoted_lure_not_unquoted_bec():
    assert identity_skip_reason(
        "support@pdax.ph", "support@pdax.ph", ["SENT"],
        ["forwarded_lure", "nlu_intent:bec"],
    ) == "outbound_sent"
    assert identity_skip_reason(
        "support@pdax.ph", "jan@pdax.ph", ["INBOX"],
        ["forwarded_lure"],
    ) == "quoted_lure"
    assert identity_skip_reason(
        "security@pdax.ph", "jan@pdax.ph", ["INBOX"],
        ["forensics_high_entropy_content", "brand_impersonation"],
    ) == "role_ticket_content"
    assert identity_skip_reason(
        "support@pdax.ph", "support@pdax.ph", ["SENT"],
        ["bec_pattern", "reply_to_freemail"],
    ) == ""
    assert identity_skip_reason("phish@evil.example", "jan@pdax.ph", ["INBOX"], ["malware_delivery"]) == ""


def test_reply_to_ticketing_on_protected_from_not_scored():
    msg = MIMEText("Hunt notes.")
    msg["From"] = "security@pdax.ph"
    msg["To"] = "jan@pdax.ph"
    msg["Subject"] = "SR-1"
    msg["Message-ID"] = "<sr@pdax.ph>"
    msg["Reply-To"] = "tickets@helpdesk.example"
    result = headers.run(ParsedEmail(msg.as_bytes()), ["pdax.ph"])
    assert result.facts["reply_to_divergent"] is True
    assert "reply_to_divergent" not in result.red_flags


def test_reply_to_freemail_on_protected_from_still_scored():
    msg = MIMEText("Please send OTP.")
    msg["From"] = "jan@pdax.ph"
    msg["To"] = "cfo@pdax.ph"
    msg["Subject"] = "Urgent"
    msg["Message-ID"] = "<x@pdax.ph>"
    msg["Reply-To"] = "attacker@gmail.com"
    result = headers.run(ParsedEmail(msg.as_bytes()), ["pdax.ph"])
    assert "reply_to_divergent" in result.red_flags


def test_calibrate_caps_quoted_lure_on_reply():
    score, findings, facts = _calibrate_content(
        82.0,
        ["forwarded_lure", "nlu_intent:bec"],
        {},
        {"raw_headers": {"in_reply_to": "<orig@example>"}},
        "Thanks, we will look into this.\n\nOn Mon wrote:\nSend BTC now",
    )
    assert findings == ["forwarded_lure", "nlu_intent:bec"]
    assert facts.get("score_capped") is True
    assert score == 40.0
