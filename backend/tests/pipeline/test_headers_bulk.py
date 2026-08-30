"""Unit tests for headers.py's Advanced Spam Protection bulk-mail signal
(TMES policy parity) — List-Unsubscribe/List-Id/Precedence parsing and the
bulk_sender_no_unsubscribe flag.

Run: python3 -m pytest tests/test_headers_bulk.py
     (or python3 tests/test_headers_bulk.py)
"""
from email.mime.text import MIMEText

from backend.parsed_email import ParsedEmail
from workers.pipeline import headers, policy

def _eml(extra_headers=None, from_addr="sender@example.com"):
    msg = MIMEText("Hello.")
    msg["From"] = from_addr
    msg["To"] = "recipient@pdax.ph"
    msg["Subject"] = "test"
    msg["Message-ID"] = "<test@example.com>"
    for k, v in (extra_headers or {}).items():
        msg[k] = v
    return ParsedEmail(msg.as_bytes())

def test_plain_email_no_bulk_signals():
    pe = _eml()
    result = headers.run(pe)
    assert result.facts["has_list_unsubscribe"] is False
    assert result.facts["precedence_bulk"] is False
    assert "bulk_sender_no_unsubscribe" not in result.red_flags

def test_bulk_precedence_without_unsubscribe_flags():
    pe = _eml({"Precedence": "bulk"})
    result = headers.run(pe)
    assert result.facts["precedence_bulk"] is True
    assert "bulk_sender_no_unsubscribe" in result.red_flags

def test_list_id_without_unsubscribe_flags():
    pe = _eml({"List-Id": "newsletter.example.com"})
    result = headers.run(pe)
    assert result.facts["has_list_id"] is True
    assert "bulk_sender_no_unsubscribe" in result.red_flags

def test_bulk_precedence_with_unsubscribe_does_not_flag():
    pe = _eml({"Precedence": "bulk", "List-Unsubscribe": "<mailto:unsub@example.com>"})
    result = headers.run(pe)
    assert result.facts["has_list_unsubscribe"] is True
    assert "bulk_sender_no_unsubscribe" not in result.red_flags

def test_one_click_unsubscribe_detected():
    pe = _eml({
        "List-Unsubscribe": "<https://example.com/unsub>",
        "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    })
    result = headers.run(pe)
    assert result.facts["list_unsubscribe_one_click"] is True

def test_non_bulk_precedence_word_does_not_flag():
    # e.g. "Precedence: auto_reply" (out-of-office) — a real value that isn't
    # bulk/list/junk shouldn't trip the heuristic.
    pe = _eml({"Precedence": "auto_reply"})
    result = headers.run(pe)
    assert result.facts["precedence_bulk"] is False
    assert "bulk_sender_no_unsubscribe" not in result.red_flags

def test_flag_is_advanced_spam_protection_category():
    assert policy.category_for_flag("bulk_sender_no_unsubscribe") == "advanced_spam_protection"

def test_advanced_spam_protection_disabled_suppresses_bulk_flag():
    from backend.models import PipelineResult, StageResult
    from workers.pipeline import runner, verdict as verdict_mod
    weights_cfg, *_ = runner.load_config()
    result = PipelineResult(stages=[
        StageResult(stage="headers", red_flags=["bulk_sender_no_unsubscribe"], sub_score=18.0),
    ])
    cfg = {"categories": {"advanced_spam_protection": {"enabled": False}}}
    verdict_mod.score_and_verdict(result, weights_cfg["weights"], weights_cfg["thresholds"], policy_cfg=cfg)
    assert result.composite_score == 0.0
    assert "policy_suppressed:bulk_sender_no_unsubscribe" in result.reasons


def test_message_id_mismatch_flagged_without_auth():
    from backend.parsed_email import ParsedEmail
    msg = MIMEText("Hello.")
    msg["From"] = "alerts@jumpcloud.com"
    msg["To"] = "recipient@pdax.ph"
    msg["Subject"] = "test"
    msg["Message-ID"] = "<id@mail.gmail.com>"
    result = headers.run(ParsedEmail(msg.as_bytes()))
    assert "message_id_domain_mismatch" in result.red_flags


def test_message_id_mismatch_skipped_when_spf_or_dkim_pass():
    from backend.parsed_email import ParsedEmail
    msg = MIMEText("Hello.")
    msg["From"] = "alerts@jumpcloud.com"
    msg["To"] = "recipient@pdax.ph"
    msg["Subject"] = "test"
    msg["Message-ID"] = "<id@mail.gmail.com>"
    msg["Authentication-Results"] = (
        "mx.google.com; spf=pass smtp.mailfrom=jumpcloud.com; dkim=pass header.d=jumpcloud.com"
    )
    result = headers.run(ParsedEmail(msg.as_bytes()))
    assert "message_id_domain_mismatch" not in result.red_flags


def test_tracking_beacon_scored_without_auth():
    from email.mime.multipart import MIMEMultipart
    from backend.parsed_email import ParsedEmail
    from workers.pipeline import urls as urls_mod
    msg = MIMEMultipart("alternative")
    msg["From"] = "noreply@vendor.example"
    msg["To"] = "me@pdax.ph"
    msg["Subject"] = "hi"
    msg["Message-ID"] = "<id@vendor.example>"
    msg.attach(MIMEText(
        '<html><body><img src="https://track.unrelated.net/pixel.gif" width="1" height="1">'
        "</body></html>",
        "html",
    ))
    result = urls_mod.run(ParsedEmail(msg.as_bytes()), ["pdax.ph"])
    assert "tracking_beacon_detected" in result.red_flags


def test_tracking_beacon_not_scored_when_auth_passes():
    from email.mime.multipart import MIMEMultipart
    from backend.parsed_email import ParsedEmail
    from workers.pipeline import urls as urls_mod
    msg = MIMEMultipart("alternative")
    msg["From"] = "noreply@vendor.example"
    msg["To"] = "me@pdax.ph"
    msg["Subject"] = "hi"
    msg["Message-ID"] = "<id@vendor.example>"
    msg["Authentication-Results"] = "mx.google.com; spf=pass smtp.mailfrom=vendor.example"
    msg.attach(MIMEText(
        '<html><body><img src="https://track.unrelated.net/pixel.gif" width="1" height="1">'
        "</body></html>",
        "html",
    ))
    result = urls_mod.run(ParsedEmail(msg.as_bytes()), ["pdax.ph"])
    assert "tracking_beacon_detected" not in result.red_flags
    assert result.facts["tracking_beacons"]

