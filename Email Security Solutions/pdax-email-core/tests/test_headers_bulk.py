"""Unit tests for headers.py's Advanced Spam Protection bulk-mail signal
(TMES policy parity) — List-Unsubscribe/List-Id/Precedence parsing and the
bulk_sender_no_unsubscribe flag.

Run: python3 -m pytest tests/test_headers_bulk.py
     (or python3 tests/test_headers_bulk.py)
"""
import sys
from email.mime.text import MIMEText
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.parsed_email import ParsedEmail
from app.pipeline import headers, policy


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
    from app.models import PipelineResult, StageResult
    from app.pipeline import runner, verdict as verdict_mod
    weights_cfg, *_ = runner.load_config()
    result = PipelineResult(stages=[
        StageResult(stage="headers", red_flags=["bulk_sender_no_unsubscribe"], sub_score=18.0),
    ])
    cfg = {"categories": {"advanced_spam_protection": {"enabled": False}}}
    verdict_mod.score_and_verdict(result, weights_cfg["weights"], weights_cfg["thresholds"], policy_cfg=cfg)
    assert result.composite_score == 0.0
    assert "policy_suppressed:bulk_sender_no_unsubscribe" in result.reasons


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); passed += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
