"""Deception-structure detection: trusted channel + foreign brand lure."""
from __future__ import annotations

import sys
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pipeline.runner import run_pipeline
from app.pipeline import headers
from app.parsed_email import ParsedEmail


def _eml_bytes(*, subject: str, html: str,
               from_addr: str = "testflight_no_reply@email.apple.com",
               reply_to: str = "attacker@icloud.com") -> bytes:
    msg = EmailMessage()
    msg["From"] = f"Dev via TestFlight <{from_addr}>"
    msg["To"] = "support@pdax.ph"
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content("View in TestFlight")
    msg.add_alternative(html, subtype="html")
    return msg.as_bytes()


_TF_LINK = "https://testflight.apple.com/join/abc123"


def test_openai_lure_is_malicious():
    raw = _eml_bytes(
        subject="Invited to test OpenAI AdsGPT",
        html=f'<a href="{_TF_LINK}">View in TestFlight</a><p>OpenAI AdsGPT Ad Insights</p>',
    )
    r = run_pipeline(raw, source="test")
    assert r.verdict.value == "MALICIOUS"
    assert r.hard_override == "service_abuse_testflight_brand_lure"
    dec = next(s for s in r.stages if s.stage == "deception")
    assert "deception_structure_service_abuse" in dec.red_flags
    assert "trusted_channel_brand_mismatch" in dec.red_flags


def test_binance_lure_on_testflight_is_malicious():
    raw = _eml_bytes(
        subject="Invited to test Binance Pro Trader",
        html=f'<a href="{_TF_LINK}">View</a><p>Binance Pro for iOS</p>',
    )
    r = run_pipeline(raw, source="test")
    assert r.verdict.value == "MALICIOUS"
    assert "service_abuse_testflight_brand_lure" in (r.reasons or [])


def test_benign_testflight_without_brand_lure_not_override():
    raw = _eml_bytes(
        subject="Jane Doe has invited you to test Acme Inventory",
        html=f'<a href="{_TF_LINK}">View in TestFlight</a>'
             f"<h2>Acme Inventory</h2><p>By Jane Doe for iOS.</p>",
    )
    r = run_pipeline(raw, source="test")
    assert r.hard_override != "service_abuse_testflight_brand_lure"
    assert r.hard_override != "deception_structure_service_abuse"
    dec = next(s for s in r.stages if s.stage == "deception")
    assert "service_abuse_testflight_brand_lure" not in dec.red_flags
    # Freemail Reply-To on Apple From is a soft reinforcer only.
    assert "trusted_channel_reply_to_freemail" in dec.red_flags


def test_non_apple_sender_with_openai_text_not_override():
    raw = _eml_bytes(
        subject="OpenAI invite",
        html=f'<a href="{_TF_LINK}">join</a> OpenAI',
        from_addr="noreply@example.com",
    )
    r = run_pipeline(raw, source="test")
    assert r.hard_override != "service_abuse_testflight_brand_lure"
    assert r.hard_override != "deception_structure_service_abuse"


def test_reply_to_freemail_header_flag():
    raw = _eml_bytes(
        subject="hello",
        html="<p>hi</p>",
        from_addr="alerts@vendor.example",
        reply_to="person@gmail.com",
    )
    pe = ParsedEmail(raw)
    st = headers.run(pe)
    assert st.facts.get("reply_to_freemail") is True
    assert "reply_to_freemail" in st.red_flags


def test_corpus_sample_is_malicious():
    raw = (Path(__file__).resolve().parents[1] / "samples" / "testflight_no_reply.eml").read_bytes()
    r = run_pipeline(raw, source="test")
    assert r.verdict.value == "MALICIOUS"
    assert r.hard_override == "service_abuse_testflight_brand_lure"
    dec = next(s for s in r.stages if s.stage == "deception")
    assert "deception_structure_service_abuse" in dec.red_flags


if __name__ == "__main__":
    failed = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("OK ", name)
            except Exception as e:
                failed += 1
                print("FAIL", name, type(e).__name__, e)
    raise SystemExit(1 if failed else 0)
