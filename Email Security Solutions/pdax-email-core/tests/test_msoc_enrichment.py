"""Tests for MSOC-gap enrichments wired into eml_analysis_agent.parse_eml."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eml_analysis_agent import _SYSTEM_PROMPT, render_markdown


_MIN_EML = (
    b"From: Mikaela Laysa <mikaela.laysa@interfarmainc.com>\r\n"
    b"To: victim@pdax.ph\r\n"
    b"Subject: Shared document\r\n"
    b"Message-ID: <test@example.com>\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<html><body><a href=\"https://intakeq.com/c/abc\">documentcloud.adobe.com</a></body></html>\r\n"
)


def test_system_prompt_includes_msoc_fields():
    for key in ("sender_legitimacy", "landing_page_analysis",
                "investigation_findings", "recommended_actions"):
        assert key in _SYSTEM_PROMPT
    assert "RISK CALIBRATION" in _SYSTEM_PROMPT
    assert "weakest level" in _SYSTEM_PROMPT
    assert "NO leading" in _SYSTEM_PROMPT or "without leading number" in _SYSTEM_PROMPT


def test_normalize_list_items_strips_leading_numbers():
    from eml_analysis_agent import _normalize_analysis, _normalize_list_items
    assert _normalize_list_items(["1. Do not click", "2) Quarantine", "- Block"]) == [
        "Do not click", "Quarantine", "Block",
    ]
    a = _normalize_analysis({
        "investigation_findings": ["1. Display mismatch"],
        "recommended_actions": ["1. Report to SOC"],
    })
    assert a["investigation_findings"] == ["Display mismatch"]
    assert a["recommended_actions"] == ["Report to SOC"]


def test_render_markdown_does_not_double_number_actions():
    from eml_analysis_agent import render_markdown
    analysis = {
        "metadata": {"subject": "Shared document", "from": "a@b.com",
                     "to": [], "cc": [], "reply_to": "", "date": "", "message_id": ""},
        "authentication_forensics": {
            "originating_ip": "1.2.3.4", "spf_status": "PASS", "dkim_status": "PASS",
            "address_mismatch_detected": False, "mismatch_details": "",
        },
        "content_analysis": {
            "summary": "Phish lure", "category": "phishing", "sentiment": "urgent",
            "entities": {"people": [], "organizations": [],
                         "dates_mentioned": [], "amounts_mentioned": []},
            "action_items": [],
        },
        "sender_legitimacy": {},
        "landing_page_analysis": [],
        "investigation_findings": ["1. Link text lied"],
        "recommended_actions": ["1. Do not click links.", "2. Verify via official channels."],
        "threat_assessment": {
            "risk_level": "HIGH", "risk_score": 70, "indicators": [],
            "suspicious_urls": [], "attachment_risks": [],
        },
    }
    md = render_markdown(Path("sample.eml"), analysis)
    assert "1. Do not click links." in md
    assert "1. 1. Do not click" not in md
    assert "2. Verify via official channels." in md
    assert "2. 2. Verify" not in md


def test_render_markdown_includes_msoc_sections():
    analysis = {
        "metadata": {"subject": "Shared document", "from": "a@b.com",
                     "to": [], "cc": [], "reply_to": "", "date": "", "message_id": ""},
        "authentication_forensics": {
            "originating_ip": "1.2.3.4", "spf_status": "PASS", "dkim_status": "PASS",
            "address_mismatch_detected": False, "mismatch_details": "",
        },
        "content_analysis": {
            "summary": "Phish lure", "category": "phishing", "sentiment": "urgent",
            "entities": {"people": [], "organizations": ["Interfarma"],
                         "dates_mentioned": [], "amounts_mentioned": []},
            "action_items": [],
        },
        "sender_legitimacy": {
            "claimed_organization": "Interfarma",
            "claimed_role": "Regulatory Affairs Officer",
            "alignment_assessment": "Content does not align.",
            "evidence": ["Display/URL mismatch"],
            "osint_limitations": "RDAP-only; no LinkedIn scrape.",
        },
        "landing_page_analysis": [{
            "final_url": "https://intakeq.com/c/abc",
            "title": "Waverley Training",
            "forms_found": ["Full Name", "Email"],
            "context_mismatch": True,
            "notes": "Unrelated intake form",
        }],
        "investigation_findings": [
            "Auth passed but link text mismatched destination.",
            "Landing page is an unrelated intake form.",
        ],
        "recommended_actions": [
            "Do not click links.",
            "Verify via official channels.",
        ],
        "threat_assessment": {
            "risk_level": "HIGH", "risk_score": 80, "indicators": ["display_mismatch"],
            "suspicious_urls": [], "attachment_risks": [],
        },
    }
    md = render_markdown(Path("sample.eml"), analysis)
    assert "## 1. Email Authentication" in md
    assert "## 5. Landing Page" in md
    assert "## 7. Recommended Actions" in md
    assert "Waverley Training" in md
    assert "Do not click links." in md


def test_parse_eml_attaches_landing_and_osint_when_enabled():
    from eml_analysis_agent import parse_eml

    tmp = Path(tempfile.mkdtemp()) / "phish.eml"
    tmp.write_bytes(_MIN_EML)

    fake_landing = [{
        "requested_url": "https://intakeq.com/c/abc",
        "final_url": "https://intakeq.com/c/abc",
        "title": "Waverley",
        "form_fields": ["Email"],
        "fetched": True,
        "degraded": False,
        "error": "",
    }]
    fake_rdap = {
        "domain": "intakeq.com", "age_days": 2000, "registered": "2018-01-01",
        "registrar": "Example", "status": [],
    }

    old_land = os.environ.get("SEG_LANDING_FETCH")
    old_rdap = os.environ.get("SEG_RDAP_LOOKUP")
    os.environ["SEG_LANDING_FETCH"] = "1"
    os.environ["SEG_RDAP_LOOKUP"] = "1"
    try:
        with mock.patch("app.landing_fetch.analyze_urls", return_value=fake_landing), \
             mock.patch("app.rdap_client.domain_rdap_summary", return_value=fake_rdap):
            parsed = parse_eml(tmp)
        assert parsed.get("landing_pages") == fake_landing
        assert any(d.get("domain") == "intakeq.com" for d in parsed.get("domain_osint") or [])
    finally:
        if old_land is None:
            os.environ.pop("SEG_LANDING_FETCH", None)
        else:
            os.environ["SEG_LANDING_FETCH"] = old_land
        if old_rdap is None:
            os.environ.pop("SEG_RDAP_LOOKUP", None)
        else:
            os.environ["SEG_RDAP_LOOKUP"] = old_rdap


def test_call_agent_retries_on_finish_reason_length():
    """Empty content + finish_reason=length must bump max_tokens and retry."""
    from eml_analysis_agent import call_agent

    class _Msg:
        def __init__(self, content):
            self.content = content

    class _Choice:
        def __init__(self, content, finish_reason):
            self.message = _Msg(content)
            self.finish_reason = finish_reason

    class _Resp:
        def __init__(self, content, finish_reason):
            self.choices = [_Choice(content, finish_reason)]

    seen_tokens = []

    class _Client:
        def __init__(self):
            self.n = 0
            self.chat = self
            self.completions = self

        def create(self, **kwargs):
            seen_tokens.append(kwargs.get("max_tokens"))
            self.n += 1
            if self.n == 1:
                return _Resp(None, "length")
            return _Resp('{"threat_assessment": {"risk_level": "LOW", "risk_score": 5}}', "stop")

    out = call_agent(_Client(), "zai-org/glm-4.7-maas", 6000, "analyze this")
    assert out["threat_assessment"]["risk_level"] == "LOW"
    assert seen_tokens[0] == 6000
    assert seen_tokens[1] >= 12000


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
