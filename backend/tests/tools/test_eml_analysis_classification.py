"""Unit tests for analyst verdict classification in eml_analysis_agent.

Run: python3 tests/test_eml_analysis_classification.py
"""
from pathlib import Path

from cli.eml_analysis_agent import (
    _canon_classification,
    _classification_from_risk,
    ensure_classification,
    render_markdown,
)

def test_canon_classification_labels():
    assert _canon_classification("Phishing") == "Phishing"
    assert _canon_classification("HIGH — Phishing") == "Phishing"
    assert _canon_classification("CRITICAL — Malware Delivery") == "Malware"
    assert _canon_classification("Legitimate") == "Benign"
    assert _canon_classification("business email compromise") == "BEC"

def test_classification_from_risk():
    assert _classification_from_risk("LOW") == "Benign"
    assert _classification_from_risk("MEDIUM") == "Suspicious"
    assert _classification_from_risk("HIGH") == "Malicious"
    assert _classification_from_risk("CRITICAL") == "Malicious"

def test_ensure_classification_prefers_model_label():
    analysis = {
        "threat_assessment": {
            "classification": "Phishing",
            "risk_level": "HIGH",
            "risk_score": 70,
        },
        "content_analysis": {"category": "Newsletter"},
    }
    ensure_classification(analysis)
    assert analysis["threat_assessment"]["classification"] == "Phishing"

def test_ensure_classification_uses_playbook_when_missing():
    analysis = {"threat_assessment": {"risk_level": "HIGH", "risk_score": 70}}
    playbook = {"classification": "Phishing", "verdict": "HIGH — Phishing"}
    ensure_classification(analysis, playbook)
    assert analysis["threat_assessment"]["classification"] == "Phishing"

def test_ensure_classification_falls_back_to_risk():
    analysis = {"threat_assessment": {"risk_level": "MEDIUM", "risk_score": 40}}
    ensure_classification(analysis)
    assert analysis["threat_assessment"]["classification"] == "Suspicious"

def test_render_markdown_includes_verdict_section():
    analysis = {
        "metadata": {"subject": "Wire transfer"},
        "authentication_forensics": {},
        "content_analysis": {"summary": "Pay now", "category": "BEC", "entities": {}, "action_items": []},
        "sender_legitimacy": {},
        "landing_page_analysis": [],
        "investigation_findings": [],
        "recommended_actions": [],
        "threat_assessment": {
            "classification": "BEC",
            "risk_level": "HIGH",
            "risk_score": 72,
            "indicators": ["wire_transfer_ask"],
            "suspicious_urls": [],
            "attachment_risks": [],
        },
    }
    md = render_markdown(Path("sample.eml"), analysis)
    assert "## Verdict" in md
    assert "**BEC**" in md

def test_render_markdown_includes_body_structure():
    analysis = {
        "metadata": {"subject": "Fw: invoice"},
        "authentication_forensics": {},
        "content_analysis": {
            "summary": "Wrapper around a forwarded lure.",
            "category": "Phishing",
            "entities": {},
            "action_items": [],
            "body_structure": {
                "is_forwarded": True,
                "is_reply": False,
                "primary_content": "Please see below.",
                "quoted_or_forwarded_content": "Click to reset your password.",
                "footer_content": "Sent from my iPhone",
                "footer_worth_assessing": False,
                "footer_assessment": "Device signature; not scored.",
            },
        },
        "sender_legitimacy": {},
        "landing_page_analysis": [],
        "investigation_findings": [],
        "recommended_actions": [],
        "threat_assessment": {
            "classification": "Phishing",
            "risk_level": "HIGH",
            "risk_score": 70,
            "indicators": [],
            "suspicious_urls": [],
            "attachment_risks": [],
        },
    }
    md = render_markdown(Path("fw.eml"), analysis)
    assert "Message structure (LLM)" in md
    assert "forwarded" in md
    assert "ordinary boilerplate" in md
    assert "Please see below." in md
    assert "Device signature" in md

