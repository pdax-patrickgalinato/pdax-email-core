"""Unit tests for app/rdap_client.py (RDAP domain-age lookup) and its wiring
into app/pipeline/sender.py — Web Reputation (TMES policy parity). All HTTP
is mocked via an injected http_get; nothing here touches a real network.

Run: python3 -m pytest tests/test_rdap.py  (or python3 tests/test_rdap.py)
"""
import sys
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.parsed_email import ParsedEmail
from app.pipeline import policy, sender
from app.rdap_client import domain_age_days, domain_rdap_summary


def _rdap_response(days_ago, event_action="registration"):
    date = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    return 200, {
        "events": [{"eventAction": event_action, "eventDate": date}],
        "status": ["client transfer prohibited"],
        "entities": [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc."]]],
        }],
    }


# --- app/rdap_client.py directly ---------------------------------------------

def test_domain_age_days_parses_registration_event():
    http = lambda url: _rdap_response(400)
    age = domain_age_days("example.com", http_get=http)
    assert 399 <= age <= 401


def test_domain_age_days_no_domain_returns_none():
    assert domain_age_days("", http_get=lambda url: (200, {})) is None


def test_domain_age_days_non_200_degrades_to_none():
    http = lambda url: (404, None)
    assert domain_age_days("nonexistent.example", http_get=http) is None


def test_domain_age_days_connection_error_degrades_to_none():
    http = lambda url: (0, None)   # simulates timeout/connection error
    assert domain_age_days("example.com", http_get=http) is None


def test_domain_age_days_missing_registration_event_returns_none():
    http = lambda url: (200, {"events": [{"eventAction": "last changed", "eventDate": "2020-01-01T00:00:00Z"}]})
    assert domain_age_days("example.com", http_get=http) is None


def test_domain_age_days_malformed_date_returns_none():
    http = lambda url: (200, {"events": [{"eventAction": "registration", "eventDate": "not-a-date"}]})
    assert domain_age_days("example.com", http_get=http) is None


def test_domain_age_days_empty_events_returns_none():
    http = lambda url: (200, {"events": []})
    assert domain_age_days("example.com", http_get=http) is None


def test_domain_rdap_summary_includes_registrar_and_age():
    http = lambda url: _rdap_response(100)
    summary = domain_rdap_summary("example.com", http_get=http)
    assert summary is not None
    assert summary["domain"] == "example.com"
    assert 99 <= summary["age_days"] <= 101
    assert summary["registered"]
    assert "Example Registrar" in summary["registrar"]
    assert "client transfer prohibited" in summary["status"]


def test_domain_rdap_summary_degrades_on_404():
    assert domain_rdap_summary("missing.example", http_get=lambda url: (404, None)) is None


# --- sender.py wiring ---------------------------------------------------------

def _eml(from_addr):
    msg = MIMEText("Hello.")
    msg["From"] = from_addr
    msg["To"] = "recipient@pdax.ph"
    msg["Subject"] = "test"
    msg["Message-ID"] = "<test@example.com>"
    return ParsedEmail(msg.as_bytes())


def test_sender_no_rdap_lookup_by_default():
    # No rdap_lookup passed, SEG_RDAP_LOOKUP unset (default off in test env)
    # -> must not attempt any lookup at all.
    pe = _eml("someone@example.com")
    result = sender.run(pe, [], [])
    assert result.facts["domain_age_days"] is None
    assert not any(f.startswith("domain_age_low") for f in result.red_flags)


def test_sender_young_domain_flags():
    pe = _eml("someone@freshly-registered.example")
    result = sender.run(pe, [], [], rdap_lookup=lambda d: 5)
    assert result.facts["domain_age_days"] == 5
    assert "domain_age_low:5" in result.red_flags
    assert result.sub_score >= 25


def test_sender_established_domain_no_flag():
    pe = _eml("someone@long-established.example")
    result = sender.run(pe, [], [], rdap_lookup=lambda d: 3650)
    assert result.facts["domain_age_days"] == 3650
    assert not any(f.startswith("domain_age_low") for f in result.red_flags)


def test_sender_rdap_failure_degrades_no_flag():
    pe = _eml("someone@example.com")
    result = sender.run(pe, [], [], rdap_lookup=lambda d: None)
    assert result.facts["domain_age_days"] is None
    assert not any(f.startswith("domain_age_low") for f in result.red_flags)


def test_domain_age_low_flag_category_and_gating():
    assert policy.category_for_flag("domain_age_low:5") == "web_reputation"

    from app.models import PipelineResult, StageResult
    from app.pipeline import runner, verdict as verdict_mod
    weights_cfg, *_ = runner.load_config()
    result = PipelineResult(stages=[
        StageResult(stage="sender", red_flags=["domain_age_low:5"], sub_score=25.0),
    ])
    cfg = {"categories": {"web_reputation": {"enabled": False}}}
    verdict_mod.score_and_verdict(result, weights_cfg["weights"], weights_cfg["thresholds"], policy_cfg=cfg)
    assert result.composite_score == 0.0
    assert "policy_suppressed:domain_age_low:5" in result.reasons


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
