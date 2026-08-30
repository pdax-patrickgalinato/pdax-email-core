"""Unit tests. Run: python3 -m pytest tests/test_core.py  (or python3 tests/test_core.py)"""
from backend.domainutils import registrable_domain, normalize_confusables, levenshtein
from backend.paths import TEST_EML_DIR
from workers.pipeline.runner import run_pipeline

def test_registrable_domain():
    assert registrable_domain("mail.google.com") == "google.com"
    assert registrable_domain("a.b.pdax.com.ph") == "pdax.com.ph"
    assert registrable_domain("PDAX.PH") == "pdax.ph"

def test_confusables():
    assert normalize_confusables("pd4x.ph") == "pdax.ph"
    assert normalize_confusables("g00gle.com") == "google.com"

def test_levenshtein_cap():
    assert levenshtein("pdax", "pdax") == 0
    assert levenshtein("pdax", "pdaxx") == 1
    assert levenshtein("pdax", "zzzz", cap=1) == 2   # exceeds cap -> cap+1

def _verdict(name):
    # Synthetic fixtures (not production mail) purpose-built to exercise
    # specific hard-override code paths deterministically.
    raw = (TEST_EML_DIR / name).read_bytes()
    return run_pipeline(raw, source="test").verdict.value

def test_clean_is_clean():
    assert _verdict("clean-normal.eml") in ("CLEAN", "LOW")

def test_lookalike_is_malicious():
    assert _verdict("phish-lookalike.eml") == "MALICIOUS"

def test_bec_is_flagged():
    assert _verdict("bec-giftcard.eml") in ("SUSPICIOUS", "MALICIOUS")

def test_testflight_brand_lure_is_malicious():
    """Apple TestFlight service abuse (OpenAI/Meta lure) — hard override."""
    raw = (TEST_EML_DIR / "testflight-no-reply.eml").read_bytes()
    result = run_pipeline(raw, source="test")
    assert result.verdict.value == "MALICIOUS"
    assert result.hard_override == "service_abuse_testflight_brand_lure"
    assert "service_abuse_testflight_brand_lure" in result.reasons
    dec = next(s for s in result.stages if s.stage == "deception")
    assert "service_abuse_testflight_brand_lure" in dec.red_flags
    assert "deception_structure_service_abuse" in dec.red_flags

