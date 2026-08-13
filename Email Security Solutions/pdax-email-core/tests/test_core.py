"""Unit tests. Run: python3 -m pytest tests/test_core.py  (or python3 tests/test_core.py)"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.domainutils import registrable_domain, normalize_confusables, levenshtein
from app.pipeline.runner import run_pipeline


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
    # Synthetic fixtures (not real captured mail) purpose-built to exercise
    # specific hard-override code paths deterministically — see
    # samples/fixtures/ and samples/labels.yaml for why these are split from
    # the real-mail corpus that tests/run_eval.py evaluates.
    raw = (Path(__file__).resolve().parents[1] / "samples" / "fixtures" / name).read_bytes()
    return run_pipeline(raw, source="test").verdict.value


def test_clean_is_clean():
    assert _verdict("clean_normal.eml") in ("CLEAN", "LOW")


def test_lookalike_is_malicious():
    assert _verdict("phish_lookalike.eml") == "MALICIOUS"


def test_bec_is_flagged():
    assert _verdict("bec_giftcard.eml") in ("SUSPICIOUS", "MALICIOUS")


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
