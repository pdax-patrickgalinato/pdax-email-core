"""Unit tests for the TMES-parity policy layer (rules/policy.yaml,
app/pipeline/policy.py, and its wiring into verdict.score_and_verdict()).
Run: python3 -m pytest tests/test_policy.py  (or python3 tests/test_policy.py)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models import PipelineResult, StageResult, Verdict
from app.pipeline import policy, runner, verdict

_FIXTURES = Path(__file__).resolve().parents[1] / "samples" / "fixtures"


def _weights_thresholds():
    weights_cfg, *_ = runner.load_config()
    return weights_cfg["weights"], weights_cfg["thresholds"]


def _run(raw_name):
    raw = (_FIXTURES / raw_name).read_bytes()
    return runner.run_pipeline(raw, source="test")


def _run_with_policy(raw_name, policy_cfg):
    weights_cfg, protected, vips, _, banned_ext = runner.load_config()
    raw = (_FIXTURES / raw_name).read_bytes()
    return runner.run_pipeline(raw, source="test",
                               config=(weights_cfg, protected, vips, policy_cfg, banned_ext))


def _disabled(category):
    cfg = {"categories": {c: {"enabled": True} for c in policy.ALL_CATEGORIES}}
    cfg["categories"][category] = {"enabled": False}
    return cfg


# --- category_for_flag / is_enabled / filter_flags --------------------------

def test_category_for_flag_known_flags():
    assert policy.category_for_flag("url_lookalike:pdax.ph") == "web_reputation"
    assert policy.category_for_flag("banned_attachment:exe") == "file_blocking"
    assert policy.category_for_flag("threat_intel_hit") == "correlated_intelligence"
    assert policy.category_for_flag("intel_domain:evil.com") == "correlated_intelligence"


def test_category_for_flag_underscore_joined_tags_no_colon():
    # Regression test: category_for_flag's prefix matching must handle BOTH
    # "prefix:value" tags (url_lookalike:pdax.ph) AND plain underscore-joined
    # tags with no colon at all (forensics_type_mismatch,
    # bulk_sender_no_unsubscribe, correlation_seen_before:x:1 — the latter
    # has a colon but the registered prefix is the full segment before it,
    # "correlation_seen_before", not a truncation like "correlation"). A
    # naive `flag.split(":",1)[0] in prefix_set` check silently fails all of
    # these since the split-off segment never equals a shorter registered
    # prefix — caught while building Phase 4, but it also broke Malware
    # Scanning's category (Phase 1) and part of Correlated Intelligence
    # (Phase 3) from the moment they were built.
    assert policy.category_for_flag("forensics_type_mismatch") == "malware_scanning"
    assert policy.category_for_flag("forensics_office_macro") == "malware_scanning"
    assert policy.category_for_flag("forensics_archive_contains_executable") == "malware_scanning"
    assert policy.category_for_flag("bulk_sender_no_unsubscribe") == "advanced_spam_protection"
    assert policy.category_for_flag("correlation_seen_before:x.example:1") == "correlated_intelligence"
    assert policy.category_for_flag("spoofed_attachment_type:jpg->exe") == "file_blocking"
    assert policy.category_for_flag("double_extension_executable:invoice.pdf.exe") == "file_blocking"


def test_category_for_flag_ungated_flags():
    # Sender identity / phishing-content signals aren't owned by any of the
    # 6 TMES categories — see policy.py's module docstring.
    assert policy.category_for_flag("spf_fail") is None
    assert policy.category_for_flag("lookalike_of:pdax.ph") is None
    assert policy.category_for_flag("bec_pattern") is None
    assert policy.category_for_flag("vip_name_spoof:CEO") is None


def test_is_enabled_defaults():
    assert policy.is_enabled(None, "file_blocking") is True   # None = everything on
    assert policy.is_enabled({}, "file_blocking") is True     # missing key -> default
    assert policy.is_enabled({}, "virtual_analyzer") is False  # default-off category


def test_filter_flags_splits_by_category():
    cfg = _disabled("file_blocking")
    active, suppressed = policy.filter_flags(
        ["banned_attachment:exe", "macro_capable_doc:docm", "spf_fail"], cfg)
    assert active == ["macro_capable_doc:docm", "spf_fail"]
    assert suppressed == ["banned_attachment:exe"]


# --- score_and_verdict gating (direct, no email parsing needed) ------------

def test_default_policy_cfg_none_matches_baseline():
    weights, thresholds = _weights_thresholds()
    result = PipelineResult(stages=[
        StageResult(stage="intel", red_flags=["intel_domain:evil.com"], sub_score=100.0),
    ])
    verdict.score_and_verdict(result, weights, thresholds, policy_cfg=None)
    assert result.verdict == Verdict.MALICIOUS
    assert result.hard_override == "threat_intel_hit"


def test_correlated_intelligence_disabled_suppresses_intel_override():
    weights, thresholds = _weights_thresholds()
    result = PipelineResult(stages=[
        StageResult(stage="intel", red_flags=["intel_domain:evil.com"], sub_score=100.0),
    ])
    cfg = _disabled("correlated_intelligence")
    verdict.score_and_verdict(result, weights, thresholds, policy_cfg=cfg)
    assert result.hard_override is None
    assert result.verdict != Verdict.MALICIOUS
    assert "policy_suppressed:intel_domain:evil.com" in result.reasons


def test_malware_scanning_disabled_does_not_affect_file_blocking():
    weights, thresholds = _weights_thresholds()
    # A single attachments-stage StageResult carrying one flag from each of
    # the two categories that stage feeds today.
    result = PipelineResult(stages=[
        StageResult(stage="attachments",
                    red_flags=["banned_attachment:exe", "macro_capable_doc:docm"],
                    sub_score=85.0),
    ])
    cfg = _disabled("malware_scanning")
    verdict.score_and_verdict(result, weights, thresholds, policy_cfg=cfg)
    # file_blocking's hard override still fires — malware_scanning being off
    # must not suppress it. Like every other hard override (e.g.
    # threat_intel_hit), a decisive branch returns immediately without
    # reaching the weighted-composite section, so it never gets to tag
    # OTHER flags from the same stage as policy_suppressed — that tagging
    # only happens on the weighted-composite path. Only the deciding
    # override's own flags populate result.reasons here, same as today's
    # pre-existing behavior for every other hard override.
    assert result.hard_override == "banned_attachment_type"
    assert result.verdict == Verdict.MALICIOUS
    assert result.reasons == ["banned_attachment:exe"]


# --- end-to-end through run_pipeline() for wiring confidence ---------------

def test_e2e_default_policy_phish_lookalike_still_malicious():
    r = _run("phish_lookalike.eml")
    assert r.verdict == Verdict.MALICIOUS
    assert r.hard_override == "url_lookalike_domain"


def test_e2e_web_reputation_disabled_suppresses_lookalike_override():
    r = _run_with_policy("phish_lookalike.eml", _disabled("web_reputation"))
    assert r.hard_override != "url_lookalike_domain"
    assert any(f.startswith("policy_suppressed:url_lookalike") for f in r.reasons)


def test_e2e_virtual_analyzer_toggle_has_no_observable_effect_yet():
    # No SandboxProvider exists until Phase 6 — enabling or disabling this
    # toggle right now must be a no-op either way. This is the "before"
    # baseline a future real sandbox provider's tests should diff against.
    weights_cfg, protected, vips, _, banned_ext = runner.load_config()
    on_cfg = {"categories": {c: {"enabled": True} for c in policy.ALL_CATEGORIES}}
    off_cfg = _disabled("virtual_analyzer")
    raw = (_FIXTURES / "clean_normal.eml").read_bytes()
    r_on = runner.run_pipeline(raw, source="test", config=(weights_cfg, protected, vips, on_cfg, banned_ext))
    r_off = runner.run_pipeline(raw, source="test", config=(weights_cfg, protected, vips, off_cfg, banned_ext))
    assert r_on.verdict == r_off.verdict
    assert r_on.composite_score == r_off.composite_score


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
