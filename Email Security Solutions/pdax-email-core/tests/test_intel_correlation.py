"""Unit tests for the local verdict-history correlation store
(app/pipeline/correlation.py) and its wiring into intel.py::run() /
runner.py::run_pipeline(). Every test uses an isolated temp-file SQLite DB —
never the real project data/ directory.

Run: python3 -m pytest tests/test_intel_correlation.py
     (or python3 tests/test_intel_correlation.py)
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models import Verdict
from app.parsed_email import ParsedEmail
from app.pipeline import intel, runner
from app.pipeline.correlation import CorrelationStore

_FIXTURES = Path(__file__).resolve().parents[1] / "samples" / "fixtures"


def _tmp_store() -> CorrelationStore:
    tmp = Path(tempfile.mkstemp(suffix=".sqlite3")[1])
    return CorrelationStore(db_path=tmp)


# --- CorrelationStore directly ----------------------------------------------

def test_lookup_empty_store_returns_no_flags():
    store = _tmp_store()
    assert store.lookup(domains=["evil.example"]) == []


def test_record_then_lookup_finds_it():
    store = _tmp_store()
    store.record(verdict="MALICIOUS", message_id="<a@b>", domains=["evil.example"])
    flags = store.lookup(domains=["evil.example"])
    assert flags == ["correlation_seen_before:evil.example:1"]


def test_record_increments_count_on_repeat():
    store = _tmp_store()
    store.record(verdict="MALICIOUS", message_id="<a@b>", domains=["evil.example"])
    store.record(verdict="SUSPICIOUS", message_id="<c@d>", domains=["evil.example"])
    flags = store.lookup(domains=["evil.example"])
    assert flags == ["correlation_seen_before:evil.example:2"]


def test_clean_verdict_never_recorded():
    store = _tmp_store()
    written = store.record(verdict="CLEAN", message_id="<a@b>", domains=["ok.example"])
    assert written is False
    assert store.lookup(domains=["ok.example"]) == []


def test_low_verdict_never_recorded():
    store = _tmp_store()
    written = store.record(verdict="LOW", message_id="<a@b>", domains=["ok.example"])
    assert written is False


def test_lookup_across_ioc_types():
    store = _tmp_store()
    store.record(verdict="MALICIOUS", ips=["1.2.3.4"], hashes=["deadbeef"], senders=["a@evil.example"])
    assert store.lookup(ips=["1.2.3.4"]) == ["correlation_seen_before:1.2.3.4:1"]
    assert store.lookup(hashes=["deadbeef"]) == ["correlation_seen_before:deadbeef:1"]
    assert store.lookup(senders=["a@evil.example"]) == ["correlation_seen_before:a@evil.example:1"]


def test_lookup_and_record_degrade_on_storage_error_not_raise():
    # An unwritable path (a directory that can't be created, e.g. under a
    # nonexistent root with no permission) should degrade to a no-op rather
    # than raising — same fail-soft contract as every other enrichment hook.
    bogus = Path("/nonexistent-root-for-test/definitely/not/writable.sqlite3")
    store = CorrelationStore(db_path=bogus)
    assert store.lookup(domains=["x.example"]) == []
    assert store.record(verdict="MALICIOUS", domains=["x.example"]) is False


# --- intel.run() integration: weighted, not a hard override -----------------

def test_intel_run_correlation_hit_is_weighted_not_override():
    store = _tmp_store()
    store.record(verdict="MALICIOUS", domains=["repeat-offender.example"])
    pe = ParsedEmail(_FIXTURES.joinpath("clean_normal.eml").read_bytes())
    # Force the sender domain to match what we seeded, without needing a new
    # fixture file — url_stage_facts/attach_facts empty is fine, run() only
    # needs pe.from_domain for the domain candidate list here.
    pe.msg.replace_header("From", "Someone <someone@repeat-offender.example>")
    result = intel.run(pe, intel.LocalIOCClient(), {}, {}, correlation_store=store)
    assert result.red_flags == ["correlation_seen_before:repeat-offender.example:1"]
    assert 0 < result.sub_score < 90.0   # weighted, and strictly below a real intel-hit's 90


def test_intel_run_no_correlation_store_is_noop():
    pe = ParsedEmail(_FIXTURES.joinpath("clean_normal.eml").read_bytes())
    result = intel.run(pe, intel.LocalIOCClient(), {}, {}, correlation_store=None)
    assert result.red_flags == []
    assert result.sub_score == 0.0


def test_verdict_hard_override_requires_intel_prefix_not_correlation():
    from app.models import PipelineResult, StageResult
    from app.pipeline import verdict as verdict_mod
    weights_cfg, *_ = runner.load_config()
    result = PipelineResult(stages=[
        StageResult(stage="intel", red_flags=["correlation_seen_before:x.example:3"], sub_score=75.0),
    ])
    verdict_mod.score_and_verdict(result, weights_cfg["weights"], weights_cfg["thresholds"])
    assert result.hard_override is None   # correlation alone must never trigger threat_intel_hit


# --- end-to-end through run_pipeline() --------------------------------------

def test_e2e_write_path_persists_malicious_verdict_iocs():
    store = _tmp_store()
    weights_cfg, protected, vips, policy_cfg, banned_ext = runner.load_config()
    raw = _FIXTURES.joinpath("phish_lookalike.eml").read_bytes()

    result1 = runner.run_pipeline(
        raw, source="test",
        config=(weights_cfg, protected, vips, policy_cfg, banned_ext),
        correlation_store=store,
    )
    assert result1.verdict == Verdict.MALICIOUS
    # First pass: nothing recorded yet at lookup time (recording happens
    # after the verdict is final), so no correlation flag on this run.
    assert not any(f.startswith("correlation_seen_before") for f in result1.reasons)

    # Second run of an email sharing the same lookalike domain IOC should now
    # see it — proves the write path actually persisted after the first run.
    result2 = runner.run_pipeline(
        raw, source="test",
        config=(weights_cfg, protected, vips, policy_cfg, banned_ext),
        correlation_store=store,
    )
    intel_stage = result2.stage("intel")
    assert any(f.startswith("correlation_seen_before:pdaxx.ph") for f in intel_stage.red_flags)


def test_e2e_correlation_store_false_disables_write_path():
    weights_cfg, protected, vips, policy_cfg, banned_ext = runner.load_config()
    raw = _FIXTURES.joinpath("phish_lookalike.eml").read_bytes()
    # correlation_store=False must not create/touch anything, and must not
    # error even though the verdict is MALICIOUS (a recordable verdict).
    result = runner.run_pipeline(
        raw, source="test",
        config=(weights_cfg, protected, vips, policy_cfg, banned_ext),
        correlation_store=False,
    )
    assert result.verdict == Verdict.MALICIOUS


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
