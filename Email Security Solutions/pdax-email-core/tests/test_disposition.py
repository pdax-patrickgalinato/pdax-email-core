"""Unit tests for post-verdict disposition + shadow/quarantine enforcement.

Run: python3 tests/test_disposition.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.disposition import (
    LocalQuarantineClient, ShadowEnforcementClient, decide_disposition,
    keep_blocked, list_spool_entries, load_disposition_policy,
    reevaluate_spool_entry, release_from_quarantine, resolve_enforce_mode,
)
from app.models import Disposition, EnforceMode, PipelineResult, StageResult, StageStatus, Verdict
from app.pipeline.runner import run_pipeline


def _result(verdict=Verdict.CLEAN, hard_override=None, errored=False) -> PipelineResult:
    r = PipelineResult(verdict=verdict, hard_override=hard_override, composite_score=50)
    if errored:
        r.stages = [StageResult(stage="intel", status=StageStatus.ERROR,
                                red_flags=["stage_error:Timeout"], facts={"error": "timeout"})]
    return r


def test_resolve_enforce_mode_defaults_shadow():
    os.environ.pop("PDAX_ENFORCE", None)
    assert resolve_enforce_mode() == EnforceMode.SHADOW
    assert resolve_enforce_mode("quarantine") == EnforceMode.QUARANTINE
    assert resolve_enforce_mode("reject") == EnforceMode.REJECT


def test_clean_and_low_deliver():
    r = _result(Verdict.CLEAN)
    decide_disposition(r, enforce_mode=EnforceMode.SHADOW)
    assert r.disposition == Disposition.DELIVER

    r = _result(Verdict.LOW)
    decide_disposition(r, enforce_mode=EnforceMode.SHADOW)
    assert r.disposition == Disposition.LOG


def test_suspicious_and_malicious_quarantine_by_default():
    r = _result(Verdict.SUSPICIOUS)
    decide_disposition(r, enforce_mode=EnforceMode.SHADOW)
    assert r.disposition == Disposition.QUARANTINE

    r = _result(Verdict.MALICIOUS, hard_override="url_lookalike_domain")
    decide_disposition(r, enforce_mode=EnforceMode.QUARANTINE)
    assert r.disposition == Disposition.QUARANTINE
    assert "hard_override" in r.disposition_reason


def test_reject_requires_mode_and_policy_flag():
    policy = dict(load_disposition_policy())
    policy["allow_reject_on_malicious"] = False
    r = _result(Verdict.MALICIOUS)
    decide_disposition(r, policy=policy, enforce_mode=EnforceMode.REJECT)
    assert r.disposition == Disposition.QUARANTINE

    policy["allow_reject_on_malicious"] = True
    r = _result(Verdict.MALICIOUS)
    decide_disposition(r, policy=policy, enforce_mode=EnforceMode.REJECT)
    assert r.disposition == Disposition.REJECT


def test_pipeline_error_fails_open():
    r = _result(Verdict.MALICIOUS, errored=True)
    decide_disposition(r, enforce_mode=EnforceMode.QUARANTINE)
    assert r.disposition == Disposition.DELIVER
    assert "pipeline stage error" in r.disposition_reason


def test_shadow_client_always_releases():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        r = _result(Verdict.MALICIOUS)
        decide_disposition(r, enforce_mode=EnforceMode.SHADOW)
        client = ShadowEnforcementClient(log_dir=tmp)
        tag = client.apply("qid1", b"From: a\n\nbody", r)
        assert tag == "shadow_release"
        assert r.enforcement_applied == "shadow_release"
        log = tmp / "shadow_enforcement.jsonl"
        assert log.is_file()
        rec = json.loads(log.read_text().splitlines()[0])
        assert rec["disposition_intended"] == "QUARANTINE"
        assert rec["action_taken"] == "shadow_release"


def test_local_quarantine_writes_spool():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        r = _result(Verdict.MALICIOUS)
        decide_disposition(r, enforce_mode=EnforceMode.QUARANTINE)
        client = LocalQuarantineClient(root=tmp, mode=EnforceMode.QUARANTINE)
        tag = client.apply("badmsg", b"From: evil@x\n\nclick", r)
        assert tag == "quarantined"
        qdirs = list((tmp / "quarantine").iterdir())
        assert len(qdirs) == 1
        assert (qdirs[0] / "message.eml").read_bytes().startswith(b"From:")
        meta = json.loads((qdirs[0] / "meta.json").read_text())
        assert meta["verdict"] == "MALICIOUS"
        assert meta["disposition"] == "QUARANTINE"


def test_release_from_quarantine():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        r = _result(Verdict.SUSPICIOUS)
        decide_disposition(r, enforce_mode=EnforceMode.QUARANTINE)
        client = LocalQuarantineClient(root=tmp, mode=EnforceMode.QUARANTINE)
        client.apply("holdme", b"raw", r)
        qid = next((tmp / "quarantine").iterdir()).name
        dest = release_from_quarantine(tmp, qid)
        assert "released" in str(dest)
        assert not (tmp / "quarantine" / qid).exists()
        assert (dest / "message.eml").is_file()


def test_run_pipeline_fills_disposition():
    raw = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: hi\r\n\r\nhello\r\n"
    result = run_pipeline(raw, source="smtp_hold")
    assert result.disposition in (Disposition.DELIVER, Disposition.LOG, Disposition.QUARANTINE)
    assert result.enforce_mode == EnforceMode.SHADOW
    assert result.disposition_reason


def test_reeval_keeps_history_and_can_keep_blocked():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        r = _result(Verdict.MALICIOUS)
        decide_disposition(r, enforce_mode=EnforceMode.QUARANTINE)
        client = LocalQuarantineClient(root=tmp, mode=EnforceMode.QUARANTINE)
        # Store a simple clean-looking body — reeval should still produce a result
        client.apply("holdme", b"From: a@b.com\r\nTo: c@d.com\r\nSubject: x\r\n\r\nhi\r\n", r)
        qid = next((tmp / "quarantine").iterdir()).name
        out = reevaluate_spool_entry(tmp, qid, auto_release=False, auto_block=False)
        assert out["action"] == "kept"
        meta = json.loads((tmp / "quarantine" / qid / "meta.json").read_text())
        assert meta.get("reeval_history") and meta["last_reeval"]["new_verdict"]
        # Confirm block
        dest = keep_blocked(tmp, qid)
        assert "rejected" in str(dest)
        rows = list_spool_entries(tmp)
        assert any(row["bucket"] == "rejected" for row in rows)


if __name__ == "__main__":
    os.environ.pop("PDAX_ENFORCE", None)
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            passed += 1
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            print(f"FAIL {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
