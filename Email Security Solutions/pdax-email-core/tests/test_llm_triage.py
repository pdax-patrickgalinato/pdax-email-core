"""Unit tests for the LLM-call triage (app/pipeline/runner.py's cascade).

Goal being tested: don't spend a paid/rate-limited AI-provider call on every
email — only on the ones where the free heuristic-only score sits close
enough to a verdict threshold that a deeper read could plausibly change the
outcome. Hard overrides and comfortably-clean/comfortably-malicious cases
should never reach the real provider. All calls are mocked; nothing here
touches a real API. Run: python3 tests/test_llm_triage.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pipeline.content_ai import GeminiProvider
from app.pipeline.runner import run_pipeline

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


class CountingFakeClient:
    """Records every real generate_content call so tests can assert on
    whether the (expensive, rate-limited) provider was actually invoked."""
    def __init__(self, payload=None):
        import json
        self.calls = []
        self._payload = payload or {"score": 80, "findings": ["urgency_language"], "summary": "Escalated read."}
        self._json = json

        class _Models:
            def __init__(self, outer):
                self._outer = outer
            def generate_content(self, **kwargs):
                self._outer.calls.append(kwargs)
                class _Resp:
                    pass
                r = _Resp()
                r.text = self._outer._json.dumps(self._outer._payload)
                return r
        self.models = _Models(self)


_AMBIGUOUS_RAW = (
    b"Return-Path: <ops@vendor-notice.com>\r\n"
    b"From: \"Vendor Ops\" <ops@vendor-notice.com>\r\n"
    b"To: pat@pdax.ph\r\n"
    b"Message-ID: <mid1@vendor-notice.com>\r\n"
    b"Subject: Please action urgently\r\n"
    b"Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n"
    b"Hi,\r\n\r\nPlease verify your account immediately to continue.\r\n\r\nThanks\r\n"
)


def _run(raw_name_or_bytes, **kwargs):
    if isinstance(raw_name_or_bytes, bytes):
        raw = raw_name_or_bytes
    else:
        raw = (SAMPLES / raw_name_or_bytes).read_bytes()
    return run_pipeline(raw, source="test", **kwargs)


def test_triage_off_by_default_always_calls_provider():
    client = CountingFakeClient({"score": 5, "findings": [], "summary": "Clean."})
    provider = GeminiProvider(client=client)
    _run("clean_normal.eml", content_provider=provider)  # llm_triage not passed -> defaults off
    assert len(client.calls) == 1


def test_triage_on_skips_hard_override_case():
    client = CountingFakeClient()
    provider = GeminiProvider(client=client)
    result = _run("phish_lookalike.eml", content_provider=provider, llm_triage=True)
    assert len(client.calls) == 0
    content_stage = result.stage("content_ai")
    assert content_stage.facts.get("triage_skipped_llm") is True
    assert content_stage.facts.get("provider") == "heuristic"


def test_triage_on_skips_comfortably_clean_case():
    client = CountingFakeClient()
    provider = GeminiProvider(client=client)
    result = _run("clean_normal.eml", content_provider=provider, llm_triage=True)
    assert len(client.calls) == 0
    assert result.verdict.value in ("CLEAN", "LOW")
    assert result.stage("content_ai").facts.get("triage_skipped_llm") is True


def test_triage_on_escalates_ambiguous_case():
    client = CountingFakeClient({"score": 80, "findings": ["urgency_language", "ai:novel_pattern"], "summary": "Deeper read flags this."})
    provider = GeminiProvider(client=client)
    result = _run(_AMBIGUOUS_RAW, content_provider=provider, llm_triage=True)
    assert len(client.calls) == 1   # heuristic score here sits near the LOW boundary -> escalates
    content_stage = result.stage("content_ai")
    assert content_stage.facts.get("triage_escalated") is True
    assert content_stage.facts.get("provider") == "gemini"
    assert "ai:novel_pattern" in content_stage.red_flags


def test_env_var_enables_triage_without_explicit_kwarg():
    old = os.environ.get("PDAX_LLM_TRIAGE")
    try:
        os.environ["PDAX_LLM_TRIAGE"] = "1"
        client = CountingFakeClient()
        provider = GeminiProvider(client=client)
        _run("clean_normal.eml", content_provider=provider)  # no llm_triage kwarg
        assert len(client.calls) == 0
    finally:
        if old is None:
            os.environ.pop("PDAX_LLM_TRIAGE", None)
        else:
            os.environ["PDAX_LLM_TRIAGE"] = old


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
