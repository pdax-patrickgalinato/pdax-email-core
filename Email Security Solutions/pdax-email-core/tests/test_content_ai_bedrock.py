"""Unit tests for BedrockProvider — schema validation, repair retry, and
graceful degradation. All calls are mocked; nothing here touches AWS, so it
runs offline like the rest of the suite. Run: python3 tests/test_content_ai_bedrock.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pipeline import content_ai
from app.pipeline.content_ai import BedrockProvider, GeminiProvider, get_default_provider, _TOOL_NAME


def _tool_response(input_dict):
    return {"output": {"message": {"role": "assistant", "content": [
        {"toolUse": {"toolUseId": "t1", "name": _TOOL_NAME, "input": input_dict}}
    ]}}}


def _no_tool_response():
    return {"output": {"message": {"role": "assistant", "content": [{"text": "no tool call"}]}}}


class FakeClient:
    """Returns queued responses in order, one per .converse() call."""
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


def test_valid_response_maps_correctly():
    client = FakeClient([_tool_response({
        "score": 82, "findings": ["bec_pattern", "urgency_language"], "summary": "Gift-card BEC."
    })])
    provider = BedrockProvider(client=client)
    score, findings, facts = provider.analyze("Quick task", "Buy gift cards now", {})
    assert score == 82.0
    assert findings == ["bec_pattern", "urgency_language"]
    assert facts["provider"] == "bedrock"
    assert facts["summary"] == "Gift-card BEC."
    assert len(client.calls) == 1


def test_repair_retry_recovers_from_schema_violation():
    client = FakeClient([
        _tool_response({"score": 150, "findings": ["bec_pattern"], "summary": "oops out of range"}),
        _tool_response({"score": 70, "findings": ["bec_pattern"], "summary": "fixed"}),
    ])
    provider = BedrockProvider(client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 70.0
    assert facts["summary"] == "fixed"
    assert len(client.calls) == 2   # one initial call + one repair call


def test_persistent_schema_violation_degrades_honestly():
    client = FakeClient([
        _tool_response({"score": 150, "findings": [], "summary": "bad"}),
        _tool_response({"score": -5, "findings": [], "summary": "still bad"}),
    ])
    provider = BedrockProvider(client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 0.0
    assert findings == []
    assert facts["degraded"] is True
    assert facts["provider"] == "bedrock"


def test_missing_tool_call_degrades():
    client = FakeClient([_no_tool_response()])
    provider = BedrockProvider(client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 0.0
    assert facts["degraded"] is True


def test_get_default_provider_respects_env():
    old = os.environ.get("PDAX_CONTENT_PROVIDER")
    try:
        os.environ.pop("PDAX_CONTENT_PROVIDER", None)
        assert isinstance(get_default_provider(), content_ai.HeuristicProvider)

        os.environ["PDAX_CONTENT_PROVIDER"] = "bedrock"
        assert isinstance(get_default_provider(), BedrockProvider)

        os.environ["PDAX_CONTENT_PROVIDER"] = "gemini"
        assert isinstance(get_default_provider(), GeminiProvider)

        os.environ["PDAX_CONTENT_PROVIDER"] = "null"
        assert isinstance(get_default_provider(), content_ai.NullProvider)
    finally:
        if old is None:
            os.environ.pop("PDAX_CONTENT_PROVIDER", None)
        else:
            os.environ["PDAX_CONTENT_PROVIDER"] = old


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
