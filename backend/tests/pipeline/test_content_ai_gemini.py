"""Unit tests for GeminiProvider — schema validation, repair retry, and
graceful degradation. All calls are mocked; nothing here touches Google's API,
so it runs offline like the rest of the suite. Run:
    python3 tests/test_content_ai_gemini.py
"""
import json

from workers.pipeline.content_ai import GeminiProvider

class FakeResponse:
    def __init__(self, payload=None, raw_text=None):
        self.text = raw_text if raw_text is not None else (
            json.dumps(payload) if payload is not None else None)

class FakeModels:
    """Returns queued responses in order, one per .generate_content() call."""
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)

class FakeClient:
    def __init__(self, responses):
        self.models = FakeModels(responses)

    @property
    def calls(self):
        return self.models.calls

def test_valid_response_maps_correctly():
    client = FakeClient([FakeResponse({
        "score": 88, "findings": ["bec_pattern", "urgency_language"], "summary": "Gift-card BEC."
    })])
    provider = GeminiProvider(client=client)
    score, findings, facts = provider.analyze("Quick task", "Buy gift cards now", {})
    assert score == 88.0
    assert findings == ["bec_pattern", "urgency_language"]
    assert facts["provider"] == "gemini"
    assert facts["summary"] == "Gift-card BEC."
    assert len(client.calls) == 1

def test_repair_retry_recovers_from_schema_violation():
    client = FakeClient([
        FakeResponse({"score": 150, "findings": ["bec_pattern"], "summary": "oops out of range"}),
        FakeResponse({"score": 70, "findings": ["bec_pattern"], "summary": "fixed"}),
    ])
    provider = GeminiProvider(client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 70.0
    assert facts["summary"] == "fixed"
    assert len(client.calls) == 2   # one initial call + one repair call

def test_persistent_schema_violation_degrades_honestly():
    client = FakeClient([
        FakeResponse({"score": 150, "findings": [], "summary": "bad"}),
        FakeResponse({"score": -5, "findings": [], "summary": "still bad"}),
    ])
    provider = GeminiProvider(client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 0.0
    assert findings == []
    assert facts["degraded"] is True
    assert facts["provider"] == "gemini"

def test_empty_response_degrades():
    client = FakeClient([FakeResponse(None)])
    provider = GeminiProvider(client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 0.0
    assert facts["degraded"] is True

def test_malformed_json_degrades():
    client = FakeClient([
        FakeResponse(raw_text="not json {{{"),
        FakeResponse(raw_text="still not json"),
    ])
    provider = GeminiProvider(client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 0.0
    assert facts["degraded"] is True
    assert len(client.calls) == 2

