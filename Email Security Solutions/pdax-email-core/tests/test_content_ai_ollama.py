"""Unit tests for OllamaProvider — local, self-hosted content-AI provider
(Phase 7 of the TMES policy-parity plan). All calls are mocked; nothing here
touches a real Ollama server, so it runs offline like the rest of the suite.
Run: python3 tests/test_content_ai_ollama.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pipeline.content_ai import OllamaProvider, get_default_provider


class FakeMessage:
    def __init__(self, content):
        self.content = content


class FakeChoice:
    def __init__(self, content):
        self.message = FakeMessage(content)


class FakeResponse:
    def __init__(self, payload=None, raw_text=None):
        text = raw_text if raw_text is not None else (json.dumps(payload) if payload is not None else None)
        self.choices = [FakeChoice(text)] if text is not None else []


class FakeCompletions:
    """Returns queued responses in order, one per .create() call."""
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


class FakeChat:
    def __init__(self, responses):
        self.completions = FakeCompletions(responses)


class FakeClient:
    def __init__(self, responses):
        self.chat = FakeChat(responses)

    @property
    def calls(self):
        return self.chat.completions.calls


def test_valid_response_maps_correctly():
    client = FakeClient([FakeResponse({
        "score": 72, "findings": ["bec_pattern"], "summary": "Gift-card BEC pattern."
    })])
    provider = OllamaProvider(model_id="llama3.1:8b", client=client)
    score, findings, facts = provider.analyze("quick task", "buy gift cards", {})
    assert score == 72.0
    assert findings == ["bec_pattern"]
    assert facts["provider"] == "ollama"
    assert facts["model_id"] == "llama3.1:8b"
    assert facts["summary"] == "Gift-card BEC pattern."
    assert len(client.calls) == 1


def test_repair_retry_recovers_from_schema_violation():
    # Small local models are called out in the class docstring as MORE prone
    # to schema drift than the frontier hosted providers — this is exactly
    # the case the shared repair-retry logic exists for.
    client = FakeClient([
        FakeResponse({"score": 150, "findings": [], "summary": "out of range"}),
        FakeResponse({"score": 55, "findings": [], "summary": "fixed"}),
    ])
    provider = OllamaProvider(model_id="llama3.1:8b", client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 55.0
    assert facts["summary"] == "fixed"
    assert len(client.calls) == 2


def test_persistent_schema_violation_degrades_honestly():
    client = FakeClient([
        FakeResponse(raw_text="not json"),
        FakeResponse(raw_text="still not json"),
    ])
    provider = OllamaProvider(model_id="llama3.1:8b", client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 0.0
    assert findings == []
    assert facts["degraded"] is True
    assert facts["provider"] == "ollama"


def test_empty_response_degrades():
    client = FakeClient([FakeResponse(None)])
    provider = OllamaProvider(model_id="llama3.1:8b", client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 0.0
    assert facts["degraded"] is True


def test_missing_model_id_degrades_without_client_injection():
    # No injected client and no model_id -> _get_client() raises before any
    # network call (connection-refused/no-server-running shaped failure in
    # the real world) — analyze() must still degrade honestly, not crash.
    provider = OllamaProvider(model_id=None)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 0.0
    assert facts["degraded"] is True
    assert facts["provider"] == "ollama"


def test_context_summary_reaches_the_prompt():
    client = FakeClient([FakeResponse({"score": 10, "findings": [], "summary": "ok"})])
    provider = OllamaProvider(model_id="llama3.1:8b", client=client)
    context = {"sender": {"lookalike_of": "pdax.ph"}}
    provider.analyze("subject", "body", context)
    sent_messages = client.calls[0]["messages"]
    user_message = next(m["content"] for m in sent_messages if m["role"] == "user")
    assert "lookalike of protected domain 'pdax.ph'" in user_message


def test_default_host_and_env_overrides():
    import os
    old_host = os.environ.pop("SEG_OLLAMA_HOST", None)
    old_model = os.environ.pop("SEG_OLLAMA_MODEL_ID", None)
    try:
        provider = OllamaProvider()
        assert provider.host == "http://localhost:11434"
        assert provider.model_id is None

        os.environ["SEG_OLLAMA_HOST"] = "http://gpu-box:11434/"
        os.environ["SEG_OLLAMA_MODEL_ID"] = "qwen2.5:14b"
        provider2 = OllamaProvider()
        assert provider2.host == "http://gpu-box:11434"   # trailing slash stripped
        assert provider2.model_id == "qwen2.5:14b"
    finally:
        for k, v in (("SEG_OLLAMA_HOST", old_host), ("SEG_OLLAMA_MODEL_ID", old_model)):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_get_default_provider_respects_env():
    import os
    old = os.environ.get("SEG_CONTENT_PROVIDER")
    try:
        os.environ["SEG_CONTENT_PROVIDER"] = "ollama"
        assert isinstance(get_default_provider(), OllamaProvider)
    finally:
        if old is None:
            os.environ.pop("SEG_CONTENT_PROVIDER", None)
        else:
            os.environ["SEG_CONTENT_PROVIDER"] = old


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
