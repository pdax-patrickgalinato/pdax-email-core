"""Unit tests for GLMProvider — schema validation, repair retry, and graceful
degradation. All calls are mocked; nothing here touches Vertex AI/GLM, so it
runs offline like the rest of the suite. Run:
    python3 tests/test_content_ai_glm.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pipeline import content_ai
from app.pipeline.content_ai import GLMProvider, _ServiceAccountTokenProvider, get_default_provider


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
        "score": 78, "findings": ["bec_pattern", "urgency_language"], "summary": "Gift-card BEC."
    })])
    provider = GLMProvider(project_id="proj-1", client=client)
    score, findings, facts = provider.analyze("Quick task", "Buy gift cards now", {})
    assert score == 78.0
    assert findings == ["bec_pattern", "urgency_language"]
    assert facts["provider"] == "glm"
    assert facts["summary"] == "Gift-card BEC."
    assert len(client.calls) == 1


def test_repair_retry_recovers_from_schema_violation():
    client = FakeClient([
        FakeResponse({"score": 150, "findings": ["bec_pattern"], "summary": "oops out of range"}),
        FakeResponse({"score": 65, "findings": ["bec_pattern"], "summary": "fixed"}),
    ])
    provider = GLMProvider(project_id="proj-1", client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 65.0
    assert facts["summary"] == "fixed"
    assert len(client.calls) == 2


def test_persistent_schema_violation_degrades_honestly():
    client = FakeClient([
        FakeResponse({"score": 150, "findings": [], "summary": "bad"}),
        FakeResponse({"score": -5, "findings": [], "summary": "still bad"}),
    ])
    provider = GLMProvider(project_id="proj-1", client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 0.0
    assert findings == []
    assert facts["degraded"] is True
    assert facts["provider"] == "glm"


def test_empty_response_degrades():
    client = FakeClient([FakeResponse(None)])
    provider = GLMProvider(project_id="proj-1", client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 0.0
    assert facts["degraded"] is True


def test_malformed_json_degrades():
    client = FakeClient([
        FakeResponse(raw_text="not json {{{"),
        FakeResponse(raw_text="still not json"),
    ])
    provider = GLMProvider(project_id="proj-1", client=client)
    score, findings, facts = provider.analyze("x", "y", {})
    assert score == 0.0
    assert facts["degraded"] is True
    assert len(client.calls) == 2


def test_missing_project_id_degrades_without_client_injection():
    # No injected client and no project id -> _get_client() raises before any
    # network call; analyze() must still degrade honestly, not crash.
    import os
    old = os.environ.pop("SEG_GLM_PROJECT_ID", None)
    try:
        provider = GLMProvider(project_id="")
        score, findings, facts = provider.analyze("x", "y", {})
        assert score == 0.0
        assert facts["degraded"] is True
    finally:
        if old is not None:
            os.environ["SEG_GLM_PROJECT_ID"] = old


def _write_fake_credentials_file(payload):
    import tempfile
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(payload, f)
    f.close()
    return f.name


def test_project_id_derived_from_credentials_file():
    import os
    path = _write_fake_credentials_file({"type": "service_account", "project_id": "derived-proj"})
    old = os.environ.pop("SEG_GLM_PROJECT_ID", None)
    try:
        provider = GLMProvider(credentials_path=path)
        assert provider.project_id == "derived-proj"
    finally:
        if old is not None:
            os.environ["SEG_GLM_PROJECT_ID"] = old
        os.unlink(path)


def test_explicit_project_id_wins_over_credentials_file():
    import os
    path = _write_fake_credentials_file({"project_id": "from-file"})
    try:
        provider = GLMProvider(project_id="explicit-proj", credentials_path=path)
        assert provider.project_id == "explicit-proj"
    finally:
        os.unlink(path)


def test_project_id_from_credentials_handles_missing_file():
    provider = GLMProvider(credentials_path="/no/such/file.json")
    assert provider.project_id == ""


def test_resolve_api_key_prefers_explicit_key_over_credentials():
    provider = GLMProvider(project_id="p", api_key="fixed-key", credentials_path="/some/path.json")
    assert provider._resolve_api_key() == "fixed-key"


def test_resolve_api_key_falls_back_to_service_account_token_provider():
    provider = GLMProvider(project_id="p", credentials_path="/some/path.json")
    resolved = provider._resolve_api_key()
    assert callable(resolved)
    assert isinstance(resolved, _ServiceAccountTokenProvider)
    # built once and cached, not rebuilt on every call
    assert provider._resolve_api_key() is resolved


def test_resolve_api_key_none_without_any_credentials():
    import os
    saved = {k: os.environ.pop(k, None) for k in
              ("SEG_GLM_API_KEY", "SEG_GLM_CREDENTIALS_PATH", "GOOGLE_APPLICATION_CREDENTIALS")}
    try:
        provider = GLMProvider(project_id="p")
        assert provider._resolve_api_key() is None
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


class FakeCredentials:
    def __init__(self, tokens):
        self._tokens = list(tokens)
        self.valid = False
        self.token = None

    def refresh(self, request):
        self.token = self._tokens.pop(0)
        self.valid = True


def test_service_account_token_provider_mints_and_caches_token():
    fake_creds = FakeCredentials(["token-1"])
    provider = _ServiceAccountTokenProvider(
        "/fake/path.json", credentials=fake_creds, request_factory=lambda: "fake-request")
    assert provider() == "token-1"
    assert provider() == "token-1"  # still valid — no second refresh
    assert fake_creds._tokens == []


def test_service_account_token_provider_refreshes_when_expired():
    fake_creds = FakeCredentials(["token-1", "token-2"])
    provider = _ServiceAccountTokenProvider(
        "/fake/path.json", credentials=fake_creds, request_factory=lambda: "fake-request")
    assert provider() == "token-1"
    fake_creds.valid = False  # simulate the ~1hr token expiring
    assert provider() == "token-2"


def test_get_default_provider_respects_env():
    import os
    from app.pipeline.content_ai import FallbackProvider
    old = os.environ.get("SEG_CONTENT_PROVIDER")
    try:
        os.environ["SEG_CONTENT_PROVIDER"] = "glm"
        # When GLM is configured, get_default_provider() returns a FallbackProvider
        # whose primary slot is GLMProvider (with up to 4 fallbacks + HeuristicProvider).
        p = get_default_provider()
        assert isinstance(p, FallbackProvider), (
            f"Expected FallbackProvider when SEG_CONTENT_PROVIDER=glm, got {type(p)}"
        )
        assert any(isinstance(slot, GLMProvider) for slot in p._providers), (
            "FallbackProvider must have at least one GLMProvider slot"
        )
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
