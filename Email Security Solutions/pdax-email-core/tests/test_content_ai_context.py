"""Unit tests for Phase 7 (AI-Assisted Holistic Analysis) of the TMES
policy-parity plan: content_ai._summarize_context(), HeuristicProvider's new
free summary, and confirming the enriched context actually reaches the
constructed prompt for every real provider (previously `context` was
threaded through but silently dropped — see content_ai.py's module
docstring). All provider calls are mocked; nothing here touches a real API.

Run: python3 -m pytest tests/test_content_ai_context.py
     (or python3 tests/test_content_ai_context.py)
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pipeline.content_ai import (
    BedrockProvider, GeminiProvider, GLMProvider, HeuristicProvider, _summarize_context,
)

# --- _summarize_context() directly ------------------------------------------

def test_empty_context_gives_no_findings_message():
    assert _summarize_context({}) == "No notable findings from the other deterministic stages."
    assert _summarize_context(None) == "No notable findings from the other deterministic stages."


def test_headers_auth_failures_summarized():
    context = {"headers": {"spf": "fail", "dkim": "fail", "dmarc": "fail",
                           "return_path_mismatch": True, "reply_to_divergent": True}}
    summary = _summarize_context(context)
    assert "SPF=fail" in summary
    assert "DKIM=fail" in summary
    assert "DMARC=fail" in summary
    assert "Return-Path domain mismatch" in summary
    assert "Reply-To diverges" in summary


def test_bulk_mail_signal_summarized():
    context = {"headers": {"precedence_bulk": True, "has_list_unsubscribe": False}}
    assert "presents as bulk mail" in _summarize_context(context)
    assert "missing List-Unsubscribe" in _summarize_context(context)


def test_sender_findings_summarized():
    context = {"sender": {"lookalike_of": "pdax.ph", "vip_name_spoof": "CEO",
                          "domain_age_days": 3}}
    summary = _summarize_context(context)
    assert "lookalike of protected domain 'pdax.ph'" in summary
    assert "spoofs watched VIP name 'CEO'" in summary
    assert "registered 3 day(s) ago" in summary


def test_attachment_forensics_summarized():
    context = {"attachments": {"attachments": [
        {"filename": "invoice.exe", "forensics": {"static_severity": "HIGH",
                                                   "risk_flags": ["executable_content"]}},
    ]}}
    summary = _summarize_context(context)
    assert "invoice.exe: static severity HIGH" in summary
    assert "executable_content" in summary


def test_intel_hits_summarized():
    context = {"intel": {"hits": ["intel_domain:evil.example"],
                         "correlation_hits": ["correlation_seen_before:evil.example:2"]}}
    summary = _summarize_context(context)
    assert "external threat-intel hit(s): intel_domain:evil.example" in summary
    assert "seen in prior flagged mail" in summary


def test_non_dict_context_degrades_gracefully():
    assert _summarize_context("not a dict") == "No notable findings from the other deterministic stages."
    assert _summarize_context(123) == "No notable findings from the other deterministic stages."


# --- HeuristicProvider's free summary ---------------------------------------

def test_heuristic_provider_summary_reflects_findings_and_context():
    provider = HeuristicProvider()
    context = {"sender": {"lookalike_of": "pdax.ph"}}
    score, findings, facts = provider.analyze("urgent payment", "wire transfer now", context)
    assert "bec_pattern" in facts["summary"]
    assert "lookalike of protected domain 'pdax.ph'" in facts["summary"]


def test_heuristic_provider_summary_no_findings():
    provider = HeuristicProvider()
    score, findings, facts = provider.analyze("hi", "just checking in", {})
    assert "none" in facts["summary"]
    assert "No notable findings" in facts["summary"]


# --- context reaches the constructed prompt: Bedrock + GLM -------------------
# (Ollama and Gemini variants covered in their own dedicated test files —
# this file focuses on _summarize_context() plus one representative check
# per remaining provider shape: Bedrock's Converse "messages" list, and
# GLM's chat "messages" list.)

class _FakeBedrockClient:
    def __init__(self, response):
        self._response = response
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return self._response


def _bedrock_tool_response(score, findings, summary):
    return {"output": {"message": {"content": [{"toolUse": {
        "name": "emit_phishing_content_analysis",
        "input": {"score": score, "findings": findings, "summary": summary},
    }}]}}}


def test_bedrock_context_reaches_prompt():
    client = _FakeBedrockClient(_bedrock_tool_response(10, [], "ok"))
    provider = BedrockProvider(client=client)
    context = {"intel": {"hits": ["intel_domain:evil.example"]}}
    provider.analyze("subject", "body", context)
    sent_text = client.calls[0]["messages"][0]["content"][0]["text"]
    assert "Deterministic findings from other stages" in sent_text
    assert "intel_domain:evil.example" in sent_text


class _GeminiFakeResponse:
    def __init__(self, payload):
        self.text = json.dumps(payload)


class _GeminiFakeModels:
    def __init__(self, response):
        self._response = response
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        return self._response


class _GeminiFakeClient:
    def __init__(self, response):
        self.models = _GeminiFakeModels(response)


def test_gemini_context_reaches_prompt():
    client = _GeminiFakeClient(_GeminiFakeResponse({"score": 10, "findings": [], "summary": "ok"}))
    provider = GeminiProvider(client=client)
    context = {"sender": {"vip_name_spoof": "CEO"}}
    provider.analyze("subject", "body", context)
    sent_text = client.models.calls[0]["contents"][0]["parts"][0]["text"]
    assert "Deterministic findings from other stages" in sent_text
    assert "spoofs watched VIP name 'CEO'" in sent_text


class _GLMFakeMessage:
    def __init__(self, content):
        self.content = content


class _GLMFakeChoice:
    def __init__(self, content):
        self.message = _GLMFakeMessage(content)


class _GLMFakeResponse:
    def __init__(self, payload):
        self.choices = [_GLMFakeChoice(json.dumps(payload))]


class _GLMFakeCompletions:
    def __init__(self, response):
        self._response = response
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._response


class _GLMFakeChat:
    def __init__(self, response):
        self.completions = _GLMFakeCompletions(response)


class _GLMFakeClient:
    def __init__(self, response):
        self.chat = _GLMFakeChat(response)


def test_glm_context_reaches_prompt():
    client = _GLMFakeClient(_GLMFakeResponse({"score": 10, "findings": [], "summary": "ok"}))
    provider = GLMProvider(project_id="proj-1", client=client)
    context = {"attachments": {"attachments": [
        {"filename": "bad.exe", "forensics": {"static_severity": "HIGH", "risk_flags": ["executable_content"]}},
    ]}}
    provider.analyze("subject", "body", context)
    sent_messages = client.chat.completions.calls[0]["messages"]
    user_message = next(m["content"] for m in sent_messages if m["role"] == "user")
    assert "Deterministic findings from other stages" in user_message
    assert "bad.exe: static severity HIGH" in user_message


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
