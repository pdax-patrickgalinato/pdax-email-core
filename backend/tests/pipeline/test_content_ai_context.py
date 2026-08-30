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

from workers.pipeline.content_ai import (
    BedrockProvider, GeminiProvider, GLMProvider, HeuristicProvider, _summarize_context,
)

# --- _summarize_context() directly ------------------------------------------

def test_empty_context_gives_no_findings_message():
    assert _summarize_context({}) == "No notable findings from the other deterministic stages."
    assert _summarize_context(None) == "No notable findings from the other deterministic stages."


def test_feedback_training_summarized():
    summary = _summarize_context({
        "feedback": {
            "benign_sender": True,
            "benign_domain": True,
            "benign_url_hosts": ["zoom.us"],
        }
    })
    assert "Analyst training" in summary
    assert "not-malicious" in summary
    assert "zoom.us" in summary

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

def test_thread_headers_surfaced_as_facts_not_verdict():
    summary = _summarize_context({
        "raw_headers": {"in_reply_to": "<mid@example.com>", "references": "<mid@example.com>"},
    })
    assert "In-Reply-To present" in summary
    assert "References present" in summary
    assert "facts only" in summary


def test_conversation_thread_transcript_summarized():
    summary = _summarize_context({
        "thread": {
            "count": 2,
            "transcript": "[1] From: a@pdax.ph  Subject: Invoice\n    Please pay.\n"
                          "[2] CURRENT MESSAGE — score this turn",
        }
    })
    assert "Conversation thread (2 messages" in summary
    assert "a@pdax.ph" in summary
    assert "score the Subject/Body above as the current turn" in summary

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


# --- organizational context notes reach the system prompt --------------------

def test_system_prompt_omits_org_context_when_no_notes(tmp_path, monkeypatch):
    from backend.stores import org_config
    from workers.pipeline import content_ai

    p = tmp_path / "org.yaml"
    p.write_text("organization:\n  display_name: PDAX\n  regulator_context: a BSP-regulated crypto exchange\n")
    monkeypatch.setattr(org_config, "_ORG_PATH", p)
    prompt = content_ai._system_prompt()
    assert "You are an email threat analyst for PDAX, a BSP-regulated crypto exchange." in prompt
    assert "Organizational context" not in prompt


def test_system_prompt_includes_org_context_notes(tmp_path, monkeypatch):
    from backend.stores import org_config
    from workers.pipeline import content_ai

    p = tmp_path / "org.yaml"
    p.write_text(
        "organization:\n"
        "  display_name: PDAX\n"
        "  regulator_context: a BSP-regulated crypto exchange\n"
        "  context_notes:\n"
        "    - support@pdax.ph is the customer-support inbox where clients raise concerns\n"
        "    - PDAX is a Philippine-based crypto exchange\n"
    )
    monkeypatch.setattr(org_config, "_ORG_PATH", p)
    prompt = content_ai._system_prompt()
    assert "Organizational context" in prompt
    assert "support@pdax.ph is the customer-support inbox where clients raise concerns" in prompt
    assert "PDAX is a Philippine-based crypto exchange" in prompt
    assert "do not override deterministic findings" in prompt


def test_bedrock_system_prompt_includes_org_context(tmp_path, monkeypatch):
    from backend.stores import org_config

    p = tmp_path / "org.yaml"
    p.write_text(
        "organization:\n"
        "  display_name: PDAX\n"
        "  context_notes:\n"
        "    - support@pdax.ph is the customer-support inbox\n"
    )
    monkeypatch.setattr(org_config, "_ORG_PATH", p)
    client = _FakeBedrockClient(_bedrock_tool_response(10, [], "ok"))
    BedrockProvider(client=client).analyze("subject", "body", {})
    system_text = client.calls[0]["system"][0]["text"]
    assert "support@pdax.ph is the customer-support inbox" in system_text


def test_system_prompt_live_reloads_after_note_added(tmp_path, monkeypatch):
    from backend.stores import org_config
    from workers.pipeline import content_ai

    p = tmp_path / "org.yaml"
    p.write_text("organization:\n  display_name: PDAX\n")
    monkeypatch.setattr(org_config, "_ORG_PATH", p)
    assert "support@pdax.ph is the customer-support inbox" not in content_ai._system_prompt()
    org_config.add_context_note("support@pdax.ph is the customer-support inbox")
    assert "support@pdax.ph is the customer-support inbox" in content_ai._system_prompt()


def test_auth_pass_summarized_for_the_model():
    summary = _summarize_context({
        "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
    })
    assert "authentication passed" in summary
    assert "SPF=pass" in summary
    assert "DKIM=pass" in summary


def test_system_prompt_includes_fp_scoring_calibration():
    from workers.pipeline import content_ai
    prompt = content_ai._system_prompt()
    assert "false-positive control" in prompt
    assert "Keep score below 40" in prompt


def test_padding_ignored_in_quoted_history():
    body = "Thanks for the update.\n\nOn Mon, 1 Jan 2026 wrote:\n" + ("\n" * 20) + "old thread"
    _, findings, _ = HeuristicProvider().analyze("Status", body, {})
    assert "content_padding_evasion" not in findings


def test_padding_flagged_in_unquoted_primary_body():
    body = "Please review.\n" + ("\n" * 20) + "click the link to verify"
    _, findings, _ = HeuristicProvider().analyze("Status", body, {})
    assert "content_padding_evasion" in findings


def test_fake_reply_prefix_not_flagged_when_thread_headers_present():
    context = {"raw_headers": {"in_reply_to": "<mid@example.com>"}}
    _, findings, _ = HeuristicProvider().analyze("Re: invoice", "see below", context)
    assert "fake_reply_prefix" not in findings


def test_calibrate_strips_fake_reply_and_caps_soft_llm_score():
    from email.mime.text import MIMEText
    from backend.parsed_email import ParsedEmail
    from workers.pipeline import content_ai

    class _Inflated:
        def analyze(self, subject, body, context):
            return 62.0, [
                "brand_impersonation", "unusual_request", "fake_reply_prefix",
            ], {
                "provider": "glm",
                "nlu_intent": "credential_theft",
                "nlu_confidence": 0.91,
                "summary": "Google impersonation",
            }

    msg = MIMEText("Your JumpCloud weekly digest.")
    msg["From"] = "noreply@jumpcloud.com"
    msg["To"] = "me@pdax.ph"
    msg["Subject"] = "Re: Weekly digest"
    msg["Message-ID"] = "<id@mail.gmail.com>"
    pe = ParsedEmail(msg.as_bytes())
    context = {
        "headers": {"spf": "pass", "dkim": "pass"},
        "raw_headers": {"in_reply_to": "<prev@mail.gmail.com>"},
    }
    result = content_ai.run(pe, _Inflated(), context)
    assert "fake_reply_prefix" not in result.red_flags
    assert result.sub_score == 40.0
    assert result.facts.get("score_capped") is True


def test_calibrate_does_not_cap_hard_bec_content():
    from email.mime.text import MIMEText
    from backend.parsed_email import ParsedEmail
    from workers.pipeline import content_ai

    class _Bec:
        def analyze(self, subject, body, context):
            return 70.0, ["bec_pattern", "nlu_intent:bec"], {
                "provider": "glm", "nlu_intent": "bec", "nlu_confidence": 0.9,
            }

    msg = MIMEText("Please buy gift cards and send the codes.")
    msg["From"] = "ceo@evil.example"
    msg["To"] = "me@pdax.ph"
    msg["Subject"] = "urgent"
    pe = ParsedEmail(msg.as_bytes())
    result = content_ai.run(pe, _Bec(), {"headers": {"spf": "none"}})
    assert result.sub_score == 70.0
    assert result.facts.get("score_capped") is not True


def test_calibrate_does_not_cap_when_other_stages_corroborate():
    from email.mime.text import MIMEText
    from backend.parsed_email import ParsedEmail
    from workers.pipeline import content_ai

    class _Soft:
        def analyze(self, subject, body, context):
            return 62.0, ["brand_impersonation", "unusual_request"], {
                "provider": "glm",
            }

    msg = MIMEText("Please verify your account.")
    msg["From"] = "it@evil.example"
    msg["To"] = "me@pdax.ph"
    msg["Subject"] = "IT"
    pe = ParsedEmail(msg.as_bytes())
    result = content_ai.run(pe, _Soft(), {"headers": {"spf": "fail"}})
    assert result.sub_score == 62.0
    assert result.facts.get("score_capped") is not True


