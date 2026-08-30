"""Unit tests for workers/pipeline/sandbox.py (Virtual Analyzer interface stub —
TMES policy parity) and its wiring into attachments.py. No real detonation
exists yet — these tests confirm the interface is honest about that and has
zero observable effect on scoring/verdict either way.

Run: python3 -m pytest tests/test_sandbox.py  (or python3 tests/test_sandbox.py)
"""
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from backend.parsed_email import ParsedEmail
from workers.pipeline import attachments, policy, sandbox

def _eml_with_attachment(filename, payload):
    msg = MIMEMultipart()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@pdax.ph"
    msg["Subject"] = "see attached"
    msg["Message-ID"] = "<test@example.com>"
    msg.attach(MIMEText("See attached.", "plain"))
    part = MIMEApplication(payload, _subtype="octet-stream")
    part.add_header("Content-Disposition", "attachment", filename=filename)
    msg.attach(part)
    return ParsedEmail(msg.as_bytes())

# --- sandbox.py directly ------------------------------------------------------

def test_null_provider_always_degraded_zero():
    provider = sandbox.NullSandboxProvider()
    score, findings, facts = provider.detonate("a.exe", "application/octet-stream", b"MZ")
    assert score == 0.0
    assert findings == []
    assert facts["provider"] == "null_sandbox"

def test_default_provider_is_null():
    assert isinstance(sandbox.get_default_sandbox_provider(), sandbox.NullSandboxProvider)

def test_unrecognized_env_choice_falls_back_to_null():
    import os
    old = os.environ.get("SEG_SANDBOX_PROVIDER")
    try:
        os.environ["SEG_SANDBOX_PROVIDER"] = "some_future_vendor"
        assert isinstance(sandbox.get_default_sandbox_provider(), sandbox.NullSandboxProvider)
    finally:
        if old is None:
            os.environ.pop("SEG_SANDBOX_PROVIDER", None)
        else:
            os.environ["SEG_SANDBOX_PROVIDER"] = old

# --- attachments.py wiring -----------------------------------------------------

def test_virtual_analyzer_disabled_never_calls_provider():
    calls = []
    class RecordingProvider:
        def detonate(self, filename, content_type, payload):
            calls.append(filename)
            return 0.0, [], {}
    pe = _eml_with_attachment("payload.bin", b"data")
    cfg = {"categories": {"virtual_analyzer": {"enabled": False}}}
    attachments.run(pe, policy_cfg=cfg, sandbox_provider=RecordingProvider())
    assert calls == []   # never invoked — the whole point of gating at call time

def test_virtual_analyzer_enabled_calls_provider_per_attachment():
    calls = []
    class RecordingProvider:
        def detonate(self, filename, content_type, payload):
            calls.append(filename)
            return 0.0, [], {}
    pe = _eml_with_attachment("payload.bin", b"data")
    cfg = {"categories": {"virtual_analyzer": {"enabled": True}}}
    attachments.run(pe, policy_cfg=cfg, sandbox_provider=RecordingProvider())
    assert calls == ["payload.bin"]

def test_default_null_sandbox_has_zero_effect_enabled_or_disabled():
    pe_a = _eml_with_attachment("clean.txt", b"hello world")
    pe_b = _eml_with_attachment("clean.txt", b"hello world")
    on_cfg = {"categories": {"virtual_analyzer": {"enabled": True}}}
    off_cfg = {"categories": {"virtual_analyzer": {"enabled": False}}}
    result_on = attachments.run(pe_a, policy_cfg=on_cfg)
    result_off = attachments.run(pe_b, policy_cfg=off_cfg)
    assert result_on.sub_score == result_off.sub_score
    assert result_on.red_flags == result_off.red_flags

def test_sandbox_flag_category_is_virtual_analyzer():
    assert policy.category_for_flag("sandbox_malware_detected") == "virtual_analyzer"

