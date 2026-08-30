"""End-to-end tests for wiring app/attachment_forensics.py into the scored
pipeline (workers/pipeline/attachments.py::run()), as opposed to
tests/test_forensics.py which tests analyze_attachment() directly/in isolation.

Run: python3 -m pytest tests/test_attachments_wiring.py
     (or python3 tests/test_attachments_wiring.py)
"""
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from backend.models import Verdict
from backend.parsed_email import ParsedEmail
from workers.pipeline import attachments, runner

def _eml_with_attachment(filename, payload, content_type="application/octet-stream",
                         from_addr="sender@example.com", subject="see attached"):
    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = "recipient@pdax.ph"
    msg["Subject"] = subject
    msg["Message-ID"] = "<test-attachment@example.com>"
    msg.attach(MIMEText("Please see the attached file.", "plain"))
    maintype, _, subtype = content_type.partition("/")
    part = MIMEApplication(payload, _subtype=subtype or "octet-stream")
    part.add_header("Content-Disposition", "attachment", filename=filename)
    msg.attach(part)
    return msg.as_bytes()

def test_stage_flags_spoofed_executable_as_forensics_malware_scanning():
    raw = _eml_with_attachment("invoice.png", b"MZ\x90\x00" + b"\x00" * 128, "image/png")
    pe = ParsedEmail(raw)
    result = attachments.run(pe)
    assert any(f.startswith("forensics_") for f in result.red_flags)
    assert "forensics_executable_content" in result.red_flags
    # type_mismatch is remapped to spoofed_attachment_type:... (File Blocking,
    # Phase 2), not forensics_type_mismatch (Malware Scanning) — both fire
    # from the same underlying forensics finding.
    assert any(f.startswith("spoofed_attachment_type:") for f in result.red_flags)
    assert "forensics_type_mismatch" not in result.red_flags
    assert result.sub_score > 0
    assert result.facts["attachments"][0]["forensics"]["static_severity"] == "HIGH"

def test_stage_severity_points_come_from_weights_yaml():
    weights_cfg, *_ = runner.load_config()
    points = weights_cfg["forensics_severity_points"]
    raw = _eml_with_attachment("invoice.png", b"MZ\x90\x00" + b"\x00" * 128, "image/png")
    pe = ParsedEmail(raw)
    result = attachments.run(pe, points)
    assert result.sub_score >= points["HIGH"]

def test_stage_clean_attachment_no_forensics_flags():
    raw = _eml_with_attachment("photo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "image/png")
    pe = ParsedEmail(raw)
    result = attachments.run(pe)
    assert not any(f.startswith("forensics_") for f in result.red_flags)
    assert result.facts["attachments"][0]["forensics"]["static_severity"] == "NONE"

def test_embedded_pdf_url_feeds_iocs():
    pdf = (b"%PDF-1.4\n/OpenAction /JavaScript\n"
           b"/URI (https://evil-example.test/payload)\n" + b"\x00" * 64)
    raw = _eml_with_attachment("notice.pdf", pdf, "application/pdf")
    result = runner.run_pipeline(raw, source="test")
    assert "https://evil-example.test/payload" in result.iocs.urls

def test_e2e_renamed_executable_is_malicious():
    # invoice.pdf.exe shape: a benign-looking inner extension followed by a
    # dangerous outer one -> double_extension_executable -> File Blocking
    # hard override (Phase 2), even though "exe" itself would also already
    # be banned by extension alone here — the point is this path doesn't
    # depend on the declared extension being literally banned.
    raw = _eml_with_attachment("invoice.pdf.exe", b"MZ\x90\x00" + b"\x00" * 128,
                               "application/octet-stream")
    result = runner.run_pipeline(raw, source="test")
    assert result.verdict == Verdict.MALICIOUS
    assert result.hard_override in ("banned_attachment_type", "spoofed_or_double_extension_attachment")

def test_e2e_spoofed_type_mismatch_is_malicious_even_with_safe_extension():
    # A Windows PE executable disguised with a .png extension/content-type —
    # not in any banned-extension list, so only the magic-byte mismatch
    # (spoofed_attachment_type) can catch this.
    raw = _eml_with_attachment("photo.png", b"MZ\x90\x00" + b"\x00" * 128, "image/png")
    result = runner.run_pipeline(raw, source="test")
    assert result.hard_override == "spoofed_or_double_extension_attachment"
    assert result.verdict == Verdict.MALICIOUS

def test_e2e_file_blocking_disabled_suppresses_spoof_override():
    weights_cfg, protected, vips, _, banned_ext = runner.load_config()
    off_cfg = {"categories": {"file_blocking": {"enabled": False}}}
    raw = _eml_with_attachment("photo.png", b"MZ\x90\x00" + b"\x00" * 128, "image/png")
    result = runner.run_pipeline(raw, source="test",
                                 config=(weights_cfg, protected, vips, off_cfg, banned_ext))
    assert result.hard_override != "spoofed_or_double_extension_attachment"
    assert any(f.startswith("policy_suppressed:spoofed_attachment_type") for f in result.reasons)

def test_e2e_pdf_auto_executing_action_contributes_to_verdict():
    pdf = (b"%PDF-1.4\n/OpenAction /JavaScript\n" + b"\x00" * 64)
    raw = _eml_with_attachment("notice.pdf", pdf, "application/pdf")
    result = runner.run_pipeline(raw, source="test")
    atts_stage = result.stage("attachments")
    assert "forensics_pdf_auto_executing_action" in atts_stage.red_flags
    assert atts_stage.sub_score > 0
    # Not a hard override on its own (that's file_blocking/banned-extension
    # territory) — just confirms the weighted-composite path picked it up.
    assert result.composite_score > 0

