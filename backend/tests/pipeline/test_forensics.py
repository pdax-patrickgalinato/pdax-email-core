"""Unit tests for the offline attachment/URL static forensics.

Run: python3 -m pytest tests/test_forensics.py  (or python3 tests/test_forensics.py)

Every input is synthesized in-memory — no real malware, no network, no disk.
"""
import io
import zipfile

from workers.pipeline import attachment_forensics as af
from workers.pipeline import url_forensics as uf

# ---------------------------------------------------------------- attachments
def test_executable_disguised_as_image():
    pe = b"MZ\x90\x00" + b"\x00" * 128
    r = af.analyze_attachment("invoice.png", "image/png", pe)
    assert r["detected_type"] == "dos_pe_executable"
    assert r["type_mismatch"] is True
    assert "executable_content" in r["risk_flags"]
    assert r["static_severity"] == "HIGH"

def test_banned_extension():
    r = af.analyze_attachment("update.exe", "application/octet-stream", b"MZ\x00")
    assert "dangerous_extension" in r["risk_flags"]
    assert "executable_content" in r["risk_flags"]

def test_double_extension():
    r = af.analyze_attachment("statement.pdf.exe", "application/octet-stream", b"MZ\x00")
    assert "double_extension_executable" in r["risk_flags"]

def test_encrypted_zip_with_executable():
    buf = io.BytesIO()
    zf = zipfile.ZipFile(buf, "w")
    zf.writestr("payload.exe", b"MZfakebody")
    zf.infolist()[-1].flag_bits |= 0x1  # mark entry encrypted
    zf.close()
    r = af.analyze_attachment("docs.zip", "application/zip", buf.getvalue())
    assert "encrypted_archive" in r["risk_flags"]
    assert "archive_contains_executable" in r["risk_flags"]
    assert r["static_severity"] == "HIGH"

def test_ooxml_macro_detection():
    buf = io.BytesIO()
    zf = zipfile.ZipFile(buf, "w")
    zf.writestr("[Content_Types].xml", "<Types/>")
    zf.writestr("word/vbaProject.bin", b"\x00\x01\x02")
    zf.close()
    r = af.analyze_attachment("report.docm", "application/vnd.ms-word.document.macroEnabled.12", buf.getvalue())
    assert "office_macro" in r["risk_flags"]
    assert r["findings"]["office_macro"]["source"] == "ooxml_vbaproject"

def test_pdf_active_content_and_embedded_url():
    pdf = b"%PDF-1.7\n1 0 obj<</OpenAction<</S/JavaScript/JS(app.alert\\(1\\))>>>>\n/URI (http://evil.example/x)\n"
    r = af.analyze_attachment("statement.pdf", "application/pdf", pdf)
    active = r["findings"]["pdf"]["active_content"]
    assert "pdf_javascript" in active and "pdf_openaction" in active
    assert "pdf_auto_executing_action" in r["risk_flags"]
    assert "http://evil.example/x" in r["embedded_urls"]

def test_html_credential_form():
    html = b"<html><body><form><input type=\"password\" name=p></form></body></html>"
    r = af.analyze_attachment("login.html", "text/html", html)
    assert "html_credential_form" in r["risk_flags"]

def test_benign_png_is_low():
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    r = af.analyze_attachment("logo.png", "image/png", png)
    assert r["type_mismatch"] is False
    assert r["static_severity"] in ("NONE", "LOW")

def test_forensics_never_raises_on_garbage():
    r = af.analyze_attachment("weird.bin", "application/octet-stream", b"\xff" * 500)
    assert "sha256" in r  # returned a fact sheet rather than raising

# ----------------------------------------------------------------------- urls
def test_unwrap_trendmicro_clicktime():
    w = ("https://ddec1-0-en-ctp.trendmicro.com:443/wis/clicktime/v1/query"
         "?url=https%3a%2f%2fsecure-login.account-verify.top%2fportal&umid=x&auth=y")
    info = uf.analyze_url(w)
    assert info["unwrapped_url"] == "https://secure-login.account-verify.top/portal"
    assert info["registrable_domain"] == "account-verify.top"
    assert info["gateway_wrapped"] is True
    assert "risky_tld:top" in info["flags"]

def test_unwrap_safelinks():
    w = ("https://nam.safelinks.protection.outlook.com/?url=https%3A%2F%2Fbad.example%2Fa"
         "&data=05%7C01")
    info = uf.analyze_url(w)
    assert info["registrable_domain"] == "bad.example"

def test_ip_literal_and_credential():
    info = uf.analyze_url("http://user:pass@185.220.101.47/login")
    assert "ip_literal_host" in info["flags"]
    assert "credential_in_url" in info["flags"]

def test_punycode():
    info = uf.analyze_url("https://xn--pypal-4ve.com/verify")
    assert "idn_punycode" in info["flags"]

def test_display_target_mismatch():
    info = uf.analyze_url("https://evil-track.top/collect", display_text="www.paypal.com")
    assert info["display_target_mismatch"] is True
    assert "display_target_mismatch" in info["flags"]

def test_anchor_mismatch_from_html():
    html = '<a href="https://evil-track.top/go">Sign in to Microsoft</a>'
    links = uf.build_link_analysis("", html)
    assert links and links[0]["registrable_domain"] == "evil-track.top"

def test_image_hyperlink_detected():
    html = '<a href="https://myphotos.s.gy/x.png"><img src="cid:ii" alt="shot"></a>'
    links = uf.build_link_analysis("", html)
    assert links and links[0].get("wraps_image") is True
    assert "image_hyperlink" in links[0]["flags"]
    # Plaintext Gmail form
    text = '[image: photo.png] <https://myphotos.s.gy/photo.png>'
    links2 = uf.build_link_analysis(text, "")
    assert any(l.get("wraps_image") for l in links2)

def test_signature_style_text_link_does_not_imply_image_wrap():
    html = '<a href="https://www.linkedin.com/in/x">LinkedIn</a>'
    links = uf.build_link_analysis("", html)
    assert links and links[0].get("wraps_image") is False

