"""Unit tests for email_forensic_playbook.py v2.0 (deterministic playbook scorer).

Run: python3 -m pytest tests/test_playbook.py  (or python3 tests/test_playbook.py)
Offline; no network, no LLM.
"""

from cli import email_forensic_playbook as pb

# ----------------------------------------------------------- core scorer
def test_authors_example_scores_critical_phishing():
    email = {
        "body": "Hello customer service, I encountered an error. See screenshot: "
                "https://psce.pw/image157#image.png",
        "headers": {"dkim": "fail", "arc": "fail"},
        "attachments": [{"filename": "photo_2026-05-28_21-33-01.jpg", "size_kb": 7.6, "mime": "image/jpeg"}],
    }
    r = pb.analyze_email(email)
    assert r["score"] >= 100
    assert r["risk_band"] == "CRITICAL"
    assert "Phishing" in r["verdict"]
    assert any("URL shortener" in f for f in r["findings"])
    assert any("Image too small" in f for f in r["findings"])

def test_shortener_exact_match_no_false_positive():
    # substring "t.co" must NOT match microsoft.com / hostpilot.com
    assert pb.analyze_url("https://microsoft.com/a")[0] == 0
    assert pb.analyze_url("https://rw-china.hostpilot.com/a")[0] == 0
    assert "URL shortener used" in pb.analyze_url("https://bit.ly/x")[1]
    assert "URL shortener used" in pb.analyze_url("https://psce.pw/image1#a.png")[1]
    assert "URL shortener used" in pb.analyze_url("https://cutt.ly/abc")[1]

def test_fragment_and_keyword_scoring():
    score, findings = pb.analyze_url("https://good.example/verify#section")
    assert "Fragment used (possible disguise)" in findings
    assert "Suspicious keyword in URL path/query" in findings
    assert score >= 20

def test_classify_thresholds():
    assert pb.risk_band(0) == "LOW"
    assert pb.risk_band(30) == "LOW"
    assert pb.risk_band(31) == "MEDIUM"
    assert pb.risk_band(61) == "HIGH"
    assert pb.risk_band(100) == "CRITICAL"
    assert "Legitimate" in pb.classify(10)
    assert "Suspicious" in pb.classify(40)
    assert "Phishing" in pb.classify(70)
    assert "Malware Delivery" in pb.classify(110, malware_signals=True)

def test_critical_executable_and_macro_types():
    s, f, mal = pb.analyze_attachment({"filename": "a.exe", "size_kb": 10, "mime": "application/octet-stream"})
    assert mal and s >= 20 and any("executable" in x.lower() for x in f)
    s, f, mal = pb.analyze_attachment({"filename": "r.docm", "size_kb": 80, "mime": "application/vnd.ms-word.document.macroEnabled.12"})
    assert mal and s >= 30 and any("Macro" in x for x in f)
    s, f, mal = pb.analyze_attachment({"filename": "d.zip", "size_kb": 40, "mime": "application/zip"})
    assert any("Archive" in x for x in f)

# ----------------------------------------------------------- auth parsing
def test_dmarc_fail_is_not_arc_fail():
    parsed = {"auth_headers_raw": {"authentication_results": "spf=pass dkim=pass dmarc=fail"}}
    h = pb._auth_from_parsed(parsed)
    assert h.get("dkim") == "pass"
    assert h.get("dmarc") == "fail"
    assert "arc" not in h

def test_real_arc_fail_detected():
    parsed = {"auth_headers_raw": {"arc_authentication_results": "i=1; arc=fail (body hash mismatch)"}}
    assert pb._auth_from_parsed(parsed).get("arc") == "fail"

def test_spf_fail_from_received_spf():
    parsed = {"auth_headers_raw": {"received_spf": "Fail (domain of x does not designate)"}}
    assert pb._auth_from_parsed(parsed).get("spf") == "fail"

# ----------------------------------------------------------- adapter / magic bytes
def _forensic(**kw):
    base = {"filename": "f", "declared_content_type": "", "declared_extension": "",
            "detected_type": "", "detected_category": "", "size_bytes": 1000,
            "type_mismatch": False, "risk_flags": [], "is_inline": False}
    base.update(kw)
    return base

def test_run_playbook_unwraps_and_scores_shortener():
    parsed = {
        "metadata": {"subject": "See screenshot"},
        "text_body": "please view",
        "auth_headers_raw": {},
        "attachment_forensics": [_forensic(filename="x.jpg", detected_category="image",
                                           declared_content_type="image/jpeg", size_bytes=5000)],
        "link_analysis": [{"unwrapped_url": "https://psce.pw/image9#a.png", "raw_url": "https://gw/",
                           "flags": ["url_shortener", "risky_tld:pw"], "registrable_domain": "psce.pw"}],
    }
    r = pb.run_playbook(parsed)
    assert any("URL shortener used" in f for f in r["findings"])
    assert r["actions"]

def test_disguised_executable_scores_malware():
    parsed = {
        "metadata": {"subject": "invoice"},
        "text_body": "see attached",
        "auth_headers_raw": {},
        "attachment_forensics": [_forensic(filename="invoice.png", declared_extension="png",
                                           detected_category="executable", detected_type="dos_pe_executable",
                                           type_mismatch=True, risk_flags=["executable_content", "type_mismatch"])],
        "link_analysis": [],
    }
    r = pb.run_playbook(parsed)
    assert any("mismatch" in f.lower() or "executable" in f.lower() for f in r["findings"])
    assert r["score"] >= 40
    assert r.get("malware_signals") or "Malware" in r["verdict"] or r["score"] >= 40

def test_archive_with_executable():
    parsed = {
        "metadata": {"subject": "docs"},
        "text_body": "",
        "auth_headers_raw": {},
        "attachment_forensics": [_forensic(filename="image.zip", declared_extension="zip",
                                           detected_category="archive",
                                           risk_flags=["archive_contains_executable"])],
        "link_analysis": [],
    }
    r = pb.run_playbook(parsed)
    assert any("Archive contains executable" in f for f in r["findings"])
    assert r["malware_signals"] is True

def test_inline_logo_not_scored_as_lure_but_real_attachment_is():
    inline = _forensic(filename="logo.png", detected_category="image",
                       declared_content_type="image/png", size_bytes=6000, is_inline=True)
    real = _forensic(filename="photo_x.jpg", detected_category="image",
                     declared_content_type="image/jpeg", size_bytes=6000, is_inline=False)
    base = {"metadata": {"subject": "s"}, "text_body": "", "auth_headers_raw": {}, "link_analysis": []}

    r_inline = pb.run_playbook(dict(base, attachment_forensics=[inline]))
    assert not any("Image too small" in f for f in r_inline["findings"])

    r_real = pb.run_playbook(dict(base, attachment_forensics=[real]))
    assert any("Image too small" in f for f in r_real["findings"])

def test_image_link_lure_raises_for_offbrand_file_host():
    """Screenshot-style image wrapping s.gy + SE context → lure score."""
    parsed = {
        "metadata": {
            "subject": "I can't register — error",
            "from": "evil@gmail.com",
            "to": ["support@pdax.ph"],
        },
        "text_body": "I keep getting an error during registration.\n"
                     "[image: photo.png] <https://myphotos.s.gy/photo.png>",
        "auth_headers_raw": {},
        "attachment_forensics": [_forensic(
            filename="image", detected_category="image", declared_extension="",
            declared_content_type="image/png", size_bytes=6000, is_inline=True)],
        "link_analysis": [{
            "unwrapped_url": "https://myphotos.s.gy/photo.png",
            "raw_url": "https://myphotos.s.gy/photo.png",
            "registrable_domain": "s.gy",
            "wraps_image": True,
            "flags": ["image_hyperlink", "url_shortener"],
        }],
    }
    r = pb.run_playbook(parsed)
    assert any("Image linked to off-brand" in f for f in r["findings"])
    assert r["score"] >= 25 + 25  # SE + image-link lure at minimum

def test_signature_logo_to_linkedin_not_flagged():
    parsed = {
        "metadata": {
            "subject": "Re: meeting notes",
            "from": "alice@acme.com",
            "to": ["bob@pdax.ph"],
        },
        "text_body": "Thanks, see you tomorrow.\nAlice",
        "auth_headers_raw": {},
        "attachment_forensics": [_forensic(
            filename="linkedin.png", detected_category="image",
            declared_content_type="image/png", size_bytes=4000, is_inline=True)],
        "link_analysis": [{
            "unwrapped_url": "https://www.linkedin.com/in/alice",
            "registrable_domain": "linkedin.com",
            "wraps_image": True,
            "flags": ["image_hyperlink"],
        }],
    }
    r = pb.run_playbook(parsed)
    assert not any("Image linked to off-brand" in f for f in r["findings"])

def test_signature_logo_to_sender_domain_not_flagged():
    parsed = {
        "metadata": {
            "subject": "Hello",
            "from": "sales@acme.com",
            "to": ["support@pdax.ph"],
        },
        "text_body": "Best regards",
        "auth_headers_raw": {},
        "attachment_forensics": [_forensic(
            filename="logo.png", detected_category="image",
            declared_content_type="image/png", size_bytes=8000, is_inline=True)],
        "link_analysis": [{
            "unwrapped_url": "https://www.acme.com/",
            "registrable_domain": "acme.com",
            "wraps_image": True,
            "flags": ["image_hyperlink"],
        }],
    }
    r = pb.run_playbook(parsed)
    assert not any("Image linked to off-brand" in f for f in r["findings"])

def test_offbrand_image_link_without_amplifier_not_flagged():
    """Partner site behind a logo, no SE / shortener / bait name — leave alone."""
    parsed = {
        "metadata": {
            "subject": "Intro",
            "from": "a@acme.com",
            "to": ["b@pdax.ph"],
        },
        "text_body": "Nice to meet you.",
        "auth_headers_raw": {},
        "attachment_forensics": [_forensic(
            filename="logo.png", detected_category="image",
            declared_content_type="image/png", size_bytes=12000, is_inline=True)],
        "link_analysis": [{
            "unwrapped_url": "https://partner-example.org/about",
            "registrable_domain": "partner-example.org",
            "wraps_image": True,
            "flags": ["image_hyperlink"],
        }],
    }
    r = pb.run_playbook(parsed)
    assert not any("Image linked to off-brand" in f for f in r["findings"])

