"""Unit tests for app/landing_fetch.py — SSRF guards + mocked HTML fetch.

Never hits a real network. Run: python3 tests/test_landing_fetch.py
"""
from __future__ import annotations

import os
import socket

from workers.pipeline import landing_fetch

def test_url_allowed_blocks_localhost():
    ok, reason = landing_fetch.url_allowed("http://localhost/admin")
    assert ok is False
    assert "localhost" in reason or "private" in reason

def test_url_allowed_blocks_private_ip():
    ok, reason = landing_fetch.url_allowed("http://127.0.0.1/")
    assert ok is False
    ok2, _ = landing_fetch.url_allowed("http://10.0.0.5/phish")
    assert ok2 is False
    ok3, _ = landing_fetch.url_allowed("http://169.254.169.254/latest/meta-data/")
    assert ok3 is False

def test_url_allowed_blocks_non_http():
    ok, reason = landing_fetch.url_allowed("file:///etc/passwd")
    assert ok is False
    assert "scheme" in reason

def test_url_allowed_accepts_public_https():
    # Avoid live DNS in sandbox/CI — inject a public A record.
    from unittest import mock
    fake = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]
    with mock.patch("workers.pipeline.landing_fetch.socket.getaddrinfo", return_value=fake):
        ok, reason = landing_fetch.url_allowed("https://example.com/path")
    assert ok is True, reason

def test_fetch_one_ssrf_degrades_without_raising():
    out = landing_fetch.fetch_one("http://127.0.0.1/")
    assert out["degraded"] is True
    assert out["fetched"] is False
    assert out["error"]

def test_fetch_one_with_injected_opener_parses_form():
    html = b"""<!DOCTYPE html><html><head><title>Waverley Training Services PROPOSAL</title>
    <meta name="description" content="Intake form"></head>
    <body><form><input name="Full Name"><input name="Email Address" type="email">
    <input type="password" name="secret"></form>
    <script src="https://cdn.example.net/app.js"></script></body></html>"""

    def opener(url, timeout):
        return 200, "https://intakeq.com/c/eGfZaR", {}, html

    out = landing_fetch.fetch_one("https://example.com/start", opener=opener)
    assert out["fetched"] is True
    assert out["degraded"] is False
    assert "Waverley" in out["title"]
    assert "Full Name" in out["form_fields"]
    assert out["has_password_field"] is True
    assert "cdn.example.net" in out["script_hosts"]
    assert out["final_url"].endswith("/eGfZaR")

def test_analyze_urls_respects_flag_off():
    old = os.environ.pop("SEG_LANDING_FETCH", None)
    try:
        assert landing_fetch.analyze_urls(["https://example.com/a"]) == []
    finally:
        if old is not None:
            os.environ["SEG_LANDING_FETCH"] = old

def test_analyze_urls_with_opener_bypasses_flag():
    def opener(url, timeout):
        return 200, url, {}, b"<html><title>OK</title></html>"
    out = landing_fetch.analyze_urls(
        ["https://example.com/one", "https://example.com/two"], opener=opener)
    # Same registrable domain → only one fetch
    assert len(out) == 1
    assert out[0]["title"] == "OK"

def test_candidate_urls_prefers_mismatch():
    links = [
        {"unwrapped_url": "https://benign.example/x", "flags": [], "mismatch": False},
        {"unwrapped_url": "https://intakeq.com/c/abc", "flags": ["display_target_mismatch"],
         "mismatch": True},
    ]
    cands = landing_fetch.candidate_urls_from_link_analysis(links)
    assert cands[0].startswith("https://intakeq.com/")

