"""Unit tests for attacker-controlled header sanitization in reports."""
from __future__ import annotations

from backend.report import _sanitize, _slack_escape


def test_sanitize_strips_ansi_and_newlines():
    raw = "hi\x1b[0m\r\nVERDICT: CLEAN"
    out = _sanitize(raw)
    assert "\x1b" not in out
    assert "\n" not in out
    assert "\r" not in out
    assert "VERDICT: CLEAN" in out


def test_sanitize_empty():
    assert _sanitize("") == ""
    assert _sanitize(None) == ""


def test_slack_escape_blocks_channel_mention():
    assert _slack_escape("<!channel>") == "&lt;!channel&gt;"
    assert "&amp;" in _slack_escape("A & B")
    assert _slack_escape("plain") == "plain"
