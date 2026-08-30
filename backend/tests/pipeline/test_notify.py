"""Unit tests for quarantine notification gating. SMTP is mocked."""
from __future__ import annotations

from unittest import mock

from backend.models import PipelineResult, Verdict
from backend.notify import _threshold_met, send_quarantine_notification


def test_threshold_order():
    assert _threshold_met("SUSPICIOUS", "SUSPICIOUS")
    assert _threshold_met("MALICIOUS", "SUSPICIOUS")
    assert not _threshold_met("SUSPICIOUS", "MALICIOUS")
    assert not _threshold_met("CLEAN", "SUSPICIOUS")


def test_send_never_raises():
    send_quarantine_notification(b"not-even-an-email", PipelineResult())


def test_disabled_config_does_not_touch_smtp(monkeypatch):
    monkeypatch.setattr("backend.notify._load_config", lambda: {"enabled": False})
    with mock.patch("smtplib.SMTP") as smtp:
        send_quarantine_notification(
            b"From: a@b.com\r\nTo: victim@pdax.ph\r\n\r\nbody\r\n",
            PipelineResult(verdict=Verdict.MALICIOUS, subject="x", from_header="a@b.com"),
        )
        smtp.assert_not_called()


def test_enabled_sends_via_smtp(monkeypatch):
    monkeypatch.setattr(
        "backend.notify._load_config",
        lambda: {
            "enabled": True,
            "threshold": "SUSPICIOUS",
            "smtp_host": "smtp.example",
            "smtp_port": 587,
            "smtp_user": "segs",
            "from_addr": "segs@pdax.ph",
        },
    )
    monkeypatch.setenv("SEGS_NOTIFY_SMTP_PASS", "secret")
    raw = (
        b"From: phish@evil.example\r\n"
        b"To: victim@pdax.ph\r\n"
        b"Subject: hold me\r\n\r\n"
        b"body\r\n"
    )
    result = PipelineResult(
        verdict=Verdict.SUSPICIOUS,
        subject="hold me",
        from_header="phish@evil.example",
        composite_score=50,
        reasons=["lookalike_of:pdax.ph"],
    )
    fake = mock.MagicMock()
    fake.__enter__.return_value = fake
    fake.__exit__.return_value = False
    with mock.patch("smtplib.SMTP", return_value=fake) as smtp:
        send_quarantine_notification(raw, result)
    smtp.assert_called_once()
    fake.starttls.assert_called_once()
    fake.login.assert_called_once()
    fake.sendmail.assert_called_once()
