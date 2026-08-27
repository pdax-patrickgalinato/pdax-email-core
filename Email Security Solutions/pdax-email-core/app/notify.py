"""Quarantine receiver notification — sends a plain-text email to the original
recipient(s) when their email is held by SEGS for review.

Configuration is read from rules/notify_config.yaml at call time (no restart
needed to enable/disable). The SMTP password is read exclusively from the
SEGS_NOTIFY_SMTP_PASS environment variable — never stored in the YAML file.

Call send_quarantine_notification() after enforcement is applied. Failures are
logged to stderr and never re-raised — a broken SMTP server must never block
email processing.
"""
from __future__ import annotations

import os
import smtplib
import ssl
import textwrap
from email.mime.text import MIMEText
from email.utils import formatdate
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models import PipelineResult

_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
_CONFIG_FILE = _RULES_DIR / "notify_config.yaml"

_NOTIFY_VERDICTS = {"SUSPICIOUS", "MALICIOUS"}


def _load_config() -> dict:
    try:
        import yaml
        if _CONFIG_FILE.is_file():
            return yaml.safe_load(_CONFIG_FILE.read_text()) or {}
    except Exception:
        pass
    return {}


def _threshold_met(verdict_value: str, threshold: str) -> bool:
    order = {"SUSPICIOUS": 0, "MALICIOUS": 1}
    return order.get(verdict_value, -1) >= order.get(threshold, 0)


def send_quarantine_notification(raw: bytes, result: "PipelineResult") -> None:
    """Send a 'your email was held' notice to the original recipient(s).

    Only fires when notify_config.yaml has enabled=true, verdict meets the
    configured threshold, and SMTP settings are populated. Never raises.
    """
    try:
        _send(raw, result)
    except Exception as exc:
        import sys
        print(f"[notify] failed to send quarantine notification: {exc}", file=sys.stderr)


def _send(raw: bytes, result: "PipelineResult") -> None:
    cfg = _load_config()
    if not cfg.get("enabled"):
        return

    verdict_value = result.verdict.value
    if verdict_value not in _NOTIFY_VERDICTS:
        return
    threshold = str(cfg.get("threshold", "SUSPICIOUS")).upper()
    if not _threshold_met(verdict_value, threshold):
        return

    smtp_host = str(cfg.get("smtp_host", "")).strip()
    smtp_user = str(cfg.get("smtp_user", "")).strip()
    smtp_pass = os.environ.get("SEGS_NOTIFY_SMTP_PASS", "").strip()
    from_addr = str(cfg.get("from_addr", "segs-alerts@pdax.ph")).strip()
    smtp_port = int(cfg.get("smtp_port", 587))

    if not smtp_host:
        return

    # Parse recipients from the original raw message.
    from app.parsed_email import ParsedEmail
    pe = ParsedEmail(raw)
    to_addrs = pe.to_addrs
    if not to_addrs:
        return

    def _safe_header(v: str, max_len: int = 500) -> str:
        """Strip CR/LF to prevent SMTP header injection; truncate to max_len."""
        return v.replace("\r", " ").replace("\n", " ").strip()[:max_len]

    subject = _safe_header(result.subject or "(no subject)")
    sender = _safe_header(result.from_header or "(unknown sender)")
    score = result.composite_score
    reasons = result.reasons or []
    reason_summary = ", ".join(reasons[:5]) if reasons else "no specific flags"
    if len(reasons) > 5:
        reason_summary += f" (+{len(reasons) - 5} more)"

    verdict_label = {"SUSPICIOUS": "held for review", "MALICIOUS": "blocked"}.get(verdict_value, verdict_value.lower())

    body = textwrap.dedent(f"""\
        This is an automated security notice from the PDAX Secure Email Gateway.

        An email addressed to you has been {verdict_label} by our security system
        and was not delivered to your inbox.

        Email details
        -------------
        From    : {sender}
        Subject : {subject}
        Verdict : {verdict_value} (score {score}/100)
        Reason  : {reason_summary}

        If you were expecting this email and believe it was held in error,
        please contact your IT/Security team and reference the subject line above.

        Do not reply to this notification — this mailbox is not monitored.

        --
        PDAX Secure Email Gateway (SEGS)
    """)

    for recipient in to_addrs:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = f"[SEGS Security] Email held for review: {subject}"
        msg["From"] = from_addr
        msg["To"] = recipient
        msg["Date"] = formatdate(localtime=False)

        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, [recipient], msg.as_string())
