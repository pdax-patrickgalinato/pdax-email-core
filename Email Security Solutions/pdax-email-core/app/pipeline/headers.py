"""Stage 1 — Header analysis.

Parses the Authentication-Results header (authoritative when the message
already transited a trusted resolver like Google) plus Return-Path / Reply-To /
Message-ID anomalies. In the gateway, Rspamd re-verifies DKIM/DMARC
cryptographically; here we read the AR header so the core runs offline.

Also carries the Advanced Spam Protection bulk-mail signal (TMES policy
parity) — deliberately small and separate from the phishing/BEC content
heuristics in content_ai.py, since nothing else in this pipeline represents
"unsolicited bulk mail" as a concept at all. See bulk_sender_no_unsubscribe
below.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from ..models import HeaderFacts, StageResult, StageStatus
from ..parsed_email import ParsedEmail
from ..domainutils import registrable_domain
from ..lists import freemail_domains

_AR_TOKEN = {
    "spf": re.compile(r"spf=(\w+)", re.I),
    "dkim": re.compile(r"dkim=(\w+)", re.I),
    "dmarc": re.compile(r"dmarc=(\w+)", re.I),
}
_DMARC_POLICY = re.compile(r"p=(\w+)", re.I)
_PRECEDENCE_BULK = re.compile(r"\b(bulk|list|junk)\b", re.I)
_ONE_CLICK_UNSUB = re.compile(r"List-Unsubscribe\s*=\s*One-Click", re.I)

# Domain-like tokens in display names — used for display-name impersonation detection.
# Matches e.g. "PayPal" in "PayPal Security <attacker@evil.com>" if PayPal.com is
# detected as a token, but more precisely matches full domain strings in the display name.
_DOMAIN_LIKE = re.compile(r'\b([a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,})\b')

# Received header trailing date: always after a semicolon
_RECEIVED_DATE_RE = re.compile(r";\s*(.+)$")

# X-Mailer values associated with automated/bulk/scripted sending tools
_XMAILER_BLOCKLIST = re.compile(
    r"phpmailer|libwww-perl|the\s*bat!|mass\s*mailer|bombastic"
    r"|smtp-mailer|myfirstmailer|blat\b|sendblaster|mime-version\s*auto",
    re.I,
)


def _received_timestamps(msg) -> list:
    """Parse date timestamps from Received headers (newest-first order)."""
    timestamps = []
    for received in msg.get_all("Received", []):
        # Unfold continuation whitespace lines
        cleaned = re.sub(r"\r?\n[ \t]+", " ", received).strip()
        m = _RECEIVED_DATE_RE.search(cleaned)
        if not m:
            continue
        try:
            dt = parsedate_to_datetime(m.group(1).strip())
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            timestamps.append(dt)
        except Exception:
            pass
    return timestamps


def run(pe: ParsedEmail) -> StageResult:
    t0 = time.perf_counter()
    ar = " ".join(pe.msg.get_all("Authentication-Results", []))

    def tok(name: str) -> str:
        m = _AR_TOKEN[name].search(ar)
        return m.group(1).lower() if m else "none"

    from_dom = registrable_domain(pe.from_domain)
    rp_dom = registrable_domain(pe.return_path_domain)
    reply_dom = registrable_domain(pe.reply_to_domain)

    pol_m = _DMARC_POLICY.search(ar)
    facts = HeaderFacts(
        spf=tok("spf"),
        dkim=tok("dkim"),
        dmarc=tok("dmarc"),
        dmarc_policy=pol_m.group(1).lower() if pol_m else "none",
        from_domain=from_dom,
        return_path_domain=rp_dom,
        reply_to_domain=reply_dom,
        return_path_mismatch=bool(rp_dom and from_dom and rp_dom != from_dom),
        reply_to_divergent=bool(reply_dom and from_dom and reply_dom != from_dom),
        reply_to_freemail=bool(reply_dom and reply_dom in freemail_domains()),
        message_id_domain=pe.message_id_domain,
    )
    # alignment: DMARC passes only if SPF or DKIM aligns with the From domain
    facts.dmarc_aligned = facts.dmarc == "pass"

    # Advanced Spam Protection: bulk-mail signals.
    list_unsub = pe.msg.get("List-Unsubscribe")
    list_unsub_post = pe.msg.get("List-Unsubscribe-Post", "")
    precedence = pe.msg.get("Precedence", "")
    facts.has_list_unsubscribe = bool(list_unsub)
    facts.list_unsubscribe_one_click = bool(_ONE_CLICK_UNSUB.search(list_unsub_post))
    facts.precedence_bulk = bool(_PRECEDENCE_BULK.search(precedence))
    facts.has_list_id = bool(pe.msg.get("List-Id"))

    # --- Missing required headers (script-generated or spoofed signals) ---
    facts.missing_message_id = not bool(pe.header("Message-ID").strip())
    facts.missing_mime_version = not bool(pe.msg.get("MIME-Version"))

    # --- Date anomaly ---
    date_str = pe.header("Date")
    if date_str:
        try:
            msg_dt = parsedate_to_datetime(date_str)
            if msg_dt.tzinfo is None:
                msg_dt = msg_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            delta_hours = (msg_dt - now).total_seconds() / 3600
            if delta_hours > 48:
                facts.date_anomaly = "future"
            elif delta_hours < -720:   # >30 days in the past
                facts.date_anomaly = "stale"
        except Exception:
            pass

    # --- X-Mailer blocklist ---
    x_mailer_raw = pe.msg.get("X-Mailer", "") or pe.msg.get("User-Agent", "")
    if x_mailer_raw and _XMAILER_BLOCKLIST.search(x_mailer_raw):
        facts.suspicious_x_mailer = True
        facts.x_mailer_value = x_mailer_raw[:120]

    # --- Display name domain impersonation ---
    # Attackers write "PayPal <phisher@evil.com>" — the display name contains a
    # brand/domain the actual sender email doesn't belong to.
    display = pe.from_display or ""
    if display and from_dom:
        for token in _DOMAIN_LIKE.findall(display):
            tok_reg = registrable_domain(token)
            if tok_reg and tok_reg != from_dom:
                facts.display_name_domain_impersonation = True
                break

    # --- Inter-hop Received delay ---
    # Timestamps are newest-first (Received headers are prepended at each hop).
    # A gap > 4 hours between consecutive hops is anomalous.
    timestamps = _received_timestamps(pe.msg)
    if len(timestamps) >= 2:
        max_delay = 0.0
        for i in range(len(timestamps) - 1):
            delay_h = abs((timestamps[i] - timestamps[i + 1]).total_seconds()) / 3600
            if delay_h > max_delay:
                max_delay = delay_h
        facts.max_hop_delay_hours = round(max_delay, 1)

    flags: list[str] = []
    score = 0.0

    # --- Existing signals ---
    if facts.spf in ("fail", "softfail"):
        flags.append(f"spf_{facts.spf}"); score += 25
    if facts.dkim == "fail":
        flags.append("dkim_fail"); score += 25
    if facts.dmarc == "fail":
        flags.append("dmarc_fail"); score += 35
    if facts.return_path_mismatch:
        flags.append("return_path_mismatch"); score += 15
    if facts.reply_to_divergent:
        flags.append("reply_to_divergent"); score += 15
    if facts.reply_to_freemail:
        flags.append("reply_to_freemail"); score += 12
    # Mail presenting as bulk (Precedence: bulk/list/junk, or a List-Id) but
    # missing the List-Unsubscribe header legitimate bulk senders are
    # required to include (CAN-SPAM/RFC 8058) — spam frequently omits or
    # fakes this. Small, low-confidence, weighted-only signal on purpose —
    # not a full spam classifier, see module docstring.
    if (facts.precedence_bulk or facts.has_list_id) and not facts.has_list_unsubscribe:
        flags.append("bulk_sender_no_unsubscribe"); score += 18

    # Forged or spoofed mail often originates from infrastructure whose
    # Message-ID domain differs from the visible From domain — legitimate
    # senders almost never have this mismatch.
    mid_reg = registrable_domain(facts.message_id_domain or "")
    from_reg = facts.from_domain or ""
    if mid_reg and from_reg and mid_reg != from_reg:
        flags.append("message_id_domain_mismatch"); score += 15

    # --- New signals ---
    if facts.missing_message_id:
        flags.append("missing_message_id"); score += 10
    if facts.missing_mime_version:
        flags.append("missing_mime_version"); score += 5
    if facts.date_anomaly == "future":
        flags.append("date_anomaly_future"); score += 20
    elif facts.date_anomaly == "stale":
        flags.append("date_anomaly_stale"); score += 10
    if facts.suspicious_x_mailer:
        flags.append("suspicious_x_mailer"); score += 15
    if facts.display_name_domain_impersonation:
        flags.append("display_name_domain_impersonation"); score += 20
    if facts.max_hop_delay_hours > 4:
        flags.append(f"received_hop_delay:{facts.max_hop_delay_hours}h"); score += 12

    return StageResult(
        stage="headers",
        status=StageStatus.OK,
        sub_score=min(score, 100.0),
        red_flags=flags,
        facts=facts.model_dump(),
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
