"""Stage 10 — reporting. Human-readable text report + Slack Block Kit payload
+ JSONL audit record."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .models import PipelineResult, Verdict
from .pipeline import policy as policy_mod

_ICON = {Verdict.CLEAN: "🟢", Verdict.LOW: "🔵",
         Verdict.SUSPICIOUS: "🟠", Verdict.MALICIOUS: "🔴"}

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Human-readable descriptions for every flag a stage can emit. Machine tags
# like "brand_impersonation_display_name:sharefile" tell you a rule fired but
# not what an analyst should actually understand from that — this is the
# translation layer. Exact-match tags first; ":value" tags are matched on the
# prefix and the value is interpolated into the template.
_FLAG_DESCRIPTIONS = {
    "spf_fail": "Sender failed SPF authentication — the sending server isn't authorized to send for this domain.",
    "spf_softfail": "Sender softfailed SPF — the sending server is only weakly authorized for this domain.",
    "dkim_fail": "DKIM signature failed to verify — the message may have been altered in transit, or isn't really from the claimed domain.",
    "dmarc_fail": "DMARC failed — this domain's own policy says messages like this shouldn't be trusted.",
    "return_path_mismatch": "The bounce address (Return-Path) doesn't match the visible From domain — common in spoofed mail.",
    "reply_to_divergent": "Replies would go to a different domain than the visible sender — a classic reply-hijack tell.",
    "reply_to_freemail": "Reply-To points at a consumer freemail domain (Gmail, iCloud, etc.) — common for legitimate platform developer contacts, but a reinforcing handoff signal when the From is a trusted transactional platform pushing a foreign brand.",
    "display_name_email_mismatch": "The display name shows one email address, but the real sending address is a different one entirely.",
    "display_name_is_email": "The display name is itself formatted as an email address, matching the real sender — lower risk on its own, but unusual.",
    "freemail_corporate_persona": "Sent from a free consumer email domain (Gmail, Yahoo, etc.) but the display name claims to be IT/finance/support — a common BEC shape.",
    "html_attachment_credential_form": "An attached HTML file contains a login/password form — a classic offline credential-harvest page.",
    "url_embedded_redirect": "A link hides another destination inside its own parameters (a redirect wrapper) — not inherently bad, but the real target matters more than the visible link.",
    "url_ip_literal": "A link points straight at a raw IP address instead of a domain name — legitimate services almost never do this.",
    "url_brand_keyword_offbrand": "A link's domain contains a trust word (login, secure, verify, etc.) despite not being a recognized brand domain.",
    "url_deep_subdomain": "A link uses an unusually deep chain of subdomains — often used to bury the real (malicious) domain from casual view.",
    "url_oauth_state_email_exposure": "A Microsoft/Google-style login link has a real email address baked into its `state` parameter — legitimate apps never do this; it's a sign of a templated credential-phishing or account-reconnaissance link.",
    "url_redirect_unrelated_domain": "A tracking/redirect link's real destination is unrelated to both the wrapper and the sender's own domain — legitimate trackers redirect back to their own brand, not somewhere else.",
    "url_redirect_to_page_file": "A redirect link's real destination is a bare .html/.php page on someone else's site — the typical shape of a dropped phishing page.",
    "url_redirect_to_ip": "A redirect/tracker link's real destination is a raw IP address — no legitimate tracker's actual destination is a bare IP.",
    "anchor_href_mismatch": "The clickable text of a link names one domain, but the link actually goes somewhere else.",
    "service_abuse_testflight_brand_lure": "Legitimate Apple TestFlight mail inviting you to a beta app that impersonates OpenAI, ChatGPT, Meta, or another mega-brand — trusted-channel service abuse (auth looks clean because Apple really sent it).",
    "trusted_channel_brand_mismatch": "Mail from a trusted transactional platform (e.g. Apple TestFlight) whose subject/body names a foreign mega-brand the platform does not own — brand-vs-channel mismatch.",
    "trusted_channel_reply_to_freemail": "Trusted-platform From address with Reply-To on consumer freemail — identity handoff to a personal mailbox (reinforcing when paired with a foreign brand lure).",
    "deception_structure_service_abuse": "Composed deception structure: authentic trusted-platform channel + on-platform links + foreign brand lure. Auth passing is expected; the malice is the structure, not a spoofed envelope.",
    "lure_scarcity_reward": "Content uses scarcity and/or reward bait (limited seats, free credits) — a common social-engineering reinforcer, not proof on its own.",
    "content_padding_evasion": "The email body contains an unusually large block of blank/whitespace lines — a known trick to bury the real lure or dodge automated content scanning.",
    "urgency_language": "The wording pressures urgent action (deadlines, threats, \"immediately\") — a standard social-engineering tactic.",
    "credential_request": "The wording asks you to log in, verify, or confirm your identity/credentials.",
    "bec_pattern": "The wording matches a Business Email Compromise pattern (gift cards, wire transfers, \"are you available\").",
    "generic_greeting": "Uses a generic greeting (\"Dear Customer\", etc.) instead of your actual name — common in mass-sent phishing.",
    "payment_lure_subject": "The subject line uses a financial-document pretext (invoice, disbursement, statement, etc.) — one of the most common phishing lures.",
    "fake_reply_prefix": "The subject looks like a reply (\"Re:\") to a conversation that doesn't actually exist in this mailbox's thread history.",
    "brand_impersonation": "The email's own wording claims to be a specific brand/organization in a way that doesn't fit the rest of the message.",
    "unusual_request": "An AI reviewer flagged this as an unusual or out-of-context request.",
    "prompt_injection_attempt": "The email body tried to instruct the AI reviewer directly (e.g. \"ignore previous instructions\") — the attempt itself was treated as a red flag, not followed.",
    "threat_intel_hit": "One of this email's domains/URLs/hashes matched a known-bad indicator in threat intelligence.",
    "url_lookalike_domain": "A link's domain is a near-identical lookalike of one of the organization's protected domains.",
    "banned_attachment_type": "This email has an attachment of a file type that's outright banned (executables, scripts, etc.).",
    "sender_lookalike_domain": "The sender's own domain is a near-identical lookalike of one of the organization's protected domains.",
    "spoofed_or_double_extension_attachment": "An attachment's real file type doesn't match its declared extension, or hides an executable behind a benign-looking one (e.g. invoice.pdf.exe) — a renamed/disguised file, invisible to a simple banned-extension check.",
    "bec_vip_impersonation": "The display name impersonates a protected VIP/executive name AND the message body matches a BEC financial-request pattern — a high-confidence combination.",
    "bulk_sender_no_unsubscribe": "Presents as bulk mail (Precedence: bulk/list, or a List-Id header) but is missing the List-Unsubscribe header legitimate bulk senders are required to include — spam frequently omits or fakes this.",
    # A handful of the highest-value app/attachment_forensics.py findings,
    # curated for readability — every other forensics_<flag> tag still shows
    # up via the generic "unrecognized tag" fallback below, just less
    # polished (e.g. "Forensics pdf javascript").
    "forensics_office_macro": "Attachment contains an Office macro (VBA project) — can run code automatically when opened.",
    "forensics_archive_contains_executable": "Attachment is an archive containing an executable or macro-capable file inside it.",
    "forensics_pdf_auto_executing_action": "Attachment PDF combines an auto-triggering action with JavaScript/launch/remote-goto content — opens and runs without further clicks.",
    "forensics_high_entropy_content": "Attachment content has unusually high byte entropy for its apparent type — consistent with packed/encrypted/obfuscated payloads.",
    "forensics_possible_zip_bomb": "Attachment archive's compression ratio or uncompressed size exceeds safe bounds — consistent with a decompression-bomb resource-exhaustion attempt.",
    "forensics_encrypted_archive": "Attachment archive has password-protected/encrypted members — a known technique for hiding malicious content from automated scanning.",
    "forensics_executable_content": "Attachment's actual content is executable code, regardless of its declared file type.",
    # Extended header signals
    "missing_message_id": "Message-ID header is absent — legitimate mail servers always generate one; its absence is a sign of script-generated or spoofed mail.",
    "missing_mime_version": "MIME-Version header is absent — most modern email clients include it; its absence is a marginal signal associated with spam and scripted senders.",
    "date_anomaly_future": "The email's Date header shows a timestamp more than 2 days in the future — consistent with forged or tampered headers.",
    "date_anomaly_stale": "The email's Date header is over 30 days in the past — either an unusually delayed message or a forged timestamp.",
    "suspicious_x_mailer": "The X-Mailer or User-Agent header identifies a bulk/scripted mail tool (PHPMailer, libwww-perl, etc.) — commonly used to automate spam and phishing campaigns.",
    "display_name_domain_impersonation": "The sender's display name contains a domain that doesn't match the actual sending domain — e.g. 'PayPal <attacker@evil.com>' — a classic phishing display-name spoof.",
    # URL signals
    "tracking_beacon_detected": "The email loads external images or resources automatically on open — consistent with a tracking pixel that confirms email delivery and may capture the reader's IP address.",
    "url_ftp_scheme": "A URL in this email uses the FTP scheme — very rarely used in legitimate email; may indicate a link to a malicious file server.",
    # Attachment signals
    "oletools_vba_macro_detected": "A VBA macro was detected in the attachment by oletools static analysis — macros can execute arbitrary code when the document is opened.",
    "oletools_autoexec_or_shell": "The attachment's VBA macro contains auto-execution triggers or shell commands (AutoExec, Shell, WScript) — high-confidence malicious macro indicator.",
    # NLU intent classification
    "nlu_intent:bec": "NLU classifier identified the intent as Business Email Compromise — financial diversion, gift-card request, or wire-transfer ask.",
    "nlu_intent:callback_scam": "NLU classifier identified the intent as a callback scam — fake subscription charge or invoice asking the recipient to call a phone number.",
    "nlu_intent:credential_theft": "NLU classifier identified the intent as credential theft — login, password reset, or account-verification phishing.",
    "nlu_intent:extortion": "NLU classifier identified the intent as extortion — threats to expose compromising material unless cryptocurrency is paid.",
    "nlu_intent:steal_pii": "NLU classifier identified the intent as PII harvesting — requests for SSN, passport, bank account, or other sensitive personal data.",
    "nlu_intent:job_scam": "NLU classifier identified the intent as a job scam — fake work-from-home or remote-position offer, typically used for advance-fee or PII theft.",
    "nlu_intent:malware_delivery": "NLU classifier identified the intent as malware delivery — the message exists to get the recipient to open an attachment or link that drops/runs code.",
    "nlu_intent:ransomware": "NLU classifier identified the intent as ransomware — a ransomware delivery lure or an extortion/ransom demand referencing encrypted files.",
    "nlu_intent:reconnaissance": "NLU classifier identified the intent as reconnaissance — probing or target-profiling (test message, 'are you there', validity check) ahead of a follow-up attack.",
    # Sender history
    "first_time_sender": "This sender address has never been seen before in the past 6 months — new senders combined with suspicious content are a key BEC and phishing indicator.",
}
_FLAG_PREFIX_DESCRIPTIONS = {
    "banned_attachment": "Attachment has a banned, high-risk file type: .{value}",
    "macro_capable_doc": "Attachment is a macro-capable Office document (.{value}) — can run code when opened.",
    "url_lookalike": "A link's domain is a near-identical lookalike of the protected domain '{value}'.",
    "url_risky_tld": "A link uses a top-level domain (.{value}) associated with high spam/abuse rates.",
    "lookalike_of": "The sender's domain is a near-identical lookalike of the protected domain '{value}'.",
    "vip_name_spoof": "The display name impersonates a watched VIP/executive name ('{value}') while sending from an unrelated domain.",
    "brand_impersonation_display_name": "The display name claims to be from '{value}' (a known e-sign/file-share brand), but the sending domain has no relationship to that brand.",
    "intel_domain": "Domain '{value}' matched a known-bad threat-intelligence indicator.",
    "intel_ip": "IP '{value}' matched a known-bad threat-intelligence indicator.",
    "intel_url": "URL '{value}' matched a known-bad threat-intelligence indicator.",
    "intel_hash": "Attachment hash '{value}' matched a known-bad threat-intelligence indicator.",
    "ai": "AI reviewer identified a pattern not in the standard checklist: {value}",
    "spoofed_attachment_type": "An attachment's actual file type (from its content, not its name) doesn't match its declared extension: {value} — a classic disguised-executable trick.",
    "double_extension_executable": "Attachment filename hides an executable behind a benign-looking extension (e.g. invoice.pdf.exe): {value}",
    "service_abuse": "Trusted-platform service abuse ({value}): authentic channel mail pushing a foreign brand lure.",
    "behavioral_sender_ip_drift": "Sender '{value}' has been observed using multiple originating IPs over the past 6 months — consistent with account compromise or a lookalike sender rotating infrastructure.",
    "behavioral_ip_many_senders": "Originating IP '{value}' has sent mail from 5 or more distinct sender addresses — consistent with a shared attack platform.",
    "behavioral_ip_shortener": "Originating IP '{value}' has previously sent emails containing link-shortener URLs — consistent with a link obfuscation campaign.",
    "behavioral_shared_shortener": "Link shortener domain '{value}' was also used by different sender addresses — strong indicator of a coordinated phishing campaign.",
    "url_link_shortener": "A link in this email uses the known link-shortener service '{value}' — shorteners hide the real destination.",
    "domain_age_low": "The sender's domain was registered only {value} day(s) ago — newly-registered domains are common phishing infrastructure.",
    "received_hop_delay": "An unusually long delay ({value}) between mail relay hops — may indicate routing through a compromised proxy or timestamp manipulation.",
    "url_tracking_beacon": "External resource '{value}' is embedded as a tracking image/pixel that loads automatically when the email is opened.",
    "vt_domain_suspicious": "Domain '{value}' has a suspicious VirusTotal reputation score or category flag.",
    "vt_url_submitted": "URL '{value}' was not found in VirusTotal's database and has been submitted for scanning — re-check later for results.",
    "rare_sender": "This sender has only been seen {value} time(s) in the past 6 months — low volume senders warrant additional scrutiny when paired with suspicious content.",
    "ai_verdict_floor": "The AI threat classifier was confident enough ({value}) that this message was raised to at least SUSPICIOUS (quarantine) regardless of the numeric score.",
}


# TMES-parity policy category keys (rules/policy.yaml) -> display name, for
# the "policy_suppressed:" rendering below.
_CATEGORY_DISPLAY_NAMES = {
    "advanced_spam_protection": "Advanced Spam Protection",
    "malware_scanning": "Malware Scanning",
    "file_blocking": "File Blocking",
    "web_reputation": "Web Reputation",
    "virtual_analyzer": "Virtual Analyzer",
    "correlated_intelligence": "Correlated Intelligence",
}


def _describe_flag(flag: str) -> str:
    if flag.startswith("policy_suppressed:"):
        underlying = flag[len("policy_suppressed:"):]
        category = policy_mod.category_for_flag(underlying)
        label = _CATEGORY_DISPLAY_NAMES.get(category, "A disabled policy category")
        return f"{label} is disabled — this would have flagged: {_describe_flag(underlying)}"
    if flag in _FLAG_DESCRIPTIONS:
        return _FLAG_DESCRIPTIONS[flag]
    prefix, sep, value = flag.partition(":")
    if sep and prefix in _FLAG_PREFIX_DESCRIPTIONS:
        return _FLAG_PREFIX_DESCRIPTIONS[prefix].format(value=value)
    # Unrecognized tag (e.g. a new rule not yet added here) — still show
    # something readable rather than silently dropping it.
    return flag.replace("_", " ").replace(":", ": ").capitalize()


def _sanitize(s: str) -> str:
    """From/Subject are attacker-controlled and MIME-decoded upstream, so they
    can carry raw bytes — including ANSI escape sequences (cursor move, erase
    line, color) that a crafted Subject can use to spoof the printed verdict
    line in an analyst's terminal. Strip control chars and flatten embedded
    CR/LF so a header value can never inject a fake report line."""
    s = (s or "").replace("\r", " ").replace("\n", " ")
    return _CONTROL_CHARS.sub("", s)


def _slack_escape(s: str) -> str:
    """Slack mrkdwn treats bare &, <, > as markup — an unescaped Subject/From
    of e.g. "<!channel>" or "<@Uxxxx>" would render as a real channel-wide
    ping or user mention when this lands in Slack. Escape per Slack's API."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _verdict_margin(r: PipelineResult) -> str:
    """A bare score/verdict doesn't tell you how confidently it landed there.
    Show the distance to the next threshold up/down so "SUSPICIOUS at 45"
    reads as either "just barely" or "deep into this band"."""
    t = r.thresholds
    if not t or r.hard_override:
        return ""
    score = r.composite_score
    if r.verdict == Verdict.MALICIOUS:
        return f"  ({score - t.get('malicious', 70):.1f} points above the MALICIOUS threshold of {t.get('malicious', 70)})"
    if r.verdict == Verdict.SUSPICIOUS:
        return (f"  ({t.get('malicious', 70) - score:.1f} points below MALICIOUS ({t.get('malicious', 70)}), "
                f"{score - t.get('suspicious', 45):.1f} above SUSPICIOUS ({t.get('suspicious', 45)}))")
    if r.verdict == Verdict.LOW:
        return (f"  ({t.get('suspicious', 45) - score:.1f} points below SUSPICIOUS ({t.get('suspicious', 45)}), "
                f"{score - t.get('low', 20):.1f} above LOW ({t.get('low', 20)}))")
    return f"  ({t.get('low', 20) - score:.1f} points below the LOW threshold of {t.get('low', 20)})"


def _ioc_context(r: PipelineResult) -> dict:
    """Per-IOC context combining live VirusTotal/AbuseIPDB intel with rule-based
    analysis findings. Distinguishes confirmed threat-intel hits from structural
    anomalies observed during analysis."""
    notes: dict[str, str] = {}
    headers = r.stage("headers")
    sender = r.stage("sender")
    urls_stage = r.stage("urls")
    intel = r.stage("intel")

    if sender and isinstance(sender.facts, dict):
        from_dom = sender.facts.get("from_domain")
        if from_dom and sender.facts.get("lookalike_of"):
            notes[from_dom] = f"lookalike of protected domain '{sender.facts['lookalike_of']}'"
        if from_dom and sender.facts.get("brand_impersonation"):
            notes.setdefault(from_dom, f"display name impersonates brand '{sender.facts['brand_impersonation']}'")

    if headers and isinstance(headers.facts, dict):
        fd = headers.facts.get("from_domain")
        rp, rt = headers.facts.get("return_path_domain"), headers.facts.get("reply_to_domain")
        if headers.facts.get("return_path_mismatch") and rp:
            notes.setdefault(rp, f"Return-Path domain differs from the visible From domain ({fd})")
        if headers.facts.get("reply_to_divergent") and rt:
            notes.setdefault(rt, f"Reply-To domain differs from the visible From domain ({fd})")

    if urls_stage and isinstance(urls_stage.facts, dict):
        for rec in urls_stage.facts.get("urls", []):
            key = rec.get("url")
            if not key:
                continue
            bits = []
            if rec.get("lookalike_of"):
                bits.append(f"lookalike of protected domain '{rec['lookalike_of']}'")
            if rec.get("redirect_unrelated"):
                bits.append("redirect's real target is unrelated to the sender/wrapper domain")
            if rec.get("redirect_page_file"):
                bits.append("real target is a bare page dropped on a third-party domain")
            if rec.get("oauth_state_email_exposure"):
                bits.append("OAuth link exposes a real email address in its state parameter")
            if rec.get("ip_literal"):
                bits.append("raw IP address, not a domain")
            if bits:
                notes[key] = "; ".join(bits)

    if intel and intel.red_flags:
        for hit in intel.red_flags:
            if hit.startswith("behavioral_"):
                # format: behavioral_<rule>:<ioc_value>:<count>
                parts = hit.split(":", 2)
                if len(parts) == 3:
                    prefix, ioc_value, count = parts
                    if prefix == "behavioral_sender_ip_drift":
                        notes[ioc_value] = f"SENDER USED {count} DIFFERENT ORIGINATING IPs IN PAST 6 MONTHS"
                    elif prefix == "behavioral_ip_many_senders":
                        notes[ioc_value] = f"IP USED BY {count} DIFFERENT SENDERS IN PAST 6 MONTHS"
                    elif prefix == "behavioral_ip_shortener":
                        notes[ioc_value] = f"IP PREVIOUSLY SENT LINK-SHORTENER EMAILS ({count} OCCURRENCES)"
                    elif prefix == "behavioral_shared_shortener":
                        notes[ioc_value] = f"SHORTENER DOMAIN USED BY {count} OTHER SENDERS (COORDINATED CAMPAIGN)"
                continue
            _, _, value = hit.partition(":")
            if value:
                notes[value] = "MATCHED KNOWN-BAD THREAT INTEL"

    return notes


def _ioc_lines(label: str, values: list, notes: dict) -> list:
    """Renders one IOC category, one value per line, flagging any with
    computed context (see _ioc_context) and printing a plain "none observed"
    when the category is empty rather than an empty list literal."""
    if not values:
        return [f"  {label}: none observed"]
    out = [f"  {label}:"]
    for v in values:
        note = notes.get(str(v))
        out.append(f"    - {v}" + (f"   [{note}]" if note else ""))
    return out


def _md_table(rows: list, headers: list) -> str:
    """Minimal Markdown table builder."""
    if not rows:
        return "_None._"
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    def _pad(val: str, w: int) -> str:
        return str(val).ljust(w)
    header_row = "| " + " | ".join(_pad(h, widths[i]) for i, h in enumerate(headers)) + " |"
    sep_row = "| " + " | ".join("-" * widths[i] for i in range(len(headers))) + " |"
    data_rows = [
        "| " + " | ".join(_pad(str(row[i]) if i < len(row) else "", widths[i])
                           for i in range(len(headers))) + " |"
        for row in rows
    ]
    return "\n".join([header_row, sep_row] + data_rows)


def _intel_section(r: PipelineResult) -> list[str]:
    """Builds the Threat Intelligence section from live VT/AbuseIPDB pipeline data."""
    intel = r.stage("intel")
    if not intel or not isinstance(intel.facts, dict):
        return []

    lines: list[str] = []
    domain_details: dict = intel.facts.get("domain_details") or {}
    hits: list = intel.facts.get("hits") or []
    behavioral_hits: list = intel.facts.get("behavioral_hits") or []

    # Confirmed threat-intel hits (VT/AbuseIPDB matched indicators)
    confirmed_hits = [h for h in hits if not h.startswith("behavioral_")]
    if confirmed_hits or domain_details or behavioral_hits:
        lines += ["", "## Threat Intelligence", ""]
        lines.append(
            "_Live lookups performed by VirusTotal (domain/URL reputation) and "
            "AbuseIPDB (IP reputation). Results are cached for 6 hours._"
        )

    if confirmed_hits:
        lines += ["", "### Matched Known-Bad Indicators", ""]
        for hit in confirmed_hits:
            prefix, _, value = hit.partition(":")
            if value:
                desc = _describe_flag(hit)
                lines.append(f"- **`{value}`** — {desc}")
        lines.append("")

    if domain_details:
        lines += ["### Domain Reputation (VirusTotal)", ""]
        for domain, details in domain_details.items():
            if not isinstance(details, dict):
                continue
            lines.append(f"#### `{domain}`")
            lines.append("")
            rep = details.get("reputation")
            cats = details.get("categories") or {}
            registrar = details.get("registrar") or "—"
            created = details.get("creation_date") or "—"
            tags = details.get("tags") or []
            votes = details.get("total_votes") or {}
            votes_mal = votes.get("malicious", 0)
            votes_harm = votes.get("harmless", 0)

            table_rows = [
                ["Reputation score", str(rep) if rep is not None else "—"],
                ["Registrar", registrar],
                ["Registered", created],
                ["VT community votes (malicious)", str(votes_mal)],
                ["VT community votes (harmless)", str(votes_harm)],
                ["Tags", ", ".join(tags) if tags else "—"],
            ]
            if cats:
                cat_str = "; ".join(f"{engine}: {label}" for engine, label in list(cats.items())[:6])
                table_rows.insert(1, ["Categories", cat_str])

            lines.append(_md_table(table_rows, ["Field", "Value"]))
            lines.append("")

    if behavioral_hits:
        lines += ["### Behavioral Pattern Alerts", ""]
        for hit in behavioral_hits:
            lines.append(f"- {_describe_flag(hit)}")
        lines.append("")

    return lines


def text_report(r: PipelineResult) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    icon = _ICON.get(r.verdict, "")
    subject_safe = _sanitize(r.subject) or "(no subject)"
    from_safe = _sanitize(r.from_header) or "(unknown)"

    lines: list[str] = []

    # ── Title ────────────────────────────────────────────────────────────────
    lines += [
        f"# SEGS Security Report — {subject_safe}",
        "",
        f"**Generated:** {generated}  ",
        f"**Source file:** `{r.source}`  ",
        "",
        "---",
    ]

    # ── Executive Summary ─────────────────────────────────────────────────────
    verdict_line = f"{icon} **{r.verdict.value}** — Composite Score: **{r.composite_score}/100**"
    if _verdict_margin(r):
        verdict_line += _verdict_margin(r)

    lines += [
        "",
        "## Executive Summary",
        "",
        verdict_line,
        "",
        f"**Disposition:** {r.disposition.value}  ",
        f"**Enforcement Mode:** {r.enforce_mode.value}  ",
    ]
    if r.threat_class and r.threat_class != "none":
        _tc_label = r.threat_class.replace("_", " ").title()
        lines.append(
            f"**Threat Class (AI):** {_tc_label} "
            f"(confidence {r.threat_confidence:.0%})  ")
    if r.disposition_reason:
        lines.append(f"**Disposition Reason:** {r.disposition_reason}  ")
    if r.enforcement_applied:
        lines.append(f"**Enforcement Applied:** {r.enforcement_applied}  ")
    if r.hard_override:
        lines += [
            "",
            f"> **Hard Override:** `{r.hard_override}`  ",
            f"> {_describe_flag(r.hard_override)}",
        ]

    ai_summary = next(
        (s.facts["summary"] for s in r.stages
         if s.stage == "content_ai" and isinstance(s.facts, dict) and s.facts.get("summary")),
        None,
    )
    if ai_summary:
        lines += ["", f"**AI Assessment:** {_sanitize(ai_summary)}"]

    # ── Message Metadata ──────────────────────────────────────────────────────
    lines += [
        "",
        "---",
        "",
        "## Message Metadata",
        "",
        _md_table([
            ["From", from_safe],
            ["Subject", subject_safe],
            ["Source", r.source],
            ["Message-ID", r.message_id or "—"],
        ], ["Field", "Value"]),
    ]

    # ── Detection Findings by Stage ───────────────────────────────────────────
    lines += ["", "---", "", "## Detection Findings by Stage", ""]
    for s in r.stages:
        status_icon = {"pass": "✅", "flag": "🚩", "degraded": "⚠️", "skipped": "⏭️"}.get(
            s.status.value, "ℹ️")
        lines.append(f"### {status_icon} {s.stage.replace('_', ' ').title()} — Score: {s.sub_score:.1f}")
        lines.append("")
        if s.red_flags:
            flag_rows = [[f"`{flag}`", _describe_flag(flag)] for flag in s.red_flags]
            lines.append(_md_table(flag_rows, ["Flag", "Description"]))
        else:
            lines.append("_No flags raised._")
        if isinstance(s.facts, dict):
            err = s.facts.get("error")
            if err:
                lines.append(f"\n> **Stage error:** {_sanitize(str(err))}")
            if s.facts.get("triage_skipped_llm"):
                lines.append("\n> _Triage: heuristic-only — score not near a threshold boundary, LLM call skipped._")
            elif s.facts.get("triage_escalated"):
                lines.append("\n> _Triage: escalated to LLM — heuristic-only score was near a threshold boundary._")
        lines.append("")

    # ── Verdict Explanation ───────────────────────────────────────────────────
    lines += ["---", "", "## Verdict Explanation", ""]
    if r.reasons:
        for flag in r.reasons:
            lines.append(f"- {_describe_flag(flag)}")
    else:
        lines.append("_No red flags were raised on any stage._")
    lines += ["", f"**Raw signal tags:** `{'`, `'.join(r.reasons) if r.reasons else 'none'}`"]

    # ── Matched Detection Rules ───────────────────────────────────────────────
    if r.matched_rules:
        lines += ["", "---", "", "## Matched Detection Rules", ""]
        lines.append(
            "_Named rules that fired based on the combination of signals detected. "
            "Mirrors Sublime Security's 'Matched Feed Rules' concept._"
        )
        lines.append("")
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
        rule_rows = [
            [
                severity_icon.get(rule["severity"], "⚪") + " " + rule["severity"].upper(),
                rule["name"],
                ", ".join(rule.get("tags", [])),
            ]
            for rule in r.matched_rules
        ]
        lines.append(_md_table(rule_rows, ["Severity", "Rule", "Categories"]))
        lines.append("")
        for rule in r.matched_rules:
            lines.append(f"**{rule['name']}**")
            lines.append(f"> {rule['description']}")
            lines.append("")

    # ── Threat Intelligence (VT / AbuseIPDB) ──────────────────────────────────
    lines.extend(_intel_section(r))

    # ── Indicators of Compromise ──────────────────────────────────────────────
    notes = _ioc_context(r)
    lines += ["", "---", "", "## Indicators of Compromise", ""]

    def _md_ioc_section(label: str, values: list) -> None:
        lines.append(f"**{label}**")
        if not values:
            lines.append("- _None observed._")
            return
        for v in values:
            note = notes.get(str(v))
            suffix = f" — _{note}_" if note else ""
            lines.append(f"- `{v}`{suffix}")

    _md_ioc_section("Sender addresses", r.iocs.sender_emails)
    lines.append("")
    _md_ioc_section("Domains", r.iocs.domains)
    lines.append("")
    _md_ioc_section("IP addresses", r.iocs.ips)
    lines.append("")
    _md_ioc_section("URLs", r.iocs.urls)
    lines.append("")
    _md_ioc_section("File hashes (SHA-256)", r.iocs.hashes_sha256)
    lines.append("")
    _md_ioc_section("Authenticated relay senders", r.iocs.authenticated_relay_senders)

    # ── Footer ────────────────────────────────────────────────────────────────
    lines += [
        "",
        "---",
        "",
        "_Report generated by **SEGS** (Secure Email Gateway Suite). "
        "VirusTotal and AbuseIPDB results are sourced from live threat intelligence APIs. "
        "This report is advisory only — verify independently before taking enforcement action._",
    ]

    return "\n".join(lines)


def slack_blocks(r: PipelineResult) -> dict:
    icon = _ICON.get(r.verdict, "")
    top = "*Reason:* " + (r.hard_override or ", ".join(r.reasons[:5]) or "weighted score")
    from_safe = _slack_escape(_sanitize(r.from_header))[:120]
    subject_safe = _slack_escape(_sanitize(r.subject))[:120]
    return {
        "blocks": [
            {"type": "header",
             "text": {"type": "plain_text", "text": f"{icon} {r.verdict.value} — email analyzed"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*From:*\n{from_safe}"},
                {"type": "mrkdwn", "text": f"*Score:*\n{r.composite_score}"},
                {"type": "mrkdwn", "text": f"*Subject:*\n{subject_safe}"},
                {"type": "mrkdwn", "text": f"*Disposition:*\n{r.disposition.value} ({r.enforce_mode.value})"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn", "text": _slack_escape(top)}},
        ]
    }


def send_slack_alert(result: PipelineResult, webhook_url: str, threshold: str = "SUSPICIOUS") -> None:
    """POST a Slack Block Kit alert for SUSPICIOUS / MALICIOUS verdicts.

    threshold — minimum verdict level to alert on: "SUSPICIOUS" (default) or "MALICIOUS".
    Uses only stdlib (urllib.request) so no new dependency is needed.
    Failures are logged to stderr and never re-raised — a Slack outage must
    never block the email pipeline.
    """
    import json as _json
    import urllib.request
    import urllib.error

    ordered = ("CLEAN", "LOW", "SUSPICIOUS", "MALICIOUS")
    try:
        min_idx = ordered.index(threshold.upper())
    except ValueError:
        min_idx = ordered.index("SUSPICIOUS")

    try:
        verdict_idx = ordered.index(result.verdict.value.upper())
    except ValueError:
        return  # unknown verdict — skip

    if verdict_idx < min_idx:
        return

    try:
        payload = _json.dumps(slack_blocks(result)).encode()
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        import sys
        print(f"[SEGS] Slack alert failed: {exc}", file=sys.stderr)


def audit_record(r: PipelineResult) -> str:
    ai_summary = next(
        (s.facts["summary"] for s in r.stages
         if s.stage == "content_ai" and isinstance(s.facts, dict) and s.facts.get("summary")),
        None,
    )
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "message_id": r.message_id,
        "source": r.source,
        "verdict": r.verdict.value,
        "score": r.composite_score,
        "disposition": r.disposition.value,
        "disposition_reason": r.disposition_reason,
        "enforce_mode": r.enforce_mode.value,
        "enforcement_applied": r.enforcement_applied,
        "thresholds": r.thresholds,
        "hard_override": r.hard_override,
        "reason_tags": r.reasons,
        "reasons": [{"tag": flag, "description": _describe_flag(flag)} for flag in r.reasons],
        "ai_summary": ai_summary,
        "stages": [{"stage": s.stage, "status": s.status.value,
                    "score": s.sub_score, "flags": s.red_flags,
                    **({"error": s.facts["error"]} if isinstance(s.facts, dict) and s.facts.get("error") else {}),
                    **({"triage_skipped_llm": True} if isinstance(s.facts, dict) and s.facts.get("triage_skipped_llm") else {}),
                    **({"triage_escalated": True} if isinstance(s.facts, dict) and s.facts.get("triage_escalated") else {})}
                   for s in r.stages],
        "iocs": r.iocs.model_dump(),
        # Rule-based context per IOC — NOT a live reputation/intel lookup,
        # see _ioc_context()'s docstring. Keys are the IOC value itself.
        "ioc_context": _ioc_context(r),
    }
    return json.dumps(rec, ensure_ascii=False)
