"""Stage 2 — Sender verification.

Offline-capable: lookalike detection (homoglyph fold + bounded edit distance),
VIP display-name spoof, free-mail-claiming-corporate. Domain age / RDAP and
first-contact history are enrichment hooks (marked degraded when not wired)."""
from __future__ import annotations

import re

import time

from ..models import StageResult, StageStatus
from ..parsed_email import ParsedEmail
from ..domainutils import registrable_domain, normalize_confusables, levenshtein

FREEMAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me",
    "protonmail.com", "aol.com", "icloud.com", "yandex.com", "mail.com",
}

# Third-party SaaS/e-signature/file-share brands commonly named in a
# "'<name>' Via <Brand> Notifications" display-name shape — a doc/e-sign
# lure borrows the BRAND's trust, not an individual's, so it needs its own
# check distinct from VIP-name spoof below. List is deliberately small;
# extend as new abused brands turn up (same posture as FREEMAIL above —
# promote to a rules/*.txt file if this needs frequent, code-free tuning).
BRAND_DOMAINS = {
    "sharefile": {"sharefile.com", "citrix.com", "citrite.net"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe sign": {"adobesign.com", "echosign.com", "adobe.com"},
    "adobesign": {"adobesign.com", "echosign.com", "adobe.com"},
    "hellosign": {"hellosign.com", "dropboxsign.com"},
    "dropbox sign": {"hellosign.com", "dropboxsign.com"},
    "dropbox": {"dropbox.com", "dropboxsign.com"},
    "pandadoc": {"pandadoc.com"},
    "onedrive": {"microsoft.com", "sharepoint.com", "live.com", "office.com"},
    "sharepoint": {"microsoft.com", "sharepoint.com", "office.com"},
    "wetransfer": {"wetransfer.com"},
}


def run(pe: ParsedEmail, protected_domains: list[str], vip_names: list[str]) -> StageResult:
    t0 = time.perf_counter()
    flags: list[str] = []
    score = 0.0
    facts: dict = {}

    from_dom = registrable_domain(pe.from_domain)
    facts["from_domain"] = from_dom
    norm = normalize_confusables(from_dom)

    lookalike_of = None
    for p in protected_domains:
        p = registrable_domain(p)
        if from_dom == p:
            continue                        # exact match = legitimate, skip
        if norm == p:
            lookalike_of = p; break          # normalizes into a protected domain
        if levenshtein(norm, p, cap=1) <= 1:
            lookalike_of = p; break          # one edit away
    if lookalike_of:
        flags.append(f"lookalike_of:{lookalike_of}")
        facts["lookalike_of"] = lookalike_of
        score += 60

    # VIP display-name spoof: display name matches a protected exec name but the
    # sending domain is not a protected domain.
    display = pe.from_display.lower()
    protected_set = {registrable_domain(p) for p in protected_domains}
    if display and from_dom not in protected_set:
        for vip in vip_names:
            if vip.lower() in display:
                flags.append(f"vip_name_spoof:{vip}")
                facts["vip_name_spoof"] = vip
                score += 40
                break

    # Third-party brand spoof: display name claims a known e-sign/file-share
    # brand but the sending domain has no relationship to it.
    if display and from_dom not in protected_set:
        for brand, brand_doms in BRAND_DOMAINS.items():
            if re.search(rf"\b{re.escape(brand)}\b", display) and from_dom not in brand_doms:
                flags.append(f"brand_impersonation_display_name:{brand}")
                facts["brand_impersonation"] = brand
                score += 40
                break

    # Display name that is itself an email address differing from the real
    # sender. Mail clients show the display name prominently, so this reads as
    # "from NoReply.Payments@bank.com" while actually being someone else.
    display_raw = pe.from_display.strip()
    m = re.search(r"[\w.+-]+@([\w.-]+\.\w+)", display_raw)
    if m:
        display_dom = registrable_domain(m.group(1))
        facts["display_name_email_domain"] = display_dom
        if display_dom != from_dom:
            flags.append("display_name_email_mismatch"); score += 35
        else:
            flags.append("display_name_is_email"); score += 15

    # Corporate-claiming display name from a freemail domain
    if from_dom in FREEMAIL and any(
        kw in display for kw in ("support", "admin", "security", "it ", "helpdesk", "finance")
    ):
        flags.append("freemail_corporate_persona")
        score += 20

    # Enrichment hooks (not wired in the offline core)
    status = StageStatus.OK
    facts["domain_age_days"] = None          # RDAP hook
    facts["first_contact"] = None            # sender-history hook
    if facts["domain_age_days"] is None and facts["first_contact"] is None:
        status = StageStatus.DEGRADED        # honest: enrichment unavailable

    return StageResult(
        stage="sender",
        status=status,
        sub_score=min(score, 100.0),
        red_flags=flags,
        facts=facts,
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
