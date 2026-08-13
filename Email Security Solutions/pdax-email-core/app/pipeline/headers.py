"""Stage 1 — Header analysis.

Parses the Authentication-Results header (authoritative when the message
already transited a trusted resolver like Google) plus Return-Path / Reply-To /
Message-ID anomalies. In the gateway, Rspamd re-verifies DKIM/DMARC
cryptographically; here we read the AR header so the core runs offline.
"""
from __future__ import annotations

import re
import time

from ..models import HeaderFacts, StageResult, StageStatus
from ..parsed_email import ParsedEmail
from ..domainutils import registrable_domain

_AR_TOKEN = {
    "spf": re.compile(r"spf=(\w+)", re.I),
    "dkim": re.compile(r"dkim=(\w+)", re.I),
    "dmarc": re.compile(r"dmarc=(\w+)", re.I),
}
_DMARC_POLICY = re.compile(r"p=(\w+)", re.I)


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
        message_id_domain=pe.message_id_domain,
    )
    # alignment: DMARC passes only if SPF or DKIM aligns with the From domain
    facts.dmarc_aligned = facts.dmarc == "pass"

    flags: list[str] = []
    score = 0.0
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

    return StageResult(
        stage="headers",
        status=StageStatus.OK,
        sub_score=min(score, 100.0),
        red_flags=flags,
        facts=facts.model_dump(),
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
