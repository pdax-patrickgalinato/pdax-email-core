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

from ..models import HeaderFacts, StageResult, StageStatus
from ..parsed_email import ParsedEmail
from ..domainutils import registrable_domain

_AR_TOKEN = {
    "spf": re.compile(r"spf=(\w+)", re.I),
    "dkim": re.compile(r"dkim=(\w+)", re.I),
    "dmarc": re.compile(r"dmarc=(\w+)", re.I),
}
_DMARC_POLICY = re.compile(r"p=(\w+)", re.I)
_PRECEDENCE_BULK = re.compile(r"\b(bulk|list|junk)\b", re.I)
_ONE_CLICK_UNSUB = re.compile(r"List-Unsubscribe\s*=\s*One-Click", re.I)


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

    # Advanced Spam Protection: bulk-mail signals.
    list_unsub = pe.msg.get("List-Unsubscribe")
    list_unsub_post = pe.msg.get("List-Unsubscribe-Post", "")
    precedence = pe.msg.get("Precedence", "")
    facts.has_list_unsubscribe = bool(list_unsub)
    facts.list_unsubscribe_one_click = bool(_ONE_CLICK_UNSUB.search(list_unsub_post))
    facts.precedence_bulk = bool(_PRECEDENCE_BULK.search(precedence))
    facts.has_list_id = bool(pe.msg.get("List-Id"))

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
    # Mail presenting as bulk (Precedence: bulk/list/junk, or a List-Id) but
    # missing the List-Unsubscribe header legitimate bulk senders are
    # required to include (CAN-SPAM/RFC 8058) — spam frequently omits or
    # fakes this. Small, low-confidence, weighted-only signal on purpose —
    # not a full spam classifier, see module docstring.
    if (facts.precedence_bulk or facts.has_list_id) and not facts.has_list_unsubscribe:
        flags.append("bulk_sender_no_unsubscribe"); score += 18

    return StageResult(
        stage="headers",
        status=StageStatus.OK,
        sub_score=min(score, 100.0),
        red_flags=flags,
        facts=facts.model_dump(),
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
