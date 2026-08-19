"""Stage — deception-structure composition.

Generalizes the TestFlight lesson: malice is often a *structure*, not a failed
auth check. Authentic mail from a trusted transactional platform + a foreign
mega-brand lure in the subject/body (+ optional Reply-To freemail handoff)
is service abuse — SPF/DKIM pass on purpose.

Data-driven via rules/trusted_platforms.yaml + rules/impersonation_brands.txt.
Emits structure flags; verdict.py hard-overrides on the composed service-abuse
signal. Never sets result.verdict itself (CLAUDE.md invariant).
"""
from __future__ import annotations

import re
import time
from typing import Optional
from urllib.parse import urlparse

from ..lists import impersonation_brands, trusted_platforms
from ..models import StageResult, StageStatus
from ..parsed_email import ParsedEmail
from ..domainutils import registrable_domain


def _host(url: str) -> str:
    try:
        h = urlparse(url).hostname or ""
    except Exception:
        h = ""
    if not h:
        h = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split("?")[0]
        h = h.split("@")[-1].split(":")[0]
    return h.lower().rstrip(".")


def _brand_pattern(token: str) -> re.Pattern:
    parts = token.split()
    if len(parts) > 1:
        body = r"\s+".join(re.escape(p) for p in parts)
    else:
        body = re.escape(token)
    return re.compile(rf"\b{body}\b", re.I)


def find_foreign_brand_hits(blob: str, brands: list[str], owned: list[str]) -> list[str]:
    """Return impersonation-brand tokens found in blob that are not platform-owned."""
    owned_set = {o.strip().lower() for o in owned if o and o.strip()}
    hits = []
    for brand in brands:
        b = (brand or "").strip().lower()
        if not b or b in owned_set:
            continue
        if _brand_pattern(b).search(blob or ""):
            hits.append(b)
    return hits


def _message_blob(pe: ParsedEmail) -> str:
    return f"{pe.header('Subject') or ''}\n{pe.text_body()}\n{pe.html_body()}"


def _url_hosts(url_facts: dict) -> set[str]:
    hosts = set()
    for rec in (url_facts or {}).get("urls") or []:
        if not isinstance(rec, dict):
            continue
        h = (rec.get("host") or "").lower().rstrip(".")
        if h:
            hosts.add(h)
        u = rec.get("url") or ""
        if u:
            hosts.add(_host(u))
    return {h for h in hosts if h}


def _platform_link_hit(hosts: set[str], link_hosts: list[str]) -> bool:
    for want in link_hosts:
        want = want.lower().rstrip(".")
        if want in hosts:
            return True
        # allow subdomain of an exact configured host only when equal
        # (testflight.apple.com must match exactly, not apple.com broadly)
    return False


def _from_matches_platform(from_dom: str, from_domains: list[str]) -> bool:
    from_dom = (from_dom or "").lower().rstrip(".")
    return from_dom in {d.lower().rstrip(".") for d in from_domains}


def run(pe: ParsedEmail, header_facts: Optional[dict] = None,
        url_facts: Optional[dict] = None) -> StageResult:
    t0 = time.perf_counter()
    header_facts = header_facts or {}
    url_facts = url_facts or {}

    from_dom = registrable_domain(pe.from_domain) or header_facts.get("from_domain") or ""
    from_dom = (from_dom or "").lower().rstrip(".")
    hosts = _url_hosts(url_facts)
    # If urls stage skipped (no links), still allow pe.urls() for platform match.
    if not hosts:
        for u in pe.urls() or []:
            hosts.add(_host(u))

    blob = _message_blob(pe)
    brands = impersonation_brands()
    platforms = trusted_platforms()

    flags: list[str] = []
    score = 0.0
    facts: dict = {
        "from_domain": from_dom,
        "url_hosts": sorted(hosts),
        "matched_platform": None,
        "foreign_brands": [],
    }

    reply_to_freemail = bool(header_facts.get("reply_to_freemail"))
    brand_mismatch = False
    matched_id = None

    for plat in platforms:
        if not _from_matches_platform(from_dom, plat["from_domains"]):
            continue
        # Trusted From alone + freemail Reply-To (weighted reinforcer).
        if reply_to_freemail and "trusted_channel_reply_to_freemail" not in flags:
            flags.append("trusted_channel_reply_to_freemail")
            score += 15

        if not _platform_link_hit(hosts, plat["link_hosts"]):
            continue

        hits = find_foreign_brand_hits(blob, brands, plat["owned_brand_tokens"])
        if not hits:
            continue

        brand_mismatch = True
        matched_id = plat["id"]
        facts["matched_platform"] = matched_id
        facts["foreign_brands"] = hits
        flags.append("trusted_channel_brand_mismatch")
        flags.append("deception_structure_service_abuse")
        # Backward-compatible alias for the original TestFlight hard override /
        # tests / analyst copy.
        if matched_id == "apple_testflight":
            flags.append("service_abuse_testflight_brand_lure")
        else:
            flags.append(f"service_abuse:{matched_id}")
        score += 70
        break  # one platform match is enough for the hard-override path

    if not platforms:
        status = StageStatus.DEGRADED
        facts["error"] = "no_trusted_platforms_configured"
    elif not flags and not hosts:
        status = StageStatus.SKIPPED if not pe.urls() else StageStatus.OK
    else:
        status = StageStatus.OK

    # Empty mail with no platforms hit: OK with zero score (not skipped) so
    # stage ordering stays stable in reports.
    if not flags and status != StageStatus.DEGRADED:
        status = StageStatus.OK

    return StageResult(
        stage="deception",
        status=status,
        sub_score=min(score, 100.0),
        red_flags=sorted(set(flags)),
        facts=facts,
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
