"""Stage 7 — Threat intelligence.

Pluggable IntelClient. Offline core ships LocalIOCClient (checks a provided
set of known-bad indicators — the same set the gateway keeps in Redis). A
real client (VirusTotal/AbuseIPDB, reused from Bantay SOC) implements the
same interface and sets DEGRADED on provider outage."""
from __future__ import annotations

import time
from typing import Protocol

from ..models import StageResult, StageStatus
from ..parsed_email import ParsedEmail
from ..domainutils import registrable_domain


class IntelClient(Protocol):
    def check(self, domains: list[str], ips: list[str], urls: list[str],
              hashes: list[str]) -> tuple[list[str], bool]:
        """Return (hit_indicators, degraded)."""
        ...


class LocalIOCClient:
    def __init__(self, bad_domains=None, bad_ips=None, bad_urls=None, bad_hashes=None):
        self.bad_domains = {registrable_domain(d) for d in (bad_domains or [])}
        self.bad_ips = set(bad_ips or [])
        self.bad_urls = set(bad_urls or [])
        self.bad_hashes = set(bad_hashes or [])

    def check(self, domains, ips, urls, hashes):
        hits = []
        for d in domains:
            if registrable_domain(d) in self.bad_domains:
                hits.append(f"intel_domain:{d}")
        hits += [f"intel_ip:{i}" for i in ips if i in self.bad_ips]
        hits += [f"intel_url:{u}" for u in urls if u in self.bad_urls]
        hits += [f"intel_hash:{h}" for h in hashes if h in self.bad_hashes]
        return hits, False


def run(pe: ParsedEmail, client: IntelClient, url_stage_facts: dict,
        attach_facts: dict) -> StageResult:
    t0 = time.perf_counter()
    domains = [pe.from_domain] + [u.get("reg_domain", "") for u in url_stage_facts.get("urls", [])]
    domains = [d for d in domains if d]
    # IP-literal URL hosts + public IPs from the Received chain — previously
    # always passed as [] here, meaning IP-based intel matching was
    # structurally impossible regardless of what the IntelClient supported.
    ips = [u.get("ip", "") for u in url_stage_facts.get("urls", [])] + pe.originating_ips()
    ips = [i for i in ips if i]
    urls = [u.get("url", "") for u in url_stage_facts.get("urls", [])]
    hashes = [a.get("sha256", "") for a in attach_facts.get("attachments", [])]

    hits, degraded = client.check(domains, ips, urls, hashes)
    score = 90.0 if hits else 0.0     # an intel hit is a strong signal
    return StageResult(
        stage="intel",
        status=StageStatus.DEGRADED if degraded else StageStatus.OK,
        sub_score=score,
        red_flags=hits,
        facts={"checked_domains": sorted(set(domains)), "checked_ips": sorted(set(ips)), "hits": hits},
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
