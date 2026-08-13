"""Company-contextual scoring, intel extraction, and deep-scan helpers."""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple

import streamlit as st

from concurrent.futures import ThreadPoolExecutor, as_completed

from sentinel.config import BAND_COLORS, MAX_WORKERS, PH_TZ
from sentinel.fetch import fetch_article_text, kev_hits_for
from sentinel.intel_data import (
    CTA_SIGNALS, CVE_RE, CVSS_RE, EXPLOIT_SIGNALS, IOC_PATTERNS, INDUSTRY_PROFILES,
    MALWARE_COMPILED, MITRE_TACTICS, MITRE_TECHNIQUE_RE, RANSOMWARE_COMPILED,
    SEVERITY_SIGNALS, THREAT_ACTOR_COMPILED, _match_aliases,
)
from sentinel.ioc_utils import _llm_ioc_label, _refang_ioc
from sentinel.models import Article, FeedSource, article_llm



def parse_terms(blob: str) -> List[str]:
    """Accept newlines, commas, semicolons and 'Label: a, b, c' formats."""
    terms: List[str] = []
    for line in (blob or "").splitlines():
        if ":" in line and len(line.split(":", 1)[0]) < 40:
            line = line.split(":", 1)[1]
        for chunk in re.split(r"[,;|]", line):
            term = chunk.strip().strip("-•*").strip()
            if len(term) >= 2:
                terms.append(term)
    seen, out = set(), []
    for t in terms:
        if t.lower() not in seen:
            seen.add(t.lower())
            out.append(t)
    return out


def _term_pattern(term: str) -> re.Pattern:
    escaped = re.escape(term)
    prefix = r"\b" if term[:1].isalnum() else ""
    suffix = r"\b" if term[-1:].isalnum() else ""
    return re.compile(prefix + escaped + suffix, re.IGNORECASE)


@st.cache_data(show_spinner=False)
def compile_terms(terms: Tuple[str, ...]) -> List[Tuple[str, re.Pattern]]:
    return [(t, _term_pattern(t)) for t in terms]


def _find(text: str, compiled: Iterable[Tuple[str, re.Pattern]]) -> List[str]:
    return [term for term, pat in compiled if pat.search(text)]


def score_article(article: Article, source: FeedSource, cfg: dict) -> Article:
    haystack = f"{article.title}\n{article.summary}"
    title_only = article.title

    matched_tech = _find(haystack, cfg["tech_compiled"])
    matched_kw = _find(haystack, cfg["kw_compiled"])
    matched_ind = _find(haystack, cfg["industry_compiled"])

    threat_actors = _match_aliases(haystack, THREAT_ACTOR_COMPILED)
    malware_families = _match_aliases(haystack, MALWARE_COMPILED)
    ransomware_families = _match_aliases(haystack, RANSOMWARE_COMPILED)

    breakdown: Dict[str, float] = {}
    flags: List[str] = []

    # 1. Tech stack — the single strongest signal that an item is *yours*.
    tech_pts = min(len(matched_tech), 4) * cfg["w_tech"]
    title_tech = [t for t in matched_tech if _term_pattern(t).search(title_only)]
    if title_tech:
        tech_pts += cfg["w_tech"] * 0.5
        flags.append("Stack named in headline")
    if tech_pts:
        breakdown["Tech stack match"] = round(tech_pts, 1)

    # 2. Focus keywords.
    kw_pts = min(len(matched_kw), 5) * cfg["w_keyword"]
    if kw_pts:
        breakdown["Focus keywords"] = round(kw_pts, 1)

    # 3. Exploitation and severity language.
    exploit_hits = [s for s in EXPLOIT_SIGNALS if s in haystack.lower()]
    severity_hits = [s for s in SEVERITY_SIGNALS if s in haystack.lower()]
    exploit_pts = min(len(exploit_hits), 3) * cfg["w_exploit"]
    severity_pts = min(len(severity_hits), 3) * (cfg["w_exploit"] * 0.35)
    if exploit_pts:
        breakdown["Active exploitation language"] = round(exploit_pts, 1)
        flags.append("Exploitation reported")
    if severity_pts:
        breakdown["Severity language"] = round(severity_pts, 1)

    # 4. CVE presence and CVSS.
    cves = sorted(set(m.upper() for m in CVE_RE.findall(haystack)))
    cve_pts = min(len(cves), 3) * cfg["w_cve"]
    cvss_match = CVSS_RE.search(haystack)
    if cvss_match:
        try:
            cvss = float(cvss_match.group(1))
            if cvss >= 9.0:
                cve_pts += cfg["w_cve"] * 2
                flags.append(f"CVSS {cvss}")
            elif cvss >= 7.0:
                cve_pts += cfg["w_cve"]
        except ValueError:
            pass
    if cve_pts:
        breakdown["CVE / CVSS signal"] = round(cve_pts, 1)
    if cves:
        flags.append(f"{len(cves)} CVE(s)")

    # 4b. CISA KEV catalog hit — known-exploited CVEs jump the queue.
    kev_cves = kev_hits_for(cves, cfg.get("kev") or {})
    if kev_cves:
        kev_pts = min(len(kev_cves), 3) * cfg.get("w_kev", 18)
        breakdown["CISA KEV catalog"] = round(kev_pts, 1)
        flags.append(f"KEV: {', '.join(kev_cves[:3])}")
        # Ransomware-linked KEV entries get an extra nudge.
        catalog = (cfg.get("kev") or {}).get("cves") or {}
        if any((catalog.get(c) or {}).get("ransomware_use", "").lower() == "known"
               for c in kev_cves):
            breakdown["KEV ransomware-linked"] = round(cfg.get("w_kev", 18) * 0.4, 1)
            flags.append("KEV ransomware-linked")

    # 4c. Named threat actors / malware / ransomware families.
    actor_pts = min(len(threat_actors), 3) * cfg.get("w_actor", 10)
    if actor_pts:
        breakdown["Threat actor named"] = round(actor_pts, 1)
        flags.append(f"Actor: {threat_actors[0]}")
    malware_pts = min(len(malware_families), 3) * cfg.get("w_malware", 6)
    if malware_pts:
        breakdown["Malware family named"] = round(malware_pts, 1)
    ransom_pts = min(len(ransomware_families), 3) * cfg.get("w_ransomware", 8)
    if ransom_pts:
        breakdown["Ransomware family named"] = round(ransom_pts, 1)
        flags.append(f"Ransomware: {ransomware_families[0]}")

    # 5. Recency.
    age_days = 999.0
    if article.published:
        age_days = max(0.0, (datetime.now(timezone.utc) - article.published).total_seconds() / 86400)
    recency_pts = cfg["w_recency"] * max(0.0, 1 - (age_days / max(cfg["max_age_days"], 1)))
    if recency_pts:
        breakdown["Recency"] = round(recency_pts, 1)
    if age_days <= 1:
        flags.append("Published <24h")

    subtotal = sum(breakdown.values())

    # 6. Industry multiplier — heavy priority when the story is about your sector.
    ind_mult = 1.0
    if matched_ind:
        ind_mult = min(1.0 + cfg["w_industry_step"] * len(set(matched_ind)), cfg["w_industry_cap"])
        breakdown["Industry multiplier"] = round(ind_mult, 2)
    if cfg["industry"] in source.sectors:
        subtotal += cfg["w_sector_source"]
        breakdown["Sector-aligned source"] = float(cfg["w_sector_source"])
        flags.append("Sector authority")

    # 7. Source authority multiplier.
    auth_mult = 1.0 + (source.authority - 1.0) * cfg["w_authority_scale"]
    if abs(auth_mult - 1.0) > 0.001:
        breakdown["Source authority"] = round(auth_mult, 2)

    raw = subtotal * ind_mult * auth_mult

    # Relevance gate: without a stack, keyword, industry, actor or KEV hit an item is noise.
    if (not matched_tech and not matched_kw and not matched_ind
            and not threat_actors and not kev_cves and not ransomware_families):
        raw *= 0.45

    breakdown["Raw total (pre-curve)"] = round(raw, 1)

    # Soft cap: compress to 0–100 so genuinely exceptional items still out-rank
    # merely strong ones instead of everything piling up against a hard ceiling.
    midpoint = max(float(cfg.get("curve_midpoint", 60.0)), 5.0)
    article.score = round(100.0 * (1.0 - math.exp(-raw / midpoint)), 1)
    article.breakdown = breakdown
    article.matched_tech = matched_tech
    article.matched_keywords = matched_kw
    article.matched_industry = sorted(set(matched_ind))
    article.cves = cves
    article.kev_cves = kev_cves
    article.threat_actors = threat_actors
    article.malware_families = malware_families
    article.ransomware_families = ransomware_families
    article.flags = flags
    article.recommendation = recommend(article)
    return article


def recommend(a: Article) -> str:
    exploited = "Exploitation reported" in a.flags
    on_kev = bool(a.kev_cves)
    if a.score >= 70 and a.matched_tech and (exploited or on_kev):
        return "Critical — confirm exposure and patch"
    if a.score >= 65 and on_kev:
        return "Critical — CVE is on CISA KEV"
    if a.score >= 60 and a.matched_tech:
        return "High — check affected assets"
    if a.score >= 60 and a.threat_actors:
        return "High — threat actor activity"
    if a.score >= 60:
        return "High — assess relevance"
    if a.score >= 40:
        return "Medium — add to intel round-up"
    if a.score >= 20:
        return "Low — situational awareness"
    return "Informational — no action expected"


def _scan_intel_signals(haystack: str, exclude: str = "", cap: int = 10) -> dict:
    """Shared IOC / MITRE ATT&CK / TTP / CTA / actor scan, used for both the RSS summary and
    (on demand) the full fetched article text."""
    haystack_lower = haystack.lower()

    iocs: Dict[str, List[str]] = {}
    for label, pattern in IOC_PATTERNS:
        hits = sorted(set(pattern.findall(haystack)))
        hits = [h.rstrip(".,);'\"") for h in hits]
        hits = [h for h in dict.fromkeys(hits) if h and h != exclude]
        if hits:
            iocs[label] = hits[:cap]

    return {
        "iocs": iocs,
        "techniques": sorted(set(m.upper() for m in MITRE_TECHNIQUE_RE.findall(haystack))),
        "tactics": [name for phrase, name in MITRE_TACTICS if phrase in haystack_lower],
        "cta_signals": [s for s in CTA_SIGNALS if s in haystack_lower],
        "cves": sorted(set(m.upper() for m in CVE_RE.findall(haystack))),
        "threat_actors": _match_aliases(haystack, THREAT_ACTOR_COMPILED),
        "malware_families": _match_aliases(haystack, MALWARE_COMPILED),
        "ransomware_families": _match_aliases(haystack, RANSOMWARE_COMPILED),
    }


def extract_intel(article: Article) -> Article:
    """Pull IOCs, MITRE ATT&CK, actors/malware and CTA language out of the text."""
    signals = _scan_intel_signals(f"{article.title}\n{article.summary}", exclude=article.link)
    article.iocs = signals["iocs"]
    article.mitre_techniques = signals["techniques"]
    article.mitre_tactics = signals["tactics"]
    article.cta_signals = signals["cta_signals"]
    # Prefer the richer set from the scan; scoring already populated these, so merge.
    article.threat_actors = list(dict.fromkeys(
        article.threat_actors + signals["threat_actors"]
    ))
    article.malware_families = list(dict.fromkeys(
        article.malware_families + signals["malware_families"]
    ))
    article.ransomware_families = list(dict.fromkeys(
        article.ransomware_families + signals["ransomware_families"]
    ))
    return article


def correlate_articles(articles: List[Article], boost: float = 8.0) -> List[Article]:
    """Boost items whose CVEs or near-identical titles appear across multiple sources —
    independent corroboration is a strong CTI confidence signal."""
    by_cve: Dict[str, List[Article]] = {}
    for a in articles:
        for cve in a.cves:
            by_cve.setdefault(cve, []).append(a)

    # Title fingerprint: first ~10 significant tokens.
    def _title_key(title: str) -> str:
        tokens = re.findall(r"[a-z0-9]{3,}", title.lower())
        return " ".join(tokens[:10])

    by_title: Dict[str, List[Article]] = {}
    for a in articles:
        key = _title_key(a.title)
        if len(key) >= 12:
            by_title.setdefault(key, []).append(a)

    for a in articles:
        peer_sources: Set[str] = set()
        for cve in a.cves:
            for peer in by_cve.get(cve, []):
                if peer is not a and peer.source_name != a.source_name:
                    peer_sources.add(peer.source_name)
        for peer in by_title.get(_title_key(a.title), []):
            if peer is not a and peer.source_name != a.source_name:
                peer_sources.add(peer.source_name)

        if not peer_sources:
            continue
        a.correlated_sources = sorted(peer_sources)
        extra = min(len(peer_sources), 4) * boost
        # Re-curve: convert current curved score back roughly by adding to raw-ish points.
        # Simpler and stable: bump the displayed score with a soft ceiling.
        a.score = round(min(100.0, a.score + min(extra, 18.0)), 1)
        a.breakdown["Cross-source corroboration"] = round(min(extra, 18.0), 1)
        a.flags.append(f"Corroborated by {len(peer_sources)} source(s)")
        a.recommendation = recommend(a)
    return articles


def band_of(rec: str) -> str:
    return rec.split(" —")[0]


def build_executive_summary(a: Article) -> str:
    """Deterministic, rule-based exec paragraph — no external model calls, just a synthesis
    of fields we already scored/extracted."""
    band = band_of(a.recommendation)
    pub = a.published.strftime("%d %b %Y") if a.published else "an unknown date"
    sentences = [
        f"**{a.title}** was published by {a.source_name} ({a.category}) on {pub} and scored "
        f"**{a.score:g}/100**, placing it in the **{band}** band."
    ]
    if a.kev_cves:
        sentences.append(
            f"CISA KEV lists {', '.join(a.kev_cves)} — treat as confirmed in-the-wild exploitation."
        )
    elif "Exploitation reported" in a.flags:
        sentences.append("Active exploitation of this issue has been reported in the wild.")
    if a.cves:
        sentences.append(f"It references {len(a.cves)} CVE(s): {', '.join(a.cves)}.")
    if a.threat_actors:
        sentences.append(f"Named threat actor(s): {', '.join(a.threat_actors)}.")
    if a.ransomware_families:
        sentences.append(f"Ransomware family(ies): {', '.join(a.ransomware_families)}.")
    if a.malware_families:
        sentences.append(f"Malware family(ies): {', '.join(a.malware_families)}.")
    if a.matched_tech:
        sentences.append(f"It directly names components of your stack: {', '.join(a.matched_tech)}.")
    if a.matched_industry:
        sentences.append(f"It touches your industry focus areas: {', '.join(a.matched_industry)}.")
    if a.matched_keywords:
        sentences.append(f"It matches tracked threat focus keywords: {', '.join(a.matched_keywords)}.")
    if a.correlated_sources:
        sentences.append(
            f"Independently corroborated by: {', '.join(a.correlated_sources)}."
        )
    if a.summary:
        sentences.append(a.summary)
    return " ".join(sentences)


def collect_all_iocs(articles: List[Article], enrichment_cache: dict,
                     llm_cache: Optional[dict] = None) -> Dict[str, List[str]]:
    """Union of IOCs across the corpus (RSS + full-article + LLM enrichments)."""
    merged: Dict[str, Set[str]] = {}
    llm_cache = llm_cache or {}
    for a in articles:
        buckets = {k: set(v) for k, v in a.iocs.items()}
        key = a.link or f"title::{a.title}"
        cached = enrichment_cache.get(key)
        if cached and not cached.get("error"):
            for label, values in (cached.get("iocs") or {}).items():
                buckets.setdefault(label, set()).update(values)
        llm = article_llm(a) or llm_cache.get(key) or {}
        if llm and not llm.get("error"):
            for row in llm.get("iocs") or []:
                if not isinstance(row, dict):
                    continue
                label = _llm_ioc_label(str(row.get("type") or "Other"))
                val = _refang_ioc(str(row.get("value") or ""))
                if val and row.get("actionable", True) is not False:
                    buckets.setdefault(label, set()).add(val)
        for label, values in buckets.items():
            merged.setdefault(label, set()).update(values)
    return {k: sorted(v) for k, v in sorted(merged.items())}
def dedupe(articles: List[Article]) -> List[Article]:
    seen: Dict[str, Article] = {}
    for a in articles:
        key = a.link.strip().lower() or re.sub(r"[^a-z0-9]", "", a.title.lower())[:80]
        existing = seen.get(key)
        if existing is None or a.score > existing.score:
            seen[key] = a
    return list(seen.values())


def _merge_intel_into_article(a: Article, signals: dict) -> None:
    """Fold a full-article intel scan back into the Article so every tab/export reflects it."""
    for label, values in (signals.get("iocs") or {}).items():
        merged = sorted(set(a.iocs.get(label, []) + list(values)))[:120]
        a.iocs[label] = merged
    a.mitre_techniques = sorted(set(a.mitre_techniques + signals.get("techniques", [])))
    a.mitre_tactics = list(dict.fromkeys(a.mitre_tactics + signals.get("tactics", [])))
    a.cta_signals = list(dict.fromkeys(a.cta_signals + signals.get("cta_signals", [])))
    a.threat_actors = list(dict.fromkeys(a.threat_actors + signals.get("threat_actors", [])))
    a.malware_families = list(dict.fromkeys(a.malware_families + signals.get("malware_families", [])))
    a.ransomware_families = list(dict.fromkeys(
        a.ransomware_families + signals.get("ransomware_families", [])))
    new_cves = [c for c in signals.get("cves", []) if c not in a.cves]
    if new_cves:
        a.cves = sorted(set(a.cves + new_cves))


def deep_enrich_top(articles: List[Article], n: int, timeout: int,
                    kev: dict, progress_cb=None) -> int:
    """Fetch the full page for the top-N scored items and merge IOCs / ATT&CK / actors back in.

    This is the heavy-lifting "gather more intel" pass: RSS summaries are usually truncated,
    so pulling the article body surfaces hashes, IPs, techniques and named actors the feed hid.
    Returns the number of articles successfully enriched.
    """
    targets = [a for a in articles[:n] if a.link]
    if not targets:
        return 0
    cache: Dict[str, dict] = st.session_state.setdefault("_enrichment_cache", {})
    catalog = (kev or {}).get("cves") or {}

    def _work(a: Article):
        text, err = fetch_article_text(a.link, timeout=timeout)
        return a, text, err

    enriched = 0
    done = 0
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(targets))) as pool:
        futures = {pool.submit(_work, a): a for a in targets}
        for fut in as_completed(futures):
            a, text, err = fut.result()
            key = a.link or f"title::{a.title}"
            if err:
                cache[key] = {"error": err}
            else:
                signals = _scan_intel_signals(text, exclude=a.link, cap=25)
                signals["error"] = ""
                signals["chars"] = len(text)
                cache[key] = signals
                _merge_intel_into_article(a, signals)
                # Newly-found CVEs may now be on KEV — refresh that flag.
                a.kev_cves = kev_hits_for(a.cves, kev or {})
                if a.kev_cves and not any(f.startswith("KEV:") for f in a.flags):
                    a.flags.append(f"KEV: {', '.join(a.kev_cves[:3])}")
                enriched += 1
            done += 1
            if progress_cb:
                progress_cb(done, len(targets))
    return enriched

