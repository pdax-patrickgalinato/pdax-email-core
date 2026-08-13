"""Domain dataclasses shared across fetch, scoring, LLM, and UI."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

@dataclass(frozen=True)
class FeedSource:
    name: str
    url: str
    category: str
    authority: float = 1.0          # multiplier applied to the final score
    sectors: Tuple[str, ...] = ()   # industries this source is especially relevant to
    note: str = ""


@dataclass
class FetchResult:
    source: FeedSource
    ok: bool
    entries: int = 0
    error: str = ""
    latency_ms: int = 0
    from_cache: bool = False
    feed_title: str = ""


@dataclass
class Article:
    title: str
    link: str
    summary: str
    source_name: str
    category: str
    published: Optional[datetime]
    published_raw: str
    score: float = 0.0
    breakdown: Dict[str, float] = field(default_factory=dict)
    matched_tech: List[str] = field(default_factory=list)
    matched_keywords: List[str] = field(default_factory=list)
    matched_industry: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    recommendation: str = ""
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    cta_signals: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    ransomware_families: List[str] = field(default_factory=list)
    kev_cves: List[str] = field(default_factory=list)
    correlated_sources: List[str] = field(default_factory=list)
    llm_analysis: Dict = field(default_factory=dict)



def article_llm(article: Article) -> dict:
    """Safe read — session may still hold Article instances from before llm_analysis existed."""
    return getattr(article, "llm_analysis", None) or {}


def set_article_llm(article: Article, analysis: dict) -> None:
    try:
        article.llm_analysis = analysis
    except Exception:  # noqa: BLE001
        setattr(article, "llm_analysis", analysis)
