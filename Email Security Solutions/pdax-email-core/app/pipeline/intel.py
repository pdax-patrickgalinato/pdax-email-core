"""Stage 7 — Threat intelligence.

Pluggable IntelClient. Offline core ships LocalIOCClient (checks a provided
set of known-bad indicators — the same set the gateway keeps in Redis).
VTAbuseIPDBIntelClient (below) is the real implementation — a standalone
client written directly against VirusTotal's and AbuseIPDB's free-tier
public REST APIs (no dependency on any external/unknown client code — see
CLAUDE.md's "keep this standalone" steer), with a local SQLite cache so
free-tier rate limits are survivable. Both set DEGRADED on provider outage.

Also folds in the local verdict-history correlation lookup (see
app/pipeline/correlation.py) — PDAX's own in-house substitute for Trend
Micro's cross-customer Correlated Intelligence, since no in-house tool can
replicate a global sensor network. That lookup is deliberately weighted-only,
never a hard override — see verdict.py."""
from __future__ import annotations

import json
import os
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional, Protocol

from ..models import StageResult, StageStatus
from ..parsed_email import ParsedEmail
from ..domainutils import registrable_domain
from . import correlation as correlation_mod


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


_DEFAULT_CACHE_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "intel_cache.sqlite3"
_CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_cache (
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    source TEXT NOT NULL,
    verdict TEXT NOT NULL,
    checked_at REAL NOT NULL,
    raw_response TEXT,
    PRIMARY KEY (indicator, source)
);
"""


class IntelCache:
    """SQLite cache with a TTL — what makes free-tier VT/AbuseIPDB rate
    limits survivable. Caches both hits and misses (a confirmed-clean
    indicator is just as worth not re-querying as a confirmed-bad one)."""

    def __init__(self, db_path: Optional[Path] = None, ttl_seconds: float = 6 * 3600):
        self.db_path = Path(db_path) if db_path else _DEFAULT_CACHE_DB_PATH
        self.ttl_seconds = ttl_seconds

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        conn.executescript(_CACHE_SCHEMA)
        return conn

    def get(self, indicator: str, indicator_type: str, source: str) -> Optional[str]:
        """Returns the cached verdict ("malicious"/"clean") if fresh, else
        None (cache miss or expired — caller should query the real API).
        Degrades to None (i.e. "go ask the API") on any storage error."""
        try:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT verdict, checked_at FROM intel_cache "
                    "WHERE indicator = ? AND source = ?",
                    (indicator, source),
                ).fetchone()
                if row is None:
                    return None
                verdict, checked_at = row
                if (time.time() - checked_at) > self.ttl_seconds:
                    return None
                return verdict
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return None

    def put(self, indicator: str, indicator_type: str, source: str, verdict: str,
           raw_response: str = "") -> None:
        try:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO intel_cache (indicator, indicator_type, source, verdict, checked_at, raw_response) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(indicator, source) DO UPDATE SET "
                    "verdict=excluded.verdict, checked_at=excluded.checked_at, raw_response=excluded.raw_response",
                    (indicator, indicator_type, source, verdict, time.time(), raw_response[:4000]),
                )
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            pass   # caching is an optimization, never a hard requirement


class VTAbuseIPDBIntelClient:
    """Standalone client against VirusTotal's and AbuseIPDB's free-tier
    public REST APIs — written fresh, no dependency on any external/unknown
    client code (see module docstring). Domains/URLs/hashes go to VirusTotal;
    IPs go to AbuseIPDB (its specialty) and, as a second opinion, VirusTotal
    too if a VT key is configured.

    Both providers are optional independently — set SEG_VT_API_KEY and/or
    SEG_ABUSEIPDB_API_KEY (both free-tier signups). With neither key set,
    check() degrades honestly (empty hits, degraded=True) rather than
    raising, same contract as every other provider in this codebase.

    Free-tier rate limits (VT: 4 req/min, 500/day; AbuseIPDB: 1000/day) are
    respected via IntelCache (skip the call entirely on a cache hit) plus a
    simple time.sleep-based throttle between real calls — this is a
    correctness/politeness measure, not a guarantee against exhausting a
    given day's quota on a very large corpus.
    """

    _VT_MALICIOUS_THRESHOLD = 1        # any VT engine flagging malicious counts
    _ABUSEIPDB_SCORE_THRESHOLD = 50    # abuseConfidenceScore is 0-100

    def __init__(self, vt_api_key: Optional[str] = None, abuseipdb_api_key: Optional[str] = None,
                 cache: Optional[IntelCache] = None, http_get=None,
                 vt_min_interval_seconds: float = 15.0):
        self.vt_api_key = vt_api_key or os.environ.get("SEG_VT_API_KEY")
        self.abuseipdb_api_key = abuseipdb_api_key or os.environ.get("SEG_ABUSEIPDB_API_KEY")
        self.cache = cache or IntelCache()
        self._http_get = http_get or self._default_http_get   # injectable for tests
        self._vt_min_interval = vt_min_interval_seconds        # VT free tier: 4 req/min
        self._vt_last_call = 0.0

    @staticmethod
    def _default_http_get(url: str, headers: dict) -> tuple:
        """Returns (status_code, parsed_json_or_None). Never raises past this
        point — a connection error/timeout/non-JSON body is reported as a
        non-200-shaped result the caller treats as a miss/degrade."""
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", "replace")
                return resp.status, (json.loads(body) if body else None)
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode("utf-8", "replace"))
            except Exception:
                return e.code, None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return 0, None

    def _vt_throttle(self):
        elapsed = time.time() - self._vt_last_call
        if elapsed < self._vt_min_interval:
            time.sleep(self._vt_min_interval - elapsed)
        self._vt_last_call = time.time()

    def _vt_check(self, path: str, indicator: str, indicator_type: str) -> Optional[bool]:
        """Returns True (malicious), False (clean), or None (degraded/error —
        caller should not trust this result either way)."""
        cached = self.cache.get(indicator, indicator_type, "virustotal")
        if cached is not None:
            return cached == "malicious"
        if not self.vt_api_key:
            return None
        self._vt_throttle()
        status, data = self._http_get(
            f"https://www.virustotal.com/api/v3/{path}",
            {"x-apikey": self.vt_api_key},
        )
        if status != 200 or not data:
            return None
        stats = (data.get("data", {}).get("attributes", {}) or {}).get("last_analysis_stats", {})
        malicious = bool(stats) and stats.get("malicious", 0) >= self._VT_MALICIOUS_THRESHOLD
        self.cache.put(indicator, indicator_type, "virustotal",
                       "malicious" if malicious else "clean", json.dumps(stats))
        return malicious

    def _abuseipdb_check(self, ip: str) -> Optional[bool]:
        cached = self.cache.get(ip, "ip", "abuseipdb")
        if cached is not None:
            return cached == "malicious"
        if not self.abuseipdb_api_key:
            return None
        status, data = self._http_get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            {"Key": self.abuseipdb_api_key, "Accept": "application/json"},
        )
        if status != 200 or not data:
            return None
        score = (data.get("data", {}) or {}).get("abuseConfidenceScore", 0)
        malicious = score >= self._ABUSEIPDB_SCORE_THRESHOLD
        self.cache.put(ip, "ip", "abuseipdb", "malicious" if malicious else "clean", json.dumps(data.get("data", {})))
        return malicious

    @staticmethod
    def _vt_url_id(url: str) -> str:
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    def check(self, domains, ips, urls, hashes):
        if not self.vt_api_key and not self.abuseipdb_api_key:
            return [], True   # no keys configured at all — honest degrade

        hits = []
        any_error = False

        for d in set(domains or []):
            result = self._vt_check(f"domains/{d}", d, "domain")
            if result is None and self.vt_api_key:
                any_error = True
            elif result:
                hits.append(f"intel_domain:{d}")

        for ip in set(ips or []):
            ab_result = self._abuseipdb_check(ip)
            vt_result = self._vt_check(f"ip_addresses/{ip}", ip, "ip") if self.vt_api_key else None
            if ab_result is None and vt_result is None and (self.abuseipdb_api_key or self.vt_api_key):
                any_error = True
            elif ab_result or vt_result:
                hits.append(f"intel_ip:{ip}")

        for u in set(urls or []):
            result = self._vt_check(f"urls/{self._vt_url_id(u)}", u, "url")
            if result is None and self.vt_api_key:
                any_error = True
            elif result:
                hits.append(f"intel_url:{u}")

        for h in set(hashes or []):
            result = self._vt_check(f"files/{h}", h, "hash")
            if result is None and self.vt_api_key:
                any_error = True
            elif result:
                hits.append(f"intel_hash:{h}")

        return sorted(set(hits)), any_error


def get_default_intel_client() -> IntelClient:
    """Selects the intel client from SEG_INTEL_CLIENT. Defaults to the
    offline LocalIOCClient (empty known-bad set) so nothing calls out to
    VirusTotal/AbuseIPDB unless explicitly configured — same "gate behind a
    flag, keep the offline default" posture as content_ai.get_default_provider()."""
    choice = os.environ.get("SEG_INTEL_CLIENT", "local").strip().lower()
    if choice == "vt_abuseipdb":
        return VTAbuseIPDBIntelClient()
    return LocalIOCClient()


def run(pe: ParsedEmail, client: IntelClient, url_stage_facts: dict,
        attach_facts: dict, correlation_store=None) -> StageResult:
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

    # Local verdict-history correlation (Correlated Intelligence, standalone
    # half — see correlation.py). Reuses the exact same IOC-candidate list
    # already assembled above rather than re-deriving it.
    correlation_flags = []
    if correlation_store is not None:
        senders = [pe.from_addr] if pe.from_addr else []
        correlation_flags = correlation_store.lookup(
            domains=domains, ips=ips, urls=urls, hashes=hashes, senders=senders)

    all_flags = hits + correlation_flags
    if hits:
        score = 90.0   # a real external intel hit — strong signal (hard override in verdict.py)
    elif correlation_flags:
        # Weighted-only: "PDAX flagged this before" is real signal but
        # lower-confidence than an external hit — capped well below the
        # external-hit score so it can never look like one on its own.
        score = min(35.0 * len(correlation_flags), 75.0)
    else:
        score = 0.0

    return StageResult(
        stage="intel",
        status=StageStatus.DEGRADED if degraded else StageStatus.OK,
        sub_score=score,
        red_flags=all_flags,
        facts={"checked_domains": sorted(set(domains)), "checked_ips": sorted(set(ips)),
               "hits": hits, "correlation_hits": correlation_flags},
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
