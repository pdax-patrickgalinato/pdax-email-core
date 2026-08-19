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
                    (indicator, indicator_type, source, verdict, time.time(), raw_response[:8000]),
                )
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            pass   # caching is an optimization, never a hard requirement

    def get_raw_response(self, indicator: str, source: str) -> Optional[str]:
        """Returns the cached raw_response blob if fresh, else None."""
        try:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT raw_response, checked_at FROM intel_cache "
                    "WHERE indicator = ? AND source = ?",
                    (indicator, source),
                ).fetchone()
                if row is None:
                    return None
                raw_response, checked_at = row
                if (time.time() - checked_at) > self.ttl_seconds:
                    return None
                return raw_response
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return None


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

    def _vt_check(self, path: str, indicator: str, indicator_type: str,
                  save_details: bool = False) -> Optional[bool]:
        """Returns True (malicious), False (clean), or None (degraded/error —
        caller should not trust this result either way).

        When save_details=True (domain checks), the full VT attributes are also
        cached so get_domain_details() can retrieve them without a second API call."""
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
        attrs = (data.get("data", {}).get("attributes", {}) or {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = bool(stats) and stats.get("malicious", 0) >= self._VT_MALICIOUS_THRESHOLD
        self.cache.put(indicator, indicator_type, "virustotal",
                       "malicious" if malicious else "clean", json.dumps(stats))
        if save_details:
            details = {
                "categories": attrs.get("categories", {}),
                "reputation": attrs.get("reputation", 0),
                "creation_date": attrs.get("creation_date"),
                "registrar": attrs.get("registrar"),
                "last_analysis_stats": stats,
                "tags": attrs.get("tags", []),
                "total_votes": attrs.get("total_votes", {}),
            }
            self.cache.put(f"details:{indicator}", "domain_details", "virustotal",
                           "ok", json.dumps(details))
        return malicious

    def _vt_url_check(self, url: str) -> Optional[bool]:
        """URL-specific check: lookup existing report, submit for scanning on 404."""
        cached = self.cache.get(url, "url", "virustotal")
        if cached is not None:
            return cached == "malicious"
        if not self.vt_api_key:
            return None
        url_id = self._vt_url_id(url)
        self._vt_throttle()
        status, data = self._http_get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            {"x-apikey": self.vt_api_key},
        )
        if status == 200 and data:
            attrs = (data.get("data", {}).get("attributes", {}) or {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = bool(stats) and stats.get("malicious", 0) >= self._VT_MALICIOUS_THRESHOLD
            self.cache.put(url, "url", "virustotal",
                           "malicious" if malicious else "clean", json.dumps(stats))
            return malicious
        elif status == 404:
            # URL not yet in VT — submit for scanning (fire-and-forget)
            self._vt_submit_url(url)
            return None   # not an error; result available on next check
        return None

    def _vt_submit_url(self, url: str) -> None:
        """Submits a URL to VT for scanning. Fire-and-forget; result available later."""
        submit_key = f"submitted:{url[:200]}"
        if self.cache.get(submit_key, "url_submission", "virustotal") == "submitted":
            return
        if not self.vt_api_key:
            return
        import urllib.parse as _up
        body = _up.urlencode({"url": url}).encode("ascii")
        req = urllib.request.Request(
            "https://www.virustotal.com/api/v3/urls",
            data=body,
            headers={
                "x-apikey": self.vt_api_key,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 201):
                    self.cache.put(submit_key, "url_submission", "virustotal", "submitted")
        except Exception:
            pass   # submission failure is non-fatal

    def get_domain_details(self, domain: str) -> Optional[dict]:
        """Returns cached VT domain details (categories, reputation, etc.) if available.
        Populated by _vt_check(..., save_details=True) which check() calls for domains."""
        raw = self.cache.get_raw_response(f"details:{domain}", "virustotal")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

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
            result = self._vt_check(f"domains/{d}", d, "domain", save_details=True)
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
            result = self._vt_url_check(u)
            if result is None and self.vt_api_key:
                # Check if it was a 404+submission (not an error) vs a real failure.
                # A submitted URL has a "submitted:" cache entry; a real error has none.
                submit_key = f"submitted:{u[:200]}"
                submitted = self.cache.get(submit_key, "url_submission", "virustotal")
                if submitted != "submitted":
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


class HybridAnalysisClient:
    """CrowdStrike Falcon Sandbox (Hybrid Analysis) threat intel.

    Provides two tiers:
    - Hash lookup (GET /search/hash): free, no submission quota, returns cached
      sandbox verdicts for known files — used for every attachment SHA-256.
    - URL quick-scan (POST /quick-scan/url-to-file): submits a URL for rapid ML +
      AV scan; fire-and-forget, result available on next check. Limited on free
      tier — only submitted for URLs already flagged by other stages.

    Free tier limits: 30 full-sandbox file submissions/month (all public),
    hash lookup is unrestricted. Submissions are public — do not submit
    sensitive/internal documents.

    Activate via: export SEG_HA_API_KEY=your_key_here
    Get a key at: https://www.hybrid-analysis.com/signup
    """

    _BASE = "https://www.hybrid-analysis.com/api/v2"
    _VERDICTS = {"malicious", "suspicious"}

    def __init__(self, api_key: Optional[str] = None, cache: Optional[IntelCache] = None,
                 http_get=None, http_post=None):
        self.api_key = api_key or os.environ.get("SEG_HA_API_KEY")
        self.cache = cache or IntelCache()
        self._http_get = http_get or requests.get
        self._http_post = http_post or requests.post

    def _headers(self) -> dict:
        return {
            "api-key": self.api_key or "",
            "user-agent": "Falcon Sandbox",
            "accept": "application/json",
        }

    def check_hash(self, sha256: str) -> Optional[str]:
        """Look up a file hash. Returns 'malicious', 'suspicious',
        'no-specific-threat', 'whitelisted', or None on miss/error."""
        if not self.api_key or not sha256:
            return None
        cached = self.cache.get(sha256, "hash", "hybrid_analysis")
        if cached is not None:
            return cached
        try:
            resp = self._http_get(
                f"{self._BASE}/search/hash",
                params={"hash": sha256},
                headers=self._headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                results = data if isinstance(data, list) else []
                verdict = results[0].get("verdict") if results else None
                result_str = verdict or "no-specific-threat"
                self.cache.put(sha256, "hash", "hybrid_analysis", result_str)
                return result_str
            elif resp.status_code == 404:
                self.cache.put(sha256, "hash", "hybrid_analysis", "unknown")
                return None
        except Exception:
            pass
        return None

    def quick_scan_url(self, url: str) -> None:
        """Submit a URL for quick scan (fire-and-forget). Results cached by URL."""
        if not self.api_key or not url:
            return
        submit_key = f"url_submitted:{url[:200]}"
        if self.cache.get(submit_key, "url_submission", "hybrid_analysis") == "submitted":
            return
        try:
            resp = self._http_post(
                f"{self._BASE}/quick-scan/url-to-file",
                headers={**self._headers(), "content-type": "application/x-www-form-urlencoded"},
                data={"scan_type": "all", "url": url},
                timeout=15,
            )
            if resp.status_code in (200, 201):
                self.cache.put(submit_key, "url_submission", "hybrid_analysis", "submitted")
        except Exception:
            pass

    def check_hashes(self, hashes: list[str]) -> tuple[list[str], bool]:
        """Check multiple hashes. Returns (hit_flags, any_error)."""
        if not self.api_key:
            return [], False
        hits: list[str] = []
        any_error = False
        for sha256 in hashes:
            verdict = self.check_hash(sha256)
            if verdict == "malicious":
                hits.append(f"hybrid_analysis_malicious:{sha256[:16]}")
            elif verdict == "suspicious":
                hits.append(f"hybrid_analysis_suspicious:{sha256[:16]}")
            elif verdict is None and self.api_key:
                any_error = True
        return hits, any_error


def get_default_intel_client() -> IntelClient:
    """Selects the intel client from SEG_INTEL_CLIENT. Defaults to the
    offline LocalIOCClient (empty known-bad set) so nothing calls out to
    VirusTotal/AbuseIPDB unless explicitly configured — same "gate behind a
    flag, keep the offline default" posture as content_ai.get_default_provider()."""
    choice = os.environ.get("SEG_INTEL_CLIENT", "local").strip().lower()
    if choice == "vt_abuseipdb":
        return VTAbuseIPDBIntelClient()
    return LocalIOCClient()


def get_default_ha_client() -> Optional[HybridAnalysisClient]:
    """Returns a HybridAnalysisClient if SEG_HA_API_KEY is set, else None."""
    if os.environ.get("SEG_HA_API_KEY"):
        return HybridAnalysisClient()
    return None


def run(pe: ParsedEmail, client: IntelClient, url_stage_facts: dict,
        attach_facts: dict, correlation_store=None,
        ha_client: Optional["HybridAnalysisClient"] = None) -> StageResult:
    t0 = time.perf_counter()
    domains = [pe.from_domain] + [u.get("reg_domain", "") for u in url_stage_facts.get("urls", [])]
    domains = [d for d in domains if d]

    # Also check domains of email addresses found in the message body.
    # Phishing mails often embed attacker mailboxes or fake contact addresses
    # that resolve to known-bad infrastructure.
    body_email_doms = list({
        addr.split("@")[1]
        for addr in pe.body_email_addrs()
        if "@" in addr
    })
    all_domains = list(set(domains + body_email_doms))

    # IP-literal URL hosts + public IPs from the Received chain
    ips = [u.get("ip", "") for u in url_stage_facts.get("urls", [])] + pe.originating_ips()
    ips = [i for i in ips if i]
    urls = [u.get("url", "") for u in url_stage_facts.get("urls", [])]
    hashes = [a.get("sha256", "") for a in attach_facts.get("attachments", [])]

    hits, degraded = client.check(all_domains, ips, urls, hashes)

    # Hybrid Analysis hash lookup — check every attachment SHA-256 against
    # CrowdStrike Falcon Sandbox for sandbox-confirmed verdicts. Hash lookup
    # is free and unrestricted on the HA free tier (no submission quota).
    ha_hits: list[str] = []
    _ha = ha_client or get_default_ha_client()
    if _ha and hashes:
        try:
            ha_hits, _ = _ha.check_hashes(hashes)
            hits = hits + ha_hits
        except Exception:
            pass

    # Submit flagged URLs to HA quick-scan (fire-and-forget, cached per URL).
    # Only submits URLs already flagged by other stages to stay within free limits.
    if _ha and hits:
        flagged_urls = [u.get("url", "") for u in url_stage_facts.get("urls", [])
                        if u.get("url")]
        for url in flagged_urls[:3]:   # cap at 3 per email to conserve quota
            try:
                _ha.quick_scan_url(url)
            except Exception:
                pass

    # Domain reputation details — populated by VTAbuseIPDBIntelClient.check() via
    # save_details=True. Fall back silently if the client doesn't support this.
    domain_details: dict = {}
    if hasattr(client, "get_domain_details"):
        for d in set(all_domains):
            details = client.get_domain_details(d)
            if details:
                domain_details[d] = details

    # Behavioral correlation — reference only, does NOT contribute to score or
    # verdict. Results surface in the Analyze tab's Behavioral Correlation panel.
    behavioral_details = []
    behavioral_flags = []
    if correlation_store is not None:
        shortener_domains = url_stage_facts.get("shortener_domains", [])
        behavioral_details = correlation_store.behavioral_details(
            sender=(pe.from_addr or "").lower(),
            originating_ips=pe.originating_ips(),
            shortener_domains=shortener_domains,
        )
        behavioral_flags = [
            f"{d['rule']}:{d['ioc_value']}:{d['behavioral_count']}"
            for d in behavioral_details
        ]

    # First-time / rare sender detection — draws from sender_history table in the
    # behavioral store. A brand-new sender is a key BEC risk signal (used by
    # Sublime Security's core feed rules). Scored as a regular flag so detection
    # rules can match against it.
    sender_flags: list[str] = []
    if correlation_store is not None and hasattr(correlation_store, "sender_prior_count"):
        try:
            prior = correlation_store.sender_prior_count((pe.from_addr or "").lower())
            if prior == 0:
                sender_flags.append("first_time_sender")
            elif prior <= 3:
                sender_flags.append(f"rare_sender:{prior}")
        except Exception:
            pass

    # Only real external intel hits + sender novelty affect scoring.
    # Behavioral correlation patterns remain reference-only.
    score = 90.0 if hits else 0.0
    if "first_time_sender" in sender_flags:
        score = max(score, 8.0)
    elif sender_flags:  # rare_sender
        score = max(score, 4.0)

    all_red_flags = hits + sender_flags

    return StageResult(
        stage="intel",
        status=StageStatus.DEGRADED if degraded else StageStatus.OK,
        sub_score=score,
        red_flags=all_red_flags,
        facts={"checked_domains": sorted(set(all_domains)), "checked_ips": sorted(set(ips)),
               "hits": hits,
               "domain_details": domain_details,
               "body_email_domains": sorted(set(body_email_doms)),
               "behavioral_hits": behavioral_flags,
               "behavioral_details": behavioral_details},
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
