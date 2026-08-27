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
              hashes: list[str]) -> tuple:
        """Return (hit_indicators, degraded) or (hit_indicators, degraded, quota_flags).
        Callers must handle both lengths for backwards compatibility."""
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
        return hits, False, []


# ---------------------------------------------------------------------------
# Process-level quota tracking — persists across email scans in the same
# process so a 429 response from one email prevents useless 15-second sleeps
# for all subsequent emails until the quota window resets.
#
# VT free tier: 500 lookups/day, resets midnight UTC.
# AbuseIPDB free tier: 1000 lookups/day, resets midnight UTC.
# We back off for 1 hour when a 429 is detected (conservative — avoids
# hammering the API in the hours leading up to midnight reset while still
# recovering promptly after the reset).
# ---------------------------------------------------------------------------
_QUOTA_BACKOFF_SECONDS = 3600.0   # 1 hour — conservative daily-limit backoff
_vt_quota_exhausted_until: float = 0.0
_abuseipdb_quota_exhausted_until: float = 0.0


def _vt_quota_ok() -> bool:
    return time.time() > _vt_quota_exhausted_until


def _abuseipdb_quota_ok() -> bool:
    return time.time() > _abuseipdb_quota_exhausted_until


def _mark_vt_quota_exhausted() -> None:
    global _vt_quota_exhausted_until
    _vt_quota_exhausted_until = time.time() + _QUOTA_BACKOFF_SECONDS


def _mark_abuseipdb_quota_exhausted() -> None:
    global _abuseipdb_quota_exhausted_until
    _abuseipdb_quota_exhausted_until = time.time() + _QUOTA_BACKOFF_SECONDS


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
                  save_details: bool = False, _budget: list = None,
                  _deadline: float = 0.0) -> Optional[bool]:
        """Returns True (malicious), False (clean), or None (degraded/error —
        caller should not trust this result either way).

        When save_details=True (domain checks), the full VT attributes are also
        cached so get_domain_details() can retrieve them without a second API call.

        _budget: mutable [remaining_calls] list. When provided and exhausted,
        uncached indicators are skipped rather than sleeping for 15 s per call.
        _deadline: absolute Unix timestamp after which no new calls are made.
        Cache hits are always honoured regardless of budget or deadline."""
        cached = self.cache.get(indicator, indicator_type, "virustotal")
        if cached is not None:
            return cached == "malicious"
        if not self.vt_api_key:
            return None
        # Skip without sleeping if the process-level quota flag is set
        # (a 429 was received this run — burns no budget and no sleep time).
        if not _vt_quota_ok():
            return None
        if _deadline and time.time() >= _deadline:
            return None   # wall-clock time budget exceeded — degrade gracefully
        if _budget is not None:
            if _budget[0] <= 0:
                return None   # call-count budget exhausted
            _budget[0] -= 1
        self._vt_throttle()
        status, data = self._http_get(
            f"https://www.virustotal.com/api/v3/{path}",
            {"x-apikey": self.vt_api_key},
        )
        if status == 429:
            _mark_vt_quota_exhausted()   # tell all future calls this session
            return None
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

    def _vt_url_check(self, url: str, _budget: list = None,
                      _deadline: float = 0.0) -> Optional[bool]:
        """URL-specific check: lookup existing report, submit for scanning on 404."""
        cached = self.cache.get(url, "url", "virustotal")
        if cached is not None:
            return cached == "malicious"
        if not self.vt_api_key:
            return None
        if not _vt_quota_ok():
            return None
        if _deadline and time.time() >= _deadline:
            return None
        if _budget is not None:
            if _budget[0] <= 0:
                return None
            _budget[0] -= 1
        url_id = self._vt_url_id(url)
        self._vt_throttle()
        status, data = self._http_get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            {"x-apikey": self.vt_api_key},
        )
        if status == 429:
            _mark_vt_quota_exhausted()
            return None
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
        """Submits a URL to VT for scanning.

        Runs in a daemon thread so the HTTP POST never blocks the pipeline. The
        result is stored in the cache and available on the next email scan.
        """
        submit_key = f"submitted:{url[:200]}"
        if self.cache.get(submit_key, "url_submission", "virustotal") == "submitted":
            return
        if not self.vt_api_key or not _vt_quota_ok():
            return
        import threading as _threading
        import urllib.parse as _up
        cache_ref = self.cache
        api_key = self.vt_api_key
        body = _up.urlencode({"url": url}).encode("ascii")
        req = urllib.request.Request(
            "https://www.virustotal.com/api/v3/urls",
            data=body,
            headers={"x-apikey": api_key,
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        def _do_submit():
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status in (200, 201):
                        cache_ref.put(submit_key, "url_submission", "virustotal", "submitted")
            except Exception:
                pass
        _threading.Thread(target=_do_submit, daemon=True, name="vt-url-submit").start()

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

    def _abuseipdb_check(self, ip: str, _budget: list = None,
                         _deadline: float = 0.0) -> Optional[bool]:
        cached = self.cache.get(ip, "ip", "abuseipdb")
        if cached is not None:
            return cached == "malicious"
        if not self.abuseipdb_api_key:
            return None
        if not _abuseipdb_quota_ok():
            return None
        if _deadline and time.time() >= _deadline:
            return None
        if _budget is not None:
            if _budget[0] <= 0:
                return None
            _budget[0] -= 1
        status, data = self._http_get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            {"Key": self.abuseipdb_api_key, "Accept": "application/json"},
        )
        if status == 429:
            _mark_abuseipdb_quota_exhausted()
            return None
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

        # Per-email cap on fresh (non-cached) API calls. Each fresh VT call
        # sleeps ~15 s for the rate-limit throttle, so N fresh calls cost N×15 s.
        # Cache hits are always honoured regardless of budget or deadline.
        # Tune via SEG_VT_MAX_INDICATORS_PER_EMAIL; default 8 → ≤105 s throttle.
        max_fresh = int(os.environ.get("SEG_VT_MAX_INDICATORS_PER_EMAIL", "8"))
        budget = [max_fresh]   # mutable so sub-methods can decrement in place

        # Hard wall-clock deadline — guarantees the intel stage never stalls the
        # pipeline regardless of indicator count or VT response latency.
        # Default 90 s: worst-case 6 fresh calls (6×15 s) plus API response time.
        # Raise SEG_VT_TIME_BUDGET_SECONDS if VT coverage is more important than
        # latency (requires a paid VT tier to avoid 429 on long scans).
        time_budget = float(os.environ.get("SEG_VT_TIME_BUDGET_SECONDS", "90"))
        _deadline = time.time() + time_budget

        hits = []
        any_error = False

        # Hashes checked FIRST — highest-value signal for attachment-heavy emails;
        # a hash match is definitive malware confirmation. This ensures attachment
        # reputation lookups always run even when the budget is tight.
        for h in set(hashes or []):
            result = self._vt_check(f"files/{h}", h, "hash", _budget=budget, _deadline=_deadline)
            if result is None and self.vt_api_key:
                any_error = True
            elif result:
                hits.append(f"intel_hash:{h}")

        for d in set(domains or []):
            result = self._vt_check(f"domains/{d}", d, "domain", save_details=True,
                                    _budget=budget, _deadline=_deadline)
            if result is None and self.vt_api_key:
                any_error = True
            elif result:
                hits.append(f"intel_domain:{d}")

        for ip in set(ips or []):
            ab_result = self._abuseipdb_check(ip, _budget=budget, _deadline=_deadline)
            vt_result = (self._vt_check(f"ip_addresses/{ip}", ip, "ip",
                                        _budget=budget, _deadline=_deadline)
                         if self.vt_api_key else None)
            if ab_result is None and vt_result is None and (self.abuseipdb_api_key or self.vt_api_key):
                any_error = True
            elif ab_result or vt_result:
                hits.append(f"intel_ip:{ip}")

        for u in set(urls or []):
            result = self._vt_url_check(u, _budget=budget, _deadline=_deadline)
            if result is None and self.vt_api_key:
                # Check if it was a 404+submission (not an error) vs a real failure.
                # A submitted URL has a "submitted:" cache entry; a real error has none.
                submit_key = f"submitted:{u[:200]}"
                submitted = self.cache.get(submit_key, "url_submission", "virustotal")
                if submitted != "submitted":
                    any_error = True
            elif result:
                hits.append(f"intel_url:{u}")

        # ClamAV URL scan — checks the URL string against ClamAV's local signature
        # database (URLhaus, phishing, malware download patterns). No outbound HTTP
        # connection is made from SEGS; safe for any URL including actively malicious ones.
        # Gated by SEG_SANDBOX_PROVIDER=clamav (same switch as attachment scanning).
        if os.environ.get("SEG_SANDBOX_PROVIDER", "").strip().lower() == "clamav":
            for u in set(urls or []):
                is_mal, _sig = _clam_url_scan(u)
                if is_mal:
                    hits.append(f"intel_url_clam:{u[:200]}")

        quota_flags: list[str] = []
        if not _vt_quota_ok():
            quota_flags.append("quota_exhausted_vt")
        if not _abuseipdb_quota_ok():
            quota_flags.append("quota_exhausted_abuseipdb")

        return sorted(set(hits)), any_error, quota_flags


def _clam_url_scan(url: str) -> tuple[bool, "str | None"]:
    """Scan a URL string through ClamAV's local signature database.

    Passes the URL bytes to clamd via scan_stream — ClamAV checks against
    URLhaus, phishing, and malware-distribution URL patterns in its database.
    No outbound HTTP connection is ever made from SEGS; this is purely a local
    signature lookup, safe for any URL including actively malicious ones.

    Returns (is_malicious, signature_name). Degrades silently on any error
    (pyclamd not installed, clamd not reachable) — the caller skips the result.
    """
    socket_path = os.environ.get("SEG_CLAMD_SOCKET", "").strip() or None
    host = os.environ.get("SEG_CLAMD_HOST", "localhost").strip()
    try:
        port = int(os.environ.get("SEG_CLAMD_PORT", "3310"))
    except ValueError:
        port = 3310
    try:
        import pyclamd
        cd = (pyclamd.ClamdUnixSocket(socket_path) if socket_path
              else pyclamd.ClamdNetworkSocket(host, port))
        result = cd.scan_stream(url.encode("utf-8", "replace"))
        if result is None:
            return False, None
        _, (status, sig) = next(iter(result.items()))
        return status == "FOUND", (sig if status == "FOUND" else None)
    except ImportError:
        return False, None
    except Exception:
        return False, None


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

    _check_result = client.check(all_domains, ips, urls, hashes)
    hits = _check_result[0]
    degraded = _check_result[1]
    quota_flags: list[str] = _check_result[2] if len(_check_result) > 2 else []

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

    is_degraded = degraded or bool(quota_flags)
    return StageResult(
        stage="intel",
        status=StageStatus.DEGRADED if is_degraded else StageStatus.OK,
        sub_score=score,
        red_flags=all_red_flags,
        facts={"checked_domains": sorted(set(all_domains)), "checked_ips": sorted(set(ips)),
               "hits": hits,
               "domain_details": domain_details,
               "body_email_domains": sorted(set(body_email_doms)),
               "behavioral_hits": behavioral_flags,
               "behavioral_details": behavioral_details,
               "quota_flags": quota_flags},
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
