"""Unit tests for VTAbuseIPDBIntelClient (app/pipeline/intel.py) — VirusTotal
+ AbuseIPDB free-tier client. All HTTP is mocked via an injected http_get;
nothing here touches a real API. Same mocked-offline pattern as
tests/test_content_ai_bedrock.py/_gemini.py/_glm.py.

Run: python3 -m pytest tests/test_intel_vt_abuseipdb.py
     (or python3 tests/test_intel_vt_abuseipdb.py)
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pipeline.intel import IntelCache, VTAbuseIPDBIntelClient


def _tmp_cache() -> IntelCache:
    tmp = Path(tempfile.mkstemp(suffix=".sqlite3")[1])
    return IntelCache(db_path=tmp)


class FakeHttp:
    """Records every call; returns a scripted (status, json) response per URL
    substring, defaulting to a 200 clean/harmless-shaped response."""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        for substr, resp in self.responses.items():
            if substr in url:
                return resp
        return 200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 10}}}}


def _vt_malicious_response(n=3):
    return 200, {"data": {"attributes": {"last_analysis_stats": {"malicious": n, "harmless": 5}}}}


def _abuseipdb_response(score):
    return 200, {"data": {"abuseConfidenceScore": score, "totalReports": 12}}


# --- no keys configured: honest degrade -------------------------------------

def test_no_keys_configured_degrades_honestly():
    client = VTAbuseIPDBIntelClient(vt_api_key=None, abuseipdb_api_key=None, cache=_tmp_cache())
    hits, degraded = client.check(["evil.example"], [], [], [])
    assert hits == []
    assert degraded is True


# --- VirusTotal: domains/urls/hashes ----------------------------------------

def test_vt_domain_hit():
    http = FakeHttp({"domains/evil.example": _vt_malicious_response()})
    client = VTAbuseIPDBIntelClient(vt_api_key="fake-vt-key", cache=_tmp_cache(),
                                    http_get=http, vt_min_interval_seconds=0)
    hits, degraded = client.check(["evil.example"], [], [], [])
    assert hits == ["intel_domain:evil.example"]
    assert degraded is False


def test_vt_domain_clean():
    http = FakeHttp()   # default response is clean
    client = VTAbuseIPDBIntelClient(vt_api_key="fake-vt-key", cache=_tmp_cache(),
                                    http_get=http, vt_min_interval_seconds=0)
    hits, degraded = client.check(["ok.example"], [], [], [])
    assert hits == []
    assert degraded is False


def test_vt_hash_hit():
    http = FakeHttp({"files/deadbeef": _vt_malicious_response(10)})
    client = VTAbuseIPDBIntelClient(vt_api_key="fake-vt-key", cache=_tmp_cache(),
                                    http_get=http, vt_min_interval_seconds=0)
    hits, _ = client.check([], [], [], ["deadbeef"])
    assert hits == ["intel_hash:deadbeef"]


def test_vt_url_hit_encodes_url_id():
    http = FakeHttp({"urls/": _vt_malicious_response()})
    client = VTAbuseIPDBIntelClient(vt_api_key="fake-vt-key", cache=_tmp_cache(),
                                    http_get=http, vt_min_interval_seconds=0)
    hits, _ = client.check([], [], ["https://evil.example/x"], [])
    assert hits == ["intel_url:https://evil.example/x"]
    assert any("/urls/" in url for url, _ in http.calls)


# --- AbuseIPDB: IPs -----------------------------------------------------------

def test_abuseipdb_ip_hit_above_threshold():
    http = FakeHttp({"abuseipdb.com": _abuseipdb_response(90)})
    client = VTAbuseIPDBIntelClient(abuseipdb_api_key="fake-key", cache=_tmp_cache(),
                                    http_get=http, vt_min_interval_seconds=0)
    hits, degraded = client.check([], ["1.2.3.4"], [], [])
    assert hits == ["intel_ip:1.2.3.4"]
    assert degraded is False


def test_abuseipdb_ip_below_threshold_not_a_hit():
    http = FakeHttp({"abuseipdb.com": _abuseipdb_response(10)})
    client = VTAbuseIPDBIntelClient(abuseipdb_api_key="fake-key", cache=_tmp_cache(),
                                    http_get=http, vt_min_interval_seconds=0)
    hits, _ = client.check([], ["5.6.7.8"], [], [])
    assert hits == []


# --- caching: a cache hit skips the HTTP call entirely -----------------------

def test_cache_hit_avoids_second_http_call():
    cache = _tmp_cache()
    http = FakeHttp({"domains/evil.example": _vt_malicious_response()})
    client = VTAbuseIPDBIntelClient(vt_api_key="fake-vt-key", cache=cache,
                                    http_get=http, vt_min_interval_seconds=0)
    client.check(["evil.example"], [], [], [])
    calls_after_first = len(http.calls)
    client.check(["evil.example"], [], [], [])   # same client, same cache
    assert len(http.calls) == calls_after_first   # no new HTTP call — cache hit

    # A fresh client sharing the same cache also benefits (proves it's the
    # cache, not in-process client state, doing the skipping).
    client2 = VTAbuseIPDBIntelClient(vt_api_key="fake-vt-key", cache=cache,
                                     http_get=http, vt_min_interval_seconds=0)
    hits, _ = client2.check(["evil.example"], [], [], [])
    assert hits == ["intel_domain:evil.example"]
    assert len(http.calls) == calls_after_first


# --- outage / non-200: degrade, don't raise, don't false-positive -----------

def test_http_error_degrades_without_raising_or_false_hit():
    def failing_http(url, headers):
        return 0, None   # simulates a connection error (see _default_http_get)
    client = VTAbuseIPDBIntelClient(vt_api_key="fake-vt-key", cache=_tmp_cache(),
                                    http_get=failing_http, vt_min_interval_seconds=0)
    hits, degraded = client.check(["evil.example"], [], [], [])
    assert hits == []
    assert degraded is True


def test_rate_limited_response_degrades_without_raising():
    def rate_limited_http(url, headers):
        return 429, {"error": "quota exceeded"}
    client = VTAbuseIPDBIntelClient(vt_api_key="fake-vt-key", cache=_tmp_cache(),
                                    http_get=rate_limited_http, vt_min_interval_seconds=0)
    hits, degraded = client.check(["evil.example"], [], [], [])
    assert hits == []
    assert degraded is True


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); passed += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
