"""RDAP domain-age lookup — Web Reputation (TMES policy parity).

RDAP (RFC 7482) is a modern, structured replacement for WHOIS: read-only,
unauthenticated, no API key, no per-day rate-limit concern the way
VirusTotal/AbuseIPDB have. Uses the community bootstrap redirector at
rdap.org rather than reimplementing IANA's TLD -> registry RDAP-server
bootstrap file ourselves — one HTTP hop, same "never raise, degrade
honestly" contract as every other enrichment hook in this codebase
(BedrockProvider/GeminiProvider/GLMProvider/VTAbuseIPDBIntelClient all
follow this same pattern — see app/pipeline/content_ai.py and
app/pipeline/intel.py).

Newly-registered domains are an established phishing-infrastructure signal —
attackers frequently register a lookalike/throwaway domain shortly before a
campaign. A young domain isn't proof of anything on its own (a legitimate
new vendor/product launch looks the same), so this stays a small weighted
signal, never a hard override — see app/pipeline/sender.py and verdict.py.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

_RDAP_BASE = "https://rdap.org/domain/"
_TIMEOUT_SECONDS = 6


def _default_http_get(url: str) -> tuple:
    """Returns (status_code, parsed_json_or_None). Never raises."""
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return 0, None


def domain_age_days(domain: str, http_get=None) -> Optional[int]:
    """Days since the domain's RDAP "registration" event, or None on any
    failure — unregistered/private-WHOIS domain, network error, RDAP not
    supported for this TLD, malformed response, or a registration event
    missing/unparseable. Never raises."""
    if not domain:
        return None
    http_get = http_get or _default_http_get
    status, data = http_get(_RDAP_BASE + domain)
    if status != 200 or not data:
        return None
    for event in data.get("events", []) or []:
        if event.get("eventAction") != "registration":
            continue
        date_str = event.get("eventDate")
        if not date_str:
            continue
        try:
            registered = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            continue
        if registered.tzinfo is None:
            registered = registered.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - registered).days, 0)
    return None
