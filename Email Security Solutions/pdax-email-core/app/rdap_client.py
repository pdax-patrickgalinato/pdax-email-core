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

`domain_rdap_summary()` adds thin OSINT fields (registrar, registration date,
status) for the deep-analysis agent — still RDAP-only, no LinkedIn/web scrape.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

_RDAP_BASE = "https://rdap.org/domain/"
_TIMEOUT_SECONDS = 6


def rdap_lookup_enabled() -> bool:
    return os.environ.get("SEG_RDAP_LOOKUP", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


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


def _parse_registration(data: dict) -> tuple[Optional[datetime], Optional[int]]:
    """Returns (registered_dt, age_days)."""
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
        age = max((datetime.now(timezone.utc) - registered).days, 0)
        return registered, age
    return None, None


def _registrar_name(data: dict) -> str:
    """Best-effort registrar / registrant org from RDAP entities."""
    for ent in data.get("entities", []) or []:
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if "registrar" not in roles and "registrant" not in roles:
            continue
        # Prefer explicit handle/name fields when present
        name = ent.get("fn") or ent.get("handle") or ""
        vcard = ent.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if not isinstance(item, list) or len(item) < 4:
                    continue
                # ["fn", {}, "text", "Name"] or ["org", {}, "text", "Org"]
                if item[0] in ("fn", "org") and isinstance(item[3], str) and item[3].strip():
                    return item[3].strip()[:200]
        if isinstance(name, str) and name.strip():
            return name.strip()[:200]
    return ""


def domain_rdap_summary(domain: str, http_get=None) -> Optional[dict]:
    """Thin RDAP OSINT summary for a domain, or None on any failure.

    Fields: domain, age_days, registered (ISO date or ""), registrar, status
    (list of status strings). Never raises.
    """
    if not domain:
        return None
    http_get = http_get or _default_http_get
    try:
        status_code, data = http_get(_RDAP_BASE + domain)
    except Exception:
        return None
    if status_code != 200 or not data or not isinstance(data, dict):
        return None
    registered, age = _parse_registration(data)
    statuses = []
    for s in data.get("status") or []:
        if isinstance(s, str):
            statuses.append(s)
        elif isinstance(s, list) and s:
            statuses.append(str(s[0]))
    return {
        "domain": domain.lower().rstrip("."),
        "age_days": age,
        "registered": registered.date().isoformat() if registered else "",
        "registrar": _registrar_name(data),
        "status": statuses[:12],
    }


def domain_age_days(domain: str, http_get=None) -> Optional[int]:
    """Days since the domain's RDAP "registration" event, or None on any
    failure — unregistered/private-WHOIS domain, network error, RDAP not
    supported for this TLD, malformed response, or a registration event
    missing/unparseable. Never raises."""
    summary = domain_rdap_summary(domain, http_get=http_get)
    if not summary:
        return None
    return summary.get("age_days")
