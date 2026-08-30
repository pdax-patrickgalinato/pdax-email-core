"""Originating MTA IP: extract from Received, enrich via geo / RDAP / search.

Advisory only — not in weights.yaml, never writes the verdict. The hop picker
lives on ParsedEmail.originating_hop(); this module adds OSINT (city/ISP/ASN,
VPN vs hosting vs ESP, geo-vs-sender plausibility) and the stage snapshot
for the assessment-flow graph.

Web search is a separate Gemini call with Google Search grounding. Content
analysis uses response_schema JSON, which the Gemini API will not combine
with google_search on the same request. GLM / DeepSeek / Kimi have no native
search. The search prompt is IP + hostname + already-known geo/ISP — never
the message body.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from backend.config import get_settings
from backend.models import StageResult, StageStatus
from .rdap_client import _sanitize_ip, ip_rdap_summary, rdap_lookup_enabled

_SEARCH_MAX_CHARS = 700
_GEO_TIMEOUT = 5
_IP_API = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,country,countryCode,regionName,city,"
    "lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
)

# ccTLD → ISO country for "does this origin match the From domain?"
_TLD_COUNTRY = {
    "ph": "PH", "sg": "SG", "au": "AU", "uk": "GB", "de": "DE", "fr": "FR",
    "jp": "JP", "in": "IN", "br": "BR", "ca": "CA", "nz": "NZ", "my": "MY",
    "id": "ID", "vn": "VN", "th": "TH", "ae": "AE", "sa": "SA", "za": "ZA",
    "kr": "KR", "hk": "HK", "tw": "TW", "cn": "CN", "ru": "RU", "nl": "NL",
    "ie": "IE", "se": "SE", "ch": "CH", "es": "ES", "it": "IT", "mx": "MX",
}

# Regions where Google / Microsoft / AWS / major ESPs legitimately originate.
_ESP_HUBS = frozenset({
    "US", "SG", "IE", "NL", "DE", "GB", "JP", "AU", "IN", "CA", "FR",
    "SE", "FI", "BE", "HK", "KR", "BR",
})

_ESP_MARKERS = (
    "sendgrid", "mailgun", "amazonses", "amazon ses",
    "sparkpost", "postmark", "mandrill", "mailchimp", "constant contact",
    "sendinblue", "brevo", "mailgun.org", "mimecast", "proofpoint",
    "pphosted", "messagelabs", "barracuda", "trend micro", "tmes",
    "google llc", "google.com", "gmail", "microsoft corporation",
    "outlook.com", "protection.outlook", "office365", "ppops.net",
    "salesforce", "exacttarget", "hubspot", "mailgun", "zoho",
    "fastmail", "protonmail", "icloud.com", "apple",
    "yahoo.com", "yahoo holdings", "yahoodns", "oath holdings",
    "verizon media",
)

_VPN_MARKERS = (
    "nordvpn", "expressvpn", "mullvad", "protonvpn", "proton vpn",
    "surfshark", "ipvanish", "cyberghost", "windscribe", "tunnelbear",
    "hidemyass", "hide my ass", "private internet access", " ivpn",
    "perfect privacy", "m247", "datacamp", "cdn77", "packethub",
    "quadranet", "psychz", "choopa", "proxy service", "tor exit",
    "stormgain", "leaseweb vpn",
)

_HOSTING_MARKERS = (
    "amazon technologies", "aws ", "google cloud", "microsoft azure",
    "azure ", "digitalocean", "linode", "akamai technologies", "vultr",
    "hetzner", "ovh", "leaseweb", "contabo", "scaleway", "alibaba",
    "tencent", "oracle cloud", "oracle corporation", "cloudflare",
    "fastly", "hostwinds", "colocrossing", "hurricane electric",
    "dedicated", "vps", "cloud infrastructure", "data center",
    "datacenter", "web hosting",
)

_ROLE_LABEL = {
    "vpn_proxy": "VPN / proxy",
    "cloud_hosting": "Cloud / VPS hosting",
    "esp": "Email service / gateway",
    "isp": "ISP (residential or business)",
    "mobile_isp": "Mobile ISP",
    "unknown": "Unknown",
}


def _geo_enabled(settings=None) -> bool:
    s = settings or get_settings()
    return bool(getattr(s, "origin_ip_geo", True))


def _search_enabled(settings=None) -> bool:
    s = settings or get_settings()
    if not s.origin_ip_search:
        return False
    return bool(s.gemini_api_key or s.gemini_api_key_alt)


def _geo_http_get(url: str) -> tuple:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "SEGS-origin-ip/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=_GEO_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return 0, None


def geo_lookup(ip: str, http_get=None) -> Optional[dict]:
    """City / ISP / ASN / proxy-hosting flags from ip-api. None on failure."""
    safe = _sanitize_ip(ip)
    if not safe:
        return None
    http_get = http_get or _geo_http_get
    url = _IP_API.format(ip=urllib.parse.quote(safe))
    try:
        status, data = http_get(url)
    except Exception:
        return None
    if status != 200 or not isinstance(data, dict) or data.get("status") != "success":
        return None
    asn_raw = str(data.get("as") or "").strip()
    asn = ""
    if asn_raw.upper().startswith("AS"):
        asn = asn_raw.split()[0].upper()
    return {
        "country": str(data.get("countryCode") or "").strip().upper()[:8],
        "country_name": str(data.get("country") or "").strip()[:80],
        "region": str(data.get("regionName") or "").strip()[:80],
        "city": str(data.get("city") or "").strip()[:80],
        "lat": data.get("lat") if isinstance(data.get("lat"), (int, float)) else None,
        "lon": data.get("lon") if isinstance(data.get("lon"), (int, float)) else None,
        "timezone": str(data.get("timezone") or "").strip()[:64],
        "isp": str(data.get("isp") or "").strip()[:200],
        "org": str(data.get("org") or "").strip()[:200],
        "asn": asn[:16],
        "as_name": str(data.get("asname") or asn_raw)[:200],
        "mobile": bool(data.get("mobile")),
        "proxy": bool(data.get("proxy")),
        "hosting": bool(data.get("hosting")),
    }


def _expected_countries(sender_domain: str) -> set[str]:
    out = set(_ESP_HUBS)
    extra = str(getattr(get_settings(), "expected_mail_countries", "") or "")
    for part in extra.replace(";", ",").split(","):
        code = part.strip().upper()
        if len(code) == 2 and code.isalpha():
            out.add(code)
    tld = (sender_domain or "").rsplit(".", 1)[-1].lower()
    if tld in _TLD_COUNTRY:
        out.add(_TLD_COUNTRY[tld])
    return out


def _blob(*parts) -> str:
    return " ".join(str(p or "") for p in parts).lower()


def classify_network(facts: dict, sender_domain: str = "") -> dict:
    """VPN / hosting / ESP / ISP role plus a suspicion note. Deterministic."""
    blob = _blob(
        facts.get("hostname"), facts.get("org"), facts.get("name"),
        facts.get("isp"), facts.get("as_name"), facts.get("asn"),
        facts.get("search_summary"),
    )
    vpn = bool(facts.get("proxy")) or any(m in blob for m in _VPN_MARKERS)
    esp = any(m in blob for m in _ESP_MARKERS)
    hosting = bool(facts.get("hosting")) or any(m in blob for m in _HOSTING_MARKERS)
    if vpn:
        role = "vpn_proxy"
    elif esp:
        role = "esp"
        hosting = False
    elif hosting:
        role = "cloud_hosting"
    elif facts.get("mobile"):
        role = "mobile_isp"
    elif facts.get("isp") or facts.get("org"):
        role = "isp"
    else:
        role = "unknown"

    country = str(facts.get("country") or "").upper()
    expected = _expected_countries(sender_domain)
    geo_mismatch = bool(country) and country not in expected

    suspicion = "none"
    reasons: list[str] = []
    loc = ", ".join(p for p in (facts.get("city"), facts.get("region"),
                                facts.get("country_name") or country) if p)
    if vpn:
        suspicion = "high"
        reasons.append(
            "IP matches a VPN, proxy, or bulletproof-hosting operator — "
            "rare for legitimate corporate or ESP mail"
        )
    if geo_mismatch and role in ("vpn_proxy", "isp", "mobile_isp", "unknown"):
        if suspicion != "high":
            suspicion = "elevated"
        reasons.append(
            f"geolocation {loc or country} is unusual for sender "
            f"{sender_domain or '(unknown domain)'} (not the From ccTLD and "
            "not a typical Google/Microsoft/ESP hub)"
        )
    elif geo_mismatch and role == "cloud_hosting":
        if suspicion != "high":
            suspicion = "elevated"
        reasons.append(
            f"cloud/VPS origin in {loc or country} is outside the usual "
            "ESP/cloud-hub footprint for this sender"
        )
    if hosting and role == "cloud_hosting" and suspicion == "none":
        reasons.append(
            "origin is a cloud/VPS network rather than a residential ISP "
            "or known email provider — common for SaaS and marketing "
            "platforms, also seen on phishing kits"
        )
    if suspicion == "none":
        if role == "esp":
            reasons.append("known email-service or gateway infrastructure — expected")
        elif role == "isp":
            reasons.append("conventional ISP allocation — not inherently suspicious")
        elif role == "mobile_isp":
            reasons.append("mobile-carrier allocation")

    return {
        "network_role": role,
        "network_role_label": _ROLE_LABEL.get(role, role),
        "vpn": vpn,
        "hosting": hosting and role == "cloud_hosting",
        "geo_mismatch": geo_mismatch and role != "esp",
        "suspicion": suspicion,
        "suspicion_reason": "; ".join(reasons),
    }


def visual_score(facts: dict) -> float:
    """Display-only weight for the flow graph. Not used in composite scoring."""
    level = facts.get("suspicion") or "none"
    if level == "high":
        return 52.0
    if level == "elevated":
        return 30.0
    return 0.0


_SEARCH_CACHE: dict[str, tuple[float, str]] = {}
_SEARCH_CACHE_LOCK = threading.Lock()
_SEARCH_TTL = 6 * 3600


def _gemini_ip_search(ip: str, hostname: str = "", context: str = "", generate=None) -> str:
    """Grounded OSINT blurb for one IP. Empty string on any failure."""
    if not ip:
        return ""
    cache_key = f"{ip}|{hostname or ''}"
    now = time.time()
    with _SEARCH_CACHE_LOCK:
        hit = _SEARCH_CACHE.get(cache_key)
        if hit and (now - hit[0]) < _SEARCH_TTL:
            return hit[1]
    prompt = (
        f"Public OSINT for mail-sending IP {ip}"
        + (f" (HELO/hostname {hostname})" if hostname else "")
        + (f". Already known: {context}" if context else "")
        + ". In 3-5 sentences cover: ISP and ASN, city/country, whether this "
        "is a residential ISP, cloud/VPS, email service provider "
        "(SendGrid, Google, Microsoft 365), or a known VPN/proxy/Tor exit, "
        "and any widely reported spam or malware association. "
        "Stick to search results; do not invent."
    )
    try:
        if generate is not None:
            text = (generate(prompt) or "").strip()[:_SEARCH_MAX_CHARS]
        else:
            from google import genai  # optional — only when a Gemini key is set
            s = get_settings()
            api_key = s.gemini_api_key or s.gemini_api_key_alt
            if not api_key:
                return ""
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model=s.gemini_model_id or "gemini-flash-latest",
                contents=[{"role": "user", "parts": [{"text": prompt}]}],
                config={
                    "temperature": 0,
                    "max_output_tokens": 420,
                    "tools": [{"google_search": {}}],
                },
            )
            text = _extract_text(response)[:_SEARCH_MAX_CHARS]
    except Exception:
        return ""
    if text:
        with _SEARCH_CACHE_LOCK:
            _SEARCH_CACHE[cache_key] = (time.time(), text)
    return text


def _extract_text(response) -> str:
    candidates = getattr(response, "candidates", None)
    content = getattr(candidates[0], "content", None) if candidates else None
    parts = getattr(content, "parts", None) if content else None
    if not parts:
        return (getattr(response, "text", None) or "").strip()
    return "".join(
        p.text for p in parts
        if getattr(p, "text", None) and not getattr(p, "thought", False)
    ).strip()


def _compose_summary(facts: dict) -> str:
    ip = facts.get("ip") or ""
    if not ip:
        return ""
    bits = [ip]
    host = facts.get("hostname") or ""
    if host:
        bits.append(f"({host})")
    loc = ", ".join(p for p in (
        facts.get("city"), facts.get("region"),
        facts.get("country_name") or facts.get("country"),
    ) if p)
    if loc:
        bits.append("— " + loc)
    isp = facts.get("isp") or facts.get("org") or facts.get("name") or ""
    if isp:
        bits.append("ISP " + isp)
    if facts.get("asn"):
        bits.append(facts["asn"])
    role = facts.get("network_role_label") or ""
    if role:
        bits.append("[" + role + "]")
    if facts.get("vpn"):
        bits.append("likely VPN/proxy")
    sus = facts.get("suspicion") or "none"
    if sus != "none":
        bits.append("suspicion " + sus)
        if facts.get("suspicion_reason"):
            bits.append("(" + facts["suspicion_reason"] + ")")
    xip = facts.get("x_originating_ip") or ""
    if xip and xip != ip:
        bits.append("X-Originating-IP " + xip)
    search = (facts.get("search_summary") or "").strip()
    if search:
        bits.append("Search: " + search)
    return " ".join(bits)


def _search_context(facts: dict) -> str:
    parts = []
    if facts.get("isp"):
        parts.append("ISP " + facts["isp"])
    if facts.get("org"):
        parts.append("org " + facts["org"])
    loc = ", ".join(p for p in (facts.get("city"), facts.get("country")) if p)
    if loc:
        parts.append(loc)
    if facts.get("asn"):
        parts.append(facts["asn"])
    return "; ".join(parts)


def enrich(hop: dict, *, rdap_get=None, search_fn=None, geo_get=None,
           sender_domain: str = "") -> dict:
    """OSINT facts for an originating_hop() dict. Never raises."""
    hop = hop or {}
    ip = str(hop.get("ip") or "").strip()
    if not ip:
        return {}
    facts = {
        "ip": ip,
        "hostname": str(hop.get("hostname") or "").strip(),
        "x_originating_ip": str(hop.get("x_originating_ip") or "").strip(),
        "name": "",
        "org": "",
        "country": "",
        "country_name": "",
        "region": "",
        "city": "",
        "lat": None,
        "lon": None,
        "timezone": "",
        "isp": "",
        "asn": "",
        "as_name": "",
        "type": "",
        "mobile": False,
        "proxy": False,
        "hosting": False,
        "search_summary": "",
        "search_used": False,
        "sender_domain": (sender_domain or "").strip().lower(),
    }
    if geo_get is not None or _geo_enabled():
        try:
            geo = geo_lookup(ip, http_get=geo_get)
        except Exception:
            geo = None
        if geo:
            for key in (
                "country", "country_name", "region", "city", "lat", "lon",
                "timezone", "isp", "asn", "as_name", "mobile", "proxy", "hosting",
            ):
                if geo.get(key) not in (None, "", False):
                    facts[key] = geo[key]
            if geo.get("org") and not facts["org"]:
                facts["org"] = geo["org"]
    if rdap_lookup_enabled():
        try:
            rdap = ip_rdap_summary(ip, http_get=rdap_get)
        except Exception:
            rdap = None
        if rdap:
            facts["name"] = rdap.get("name") or facts["name"]
            if rdap.get("org"):
                facts["org"] = rdap["org"]
            if rdap.get("country") and not facts["country"]:
                facts["country"] = str(rdap["country"]).upper()[:8]
            facts["type"] = rdap.get("type") or ""
    if search_fn is not None or _search_enabled():
        fn = search_fn if search_fn is not None else (
            lambda ip_, host: _gemini_ip_search(ip_, host, _search_context(facts))
        )
        try:
            blurb = fn(ip, facts["hostname"]) or ""
        except Exception:
            blurb = ""
        facts["search_summary"] = blurb.strip()[:_SEARCH_MAX_CHARS]
        facts["search_used"] = bool(facts["search_summary"])
    facts.update(classify_network(facts, facts["sender_domain"]))
    facts["summary"] = _compose_summary(facts)
    return facts


def stage_flags(facts: dict) -> list[str]:
    flags: list[str] = []
    ip = facts.get("ip") or ""
    if ip:
        flags.append(f"origin_ip:{ip}")
    host = facts.get("hostname") or ""
    if host:
        flags.append(f"origin_hostname:{host}")
    xip = facts.get("x_originating_ip") or ""
    if xip and xip != ip:
        flags.append(f"origin_x_ip:{xip}")
    country = facts.get("country") or ""
    if country:
        flags.append(f"origin_ip_geo:{country}")
    if facts.get("isp"):
        flags.append(f"origin_ip_isp:{facts['isp'][:80]}")
    if facts.get("vpn"):
        flags.append("origin_ip_vpn")
    if facts.get("hosting"):
        flags.append("origin_ip_hosting")
    if facts.get("geo_mismatch") and country:
        flags.append(f"origin_ip_geo_mismatch:{country}")
    if facts.get("search_used"):
        flags.append("origin_ip_search")
    return flags


def stage_result(facts: dict) -> Optional[StageResult]:
    if not facts or not facts.get("ip"):
        return None
    return StageResult(
        stage="origin_ip",
        status=StageStatus.OK,
        sub_score=visual_score(facts),
        red_flags=stage_flags(facts),
        facts={
            "summary": facts.get("summary") or "",
            "ip": facts.get("ip") or "",
            "hostname": facts.get("hostname") or "",
            "x_originating_ip": facts.get("x_originating_ip") or "",
            "org": facts.get("org") or facts.get("name") or "",
            "country": facts.get("country") or "",
            "country_name": facts.get("country_name") or "",
            "region": facts.get("region") or "",
            "city": facts.get("city") or "",
            "lat": facts.get("lat"),
            "lon": facts.get("lon"),
            "isp": facts.get("isp") or "",
            "asn": facts.get("asn") or "",
            "as_name": facts.get("as_name") or "",
            "timezone": facts.get("timezone") or "",
            "network_role": facts.get("network_role") or "",
            "network_role_label": facts.get("network_role_label") or "",
            "vpn": bool(facts.get("vpn")),
            "hosting": bool(facts.get("hosting")),
            "geo_mismatch": bool(facts.get("geo_mismatch")),
            "suspicion": facts.get("suspicion") or "none",
            "suspicion_reason": facts.get("suspicion_reason") or "",
            "search_summary": facts.get("search_summary") or "",
            "search_used": bool(facts.get("search_used")),
        },
    )
