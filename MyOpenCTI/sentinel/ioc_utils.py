"""IOC refanging / normalisation helpers shared by LLM, scoring, and Wazuh."""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

# Canonical labels for LLM / enrichment IOC type strings.
LLM_IOC_TYPE_MAP = {
    "ipv4": "IPv4", "ip": "IPv4", "ip address": "IPv4",
    "ipv6": "IPv6",
    "domain": "Domain", "hostname": "Domain", "fqdn": "Domain",
    "url": "URL", "uri": "URL",
    "md5": "MD5", "sha1": "SHA-1", "sha-1": "SHA-1",
    "sha256": "SHA-256", "sha-256": "SHA-256", "sha512": "SHA-512",
    "email": "Email", "e-mail": "Email",
    "cve": "CVE",
    "mutex": "Mutex",
    "filepath": "File path", "file path": "File path", "path": "File path",
    "filename": "Filename", "file name": "Filename",
    "registry": "Registry key", "registry key": "Registry key", "regkey": "Registry key",
    "user-agent": "User-Agent", "user_agent": "User-Agent", "useragent": "User-Agent",
    "ja3": "JA3", "ja3s": "JA3S", "jarm": "JARM",
    "asn": "ASN",
    "bitcoin": "Cryptocurrency wallet", "btc": "Cryptocurrency wallet",
    "wallet": "Cryptocurrency wallet", "cryptocurrency": "Cryptocurrency wallet",
    "certificate": "Certificate / thumbprint", "thumbprint": "Certificate / thumbprint",
    "ssl": "Certificate / thumbprint",
    "mac": "MAC address", "mac address": "MAC address",
    "process": "Process / service", "service": "Process / service",
    "command": "Command line", "cmdline": "Command line", "cli": "Command line",
    "yara": "YARA / sigma ref", "sigma": "YARA / sigma ref",
    "defanged": "Defanged indicator", "defanged indicator": "Defanged indicator",
    "hash": "SHA-256", "other": "Other",
}


def _llm_ioc_label(raw_type: str) -> str:
    return LLM_IOC_TYPE_MAP.get((raw_type or "other").strip().lower(), "Other")


_PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|127\.|0\.|192\.168\.|169\.254\.|221\.0\.0\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.)"
)
_BOGUS_HOST_RE = re.compile(
    r"(?:example\.(?:com|org|net)|localhost|test\.com|invalid|localdomain|"
    r"w3\.org|schema\.org|microsoft\.com/typography|googleapis\.com|"
    r"gstatic\.com|cloudflare\.com|wp-content|wp-includes)",
    re.IGNORECASE,
)


def _refang_ioc(value: str) -> str:
    """Undo common CTI defanging so Wazuh can match the live indicator."""
    v = (value or "").strip().rstrip(".,);]'\"")
    v = v.replace("[.]", ".").replace("[.]", ".")
    v = re.sub(r"^hxxps://", "https://", v, flags=re.IGNORECASE)
    v = re.sub(r"^hxxp://", "http://", v, flags=re.IGNORECASE)
    v = v.replace("[:]", ":")
    return v.strip()


def normalize_iocs_for_wazuh(iocs: Dict[str, List[str]],
                             exclude_urls: Optional[Set[str]] = None) -> List[Tuple[str, str]]:
    """Flatten typed IOCs into (key, comment) pairs suitable for a Wazuh CDB list.

    Returns de-duplicated, refanged indicators. Skips private IPs and obvious noise.
    """
    exclude_urls = {u.lower().rstrip("/") for u in (exclude_urls or set()) if u}
    out: List[Tuple[str, str]] = []
    seen: Set[str] = set()

    for label, values in (iocs or {}).items():
        for raw in values:
            v = _refang_ioc(raw)
            if not v or len(v) < 4:
                continue
            if _BOGUS_HOST_RE.search(v):
                continue
            if label == "IPv4" and _PRIVATE_IP_RE.match(v):
                continue
            if label == "URL":
                if v.lower().rstrip("/") in exclude_urls:
                    continue
                # Prefer the host for CDB lookups; keep full URL as a second key when useful.
                host = re.sub(r"^https?://", "", v, flags=re.IGNORECASE).split("/")[0].split(":")[0]
                host = host.strip().lower()
                if host and host not in seen and not _BOGUS_HOST_RE.search(host):
                    seen.add(host)
                    out.append((host, f"url-host/{label}"))
            key = v.lower() if label in {"IPv4", "URL", "Defanged indicator"} else v.lower()
            if label in {"MD5", "SHA-1", "SHA-256"}:
                key = v.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append((v if label.startswith("SHA") or label == "MD5" else key, label))
    return out

