"""Opt-in live landing-page fetch for SEGS deep analysis (MSOC gap).

Fetches a small number of already-unwrapped http(s) URLs from an email so the
analysis agent can ground "landing page" findings (title, forms, final URL
after redirects) the way an MSOC analyst would — without executing scripts or
detonating content.

Safety (HANDOFF / claude.md):
- Off by default; enable with SEG_LANDING_FETCH=1.
- SSRF guards: private/link-local/metadata IPs, non-http(s), localhost blocked;
  DNS is resolved and re-checked before connect.
- Never raises — returns degraded facts on any failure (same contract as
  app/rdap_client.py).
- Fetched HTML is attacker-controlled untrusted data for any downstream LLM.
"""
from __future__ import annotations

import html as html_lib
import ipaddress
import re
import socket
import ssl
from html.parser import HTMLParser
from typing import Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from backend.domainutils import registrable_domain
from backend.config import get_settings

_USER_AGENT = "SEGS-LandingFetch/1.0"
_TIMEOUT = 8
_MAX_REDIRECTS = 5
_MAX_BODY = 256 * 1024
_MAX_URLS = 3

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_META_DESC_RE = re.compile(
    r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)["\']',
    re.I,
)
_META_DESC_RE_ALT = re.compile(
    r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+name=["\']description["\']',
    re.I,
)


def landing_fetch_enabled() -> bool:
    return get_settings().landing_fetch


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (getattr(ip, "is_global", None) is False)
    )


def _host_is_safe(hostname: str) -> tuple[bool, str]:
    """Returns (ok, reason). Resolves DNS and rejects private/metadata targets."""
    if not hostname:
        return False, "empty_host"
    host = hostname.strip().lower().rstrip(".")
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        return False, "localhost_blocked"
    # Literal IP in the URL
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip):
            return False, "private_or_reserved_ip"
        # Explicit cloud metadata ranges commonly abused for SSRF
        if str(ip) in ("169.254.169.254", "metadata.google.internal"):
            return False, "metadata_endpoint"
        return True, "ok"
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, "dns_resolution_failed"
    if not infos:
        return False, "dns_resolution_failed"
    for info in infos:
        sockaddr = info[4]
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if _is_blocked_ip(ip) or str(ip) == "169.254.169.254":
            return False, "resolved_to_private_or_reserved_ip"
    return True, "ok"


def url_allowed(url: str) -> tuple[bool, str]:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False, "malformed_url"
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, "scheme_not_http_https"
    if not parts.hostname:
        return False, "empty_host"
    return _host_is_safe(parts.hostname)


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.form_fields: list[str] = []
        self.has_password = False
        self.script_hosts: list[str] = []
        self._in_form = False

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        ad = { (k or "").lower(): (v or "") for k, v in attrs }
        if t == "form":
            self._in_form = True
        elif t == "input" and self._in_form:
            name = ad.get("name") or ad.get("id") or ad.get("type") or "input"
            self.form_fields.append(name)
            if (ad.get("type") or "").lower() == "password":
                self.has_password = True
        elif t == "textarea" and self._in_form:
            self.form_fields.append(ad.get("name") or "textarea")
        elif t == "script":
            src = ad.get("src")
            if src and src.startswith(("http://", "https://", "//")):
                try:
                    host = urlsplit(src if "://" in src else "https:" + src).hostname
                    if host and host not in self.script_hosts:
                        self.script_hosts.append(host)
                except ValueError:
                    pass

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._in_form = False


def _extract_page_facts(html_text: str) -> dict:
    title = ""
    m = _TITLE_RE.search(html_text or "")
    if m:
        title = html_lib.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:200]
    desc = ""
    md = _META_DESC_RE.search(html_text or "") or _META_DESC_RE_ALT.search(html_text or "")
    if md:
        desc = html_lib.unescape(md.group(1)).strip()[:300]
    parser = _FormParser()
    try:
        parser.feed(html_text or "")
    except Exception:
        pass
    return {
        "title": title,
        "meta_description": desc,
        "form_fields": parser.form_fields[:30],
        "has_password_field": parser.has_password,
        "script_hosts": parser.script_hosts[:20],
    }


def _tls_cn(url: str) -> Optional[str]:
    """Best-effort peer cert CN for https URLs. Never raises."""
    try:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            return None
        port = parts.port or 443
        ctx = ssl.create_default_context()
        with socket.create_connection((parts.hostname, port), timeout=_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=parts.hostname) as ssock:
                cert = ssock.getpeercert()
        if not cert:
            return None
        for rdn in cert.get("subject", ()):
            for k, v in rdn:
                if k == "commonName":
                    return v
        return None
    except Exception:
        return None


def fetch_one(
    url: str,
    *,
    opener: Optional[Callable] = None,
    timeout: int = _TIMEOUT,
    max_redirects: int = _MAX_REDIRECTS,
) -> dict:
    """Fetch a single URL with redirect following and SSRF checks.

    `opener(request, timeout) -> (status, final_url, headers_dict, body_bytes)`
    may be injected for tests. Never raises.
    """
    base = {
        "requested_url": url,
        "final_url": "",
        "redirect_chain": [],
        "redirect_hops": 0,
        "http_status": 0,
        "tls_cn": None,
        "title": "",
        "meta_description": "",
        "form_fields": [],
        "has_password_field": False,
        "script_hosts": [],
        "registrable_domain": "",
        "degraded": False,
        "error": "",
        "fetched": False,
    }
    ok, reason = url_allowed(url)
    if not ok and opener is None:
        base["degraded"] = True
        base["error"] = reason
        return base
    # Injected openers are for unit tests — still block obviously bad schemes,
    # but skip live DNS (sandbox/CI often has no resolver).
    if opener is not None:
        try:
            parts = urlsplit(url)
            if (parts.scheme or "").lower() not in ("http", "https"):
                base["degraded"] = True
                base["error"] = "scheme_not_http_https"
                return base
        except ValueError:
            base["degraded"] = True
            base["error"] = "malformed_url"
            return base

    if opener is not None:
        try:
            status, final_url, _headers, body = opener(url, timeout)
        except Exception as e:
            base["degraded"] = True
            base["error"] = type(e).__name__
            return base
        base["http_status"] = int(status or 0)
        base["final_url"] = final_url or url
        base["redirect_chain"] = [url] if final_url and final_url != url else []
        if final_url and final_url != url:
            base["redirect_chain"] = [url, final_url]
            base["redirect_hops"] = 1
        text = (body or b"")[:_MAX_BODY].decode("utf-8", "replace")
        facts = _extract_page_facts(text)
        base.update(facts)
        base["registrable_domain"] = registrable_domain(urlsplit(base["final_url"]).hostname or "")
        base["fetched"] = True
        return base

    current = url
    chain: list[str] = []
    body = b""
    status = 0
    for hop in range(max_redirects + 1):
        ok, reason = url_allowed(current)
        if not ok:
            base["degraded"] = True
            base["error"] = reason
            base["redirect_chain"] = chain
            base["redirect_hops"] = len(chain)
            return base
        req = Request(current, method="GET", headers={
            "User-Agent": _USER_AGENT,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        })
        try:
            with urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", None) or resp.getcode() or 200
                # http.client may already have followed redirects; record geturl
                final = resp.geturl() or current
                if final != current and final not in chain:
                    chain.append(current)
                raw = resp.read(_MAX_BODY + 1)
                body = raw[:_MAX_BODY]
                current = final
                break
        except HTTPError as e:
            # Some servers redirect via HTTPError location
            loc = e.headers.get("Location") if e.headers else None
            status = e.code
            if loc and e.code in (301, 302, 303, 307, 308) and hop < max_redirects:
                chain.append(current)
                nxt = urljoin(current, loc)
                current = nxt
                continue
            base["degraded"] = True
            base["error"] = f"http_{e.code}"
            base["http_status"] = e.code
            base["final_url"] = current
            base["redirect_chain"] = chain
            base["redirect_hops"] = len(chain)
            return base
        except (URLError, TimeoutError, OSError, ValueError, ssl.SSLError) as e:
            base["degraded"] = True
            base["error"] = type(e).__name__
            base["redirect_chain"] = chain
            base["redirect_hops"] = len(chain)
            return base
    else:
        base["degraded"] = True
        base["error"] = "too_many_redirects"
        base["redirect_chain"] = chain
        base["redirect_hops"] = len(chain)
        return base

    base["http_status"] = int(status or 0)
    base["final_url"] = current
    base["redirect_chain"] = chain + ([current] if chain else [])
    base["redirect_hops"] = len(chain)
    text = body.decode("utf-8", "replace")
    facts = _extract_page_facts(text)
    base.update(facts)
    base["registrable_domain"] = registrable_domain(urlsplit(current).hostname or "")
    if current.lower().startswith("https://"):
        base["tls_cn"] = _tls_cn(current)
    base["fetched"] = True
    return base


def analyze_urls(urls: list[str], *, opener: Optional[Callable] = None) -> list[dict]:
    """Fetch up to _MAX_URLS unique registrable destinations. Never raises."""
    if not landing_fetch_enabled() and opener is None:
        return []
    seen_domains: set[str] = set()
    out: list[dict] = []
    for raw in urls or []:
        if len(out) >= _MAX_URLS:
            break
        if not raw or not isinstance(raw, str):
            continue
        try:
            host = urlsplit(raw).hostname or ""
        except ValueError:
            continue
        reg = registrable_domain(host)
        key = reg or host.lower()
        if not key or key in seen_domains:
            continue
        seen_domains.add(key)
        out.append(fetch_one(raw, opener=opener))
    return out


def candidate_urls_from_link_analysis(link_analysis: list) -> list[str]:
    """Prefer unwrapped destinations that look suspicious or mismatched."""
    if not link_analysis:
        return []
    preferred = []
    rest = []
    for item in link_analysis:
        if not isinstance(item, dict):
            continue
        dest = item.get("unwrapped_url") or item.get("url") or ""
        if not dest.startswith(("http://", "https://")):
            continue
        flags = set(item.get("flags") or [])
        if item.get("mismatch") or flags.intersection({
            "display_target_mismatch", "url_shortener", "risky_tld",
            "ip_literal_host", "brand_keyword_offbrand",
        }):
            preferred.append(dest)
        else:
            rest.append(dest)
    # Dedupe preserving order
    seen = set()
    ordered = []
    for u in preferred + rest:
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    return ordered
