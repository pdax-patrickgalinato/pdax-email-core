"""Stage 3 — URL / link analysis.

Offline signals: anchor-vs-href mismatch, lookalike domains, brand keyword in
non-brand domain, IP-literal URLs, excessive subdomains, risky TLDs,
**embedded redirect unwrapping** (open-redirect abuse — attackers hide the real
payload in a query parameter of a legitimate tracker/gateway domain, so the
visible domain looks clean), and an OAuth `state`-param email-exposure check
(a plaintext victim address in `state` on an otherwise-legitimate authorize
endpoint is a consent-phish/recon tell, not a domain-reputation one). Trusted-
channel brand lure / TestFlight service abuse lives in deception.py (composed
structure), not here. Live redirect-following / cert inspection is a hook
(off by default; the gateway runs it from the isolated egress path)."""
from __future__ import annotations

import html
import re
import time
from urllib.parse import urlparse, parse_qs, unquote

from backend.models import StageResult, StageStatus
from backend.parsed_email import ParsedEmail
from backend.domainutils import registrable_domain, normalize_confusables, levenshtein
from .headers import auth_passed

RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml"}
BRAND_KEYWORDS = ("login", "secure", "verify", "account", "signin", "update", "wallet")

# Known link-shortener registrable domains. Used both for a mild url-stage flag
# and — crucially — to feed the behavioral correlation store (see correlation.py).
SHORTENER_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "short.io",
    "tiny.cc", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy",
    "snip.ly", "linktr.ee", "tr.im", "cli.gs", "j.mp", "youtu.be",
    "fb.me", "wp.me", "adf.ly",
})
_IP_HOST = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# Outlook Safe Links rewriter hostname pattern
_SAFE_LINKS_HOST = re.compile(r"\.safelinks\.protection\.outlook\.com$", re.I)
# FTP scheme
_FTP_RE = re.compile(r"^ftps?://", re.I)

# Query-parameter names commonly used to carry a redirect target. Legitimate
# click-trackers use these too, so the parameter alone is not a verdict — but
# the *target* it carries must be analyzed on its own merits.
REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "redirect_url", "next", "dest",
    "destination", "target", "u", "r", "link", "goto", "continue", "return",
    "returnurl", "return_url", "td_redirect", "out", "to", "forward",
}
_URLISH = re.compile(r"^https?://", re.I)
# A bare .html/.htm file at the end of a path — the classic shape of a
# credential-harvest page dropped onto a compromised site.
_HTML_FILE_PATH = re.compile(r"/[\w.-]+\.(?:html?|php)$", re.I)

# OAuth/OIDC authorize-endpoint shape. This fires on fully legitimate hosts
# (login.microsoftonline.com, accounts.google.com, etc.) — the host is never
# the tell. What's abnormal is a plaintext victim email sitting in `state`:
# legitimate apps use an opaque token there, never PII, so a real address in
# `state` is a strong sign of a templated consent-phish / recon link, not of
# domain compromise.
_OAUTH_AUTHORIZE_PATH = re.compile(r"/oauth2?(?:/v[\d.]+)?/authorize", re.I)
_EMAIL_IN_STRING = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")


def _host(url: str) -> str:
    h = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split("?")[0]
    return h.split("@")[-1].split(":")[0].lower()


def unwrap_embedded(url: str, depth: int = 0, seen=None) -> list[dict]:
    """Recursively pull redirect targets out of query parameters.

    Returns a list of {'target': url, 'wrapper_domain': d, 'param': name}.
    Depth-capped to avoid pathological nesting."""
    if seen is None:
        seen = set()
    if depth >= 3 or url in seen:
        return []
    seen.add(url)
    out: list[dict] = []
    try:
        parsed = urlparse(html.unescape(url))
        params = parse_qs(parsed.query, keep_blank_values=False)
    except Exception:
        return out

    wrapper = registrable_domain(_host(url))
    for name, values in params.items():
        if name.lower() not in REDIRECT_PARAMS:
            continue
        for v in values:
            cand = unquote(html.unescape(v)).strip()
            if not _URLISH.match(cand):
                continue
            out.append({"target": cand, "wrapper_domain": wrapper, "param": name})
            out.extend(unwrap_embedded(cand, depth + 1, seen))
    return out


def _short_url(url: str, limit: int = 96) -> str:
    u = (url or "").strip()
    return u if len(u) <= limit else u[: limit - 1] + "…"


def _chain_hosts(urls: list[str]) -> list[str]:
    hosts: list[str] = []
    for raw in urls:
        h = _host(raw)
        if h and (not hosts or hosts[-1] != h):
            hosts.append(h[:80])
    return hosts


def _chain_suspicious(hosts: list[str]) -> bool:
    regs: list[str] = []
    ip_hop = False
    shortener = False
    for h in hosts:
        if _IP_HOST.search(h):
            ip_hop = True
            continue
        reg = registrable_domain(h)
        if reg in SHORTENER_DOMAINS:
            shortener = True
        if reg and reg not in regs:
            regs.append(reg)
    return ip_hop or len(regs) >= 3 or (shortener and len(regs) >= 2)


def build_link_hops(surface_urls: list[str], landing_pages: list | None = None) -> list[dict]:
    """Compact redirect chains for the assessment-flow graph.

    Offline: query-parameter unwraps (Safe Links, Trend ClickTime, trackers).
    Optional: HTTP Location hops from landing_fetch when that flag is on.
    """
    chains: list[dict] = []
    seen: set[tuple] = set()

    def _add(urls: list[str], kind: str) -> None:
        hosts = _chain_hosts(urls)
        if len(hosts) < 2:
            return
        key = tuple(hosts)
        if key in seen:
            return
        seen.add(key)
        chains.append({
            "hosts": hosts[:10],
            "urls": [_short_url(u) for u in urls[:10]],
            "hop_count": len(hosts),
            "final": hosts[-1],
            "kind": kind,
            "suspicious": _chain_suspicious(hosts),
        })

    for u in surface_urls or []:
        hops = [u]
        for emb in unwrap_embedded(u):
            tgt = emb.get("target") or ""
            if tgt and tgt not in hops:
                hops.append(tgt)
        _add(hops, "embedded")

    for page in landing_pages or []:
        if not isinstance(page, dict):
            continue
        raw = [u for u in (page.get("redirect_chain") or []) if isinstance(u, str) and u]
        requested = page.get("requested_url") or ""
        final = page.get("final_url") or ""
        if requested and (not raw or raw[0] != requested):
            raw = [requested] + [u for u in raw if u != requested]
        if final and (not raw or raw[-1] != final):
            raw.append(final)
        _add(raw, "http")

    chains.sort(key=lambda c: (-int(c["suspicious"]), -c["hop_count"]))
    return chains[:8]


def run(pe: ParsedEmail, protected_domains: list[str]) -> StageResult:
    t0 = time.perf_counter()
    surface_urls = pe.urls()
    if not surface_urls:
        return StageResult(stage="urls", status=StageStatus.SKIPPED,
                           latency_ms=int((time.perf_counter() - t0) * 1000))

    flags: list[str] = []
    score = 0.0
    protected = [registrable_domain(p) for p in protected_domains]
    sender_dom = registrable_domain(pe.from_domain)
    url_records = []
    embedded_found = []
    shortener_domains: list = []

    # Expand the analysis set: every surface URL plus anything hidden inside it.
    analysis_set = [(u, None) for u in surface_urls]
    for u in surface_urls:
        for emb in unwrap_embedded(u):
            embedded_found.append(emb)
            analysis_set.append((emb["target"], emb))

    if embedded_found:
        flags.append("url_embedded_redirect")
        score += 5     # trackers do this legitimately; the target is what matters

    for url, emb in analysis_set:
        host = _host(url)
        is_ip = bool(_IP_HOST.search(host))
        # An IP-literal host isn't a domain — registrable_domain() would
        # mangle it into a meaningless last-two-octets string (e.g.
        # "192.168.1.1" -> "1.1"). Route it as an IP IOC instead so
        # downstream extraction/reporting doesn't misfile it as a domain.
        reg = "" if is_ip else registrable_domain(host)
        rec: dict = {"url": url, "host": host, "reg_domain": reg}
        if is_ip:
            rec["ip"] = host
        if emb:
            rec["embedded_via"] = emb["param"]
            rec["wrapper_domain"] = emb["wrapper_domain"]

        if not is_ip and reg in SHORTENER_DOMAINS:
            flags.append(f"url_link_shortener:{reg}"); score += 5
            shortener_domains.append(reg)

        if is_ip:
            flags.append("url_ip_literal"); score += 20; rec["ip_literal"] = True

        norm = normalize_confusables(reg)
        for p in protected:
            if reg != p and (norm == p or levenshtein(norm, p, cap=1) <= 1):
                flags.append(f"url_lookalike:{p}"); score += 45
                rec["lookalike_of"] = p
                break

        if reg not in protected and any(kw in host for kw in BRAND_KEYWORDS):
            flags.append("url_brand_keyword_offbrand"); score += 15
            rec["brand_keyword"] = True

        tld = reg.rsplit(".", 1)[-1] if "." in reg else ""
        if tld in RISKY_TLDS:
            flags.append(f"url_risky_tld:{tld}"); score += 10

        if host.count(".") >= 4:
            flags.append("url_deep_subdomain"); score += 8

        unescaped = html.unescape(url)
        if _OAUTH_AUTHORIZE_PATH.search(urlparse(unescaped).path):
            state_m = re.search(r"(?:^|&)state=([^&]*)", urlparse(unescaped).query, re.I)
            if state_m and _EMAIL_IN_STRING.search(unquote(state_m.group(1))):
                flags.append("url_oauth_state_email_exposure"); score += 35
                rec["oauth_state_email_exposure"] = True

        # --- signals that apply specifically to unwrapped redirect targets ---
        if emb:
            wrapper = emb["wrapper_domain"]
            if is_ip:
                # A redirect wrapper hiding a raw IP as its real target is
                # unambiguously suspicious regardless of the wrapper — no
                # legitimate tracker's "real destination" is a bare IP.
                flags.append("url_redirect_to_ip"); score += 30
                rec["redirect_unrelated"] = True
            # Target unrelated to BOTH the wrapper and the sender: a legitimate
            # tracker redirects to the brand's own property, not a third party.
            elif reg and reg != wrapper and reg != sender_dom:
                flags.append("url_redirect_unrelated_domain"); score += 30
                rec["redirect_unrelated"] = True
            # Bare .html/.php landing file on someone else's domain — the usual
            # shape of a phishing page dropped on a compromised host.
            path = urlparse(url).path
            if _HTML_FILE_PATH.search(path) and reg != sender_dom:
                flags.append("url_redirect_to_page_file"); score += 30
                rec["redirect_page_file"] = True

        url_records.append(rec)

    # FTP/FTPS URLs are almost never used in legitimate email — flag them.
    for url, _ in analysis_set:
        if _FTP_RE.match(url):
            flags.append("url_ftp_scheme"); score += 15
            break

    mismatches = pe.anchor_mismatches()
    if mismatches:
        flags.append("anchor_href_mismatch"); score += 25

    # --- Tracking beacons / pixels ---
    # These are external resources that load automatically on open (not clicked
    # links), used to confirm email delivery and capture the reader's IP.
    beacons = pe.tracking_beacons()
    beacon_records = []
    beacon_domains: set[str] = set()
    for b in beacons:
        bhost = _host(b["url"])
        breg = "" if _IP_HOST.search(bhost) else registrable_domain(bhost)
        # Skip beacons that resolve to a sender-owned or protected domain —
        # those are first-party analytics, not covert tracking.
        if breg and breg != sender_dom and breg not in protected:
            beacon_records.append({**b, "host": bhost, "reg_domain": breg})
            beacon_domains.add(breg)

    if beacon_records and not auth_passed(pe):
        # Open-tracking pixels are ubiquitous on authenticated Google /
        # JumpCloud / marketing mail. Score them only when SPF/DKIM did not
        # pass — that's when a hidden pixel is an "unknown infrastructure" tell.
        flags.append("tracking_beacon_detected"); score += 5
        for bd in beacon_domains:
            flags.append(f"url_tracking_beacon:{bd}")

    landing_pages: list = []
    try:
        from .landing_fetch import analyze_urls as _fetch_landings, landing_fetch_enabled
        if landing_fetch_enabled():
            targets = []
            for rec in url_records:
                u = rec.get("url") or ""
                if isinstance(u, str) and u.startswith(("http://", "https://")):
                    targets.append(u)
            landing_pages = _fetch_landings(targets)
    except Exception:
        landing_pages = []

    link_hops = build_link_hops(surface_urls, landing_pages)

    return StageResult(
        stage="urls",
        status=StageStatus.OK,
        sub_score=min(score, 100.0),
        red_flags=sorted(set(flags)),
        facts={"url_count": len(surface_urls), "embedded_count": len(embedded_found),
               "urls": url_records, "embedded": embedded_found,
               "anchor_mismatches": mismatches,
               "shortener_domains": sorted(set(shortener_domains)),
               "tracking_beacons": beacon_records,
               "beacon_domains": sorted(beacon_domains),
               "link_hops": link_hops,
               "link_hop_count": max((c.get("hop_count") or 0 for c in link_hops), default=0)},
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
