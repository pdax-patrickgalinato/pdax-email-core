"""Stage 3 — URL / link analysis.

Offline signals: anchor-vs-href mismatch, lookalike domains, brand keyword in
non-brand domain, IP-literal URLs, excessive subdomains, risky TLDs,
**embedded redirect unwrapping** (open-redirect abuse — attackers hide the real
payload in a query parameter of a legitimate tracker/gateway domain, so the
visible domain looks clean), and an OAuth `state`-param email-exposure check
(a plaintext victim address in `state` on an otherwise-legitimate authorize
endpoint is a consent-phish/recon tell, not a domain-reputation one). Live
redirect-following / cert inspection is a hook (off by default; the gateway
runs it from the isolated egress path)."""
from __future__ import annotations

import html
import re
import time
from urllib.parse import urlparse, parse_qs, unquote

from ..models import StageResult, StageStatus
from ..parsed_email import ParsedEmail
from ..domainutils import registrable_domain, normalize_confusables, levenshtein

RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml"}
BRAND_KEYWORDS = ("login", "secure", "verify", "account", "signin", "update", "wallet")
_IP_HOST = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

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

    mismatches = pe.anchor_mismatches()
    if mismatches:
        flags.append("anchor_href_mismatch"); score += 25

    return StageResult(
        stage="urls",
        status=StageStatus.OK,
        sub_score=min(score, 100.0),
        red_flags=sorted(set(flags)),
        facts={"url_count": len(surface_urls), "embedded_count": len(embedded_found),
               "urls": url_records,
               "embedded": embedded_found, "anchor_mismatches": mismatches},
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
