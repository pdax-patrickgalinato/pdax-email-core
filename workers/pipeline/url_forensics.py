"""Deterministic link intelligence — offline, stdlib-only.

Turns a raw URL (and, where available, the HTML anchor text that pointed at
it) into structured facts a downstream analyst — human or LLM — can judge:
the *unwrapped* destination after peeling secure-email-gateway rewrappers
(Trend Micro TMES clicktime, Microsoft SafeLinks, Proofpoint urldefense,
Mimecast), the registrable domain, IP-literal hosts, IDN/punycode, credential-
in-URL, risky TLDs, deep-subdomain burial, off-brand trust keywords, embedded
email addresses (OAuth-state exposure), and display-text-vs-target mismatch.

Architecture note (claude.md): this only produces *facts* (a dict of tags and
decoded values). It never decides a verdict and never dereferences a URL over
the network — no requests, no redirect-following. The email body and any
extracted link are attacker-controlled data; unwrapping is pure string work.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urlsplit

from backend.domainutils import registrable_domain, normalize_confusables

_URL_RE = re.compile(r'https?://[^\s<>"\'\)\]}]+', re.IGNORECASE)
_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
_IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

# TLDs with disproportionate abuse rates (curated, not exhaustive). The newer
# "file-extension" TLDs (.zip/.mov) are here because they invite filename
# confusion in links.
RISKY_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "country", "kim", "work",
    "gq", "cf", "tk", "ml", "ga", "rest", "fit", "live", "icu", "cam", "surf",
    "monster", "quest", "sbs", "cyou", "buzz", "lol", "beauty", "autos", "pw",
}
KNOWN_SHORTENERS = {
    # Synced with email_forensic_playbook.md Step 6 (non-exhaustive).
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "soo.gd", "s2r.co", "cutt.ly", "shorturl.at", "rebrand.ly", "adf.ly",
    "clk.im", "shorte.st", "bc.vc", "u.to", "lnkd.in", "rb.gy", "v.gd",
    "x.co", "psce.pw", "qr.ae", "trib.al", "ift.tt", "dlvr.it", "wp.me",
    "amzn.to", "fb.me", "youtu.be", "t.ly", "clck.ru", "gg.gg", "chilp.it",
    "mcaf.ee", "po.st", "tr.ee", "bit.do", "s.id", "short.io", "s.gy",
}
# Trust words phishers put in a hostname to borrow legitimacy. Flagged only
# when the registrable domain is NOT one of the brands they're imitating.
TRUST_WORDS = (
    "login", "signin", "sign-in", "secure", "account", "verify", "verification",
    "update", "auth", "wallet", "confirm", "security", "recover", "unlock",
    "billing", "support", "portal", "session", "validate",
)
KNOWN_BRAND_DOMAINS = {
    "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
    "google.com", "gmail.com", "apple.com", "icloud.com", "paypal.com",
    "amazon.com", "aws.amazon.com", "docusign.net", "docusign.com",
    "sharepoint.com", "dropbox.com", "adobe.com", "meta.com", "facebook.com",
    "pdax.ph",
}
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}

_MAX_UNWRAP_HOPS = 6


def extract_urls(text: str) -> list[str]:
    if not text:
        return []
    out = []
    for m in _URL_RE.findall(text):
        out.append(m.rstrip('.,;:)]}>"\''))
    return out


class _AnchorParser(HTMLParser):
    """Collects (visible_text, href, wraps_image) triples and every href.
    Pure parsing — HTMLParser does not execute scripts or fetch anything."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.pairs: list[tuple[str, str, bool]] = []
        self.hrefs: list[str] = []
        self._href_stack: list[str] = []
        self._text_stack: list[list[str]] = []
        self._img_stack: list[bool] = []

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t == "a":
            href = ""
            for k, v in attrs:
                if k.lower() == "href":
                    href = v or ""
            self._href_stack.append(href)
            self._text_stack.append([])
            self._img_stack.append(False)
            if href:
                self.hrefs.append(href)
        elif t == "img" and self._img_stack:
            self._img_stack[-1] = True

    def handle_data(self, data):
        if self._text_stack:
            self._text_stack[-1].append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href_stack:
            href = self._href_stack.pop()
            text = " ".join("".join(self._text_stack.pop()).split())
            wraps_image = self._img_stack.pop() if self._img_stack else False
            if href:
                self.pairs.append((text, href, wraps_image))


def extract_anchors(html: str) -> list[tuple[str, str]]:
    """Back-compat: (visible_text, href) pairs."""
    return [(t, h) for t, h, _ in extract_anchors_ex(html)]


def extract_anchors_ex(html: str) -> list[tuple[str, str, bool]]:
    """(visible_text, href, wraps_image) — wraps_image True when <a> contains <img>."""
    if not html:
        return []
    p = _AnchorParser()
    try:
        p.feed(html)
    except Exception:
        return []
    return p.pairs


_PLAIN_IMAGE_LINK_RE = re.compile(
    r'\[image:\s*([^\]]*)\]\s*<?(https?://[^>\s]+)>?',
    re.IGNORECASE,
)


def extract_image_hyperlinks(html: str, text: str = "") -> list[str]:
    """URLs that wrap an image (HTML <a><img>) or Gmail-style [image:] <url>."""
    out: list[str] = []
    seen = set()
    for _text, href, wraps in extract_anchors_ex(html or ""):
        if wraps and href and href not in seen:
            seen.add(href)
            out.append(href)
    for m in _PLAIN_IMAGE_LINK_RE.finditer(text or ""):
        href = m.group(2).rstrip('.,;:)]}>"\'')
        if href and href not in seen:
            seen.add(href)
            out.append(href)
    return out


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _decode_proofpoint_v2(u_value: str) -> str:
    # urldefense v2: '-' -> '%', '_' -> '/', then percent-decode.
    return unquote(u_value.replace("-", "%").replace("_", "/"))


def unwrap(url: str) -> tuple[str, list[str]]:
    """Peel gateway link-rewrite layers. Returns (final_url, chain) where chain
    lists each intermediate wrapper seen (outermost first). Never networks."""
    chain: list[str] = []
    current = url
    seen = set()
    for _ in range(_MAX_UNWRAP_HOPS):
        if current in seen:
            break
        seen.add(current)
        try:
            parts = urlsplit(current)
        except ValueError:
            break
        host = (parts.hostname or "").lower()
        path = parts.path or ""
        qs = parse_qs(parts.query)
        nxt = None

        if host.endswith("trendmicro.com") and "/wis/clicktime/" in path:
            nxt = (qs.get("url") or [None])[0]
        elif host.endswith(".safelinks.protection.outlook.com"):
            nxt = (qs.get("url") or [None])[0]
        elif "urldefense" in host:
            if "/v3/__" in current:
                m = re.search(r"/v3/__(.+?)__;", current)
                if m:
                    nxt = m.group(1)
            elif qs.get("u"):
                nxt = _decode_proofpoint_v2(qs["u"][0])
        else:
            # Generic single-hop redirect params, but only when the value is
            # itself a full http(s) URL (avoid mangling ordinary query args).
            for key in ("url", "u", "target", "dest", "destination", "redirect",
                        "redirecturl", "continue", "next", "returnurl", "goto", "link"):
                cand = (qs.get(key) or [None])[0]
                if cand:
                    cand = unquote(cand)
                    if cand.lower().startswith(("http://", "https://")):
                        nxt = cand
                        break

        if not nxt:
            break
        nxt = unquote(nxt)
        chain.append(current)
        current = nxt
    return current, chain


def analyze_url(url: str, display_text: str = "") -> dict:
    """Structured facts about one link. Pure string analysis, no network."""
    raw = (url or "").strip()
    final, chain = unwrap(raw)
    gateway_wrapped = bool(chain)

    try:
        parts = urlsplit(final)
    except ValueError:
        parts = urlsplit("")
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    reg = registrable_domain(host)
    tld = reg.rsplit(".", 1)[-1] if "." in reg else ""

    flags: list[str] = []
    labels = host.split(".") if host else []

    is_ip = bool(_IPV4_RE.match(host)) or (":" in host)
    if is_ip:
        flags.append("ip_literal_host")

    is_puny = any(l.startswith("xn--") for l in labels)
    if is_puny:
        flags.append("idn_punycode")

    has_cred = bool(parts.username) or "@" in (parts.netloc or "").split("/")[0]
    if has_cred:
        flags.append("credential_in_url")

    if scheme in DANGEROUS_SCHEMES:
        flags.append("dangerous_scheme:" + scheme)

    if tld in RISKY_TLDS:
        flags.append("risky_tld:" + tld)

    if reg in KNOWN_SHORTENERS:
        flags.append("url_shortener")

    # Sub-labels beyond the registrable domain — deep burial hides the real host.
    reg_label_count = reg.count(".") + 1 if reg else 0
    if len(labels) - reg_label_count >= 3:
        flags.append("deep_subdomain")

    if any(w in host for w in TRUST_WORDS) and reg not in KNOWN_BRAND_DOMAINS:
        flags.append("brand_keyword_offbrand")

    email_in_url = ""
    m = _EMAIL_RE.search(unquote(parts.query + " " + parts.path))
    if m:
        email_in_url = m.group(0)
        flags.append("email_in_url")

    # Display-text (anchor) vs actual target mismatch.
    display_mismatch = False
    disp = (display_text or "").strip()
    disp_host = ""
    if disp:
        dm = _URL_RE.search(disp)
        cand = dm.group(0) if dm else (disp if "." in disp and " " not in disp else "")
        if cand:
            if not cand.lower().startswith(("http://", "https://")):
                cand = "http://" + cand
            disp_host = _host_of(cand)
            disp_reg = registrable_domain(disp_host)
            if disp_reg and reg and disp_reg != reg and \
                    normalize_confusables(disp_reg) != normalize_confusables(reg):
                display_mismatch = True
                flags.append("display_target_mismatch")

    return {
        "raw_url": raw,
        "unwrapped_url": final,
        "gateway_wrapped": gateway_wrapped,
        "redirect_chain": chain,
        "scheme": scheme,
        "host": host,
        "registrable_domain": reg,
        "tld": tld,
        "is_ip_literal": is_ip,
        "is_punycode": is_puny,
        "has_credential": has_cred,
        "email_in_url": email_in_url,
        "display_text": disp,
        "display_host": disp_host,
        "display_target_mismatch": display_mismatch,
        "flags": sorted(set(flags)),
    }


def build_link_analysis(text_body: str, html_body: str,
                        extra_urls: list[str] | None = None,
                        max_links: int = 60) -> list[dict]:
    """All links across the body + attachments, deduped by unwrapped target,
    each with its analyze_url() facts. Anchor text (when present) feeds the
    display-vs-target mismatch check. Anchors that wrap an <img> (or Gmail
    [image:] plaintext form) are tagged wraps_image / image_hyperlink."""
    display_for: dict[str, str] = {}
    wraps_image_for: dict[str, bool] = {}
    ordered: list[str] = []

    def _add(u: str, disp: str = "", wraps_image: bool = False):
        if not u:
            return
        if u not in display_for:
            display_for[u] = disp
            wraps_image_for[u] = wraps_image
            ordered.append(u)
        else:
            if disp and not display_for[u]:
                display_for[u] = disp
            if wraps_image:
                wraps_image_for[u] = True

    for text, href, wraps in extract_anchors_ex(html_body):
        _add(href, text, wraps)
    for m in _PLAIN_IMAGE_LINK_RE.finditer(text_body or ""):
        _add(m.group(2).rstrip('.,;:)]}>"\''), m.group(1).strip(), True)
    for u in extract_urls(text_body):
        _add(u)
    for u in extract_urls(html_body):
        _add(u)
    for u in (extra_urls or []):
        _add(u)

    out: list[dict] = []
    seen_targets = set()
    for raw in ordered:
        if not raw.lower().startswith(("http://", "https://")):
            continue
        info = analyze_url(raw, display_for.get(raw, ""))
        if wraps_image_for.get(raw):
            info["wraps_image"] = True
            flags = list(info.get("flags") or [])
            if "image_hyperlink" not in flags:
                flags.append("image_hyperlink")
            info["flags"] = sorted(set(flags))
        else:
            info["wraps_image"] = False
        key = info["unwrapped_url"]
        if key in seen_targets:
            # Prefer keeping the wraps_image=True variant if we see it later.
            if info["wraps_image"]:
                for prev in out:
                    if prev["unwrapped_url"] == key and not prev.get("wraps_image"):
                        prev["wraps_image"] = True
                        pf = list(prev.get("flags") or [])
                        if "image_hyperlink" not in pf:
                            pf.append("image_hyperlink")
                        prev["flags"] = sorted(set(pf))
            continue
        seen_targets.add(key)
        out.append(info)
        if len(out) >= max_links:
            break
    return out
