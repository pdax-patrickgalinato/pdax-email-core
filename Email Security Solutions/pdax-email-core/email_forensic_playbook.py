"""Advanced Email Attachment & URL Forensic Analysis Playbook (v2.0).

Runnable form of email_forensic_playbook.md. Deterministic second opinion that
runs on every email carrying an attachment (via eml_analysis_agent.parse_eml).
Fully offline — no network, no live shortener expansion, no destination-page
fetch (Steps 7–8 network checks are hooks only).

Scoring follows Step 12 of the playbook; classification follows Step 13;
response actions follow Step 14. Gateway link rewrappers are peeled before URL
scoring (Golden Rule: analyze the destination, not the decoy).
"""
from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

# -----------------------------
# CONFIG (playbook Steps 2, 6, 9, 12)
# -----------------------------

# Step 6 — expanded shortener list (exact host / subdomain match only).
SUSPICIOUS_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "soo.gd", "s2r.co", "cutt.ly", "shorturl.at", "rebrand.ly", "adf.ly",
    "clk.im", "shorte.st", "bc.vc", "u.to", "lnkd.in", "rb.gy", "v.gd",
    "x.co", "psce.pw", "qr.ae", "trib.al", "ift.tt", "dlvr.it", "wp.me",
    "amzn.to", "fb.me", "youtu.be", "t.ly", "clck.ru", "gg.gg", "chilp.it",
    "mcaf.ee", "po.st", "s.gy",
]

# Image / paste hosts commonly used as "screenshot" click lures (not signature social).
IMAGE_FILE_HOSTS = {
    "s.gy", "psce.pw", "ibb.co", "imgbb.com", "postimg.cc", "prnt.sc",
    "lightshot.com", "freeimage.host", "imgpile.com",
}

# Destinations that are normal behind signature logos / social icons.
# An image linking HERE must NOT raise the image-link-lure score.
SIGNATURE_SAFE_DOMAINS = {
    "linkedin.com", "facebook.com", "fb.com", "fb.me", "twitter.com", "x.com",
    "instagram.com", "youtube.com", "youtu.be", "github.com", "glassdoor.com",
    "whatsapp.com", "wa.me", "telegram.org", "t.me", "threads.net", "tiktok.com",
    "pinterest.com", "reddit.com", "snapchat.com", "discord.com", "discord.gg",
    "microsoft.com", "aka.ms", "office.com", "office365.com", "microsoftonline.com",
    "google.com", "g.page", "maps.google.com", "apple.com", "apps.apple.com",
    "play.google.com", "zoom.us", "calendly.com", "linktr.ee",
}

# Step 6 path keywords + Step 9 urgency/threat language
URL_PATH_KEYWORDS = [
    "login", "verify", "secure", "update", "urgent", "suspend", "confirm",
    "error", "signin", "sign-in", "account", "password", "credential",
]
SE_KEYWORDS = [
    "verify", "urgent", "error", "suspend", "login", "confirm", "act now",
    "immediately", "expire", "locked", "unusual activity", "reward",
]
ATTACHMENT_FRAMING = [
    "see attached", "see the attached", "view screenshot", "see screenshot",
    "important document", "check document", "click the image", "click here",
    "view the image", "open the attachment",
]

# Step 2 — file-type risk classes
CRITICAL_EXTS = {"exe", "dll", "bat", "cmd", "ps1", "psm1", "js", "jse",
                 "vbs", "vbe", "hta", "scr", "com", "pif", "msi", "wsf"}
MACRO_EXTS = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm"}
ARCHIVE_EXTS = {"zip", "rar", "7z", "iso", "img", "cab", "gz", "tgz"}
HTML_EXTS = {"html", "htm"}
IMAGE_EXTS = {"jpg", "jpeg", "png", "gif", "bmp", "webp"}
PDF_EXTS = {"pdf"}

# Step 12 weights
W_SUSPICIOUS_DOMAIN = 30
W_URL_SHORTENER = 25
W_REDIRECT_CHAIN = 20
W_NEWLY_REGISTERED = 25   # applied only when fact is supplied (no offline WHOIS)
W_AUTH_FAIL = 20          # DKIM or SPF fail (playbook: "DKIM/SPF fail")
W_ARC_FAIL = 15           # ARC broken trust chain (Step 10)
W_DMARC_FAIL = 15
W_SOCIAL_ENGINEERING = 25
W_SUSPICIOUS_ATTACHMENT = 20
W_EMBEDDED_SCRIPT_MACRO = 30
W_OBFUSCATION = 20
W_IMAGE_LINK_LURE = 25   # Step 4: image + off-brand external link (not signature)

_IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_URL_RE = re.compile(r'https?://[^\s<>"\']+')
_EMAIL_DOMAIN_RE = re.compile(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')
_SIGNATURE_NAME_RE = re.compile(
    r'(logo|signature|\bsig\b|icon|banner|social|linkedin|facebook|twitter|'
    r'instagram|youtube|whatsapp|telegram|tiktok)',
    re.IGNORECASE,
)
_BAIT_NAME_RE = re.compile(
    r'(photo[_-]?|screenshot|image\d|\bimg\d|^image$|error|screen[_-]?)',
    re.IGNORECASE,
)


# -----------------------------
# HELPERS
# -----------------------------

def extract_urls(text):
    if not text:
        return []
    return [m.rstrip('.,;:)]}>"\'') for m in _URL_RE.findall(text)]


def get_domain(url):
    try:
        return (urlparse(url).netloc or "").lower().split("@")[-1]
    except Exception:
        return ""


def _ext(filename):
    name = (filename or "").strip().strip('"').lower()
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1]


def _all_exts(filename):
    name = (filename or "").strip().strip('"').lower()
    parts = [p for p in name.split(".") if p]
    return parts[1:] if len(parts) > 1 else []


def has_fragment(url):
    try:
        return bool(urlparse(url).fragment)
    except Exception:
        return "#" in (url or "")


def is_shortener(domain):
    domain = (domain or "").lower()
    if not domain:
        return False
    return any(domain == s or domain.endswith("." + s) for s in SUSPICIOUS_SHORTENERS)


def risk_band(total_score):
    """Step 12 thresholds → LOW / MEDIUM / HIGH / CRITICAL."""
    if total_score >= 100:
        return "CRITICAL"
    if total_score >= 61:
        return "HIGH"
    if total_score >= 31:
        return "MEDIUM"
    return "LOW"


def classify(total_score, malware_signals=False):
    """Step 13 final classification, combined with Step 12 band for display."""
    band = risk_band(total_score)
    if band == "CRITICAL":
        label = "Malware Delivery" if malware_signals else "Phishing"
    elif band == "HIGH":
        label = "Malware Delivery" if malware_signals else "Phishing"
    elif band == "MEDIUM":
        label = "Suspicious"
    else:
        label = "Legitimate"
    return f"{band} — {label}"


def recommended_actions(band, iocs):
    """Step 14 response actions."""
    if band in ("HIGH", "CRITICAL"):
        actions = [
            "Block domains & IPs",
            "Quarantine email",
            "Extract IOCs (URLs, domains, hashes, filenames)",
        ]
    elif band == "MEDIUM":
        actions = ["Flag for analyst review", "Warn user"]
    else:
        actions = ["Log for telemetry"]
    if iocs.get("domains") or iocs.get("urls"):
        actions.append("Review extracted IOCs below")
    return actions


# -----------------------------
# STEP 1–4 — ATTACHMENT ANALYSIS
# -----------------------------

def analyze_attachment(att):
    """Score one attachment per Steps 1–4 / 12 factors."""
    score = 0
    findings = []
    malware = False

    filename = att.get("filename", "") or ""
    name_l = filename.lower()
    size = float(att.get("size_kb", 0) or 0)
    mime = (att.get("mime", "") or "").lower()
    ext = _ext(filename)
    exts = _all_exts(filename)
    entropy = att.get("entropy")
    risk_flags = set(att.get("risk_flags", []) or [])

    # Step 2 — file-type risk
    if ext in CRITICAL_EXTS or "executable_content" in risk_flags:
        score += W_SUSPICIOUS_ATTACHMENT
        findings.append("Critical executable / script attachment")
        malware = True
    elif ext in MACRO_EXTS or "office_macro" in risk_flags:
        score += W_EMBEDDED_SCRIPT_MACRO
        findings.append("Macro-enabled / VBA document")
        malware = True
    elif ext in ARCHIVE_EXTS:
        score += W_SUSPICIOUS_ATTACHMENT
        findings.append("Archive / disk-image container")
    elif ext in HTML_EXTS or "html_credential_form" in risk_flags:
        score += W_SUSPICIOUS_ATTACHMENT
        findings.append("HTML attachment (credential-harvest risk)")
        if "html_credential_form" in risk_flags or "html_javascript" in risk_flags:
            score += W_EMBEDDED_SCRIPT_MACRO
            findings.append("Embedded script / credential form in HTML")
            malware = True
    elif ext in PDF_EXTS:
        if size < 50:
            score += W_SUSPICIOUS_ATTACHMENT
            findings.append("PDF unusually small (<50 KB — empty/fake risk)")
        if risk_flags & {"pdf_javascript", "pdf_launch_action", "pdf_auto_executing_action"}:
            score += W_EMBEDDED_SCRIPT_MACRO
            findings.append("PDF embedded script / launch action")
            malware = True
    elif ext in IMAGE_EXTS or mime.startswith("image"):
        # Images are often bait (Step 4) — low base, size anomaly elevates
        if size < 20:
            score += W_SUSPICIOUS_ATTACHMENT
            findings.append("Image too small (<20 KB — likely lure/thumbnail)")

    # Step 1 — filename tricks / type mismatch
    if len(exts) >= 2 and exts[-1] in CRITICAL_EXTS:
        score += W_OBFUSCATION
        findings.append("Double extension (obfuscation)")
        malware = True
    if att.get("type_mismatch") or "type_mismatch" in risk_flags:
        score += W_OBFUSCATION
        findings.append("MIME/magic-byte type mismatch")
        malware = True
    if "archive_contains_executable" in risk_flags:
        score += W_EMBEDDED_SCRIPT_MACRO
        findings.append("Archive contains executable")
        malware = True
    if "encrypted_archive" in risk_flags:
        score += W_OBFUSCATION
        findings.append("Password-encrypted archive (obfuscation)")
    # Compressed images naturally sit near max entropy — only flag packing on
    # non-image types (archives/docs/unknown), matching Step 3 intent.
    is_image = ext in IMAGE_EXTS or mime.startswith("image")
    if (not is_image) and entropy is not None and float(entropy) >= 7.9:
        score += W_OBFUSCATION
        findings.append("High entropy (packing/encryption)")

    # Generic bait filenames (finding only — scored via size/SE elsewhere)
    if "photo_" in name_l or name_l.startswith("image") or "screenshot" in name_l:
        findings.append("Generic / bait-style filename")

    return score, findings, malware


# -----------------------------
# STEP 5–7 — URL ANALYSIS
# -----------------------------

def analyze_url(url, link_meta=None):
    """Score one URL per Steps 5–7 / 12. Optional link_meta from url_forensics."""
    score = 0
    findings = []
    meta = link_meta or {}

    raw = url or ""
    domain = get_domain(raw) or (meta.get("host") or meta.get("registrable_domain") or "")
    path_q = ""
    try:
        parts = urlparse(raw)
        path_q = unquote((parts.path or "") + "?" + (parts.query or "")).lower()
    except Exception:
        path_q = raw.lower()

    flags = set(meta.get("flags", []) or [])

    # Shortener
    if is_shortener(domain) or "url_shortener" in flags:
        score += W_URL_SHORTENER
        findings.append("URL shortener used")

    # Suspicious domain — Step 6: typosquat / IDN / IP / risky TLD.
    # brand_keyword_offbrand alone is too noisy for +30 (many legit support portals).
    host_base = domain.split(":")[0]
    suspicious_domain = (
        "idn_punycode" in flags or "ip_literal_host" in flags
        or any(f.startswith("risky_tld:") for f in flags)
        or bool(_IPV4_RE.match(host_base))
        or host_base.startswith("xn--")
    )
    if suspicious_domain and not is_shortener(domain):
        score += W_SUSPICIOUS_DOMAIN
        findings.append("Suspicious domain (typosquat/IP/punycode/risky TLD)")
    elif is_shortener(domain) and (
            any(f.startswith("risky_tld:") for f in flags) or domain.endswith(".pw")):
        findings.append("Shortener on risky TLD")

    # Redirect chain — gateway wrap alone is expected on TMES; score multi-hop only.
    chain = meta.get("redirect_chain") or []
    if len(chain) >= 2 or meta.get("redirect_hops", 0) >= 2:
        score += W_REDIRECT_CHAIN
        findings.append("Redirect chain (>1 hop)")

    # Newly registered — only when caller supplies the fact (no offline WHOIS)
    if meta.get("newly_registered"):
        score += W_NEWLY_REGISTERED
        findings.append("Newly registered domain")

    # Fragment deception / display mismatch
    if has_fragment(raw):
        score += 10
        findings.append("Fragment used (possible disguise)")
    if meta.get("display_target_mismatch") or "display_target_mismatch" in flags:
        score += W_SUSPICIOUS_DOMAIN
        findings.append("Display-text vs target mismatch")

    # Path / query bait keywords
    if any(word in path_q for word in URL_PATH_KEYWORDS):
        score += 10
        findings.append("Suspicious keyword in URL path/query")

    return score, findings


# -----------------------------
# STEP 9 — SOCIAL ENGINEERING
# -----------------------------

def analyze_content(body):
    score = 0
    findings = []
    text = (body or "").lower()

    se_hit = False
    if ("hello" in text or "dear" in text) and (
            "support" in text or "customer" in text or "user" in text
            or "sir" in text or "madam" in text):
        findings.append("Generic greeting")
        se_hit = True

    if len(body or "") < 200:
        findings.append("Low content / vague message")
        se_hit = True

    if any(word in text for word in SE_KEYWORDS):
        findings.append("Social engineering keywords")
        se_hit = True

    if any(phrase in text for phrase in ATTACHMENT_FRAMING):
        findings.append("Attachment framing lure (see screenshot / open document)")
        se_hit = True

    if se_hit:
        score += W_SOCIAL_ENGINEERING

    return score, findings


# -----------------------------
# STEP 10 — AUTHENTICATION
# -----------------------------

def analyze_auth(headers):
    score = 0
    findings = []
    headers = headers or {}

    # Playbook Step 12: "DKIM/SPF fail" = +20 (apply once if either fails)
    auth_fail = False
    if headers.get("dkim") == "fail":
        findings.append("DKIM failed")
        auth_fail = True
    if headers.get("spf") == "fail":
        findings.append("SPF failed")
        auth_fail = True
    if auth_fail:
        score += W_AUTH_FAIL

    if headers.get("dmarc") == "fail":
        score += W_DMARC_FAIL
        findings.append("DMARC failed")

    if headers.get("arc") == "fail":
        score += W_ARC_FAIL
        findings.append("ARC failed")

    return score, findings


# -----------------------------
# STEP 11–14 — MAIN ANALYZER
# -----------------------------

def analyze_email(email, urls=None, link_metas=None):
    """Run the v2.0 playbook over a structured email dict.

    email keys: body, headers {dkim,spf,dmarc,arc}, attachments [{filename,size_kb,mime,...}]
    urls: optional pre-extracted (preferably unwrapped) URL list
    link_metas: optional parallel list of per-URL fact dicts from url_forensics
    """
    total_score = 0
    all_findings = []
    malware_signals = False
    iocs = {"urls": [], "domains": [], "hashes": [], "filenames": []}

    # Content
    c_score, c_findings = analyze_content(email.get("body", ""))
    total_score += c_score
    all_findings += c_findings

    # URLs
    if urls is None:
        urls = extract_urls(email.get("body", ""))
    metas = link_metas or [{}] * len(urls)
    for i, url in enumerate(urls):
        meta = metas[i] if i < len(metas) else {}
        u_score, u_findings = analyze_url(url, meta)
        total_score += u_score
        all_findings += [f"{url} -> {f}" for f in u_findings]
        if u_findings:
            iocs["urls"].append(url)
            dom = get_domain(url) or meta.get("registrable_domain")
            if dom:
                iocs["domains"].append(dom)

    # Attachments
    for att in email.get("attachments", []) or []:
        a_score, a_findings, a_malware = analyze_attachment(att)
        total_score += a_score
        all_findings += [f"{att.get('filename')} -> {f}" for f in a_findings]
        malware_signals = malware_signals or a_malware
        if att.get("filename"):
            iocs["filenames"].append(att["filename"])
        if att.get("sha256"):
            iocs["hashes"].append(att["sha256"])

    # Auth
    auth_score, auth_findings = analyze_auth(email.get("headers", {}))
    total_score += auth_score
    all_findings += auth_findings

    # Deduplicate IOC lists while preserving order
    for k in iocs:
        seen = set()
        out = []
        for v in iocs[k]:
            if v and v not in seen:
                seen.add(v)
                out.append(v)
        iocs[k] = out

    band = risk_band(total_score)
    verdict = classify(total_score, malware_signals)
    return {
        "score": total_score,
        "risk_band": band,
        "classification": verdict.split(" — ", 1)[-1],
        "verdict": verdict,
        "findings": all_findings,
        "urls": urls,
        "actions": recommended_actions(band, iocs),
        "iocs": iocs,
        "malware_signals": malware_signals,
    }


# =============================================================================
# INTEGRATION ADAPTER — bridges eml_analysis_agent.parse_eml() into the scorer.
# =============================================================================

def _auth_from_parsed(parsed):
    """Derive dkim/spf/dmarc/arc pass|fail from raw authentication headers.

    Boundary guard ([^a-z]) matters: plain 'arc=fail' also matches 'dmarc=fail'.
    """
    auth = parsed.get("auth_headers_raw", {}) or {}
    results = (auth.get("authentication_results", "") or "").lower()
    spf_hdr = (auth.get("received_spf", "") or "").lower()
    arc_hdr = (auth.get("arc_authentication_results", "") or "").lower()
    headers = {}

    dkim = re.search(r'(?:^|[^a-z])dkim=(pass|fail)', results)
    if dkim:
        headers["dkim"] = dkim.group(1)

    spf = re.search(r'(?:^|[^a-z])spf=(pass|fail)', results)
    if not spf and spf_hdr:
        if spf_hdr.startswith("pass") or " spf=pass" in spf_hdr:
            headers["spf"] = "pass"
        elif spf_hdr.startswith("fail") or " spf=fail" in spf_hdr:
            headers["spf"] = "fail"
    elif spf:
        headers["spf"] = spf.group(1)

    dmarc = re.search(r'(?:^|[^a-z])dmarc=(pass|fail)', results)
    if dmarc:
        headers["dmarc"] = dmarc.group(1)

    arc = re.search(r'(?:^|[^a-z])arc=(pass|fail)', arc_hdr or results)
    if arc:
        headers["arc"] = arc.group(1)

    return headers


# XML/namespace URIs from Office HTML — not clickable user links.
_IGNORE_URL_HOSTS = (
    "schemas.microsoft.com", "schemas.openxmlformats.org", "www.w3.org",
    "purl.org", "schemas.xmlsoap.org", "ns.adobe.com", "www.iana.org",
)


def _map_attachment(a):
    """Map forensic fact sheet → scorer attachment shape."""
    cat = a.get("detected_category", "")
    mime = a.get("declared_content_type", "") or ""
    if cat == "image":
        mime = mime if mime.startswith("image") else "image/" + (a.get("detected_type") or "")
    elif cat == "executable":
        mime = "application/x-dosexec"
    return {
        "filename": a.get("filename", ""),
        "size_kb": round(a.get("size_bytes", 0) / 1024.0, 1),
        "mime": mime,
        "sha256": a.get("sha256", ""),
        "entropy": a.get("entropy"),
        "type_mismatch": a.get("type_mismatch", False),
        "risk_flags": list(a.get("risk_flags", []) or []),
    }


def _domains_from_addresses(values) -> set:
    """Collect registrable-ish email domains from From/To/Cc/Reply-To strings."""
    from app.domainutils import registrable_domain
    out = set()
    if isinstance(values, str):
        values = [values]
    for v in values or []:
        for m in _EMAIL_DOMAIN_RE.finditer(str(v)):
            out.add(registrable_domain(m.group(1).lower()))
    return {d for d in out if d}


def _is_signature_safe_domain(reg: str, trusted: set) -> bool:
    """True for sender/recipient org domains and common signature social targets."""
    if not reg:
        return False
    if reg in SIGNATURE_SAFE_DOMAINS or reg in trusted:
        return True
    for t in trusted:
        if t and (reg == t or reg.endswith("." + t)):
            return True
    for s in SIGNATURE_SAFE_DOMAINS:
        if reg == s or reg.endswith("." + s):
            return True
    return False


def _has_se_or_framing(body: str) -> bool:
    text = (body or "").lower()
    if any(word in text for word in SE_KEYWORDS):
        return True
    if any(phrase in text for phrase in ATTACHMENT_FRAMING):
        return True
    return False


def score_image_link_lure(parsed, link_metas, body):
    """Step 4 correlation: image wrapped in / paired with an external URL.

    Signature logos (company site, LinkedIn/Facebook/etc.) are explicitly
    excluded. Only raises when the image-link destination is off-brand AND an
    amplifier is present (shortener/file-host/risky TLD, SE framing, or
    bait-style screenshot filename — not logo/signature/icon names).
    """
    from app.domainutils import registrable_domain

    meta = parsed.get("metadata", {}) or {}
    trusted = set()
    trusted |= _domains_from_addresses(meta.get("from"))
    trusted |= _domains_from_addresses(meta.get("to"))
    trusted |= _domains_from_addresses(meta.get("cc"))
    trusted |= _domains_from_addresses(meta.get("reply_to"))

    attachments = parsed.get("attachment_forensics", []) or []
    images = [
        a for a in attachments
        if (a.get("detected_category") == "image"
            or (a.get("declared_extension") or "") in IMAGE_EXTS
            or (a.get("declared_content_type") or "").startswith("image/"))
    ]
    if not images and not any(l.get("wraps_image") for l in (link_metas or [])):
        return 0, []

    # Prefer links that actually wrap an image; fall back to any link only when
    # a bait-named image exists (plaintext association without HTML wrap flag).
    image_links = [l for l in (link_metas or []) if l.get("wraps_image")
                   or "image_hyperlink" in (l.get("flags") or [])]
    if not image_links:
        bait_images = [
            a for a in images
            if _BAIT_NAME_RE.search(a.get("filename") or "")
            and not _SIGNATURE_NAME_RE.search(a.get("filename") or "")
        ]
        if not bait_images:
            return 0, []
        image_links = list(link_metas or [])

    se = _has_se_or_framing(body)
    findings = []
    for link in image_links:
        dest = link.get("unwrapped_url") or link.get("raw_url") or ""
        reg = link.get("registrable_domain") or registrable_domain(get_domain(dest))
        if not reg or get_domain(dest) in _IGNORE_URL_HOSTS:
            continue
        if _is_signature_safe_domain(reg, trusted):
            continue  # company site / LinkedIn / etc. — never a lure signal

        flags = set(link.get("flags") or [])
        amp = []
        if is_shortener(reg) or "url_shortener" in flags or reg in IMAGE_FILE_HOSTS:
            amp.append("shortener/file-host")
        if any(f.startswith("risky_tld:") for f in flags):
            amp.append("risky TLD")
        if se:
            amp.append("social-engineering context")
        # Bait-style image filename (screenshot/photo), not logo/signature.
        for a in images:
            fn = a.get("filename") or ""
            if _SIGNATURE_NAME_RE.search(fn):
                continue
            if _BAIT_NAME_RE.search(fn) or (a.get("size_bytes", 0) < 20 * 1024 and not fn):
                if _BAIT_NAME_RE.search(fn) or fn.lower() in ("image", "img", "picture", ""):
                    amp.append("bait-style image")
                    break

        if not amp:
            continue  # off-brand alone is not enough (partner/marketing links)

        findings.append(
            f"Image linked to off-brand URL {dest} "
            f"(not signature-safe; amplifiers: {', '.join(sorted(set(amp)))}"
            f"; destination={reg})"
        )

    if findings:
        # Score once even if multiple lure images — avoid CRITICAL inflation.
        return W_IMAGE_LINK_LURE, findings[:3]
    return 0, []


def run_playbook(parsed):
    """Run v2.0 playbook against eml_analysis_agent.parse_eml() output."""
    meta = parsed.get("metadata", {}) or {}
    body = ((meta.get("subject", "") or "") + "\n" + (parsed.get("text_body", "") or "")).strip()

    urls = []
    link_metas = []
    for link in parsed.get("link_analysis", []) or []:
        dest = link.get("unwrapped_url") or link.get("raw_url")
        if not dest or get_domain(dest) in _IGNORE_URL_HOSTS:
            continue
        urls.append(dest)
        link_metas.append(link)
    if not urls:
        for u in extract_urls(body):
            if get_domain(u) not in _IGNORE_URL_HOSTS:
                urls.append(u)
                link_metas.append({})

    attachments = parsed.get("attachment_forensics", []) or []
    # Tiny-image lure rule applies to delivered attachments, not signature logos.
    real_attachments = [a for a in attachments if not a.get("is_inline")]

    email = {
        "body": body,
        "headers": _auth_from_parsed(parsed),
        "attachments": [_map_attachment(a) for a in real_attachments],
    }
    result = analyze_email(email, urls=urls, link_metas=link_metas)

    # Step 4: image + off-brand link lure (signature logos explicitly excluded).
    lure_score, lure_findings = score_image_link_lure(parsed, link_metas, body)
    if lure_score:
        result["score"] += lure_score
        result["findings"] += lure_findings
        for f in lure_findings:
            # Pull destination into IOCs when present.
            if "http" in f:
                m = _URL_RE.search(f)
                if m:
                    u = m.group(0).rstrip(")")
                    if u not in result["iocs"]["urls"]:
                        result["iocs"]["urls"].append(u)
                    d = get_domain(u)
                    if d and d not in result["iocs"]["domains"]:
                        result["iocs"]["domains"].append(d)

    # Inline parts can still hide executables — fold their forensic flags in.
    for a in attachments:
        if not a.get("is_inline"):
            continue
        a_score, a_findings, a_malware = analyze_attachment(_map_attachment(a))
        # Only elevate for real threats on inline parts (not tiny logo size)
        threat_findings = [f for f in a_findings if "too small" not in f.lower()
                           and "bait-style" not in f.lower()
                           and "Generic" not in f]
        if a_score and threat_findings:
            # Re-score only threat portion
            mapped = _map_attachment(a)
            mapped["size_kb"] = 999  # suppress lure-size on inline logos
            t_score, t_findings, t_malware = analyze_attachment(mapped)
            t_findings = [f for f in t_findings if "too small" not in f.lower()
                          and "bait-style" not in f.lower()]
            if t_score and t_findings:
                result["score"] += t_score
                result["findings"] += [f"{a.get('filename')} -> {f}" for f in t_findings]
                result["malware_signals"] = result["malware_signals"] or t_malware

    result["risk_band"] = risk_band(result["score"])
    result["verdict"] = classify(result["score"], result.get("malware_signals", False))
    result["classification"] = result["verdict"].split(" — ", 1)[-1]
    result["actions"] = recommended_actions(result["risk_band"], result.get("iocs", {}))
    return result


# -----------------------------
# EXAMPLE USAGE / CLI
# -----------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        from pathlib import Path
        from eml_analysis_agent import parse_eml
        parsed = parse_eml(Path(sys.argv[1]))
        result = parsed.get("playbook") or run_playbook(parsed)
        print("File:", sys.argv[1])
        print("Score:", result["score"])
        print("Verdict:", result["verdict"])
        print("Actions:", "; ".join(result.get("actions", [])))
        print("\nFindings:")
        for f in result["findings"]:
            print("-", f)
        iocs = result.get("iocs") or {}
        if any(iocs.values()):
            print("\nIOCs:")
            for k, vals in iocs.items():
                if vals:
                    print(f"  {k}: {', '.join(vals[:10])}")
        sys.exit(0)

    email_data = {
        "body": "Hello customer service, I encountered an error. See screenshot: "
                "https://psce.pw/image157#image.png",
        "headers": {"dkim": "fail", "arc": "fail"},
        "attachments": [
            {
                "filename": "photo_2026-05-28_21-33-01.jpg",
                "size_kb": 7.6,
                "mime": "image/jpeg",
            }
        ],
    }
    result = analyze_email(email_data)
    print("Score:", result["score"])
    print("Verdict:", result["verdict"])
    print("Actions:", "; ".join(result["actions"]))
    print("\nFindings:")
    for f in result["findings"]:
        print("-", f)
