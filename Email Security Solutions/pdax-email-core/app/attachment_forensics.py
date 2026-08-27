"""Deterministic attachment static forensics — offline, stdlib-only.

Given (filename, declared MIME, raw bytes), produces a structured fact sheet a
downstream analyst (human or LLM) can judge: the *actual* file type from magic
bytes vs. the claimed extension/MIME (spoof detection), archive contents with
encryption and zip-bomb guards, Office macro presence (OOXML and legacy OLE),
PDF active-content tokens and embedded URLs, HTML credential-form / script
markers, executable detection, and byte entropy.

Safe-handling contract ("sandboxing" of the *parser*, not detonation):
  * Purely static, in-memory. Files are NEVER written to disk and NEVER
    executed, rendered, or opened by their host application.
  * Resource-bounded to defuse malicious inputs: capped scan window, capped
    archive member count, capped total uncompressed size + compression-ratio
    check (zip-bomb defense), and bounded nesting depth.
  * Every step is wrapped so a malformed/hostile file yields a "degraded"
    fact set instead of raising (mirrors the pipeline's safe() convention).

Architecture note (CLAUDE.md): this returns facts only. It assigns no verdict;
it may set an advisory `static_severity` hint, but the LLM/deterministic engine
downstream owns the decision. Any text pulled out of an attachment (PDF text,
macro strings, HTML) is attacker-controlled data, to be analyzed, not obeyed.
"""
from __future__ import annotations

import io
import math
import re
import zipfile

# ---- resource caps (the parser sandbox) --------------------------------
MAX_SCAN_BYTES = 20 * 1024 * 1024      # skip deep parsing above this size
PDF_SCAN_BYTES = 5 * 1024 * 1024       # bytes of a PDF scanned for tokens
ENTROPY_SAMPLE = 256 * 1024
MAX_ARCHIVE_MEMBERS = 3000
MAX_UNCOMPRESSED = 200 * 1024 * 1024   # zip-bomb: total inflate ceiling
MAX_RATIO = 120                        # zip-bomb: compression ratio ceiling
MAX_LISTED_MEMBERS = 60                # members surfaced into the fact sheet

# ---- extension taxonomy ------------------------------------------------
EXECUTABLE_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe",
    "wsf", "wsh", "hta", "ps1", "psm1", "msi", "msp", "jar", "cpl", "lnk",
    "reg", "inf", "sct", "application", "gadget", "dll", "sys", "scf", "url",
    "chm", "hlp", "iso", "img", "vhd", "vhdx", "cab", "ace", "apk", "appx",
}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlam", "ppam", "sldm"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "cab", "ace", "arj"}
OFFICE_EXT = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf"} | MACRO_EXT
IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff", "svg", "ico"}
DOC_MEDIA_EXT = IMAGE_EXT | {"pdf", "txt", "csv", "doc", "docx", "xls", "xlsx", "ppt", "pptx"}

# ---- magic-byte signatures: (offset, bytes, type_label, category) ------
_SIGS = [
    (0, b"%PDF-", "pdf", "pdf"),
    (0, b"MZ", "dos_pe_executable", "executable"),
    (0, b"\x7fELF", "elf_executable", "executable"),
    (0, b"\xca\xfe\xba\xbe", "mach_o_or_class", "executable"),
    (0, b"\xcf\xfa\xed\xfe", "mach_o", "executable"),
    (0, b"\xfe\xed\xfa\xce", "mach_o", "executable"),
    (0, b"PK\x03\x04", "zip", "archive"),
    (0, b"PK\x05\x06", "zip_empty", "archive"),
    (0, b"PK\x07\x08", "zip_spanned", "archive"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole_compound", "ole"),
    (0, b"Rar!\x1a\x07", "rar", "archive"),
    (0, b"7z\xbc\xaf\x27\x1c", "7zip", "archive"),
    (0, b"\x1f\x8b", "gzip", "archive"),
    (0, b"BZh", "bzip2", "archive"),
    (0, b"\xfd7zXZ\x00", "xz", "archive"),
    (0, b"{\\rtf", "rtf", "office"),
    (0, b"\x89PNG\r\n\x1a\n", "png", "image"),
    (0, b"\xff\xd8\xff", "jpeg", "image"),
    (0, b"GIF87a", "gif", "image"),
    (0, b"GIF89a", "gif", "image"),
    (0, b"BM", "bmp", "image"),
    (0, b"II*\x00", "tiff", "image"),
    (0, b"MM\x00*", "tiff", "image"),
    (0, b"%!PS", "postscript", "document"),
    (0, b"#!", "script_shebang", "script"),
    (257, b"ustar", "tar", "archive"),
]
_OOXML_MACRO_PARTS = ("word/vbaProject.bin", "xl/vbaProject.bin", "ppt/vbaProject.bin", "vbaProject.bin")
_PDF_ACTIVE_TOKENS = {
    b"/JavaScript": "pdf_javascript", b"/JS": "pdf_javascript",
    b"/OpenAction": "pdf_openaction", b"/AA": "pdf_auto_action",
    b"/Launch": "pdf_launch_action", b"/EmbeddedFile": "pdf_embedded_file",
    b"/GoToR": "pdf_remote_goto", b"/RichMedia": "pdf_rich_media",
    b"/XFA": "pdf_xfa_form", b"/AcroForm": "pdf_acroform",
    b"/SubmitForm": "pdf_submit_form",
}
_URL_BYTES_RE = re.compile(rb'https?://[^\s<>"\'\)\]}]+')
_PDF_URI_RE = re.compile(rb'/URI\s*\(\s*([^)]{1,2048}?)\)')
_OLE_MACRO_MARKERS = (b"_VBA_PROJECT", b"VBA\x00", b"Attribut\x00e VB_", b"Macros\x00", b"vbaProject")


def _ext(filename: str) -> str:
    name = (filename or "").strip().strip('"').lower()
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1]


def _all_exts(filename: str) -> list[str]:
    name = (filename or "").strip().strip('"').lower()
    parts = [p for p in name.split(".") if p]
    return parts[1:] if len(parts) > 1 else []


def detect_type(payload: bytes) -> tuple[str, str]:
    """(type_label, category) from magic bytes. category is one of:
    executable/archive/ole/pdf/office/image/script/document/html/text/unknown."""
    if not payload:
        return "empty", "unknown"
    head = payload[:512]
    for offset, sig, label, category in _SIGS:
        if payload[offset:offset + len(sig)] == sig:
            # A ZIP might really be an OOXML office doc or a JAR — refine later.
            return label, category
    stripped = head.lstrip()[:64].lower()
    if stripped.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
        return "html", "html"
    if stripped.startswith(b"<?xml"):
        return "xml", "text"
    try:
        head.decode("utf-8")
        return "text", "text"
    except UnicodeDecodeError:
        return "unknown", "unknown"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:ENTROPY_SAMPLE]
    counts = [0] * 256
    for b in sample:
        counts[b] += 1
    n = len(sample)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 2)


def _expected_categories_from_ext(ext: str) -> set:
    if ext in IMAGE_EXT:
        return {"image"}
    if ext == "pdf":
        return {"pdf"}
    if ext in {"docx", "xlsx", "pptx"} | MACRO_EXT:
        return {"archive", "office"}   # OOXML is a zip under the hood
    if ext in {"doc", "xls", "ppt"}:
        return {"ole", "office"}
    if ext == "rtf":
        return {"office", "text"}
    if ext in ARCHIVE_EXT:
        return {"archive"}
    if ext in {"exe", "scr", "com", "dll", "msi", "cpl", "sys"}:
        return {"executable", "ole"}
    if ext in {"txt", "csv", "log", "eml", "html", "htm", "xml", "json"}:
        return {"text", "html"}
    return set()


def _inspect_zip(payload: bytes, findings: dict, flags: list) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(payload))
    except Exception as e:
        flags.append("archive_unreadable")
        findings["archive_error"] = str(e)
        return
    infos = zf.infolist()[:MAX_ARCHIVE_MEMBERS]
    truncated = len(zf.infolist()) > MAX_ARCHIVE_MEMBERS
    names = [i.filename for i in infos]
    total_uncompressed = sum(i.file_size for i in infos)
    total_compressed = sum(i.compress_size for i in infos) or 1
    ratio = round(total_uncompressed / total_compressed, 1)
    encrypted = [i.filename for i in infos if (i.flag_bits & 0x1)]
    members = []
    nested_dangerous = []
    for i in infos[:MAX_LISTED_MEMBERS]:
        e = _ext(i.filename)
        members.append({"name": i.filename, "size": i.file_size,
                        "encrypted": bool(i.flag_bits & 0x1), "ext": e})
    for i in infos:
        e = _ext(i.filename)
        if e in EXECUTABLE_EXT or e in MACRO_EXT:
            nested_dangerous.append(i.filename + " (." + e + ")")

    # Is this actually an OOXML office document (zip is just its container)?
    is_ooxml = "[Content_Types].xml" in names
    has_macro = any(any(p in n for p in _OOXML_MACRO_PARTS) for n in names)

    findings["archive"] = {
        "container": "zip",
        "member_count": len(zf.infolist()),
        "listed_members": members,
        "members_truncated": truncated,
        "total_uncompressed": total_uncompressed,
        "compression_ratio": ratio,
        "encrypted_members": encrypted[:MAX_LISTED_MEMBERS],
        "is_ooxml_office": is_ooxml,
    }
    if encrypted:
        flags.append("encrypted_archive")
    if nested_dangerous:
        flags.append("archive_contains_executable")
        findings["archive"]["dangerous_members"] = nested_dangerous[:MAX_LISTED_MEMBERS]
    if ratio > MAX_RATIO or total_uncompressed > MAX_UNCOMPRESSED:
        flags.append("possible_zip_bomb")
    if is_ooxml and has_macro:
        flags.append("office_macro")
        findings["office_macro"] = {"source": "ooxml_vbaproject"}


def _inspect_ole(payload: bytes, findings: dict, flags: list) -> None:
    window = payload[:MAX_SCAN_BYTES]
    if any(marker in window for marker in _OLE_MACRO_MARKERS):
        flags.append("office_macro")
        findings["office_macro"] = {"source": "ole_vba_markers"}


def _inspect_pdf(payload: bytes, findings: dict, flags: list) -> list:
    window = payload[:PDF_SCAN_BYTES]
    active = []
    for token, label in _PDF_ACTIVE_TOKENS.items():
        if token in window:
            active.append(label)
    active = sorted(set(active))
    urls = []
    for m in _PDF_URI_RE.findall(window):
        try:
            urls.append(m.decode("latin-1").strip())
        except Exception:
            pass
    for m in _URL_BYTES_RE.findall(window):
        try:
            urls.append(m.decode("latin-1").rstrip('.,;:)]}>"\''))
        except Exception:
            pass
    urls = sorted(set(urls))
    findings["pdf"] = {"active_content": active, "embedded_urls": urls[:40]}
    for a in active:
        flags.append(a)
    # High-risk combination: an action that fires automatically + code/launch.
    if ("pdf_openaction" in active or "pdf_auto_action" in active) and \
            any(x in active for x in ("pdf_javascript", "pdf_launch_action", "pdf_remote_goto")):
        flags.append("pdf_auto_executing_action")
    return urls


def _inspect_html(payload: bytes, findings: dict, flags: list) -> list:
    try:
        text = payload[:MAX_SCAN_BYTES].decode("utf-8", "replace")
    except Exception:
        text = ""
    low = text.lower()
    has_form = "<form" in low
    has_pw = 'type="password"' in low or "type='password'" in low
    scripts = low.count("<script")
    meta_refresh = 'http-equiv="refresh"' in low or "http-equiv='refresh'" in low
    data_uri = "data:text/html" in low or "data:application" in low
    if has_form and has_pw:
        flags.append("html_credential_form")
    elif has_form:
        flags.append("html_form")
    if scripts:
        flags.append("html_javascript")
    if meta_refresh:
        flags.append("html_meta_refresh")
    if data_uri:
        flags.append("html_data_uri")
    from .url_forensics import extract_urls, extract_anchors
    urls = sorted(set(extract_urls(text) + [h for _, h in extract_anchors(text)
                                             if h.lower().startswith(("http://", "https://"))]))
    # Strip tags and collapse whitespace to give the LLM a readable preview of
    # the page's human-visible text (lure copy, brand names, form labels).
    # Kept short (2500 chars) to stay within the context budget.
    plain = re.sub(r"<[^>]{0,2048}>", " ", text)
    plain = " ".join(plain.split())[:2500]
    findings["html"] = {"has_form": has_form, "has_password_input": has_pw,
                        "script_count": scripts, "meta_refresh": meta_refresh,
                        "text_preview": plain}
    return urls[:40]


_SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_HIGH_FLAGS = {
    "executable_content", "archive_contains_executable", "pdf_launch_action",
    "pdf_auto_executing_action", "office_macro", "type_mismatch",
    "double_extension_executable", "dangerous_extension",
}
_MEDIUM_FLAGS = {
    "encrypted_archive", "possible_zip_bomb", "pdf_javascript", "pdf_openaction",
    "pdf_embedded_file", "html_credential_form", "macro_capable_extension",
    "pdf_remote_goto", "html_data_uri",
}


def _severity(flags: list) -> str:
    fs = set(flags)
    if fs & _HIGH_FLAGS:
        return "HIGH"
    if fs & _MEDIUM_FLAGS:
        return "MEDIUM"
    if fs:
        return "LOW"
    return "NONE"


def analyze_attachment(filename: str, content_type: str, payload: bytes) -> dict:
    """Full static fact sheet for one attachment. Never raises."""
    import hashlib
    payload = payload or b""
    ext = _ext(filename)
    exts = _all_exts(filename)
    findings: dict = {}
    flags: list = []
    embedded_urls: list = []

    try:
        detected_label, detected_cat = detect_type(payload)

        # --- extension policy ---
        if ext in EXECUTABLE_EXT:
            flags.append("dangerous_extension")
        if ext in MACRO_EXT:
            flags.append("macro_capable_extension")
        # double extension: a benign-looking inner ext followed by a dangerous outer one
        if len(exts) >= 2 and exts[-1] in EXECUTABLE_EXT and exts[-2] in DOC_MEDIA_EXT:
            flags.append("double_extension_executable")

        # --- magic-byte vs declared type (spoof detection) ---
        expected = _expected_categories_from_ext(ext)
        type_mismatch = False
        if payload and expected and detected_cat != "unknown" and detected_cat not in expected:
            # tolerate the OOXML case (zip magic for docx/xlsx/pptx)
            if not (detected_cat == "archive" and expected & {"office"}):
                type_mismatch = True
        if type_mismatch:
            flags.append("type_mismatch")
        if detected_cat == "executable":
            flags.append("executable_content")
        if detected_label == "script_shebang":
            flags.append("script_content")

        # --- per-category deep inspection ---
        if payload and len(payload) <= MAX_SCAN_BYTES:
            if detected_cat == "archive" and detected_label.startswith("zip"):
                _inspect_zip(payload, findings, flags)
            elif detected_cat == "ole":
                _inspect_ole(payload, findings, flags)
            elif detected_cat == "pdf":
                embedded_urls += _inspect_pdf(payload, findings, flags)
            elif detected_cat == "html" or content_type == "text/html" or ext in {"html", "htm"}:
                embedded_urls += _inspect_html(payload, findings, flags)
        elif payload:
            findings["deep_scan_skipped"] = "payload exceeds MAX_SCAN_BYTES"

        sha256 = hashlib.sha256(payload).hexdigest()
        md5 = hashlib.md5(payload).hexdigest()
        entropy = _entropy(payload)
        if entropy >= 7.9 and detected_cat in ("document", "text", "unknown", "image"):
            flags.append("high_entropy_content")

        flags = sorted(set(flags))
        return {
            "filename": filename or "(unnamed)",
            "declared_content_type": content_type or "",
            "declared_extension": ext,
            "all_extensions": exts,
            "size_bytes": len(payload),
            "sha256": sha256,
            "md5": md5,
            "entropy": entropy,
            "detected_type": detected_label,
            "detected_category": detected_cat,
            "type_mismatch": type_mismatch,
            "risk_flags": flags,
            "embedded_urls": sorted(set(embedded_urls))[:40],
            "static_severity": _severity(flags),
            "findings": findings,
            "degraded": False,
        }
    except Exception as e:  # a hostile/malformed file must not sink parsing
        return {
            "filename": filename or "(unnamed)",
            "declared_content_type": content_type or "",
            "declared_extension": ext,
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
            "risk_flags": ["forensics_error"],
            "static_severity": "LOW",
            "findings": {"error": str(e)},
            "degraded": True,
        }
