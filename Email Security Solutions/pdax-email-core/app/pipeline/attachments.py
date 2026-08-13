"""Stage 4 — Attachment analysis (static, offline core).

Type + hash + banned-extension policy + basic HTML-attachment heuristics,
plus app/attachment_forensics.py's deeper static analysis (magic-byte type
spoofing, archive/zip-bomb inspection, OLE/OOXML macro markers, PDF
active-content tokens, entropy) — TMES policy parity: this stage feeds both
Malware Scanning (forensics_* flags) and File Blocking (banned_attachment*,
and forensics-derived spoof detection, see verdict.py). Live VT hash lookups
are still a hook for the gateway build (see intel.py's IntelClient instead,
which does the hash reputation half of Malware Scanning)."""
from __future__ import annotations

import time

from ..models import StageResult, StageStatus
from ..parsed_email import ParsedEmail
from ..attachment_forensics import analyze_attachment
from . import policy as policy_mod
from . import sandbox as sandbox_mod

# Fallback only — production loads this from rules/banned_extensions.txt
# (File Blocking, TMES policy parity; data, not code, per CLAUDE.md's
# convention) via runner.py::load_config(). Kept here so this module still
# works if called directly/in a test without an explicit banned_ext list.
_DEFAULT_BANNED_EXT = {
    "exe", "js", "jse", "vbs", "vbe", "hta", "iso", "img", "lnk", "scr",
    "pif", "cmd", "bat", "ps1", "wsf", "msi", "jar", "cpl",
}
ACTIVE_DOC_EXT = {"docm", "xlsm", "pptm", "dotm"}
HARVEST_MARKERS = ("type=\"password\"", "type='password'", "<form", "onsubmit", "document.forms")

# app/attachment_forensics.py's static_severity -> points. Loaded from
# rules/weights.yaml (data, not hardcoded, per CLAUDE.md's convention) with
# an in-code fallback so this stage still works if that block is ever
# missing/malformed — never let a rules file typo take attachment scoring
# down entirely.
_DEFAULT_SEVERITY_POINTS = {"NONE": 0, "LOW": 10, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 85}

# type_mismatch and double_extension_executable are surfaced as their own
# distinct flags (Phase 2 / File Blocking's hard override) rather than the
# generic forensics_<flag> prefix — see verdict.py.
_FILE_BLOCKING_OWNED_RISK_FLAGS = {"type_mismatch", "double_extension_executable"}


def run(pe: ParsedEmail, severity_points: dict = None, banned_ext=None,
        policy_cfg: dict = None, sandbox_provider=None) -> StageResult:
    t0 = time.perf_counter()
    atts = pe.attachments()
    if not atts:
        return StageResult(stage="attachments", status=StageStatus.SKIPPED,
                           latency_ms=int((time.perf_counter() - t0) * 1000))

    severity_points = severity_points or _DEFAULT_SEVERITY_POINTS
    banned = set(banned_ext) if banned_ext else _DEFAULT_BANNED_EXT
    # Virtual Analyzer: unlike every other category (which reuses facts an
    # always-running stage already computed, then gets suppressed post-hoc
    # by verdict.py if disabled), detonation is an ACTION — with a future
    # real provider, calling it costs money/time/risk, so it's skipped
    # entirely when the category is off rather than called-and-suppressed.
    # Checked here, at call time, not just filtered afterward.
    detonate_enabled = policy_mod.is_enabled(policy_cfg, "virtual_analyzer")
    sandbox_provider = sandbox_provider or sandbox_mod.get_default_sandbox_provider()

    flags: list[str] = []
    score = 0.0
    records = []
    embedded_urls: list[str] = []
    for a in atts:
        rec = {"filename": a.filename, "ext": a.extension, "sha256": a.sha256,
               "size": a.size, "content_type": a.content_type}
        if a.extension in banned:
            flags.append(f"banned_attachment:{a.extension}"); score += 60
            rec["banned"] = True
        if a.extension in ACTIVE_DOC_EXT:
            flags.append(f"macro_capable_doc:{a.extension}"); score += 25
        if a.extension in ("html", "htm") or a.content_type == "text/html":
            body = a.payload.decode("utf-8", "replace").lower()
            if any(m in body for m in HARVEST_MARKERS):
                flags.append("html_attachment_credential_form"); score += 45
                rec["credential_form"] = True

        forensics = analyze_attachment(a.filename, a.content_type, a.payload)
        rec["forensics"] = forensics
        score += severity_points.get(forensics["static_severity"], 0)
        for rf in forensics["risk_flags"]:
            if rf in _FILE_BLOCKING_OWNED_RISK_FLAGS:
                continue   # Phase 2: emitted as spoofed_attachment_type / double_extension_executable instead
            flags.append(f"forensics_{rf}")
        if forensics.get("type_mismatch"):
            flags.append(f"spoofed_attachment_type:{forensics['declared_extension'] or 'none'}"
                         f"->{forensics['detected_type']}")
        if "double_extension_executable" in forensics["risk_flags"]:
            flags.append(f"double_extension_executable:{a.filename}")
        embedded_urls.extend(forensics.get("embedded_urls") or [])

        if detonate_enabled:
            sb_score, sb_findings, sb_facts = sandbox_provider.detonate(
                a.filename, a.content_type, a.payload)
            rec["sandbox"] = sb_facts
            score += sb_score
            for f in sb_findings:
                flags.append(f"sandbox_{f}")

        records.append(rec)

    # VT hash lookup would set DEGRADED if unavailable; offline core marks the hook.
    return StageResult(
        stage="attachments",
        status=StageStatus.DEGRADED,     # honest: no live hash reputation in offline core
        sub_score=min(score, 100.0),
        red_flags=sorted(set(flags)),
        facts={"attachment_count": len(atts), "attachments": records,
               "embedded_urls": sorted(set(embedded_urls))},
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
