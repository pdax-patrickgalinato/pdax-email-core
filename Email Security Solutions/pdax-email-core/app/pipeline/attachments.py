"""Stage 4 — Attachment analysis (static, offline core).

Type + hash + banned-extension policy + basic HTML-attachment heuristics.
Deep parsing (oletools/pdfid) and live VT hash lookups are hooks for the
gateway build; here we flag on type policy and obvious credential-harvest
markers in HTML attachments."""
from __future__ import annotations

import time

from ..models import StageResult, StageStatus
from ..parsed_email import ParsedEmail

BANNED_EXT = {
    "exe", "js", "jse", "vbs", "vbe", "hta", "iso", "img", "lnk", "scr",
    "pif", "cmd", "bat", "ps1", "wsf", "msi", "jar", "cpl",
}
ACTIVE_DOC_EXT = {"docm", "xlsm", "pptm", "dotm"}
HARVEST_MARKERS = ("type=\"password\"", "type='password'", "<form", "onsubmit", "document.forms")


def run(pe: ParsedEmail) -> StageResult:
    t0 = time.perf_counter()
    atts = pe.attachments()
    if not atts:
        return StageResult(stage="attachments", status=StageStatus.SKIPPED,
                           latency_ms=int((time.perf_counter() - t0) * 1000))

    flags: list[str] = []
    score = 0.0
    records = []
    for a in atts:
        rec = {"filename": a.filename, "ext": a.extension, "sha256": a.sha256,
               "size": a.size, "content_type": a.content_type}
        if a.extension in BANNED_EXT:
            flags.append(f"banned_attachment:{a.extension}"); score += 60
            rec["banned"] = True
        if a.extension in ACTIVE_DOC_EXT:
            flags.append(f"macro_capable_doc:{a.extension}"); score += 25
        if a.extension in ("html", "htm") or a.content_type == "text/html":
            body = a.payload.decode("utf-8", "replace").lower()
            if any(m in body for m in HARVEST_MARKERS):
                flags.append("html_attachment_credential_form"); score += 45
                rec["credential_form"] = True
        records.append(rec)

    # VT hash lookup would set DEGRADED if unavailable; offline core marks the hook.
    return StageResult(
        stage="attachments",
        status=StageStatus.DEGRADED,     # honest: no live hash reputation in offline core
        sub_score=min(score, 100.0),
        red_flags=sorted(set(flags)),
        facts={"attachment_count": len(atts), "attachments": records},
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )
