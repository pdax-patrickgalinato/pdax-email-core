"""Upload-an-EML deep analysis — dashboard Analyze page.

Calls eml_analysis_agent (GLM narrative + forensics/playbook) and a cheap
heuristic run_pipeline() so the UI can show SEGS verdict/disposition chips
alongside the advisory LLM report. Feed refresh stays heuristic-only —
this router is the only dashboard path that spends LLM tokens.
"""
from __future__ import annotations

import asyncio
import time
from email.utils import parseaddr
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from app.pipeline import content_ai, runner
from app.report import _describe_flag, _intel_section, _ioc_context, _md_table, _sanitize
from server import activity_log
from server.auth_store import User
from server.deps import get_correlation_store, require_role
from server.security import analyze_limiter

router = APIRouter(prefix="/api/analyze", tags=["analyze"])

_MAX_EML_BYTES = 15 * 1024 * 1024  # 15 MB


def _pipeline_summary(raw: bytes, filename: str, correlation_store=None) -> tuple[dict, object]:
    """SEGS pipeline run for Analyze. Returns (summary_dict, pipeline_result)."""
    result = runner.run_pipeline(
        raw, source="file", content_provider=content_ai.HeuristicProvider(),
        correlation_store=correlation_store)
    display, addr = parseaddr(result.from_header or "")
    intel_stage = result.stage("intel")
    intel_facts: dict = {}
    if intel_stage and isinstance(intel_stage.facts, dict):
        intel_facts = {
            "domain_details": intel_stage.facts.get("domain_details") or {},
            "hits": intel_stage.facts.get("hits") or [],
            "behavioral_hits": intel_stage.facts.get("behavioral_hits") or [],
            "body_email_domains": intel_stage.facts.get("body_email_domains") or [],
        }
    summary = {
        "verdict": result.verdict.value,
        "score": result.composite_score,
        "disposition": result.disposition.value,
        "disposition_reason": result.disposition_reason,
        "hard_override": result.hard_override,
        "reasons": list(result.reasons or []),
        "fromName": display or addr or "(unknown)",
        "fromAddr": addr,
        "subject": result.subject or "(no subject)",
        "stages": {
            s.stage: {
                "status": s.status.value,
                "score": s.sub_score,
                "flags": list(s.red_flags or []),
                "behavioralHits": list((s.facts or {}).get("behavioral_hits", [])),
                "behavioralDetails": list((s.facts or {}).get("behavioral_details", [])),
            }
            for s in result.stages
        },
        "sourceFile": filename,
        "intelFacts": intel_facts,
        "matchedRules": list(result.matched_rules or []),
    }
    return summary, result


def _segs_section(pipeline_result, pipeline_summary: dict) -> str:
    """Generate a Markdown section with SEGS engine results to append to the deep report."""
    from datetime import datetime, timezone

    verdict = pipeline_summary.get("verdict", "UNKNOWN")
    score = pipeline_summary.get("score", 0)
    disposition = pipeline_summary.get("disposition", "—")
    hard_override = pipeline_summary.get("hard_override")
    reasons = pipeline_summary.get("reasons") or []
    stages = pipeline_summary.get("stages") or {}
    intel_facts = pipeline_summary.get("intelFacts") or {}

    icon_map = {"CLEAN": "🟢", "LOW": "🔵", "SUSPICIOUS": "🟠", "MALICIOUS": "🔴"}
    icon = icon_map.get(verdict, "")

    lines = [
        "",
        "---",
        "",
        "## SEGS Gateway Analysis",
        "",
        "_Independent rule-based analysis by the Secure Email Gateway Suite (SEGS) engine. "
        "Runs deterministic header, sender, URL, attachment, and threat-intelligence checks "
        "without an LLM — serves as a second opinion on the advisory AI report above._",
        "",
        f"**Verdict:** {icon} {verdict} — Score: **{score}/100**  ",
        f"**Disposition:** {disposition}  ",
    ]
    if hard_override:
        lines += [
            "",
            f"> **Hard Override:** `{hard_override}`  ",
            f"> {_describe_flag(hard_override)}",
        ]
    lines.append("")

    # Stage scores table
    if stages:
        stage_rows = []
        for stage_name, sd in stages.items():
            status_icon = {"pass": "✅", "flag": "🚩", "degraded": "⚠️", "skipped": "⏭️"}.get(
                sd.get("status", ""), "ℹ️")
            flags_str = ", ".join(f"`{f}`" for f in (sd.get("flags") or [])[:5])
            if len(sd.get("flags") or []) > 5:
                flags_str += f" (+{len(sd['flags']) - 5} more)"
            stage_rows.append([
                f"{status_icon} {stage_name}",
                str(sd.get("score", 0)),
                flags_str or "—",
            ])
        lines += [
            "### Stage Scores",
            "",
            _md_table(stage_rows, ["Stage", "Score", "Flags"]),
            "",
        ]

    # Matched detection rules
    matched_rules = pipeline_summary.get("matchedRules") or []
    if matched_rules:
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
        lines += ["### Matched Detection Rules", ""]
        rule_rows = [
            [
                severity_icon.get(r["severity"], "⚪") + " " + r["severity"].upper(),
                r["name"],
                ", ".join(r.get("tags", [])),
            ]
            for r in matched_rules
        ]
        lines.append(_md_table(rule_rows, ["Severity", "Rule", "Categories"]))
        lines.append("")
        for rule in matched_rules:
            lines.append(f"**{rule['name']}**")
            lines.append(f"> {rule['description']}")
            lines.append("")

    # Verdict explanation
    if reasons:
        lines += ["### Signal Findings", ""]
        for flag in reasons:
            lines.append(f"- {_describe_flag(flag)}")
        lines += ["", f"**Raw signal tags:** `{'`, `'.join(reasons)}`", ""]

    # Threat intelligence from VT/AbuseIPDB
    intel_lines = _intel_section(pipeline_result)
    if intel_lines:
        lines.extend(intel_lines)
    elif intel_facts:
        # Fallback: render from pipeline_summary dict if PipelineResult unavailable
        domain_details = intel_facts.get("domain_details") or {}
        hits = intel_facts.get("hits") or []
        if hits or domain_details:
            lines += ["### Threat Intelligence (VirusTotal / AbuseIPDB)", ""]
            if hits:
                lines.append("**Matched known-bad indicators:**")
                for hit in hits:
                    _, _, value = hit.partition(":")
                    if value:
                        lines.append(f"- `{value}` — {_describe_flag(hit)}")
                lines.append("")
            if domain_details:
                lines.append("**Domain reputation (VirusTotal):**")
                for domain, details in domain_details.items():
                    if isinstance(details, dict):
                        rep = details.get("reputation")
                        cats = details.get("categories") or {}
                        registrar = details.get("registrar") or "—"
                        cat_str = "; ".join(f"{e}: {l}" for e, l in list(cats.items())[:4]) or "—"
                        lines.append(
                            f"- `{domain}` — reputation: {rep}, categories: {cat_str}, registrar: {registrar}"
                        )
                lines.append("")

    # IOCs from pipeline
    if pipeline_result is not None:
        iocs = pipeline_result.iocs
        notes = _ioc_context(pipeline_result)
        lines += ["### Indicators of Compromise", ""]
        for label, values in [
            ("Sender addresses", iocs.sender_emails),
            ("Domains", iocs.domains),
            ("IP addresses", iocs.ips),
            ("URLs", iocs.urls),
            ("File hashes (SHA-256)", iocs.hashes_sha256),
        ]:
            if values:
                lines.append(f"**{label}:**")
                for v in values:
                    note = notes.get(str(v))
                    suffix = f" — _{note}_" if note else ""
                    lines.append(f"- `{v}`{suffix}")
                lines.append("")

    lines += [
        "---",
        "",
        "_SEGS engine results are rule-based and deterministic. VirusTotal and AbuseIPDB "
        "lookups are live API calls cached for 6 hours. Treat this as a second opinion; "
        "always verify high-severity findings independently._",
    ]
    return "\n".join(lines)


@router.post("/eml")
async def analyze_eml(
    file: UploadFile = File(...),
    user: User = Depends(require_role("admin", "analyst")),
):
    if analyze_limiter.is_limited(user.username):
        raise HTTPException(status_code=429, detail="Too many EML analyses — wait one minute and retry")
    filename = Path(file.filename or "upload.eml").name
    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")
    # content_type may be None when the client omits it; only reject explicitly
    # wrong types, not missing ones (curl and simple JS fetch often omit it).
    ct = (file.content_type or "").lower().split(";")[0].strip()
    _ALLOWED_CT = {"", "message/rfc822", "application/octet-stream", "text/plain"}
    if ct not in _ALLOWED_CT:
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")

    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(raw) > _MAX_EML_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {_MAX_EML_BYTES // (1024 * 1024)} MB limit",
        )

    t0 = time.perf_counter()
    corr = get_correlation_store()
    try:
        pipeline, pipeline_result = await asyncio.to_thread(
            _pipeline_summary, raw, filename, corr)
    except Exception:
        raise HTTPException(status_code=500, detail="Analysis failed — check server logs") from None

    try:
        # Import lazily so missing optional deps don't break feed/auth boot.
        from eml_analysis_agent import (
            AnalysisError, analyze_eml_bytes, resolve_glm_credentials_path)

        creds = resolve_glm_credentials_path()
        if not creds.is_file():
            raise HTTPException(
                status_code=503,
                detail="GLM credentials not configured — set SEG_GLM_CREDENTIALS_PATH "
                       "or place credentials.json in the project root",
            )
        # analyze_eml_bytes is a blocking GLM call that can take minutes —
        # run it in a thread so the async event loop stays free for other requests.
        deep = await asyncio.to_thread(
            analyze_eml_bytes, raw, filename, credentials_path=str(creds))
    except HTTPException:
        raise
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail="Deep analysis service unavailable") from exc
    except AnalysisError as exc:
        # LLM exhausted all retries. Log the full detail server-side (may contain
        # API quota messages, model names, or response fragments); return a safe
        # message to the client to avoid leaking backend LLM configuration.
        import logging as _logging
        _logging.getLogger(__name__).warning("AnalysisError: %s", exc)
        raise HTTPException(status_code=422, detail="Analysis incomplete — LLM stage failed, check server logs") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Deep analysis failed — check server logs") from exc

    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    segs = (pipeline or {}).get("verdict")
    risk = ((deep.get("analysis") or {}).get("threat_assessment") or {}).get("risk_level")
    activity_log.record(
        "analyze_eml", actor=user.username, actor_role=user.role,
        detail=f"Analyzed {filename}"
               + (f" — SEGS {segs}" if segs else "")
               + (f", deep {risk}" if risk else "")
               + f" ({elapsed_ms} ms)",
        meta={"filename": filename, "verdict": segs, "risk_level": risk},
    )
    combined_markdown = (deep.get("markdown") or "") + _segs_section(pipeline_result, pipeline)
    return {
        "filename": deep["filename"],
        "analysis": deep["analysis"],
        "markdown": combined_markdown,
        "playbook": deep.get("playbook"),
        "consistency_warning": deep.get("consistency_warning"),
        "pipeline": pipeline,
        "elapsed_ms": elapsed_ms,
        "model": deep.get("model"),
    }
