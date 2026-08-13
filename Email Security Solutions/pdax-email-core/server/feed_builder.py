"""Real-data feed — Phase 12 of the dashboard-overhaul plan.

Combines two real data sources into one feed shape matching what
dashboard/index.html's (now-removed) synthetic makeEmail() used to produce
(id, ts, verdict, score, hardOverride, fromName, fromAddr, subject, stages,
reasons, iocs, status, expiresAt), so the existing renderFeed()/
renderQuarantine() logic needs field-mapping awareness, not a rewrite:

1. Fresh run_pipeline() over samples/*.eml (top-level only — NOT
   samples/fixtures/, which are unit-test fixtures, not demo content).
   Always forced to content_ai.HeuristicProvider() regardless of whatever
   SEG_CONTENT_PROVIDER is configured globally, so opening the dashboard or
   clicking "re-evaluate" never triggers a surprise paid Bedrock/Gemini/GLM
   API call — confirmed with the user as the dashboard's cost guard.
2. gateway/spool/{quarantine,rejected,released}/*/meta.json, via
   app/disposition.py::list_spool_entries() — real, already-processed
   records. The files actually on disk were written by TWO different
   schemas historically: gateway/internal_inbox_test.py's ad hoc
   core_verdict/core_score/core_disposition/playbook keys, vs. the
   production LocalQuarantineClient.apply()'s verdict/score/disposition
   keys — _norm_meta() below normalizes both onto one shape. Spool entries
   don't carry a full per-stage breakdown or IOCSet (meta.json is a
   summary) — hasStageDetail=False signals the frontend to show a fallback
   instead of a stage table for these.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path
from typing import Optional

from app import disposition
from app.pipeline import content_ai, runner
from app.report import _ioc_context

_ROOT = Path(__file__).resolve().parent.parent
_SAMPLES_DIR = _ROOT / "samples"
_SPOOL_ROOT = _ROOT / "gateway" / "spool"

_WEEK_MS = 7 * 24 * 3600 * 1000


def dashboard_content_provider():
    """The forced, always-free provider every dashboard-triggered
    run_pipeline() call uses — see module docstring's cost-guard note."""
    return content_ai.HeuristicProvider()


def _stage_dict(stage_result) -> dict:
    return {"status": stage_result.status.value, "score": stage_result.sub_score,
           "flags": stage_result.red_flags}


def _pipeline_result_to_entry(result, source_file: str, ts_ms: int) -> dict:
    display, addr = parseaddr(result.from_header or "")
    verdict = result.verdict.value
    iocs = result.iocs.model_dump()
    iocs["context"] = _ioc_context(result)
    return {
        "id": result.message_id or ("sample:" + source_file),
        "ts": ts_ms,
        "verdict": verdict,
        "score": result.composite_score,
        "hardOverride": result.hard_override,
        "fromName": display or addr or "(unknown)",
        "fromAddr": addr,
        "subject": result.subject or "(no subject)",
        "stages": {s.stage: _stage_dict(s) for s in result.stages},
        "reasons": result.reasons,
        "iocs": iocs,
        "status": "held" if verdict in ("SUSPICIOUS", "MALICIOUS") else "delivered",
        "expiresAt": ts_ms + _WEEK_MS,
        "hasStageDetail": True,
        "sourceKind": "sample",
        "sourceFile": source_file,
    }


def run_samples() -> list:
    """Runs run_pipeline() fresh over every samples/*.eml file (top-level
    only, excludes samples/fixtures/). Forced HeuristicProvider — see
    module docstring."""
    files = sorted(_SAMPLES_DIR.glob("*.eml")) + sorted(_SAMPLES_DIR.glob("*.EML"))
    now_ms = int(time.time() * 1000)
    provider = dashboard_content_provider()
    entries = []
    for i, eml_path in enumerate(files):
        raw = eml_path.read_bytes()
        result = runner.run_pipeline(raw, source="file", content_provider=provider)
        # Real captured mail carries its own (often months-old) Date:
        # header — using it verbatim would make the dashboard's "last 24h"
        # panels look empty for a demo/eval corpus that isn't live traffic.
        # Spreading synthetic "evaluated at" timestamps over the last few
        # hours keeps every other field (verdict/score/flags/sender/
        # subject) fully real while being honest that the *time shown* is
        # "when the dashboard last evaluated this," not an original
        # delivery time.
        ts_ms = now_ms - (len(files) - i) * 15 * 60 * 1000
        entries.append(_pipeline_result_to_entry(result, eml_path.name, ts_ms))
    return entries


def _read_full_meta(entry_path: str) -> dict:
    meta_path = Path(entry_path) / "meta.json"
    if not meta_path.is_file():
        return {}
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _norm_meta(meta: dict) -> dict:
    """Normalizes the two meta.json schemas seen on real disk data onto one
    shape — see module docstring."""
    return {
        "verdict": meta.get("verdict") or meta.get("core_verdict") or "",
        "score": meta.get("score", meta.get("core_score")),
        "disposition": meta.get("disposition") or meta.get("core_disposition") or "",
        "hard_override": meta.get("hard_override"),
        "reasons": meta.get("reasons") or [],
        "subject": meta.get("subject", ""),
        "from": meta.get("from", ""),
        "ts": meta.get("ts", ""),
        "message_id": meta.get("message_id", ""),
    }


def _parse_ts_ms(ts_str: str) -> int:
    if ts_str:
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            pass
    return int(time.time() * 1000)


_EMPTY_IOCS = {"sender_emails": [], "domains": [], "ips": [], "urls": [],
              "hashes_sha256": [], "authenticated_relay_senders": [], "context": {}}


def spool_entries() -> list:
    if not _SPOOL_ROOT.is_dir():
        return []
    out = []
    for summary in disposition.list_spool_entries(_SPOOL_ROOT):
        norm = _norm_meta(_read_full_meta(summary["path"]))
        verdict = norm["verdict"] or "CLEAN"
        ts_ms = _parse_ts_ms(norm["ts"])
        display, addr = parseaddr(norm["from"] or "")
        iocs = dict(_EMPTY_IOCS)
        if addr:
            iocs["sender_emails"] = [addr]
        out.append({
            "id": summary["queue_id"],
            "ts": ts_ms,
            "verdict": verdict,
            "score": norm["score"] if norm["score"] is not None else 0.0,
            "hardOverride": norm["hard_override"],
            "fromName": display or addr or "(unknown)",
            "fromAddr": addr,
            "subject": norm["subject"] or "(no subject)",
            "stages": {},
            "reasons": norm["reasons"],
            "iocs": iocs,
            "status": ("released" if summary["bucket"] == "released"
                      else "held" if summary["bucket"] in ("quarantine", "rejected") else "delivered"),
            "expiresAt": ts_ms + _WEEK_MS,
            "hasStageDetail": False,
            "sourceKind": "spool",
            "bucket": summary["bucket"],
            "queueId": summary["queue_id"],
        })
    return out


def shadow_log_entries() -> list:
    path = _SPOOL_ROOT / "shadow_logs" / "shadow_enforcement.jsonl"
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            continue
    return out


# In-memory cache — rebuilt at server startup and on-demand via
# POST /api/feed/refresh, not recomputed per GET request (running
# run_pipeline() over 21 files on every page load would be wasteful).
_cache: Optional[list] = None


def build_feed(force: bool = False) -> list:
    global _cache
    if _cache is None or force:
        combined = run_samples() + spool_entries()
        combined.sort(key=lambda e: e["ts"], reverse=True)
        _cache = combined
    return _cache
