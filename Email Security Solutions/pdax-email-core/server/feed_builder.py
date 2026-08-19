"""Real-data feed for the SEGS dashboard.

Combines:
1. Fresh run_pipeline() over samples/*.eml (top-level only — NOT
   samples/fixtures/). Content AI uses the installed LLM (GLM) when
   credentials are available — see dashboard_content_provider().
2. Optional deep-agent enrichment (same path as Analyze upload) with a
   disk cache under data/deep_cache/, so narrative risk/summary is
   available on feed rows without re-calling Vertex on every refresh.
3. gateway/spool/{quarantine,rejected,released}/*/meta.json summaries.

Set SEG_DASHBOARD_LLM=0 to force HeuristicProvider (tests / offline demos).
Set SEG_DASHBOARD_DEEP=0 to skip deep-agent enrichment.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path
from typing import Optional

from app import disposition
from app.pipeline import content_ai, runner
from app.pipeline.intel import LocalIOCClient
from app.report import _ioc_context

# The feed builder always uses the offline client — live VT/AbuseIPDB calls
# are expensive (15 s throttle per call) and belong only in user-triggered
# /api/analyze, not in background feed refreshes that run at startup and on
# every feed rebuild. The intel stage in the feed will show SKIPPED/offline,
# which is correct for historical sample display.
_FEED_INTEL_CLIENT = LocalIOCClient()

_ROOT = Path(__file__).resolve().parent.parent
_SAMPLES_DIR = _ROOT / "samples"
_SPOOL_ROOT = _ROOT / "gateway" / "spool"
_DEEP_CACHE_DIR = _ROOT / "data" / "deep_cache"

_WEEK_MS = 7 * 24 * 3600 * 1000

_deep_lock = threading.Lock()
_deep_thread: Optional[threading.Thread] = None


def _env_flag(name: str, default: str = "1") -> bool:
    return os.environ.get(name, default).strip().lower() not in ("0", "false", "no", "off")


def _glm_credentials_available() -> bool:
    try:
        from eml_analysis_agent import resolve_glm_credentials_path
        return resolve_glm_credentials_path().is_file()
    except Exception:
        return False


def dashboard_content_provider():
    """Content provider for dashboard-triggered pipeline runs.

    Prefers the installed LLM (GLM via Vertex) when credentials exist and
    SEG_DASHBOARD_LLM is not disabled. Honors an explicit SEG_CONTENT_PROVIDER
    if set to bedrock/gemini/glm/ollama/null. Falls back to HeuristicProvider
    offline.
    """
    choice = os.environ.get("SEG_CONTENT_PROVIDER", "").strip().lower()
    if choice in ("bedrock", "gemini", "glm", "ollama", "null"):
        return content_ai.get_default_provider()
    if _env_flag("SEG_DASHBOARD_LLM", "1") and _glm_credentials_available():
        return content_ai.GLMProvider()
    return content_ai.HeuristicProvider()


def _stage_dict(stage_result) -> dict:
    facts = getattr(stage_result, "facts", None) or {}
    return {
        "status": stage_result.status.value,
        "score": stage_result.sub_score,
        "flags": stage_result.red_flags,
        "summary": facts.get("summary") or "",
        "provider": facts.get("provider") or "",
        "behavioralHits": facts.get("behavioral_hits") or [],
        "behavioralDetails": facts.get("behavioral_details") or [],
    }


def _deep_summary_from_analysis(deep: dict) -> dict:
    analysis = deep.get("analysis") or {}
    threat = analysis.get("threat_assessment") or {}
    content = analysis.get("content_analysis") or {}
    landing = analysis.get("landing_page_analysis") or []
    landing_mismatch = any(
        isinstance(x, dict) and x.get("context_mismatch") for x in landing)
    actions = list(analysis.get("recommended_actions") or [])[:3]
    return {
        "risk_level": threat.get("risk_level"),
        "risk_score": threat.get("risk_score"),
        "summary": content.get("summary") or "",
        "indicators": list(threat.get("indicators") or [])[:12],
        "recommended_actions": actions,
        "landing_mismatch": bool(landing_mismatch),
        "investigation_findings": list(analysis.get("investigation_findings") or [])[:6],
        "consistency_warning": deep.get("consistency_warning"),
        "model": deep.get("model"),
        "elapsed_ms": deep.get("elapsed_ms"),
    }


def _cache_path_for_bytes(raw: bytes) -> Path:
    digest = hashlib.sha256(raw).hexdigest()
    return _DEEP_CACHE_DIR / (digest + ".json")


def load_deep_cache(raw: bytes) -> Optional[dict]:
    path = _cache_path_for_bytes(raw)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_deep_cache(raw: bytes, summary: dict) -> None:
    _DEEP_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path_for_bytes(raw)
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


def run_deep_analysis(raw: bytes, filename: str) -> Optional[dict]:
    """Full Analyze-path agent; returns a compact summary for the feed UI."""
    if not _env_flag("SEG_DASHBOARD_DEEP", "1"):
        return None
    if not _glm_credentials_available():
        return None
    cached = load_deep_cache(raw)
    if cached:
        return cached
    try:
        from eml_analysis_agent import analyze_eml_bytes
        deep = analyze_eml_bytes(raw, filename)
        summary = _deep_summary_from_analysis(deep)
        save_deep_cache(raw, summary)
        return summary
    except Exception:
        return None


def _pipeline_result_to_entry(result, source_file: str, ts_ms: int,
                             deep: Optional[dict] = None) -> dict:
    display, addr = parseaddr(result.from_header or "")
    verdict = result.verdict.value
    iocs = result.iocs.model_dump()
    iocs["context"] = _ioc_context(result)
    stages = {s.stage: _stage_dict(s) for s in result.stages}
    cai = stages.get("content_ai") or {}
    return {
        "id": result.message_id or ("sample:" + source_file),
        "ts": ts_ms,
        "verdict": verdict,
        "score": result.composite_score,
        "hardOverride": result.hard_override,
        "fromName": display or addr or "(unknown)",
        "fromAddr": addr,
        "subject": result.subject or "(no subject)",
        "stages": stages,
        "reasons": result.reasons,
        "iocs": iocs,
        "status": "held" if verdict in ("SUSPICIOUS", "MALICIOUS") else "delivered",
        "expiresAt": ts_ms + _WEEK_MS,
        "hasStageDetail": True,
        "sourceKind": "sample",
        "sourceFile": source_file,
        "aiSummary": cai.get("summary") or "",
        "aiProvider": cai.get("provider") or "",
        "deepAnalysis": deep,
    }


def run_samples(correlation_store=None) -> list:
    """Score samples for the feed.

    First pass uses HeuristicProvider so the dashboard can paint quickly.
    When GLM credentials are available, a background worker re-scores each
    sample with the LLM content stage and attaches deep-agent summaries
    (disk-cached under data/deep_cache/).
    """
    files = sorted(_SAMPLES_DIR.glob("*.eml")) + sorted(_SAMPLES_DIR.glob("*.EML"))
    now_ms = int(time.time() * 1000)
    # Fast first paint — never block server boot on Vertex round-trips.
    fast = content_ai.HeuristicProvider()
    entries = []
    pending = []  # (eml_path, raw)
    for i, eml_path in enumerate(files):
        raw = eml_path.read_bytes()
        result = runner.run_pipeline(
            raw, source="file", content_provider=fast,
            intel_client=_FEED_INTEL_CLIENT,
            correlation_store=correlation_store)
        ts_ms = now_ms - (len(files) - i) * 15 * 60 * 1000
        deep = load_deep_cache(raw) if _env_flag("SEG_DASHBOARD_DEEP", "1") else None
        entry = _pipeline_result_to_entry(result, eml_path.name, ts_ms, deep=deep)
        entries.append(entry)
        pending.append((eml_path, raw))
    if pending and (
        (_env_flag("SEG_DASHBOARD_LLM", "1") and _glm_credentials_available())
        or (_env_flag("SEG_DASHBOARD_DEEP", "1") and _glm_credentials_available())
    ):
        _schedule_llm_enrichment(pending, correlation_store=correlation_store)
    return entries


def _schedule_llm_enrichment(pending: list, correlation_store=None) -> None:
    """Background: GLM content re-score + deep-agent enrichment; patch _cache."""
    global _deep_thread

    def worker():
        llm_provider = dashboard_content_provider()
        use_llm = not isinstance(llm_provider, content_ai.HeuristicProvider)
        for eml_path, raw in pending:
            deep = None
            if _env_flag("SEG_DASHBOARD_DEEP", "1"):
                deep = run_deep_analysis(raw, eml_path.name)
            result = None
            if use_llm:
                try:
                    result = runner.run_pipeline(
                        raw, source="file", content_provider=llm_provider,
                        intel_client=_FEED_INTEL_CLIENT,
                        correlation_store=correlation_store)
                except Exception:
                    result = None
            with _deep_lock:
                if _cache is None:
                    continue
                for e in _cache:
                    if e.get("sourceKind") != "sample" or e.get("sourceFile") != eml_path.name:
                        continue
                    if result is not None:
                        updated = _pipeline_result_to_entry(
                            result, eml_path.name, e.get("ts") or int(time.time() * 1000),
                            deep=deep or e.get("deepAnalysis"))
                        e.update(updated)
                    elif deep:
                        e["deepAnalysis"] = deep
                    break

    with _deep_lock:
        if _deep_thread is not None and _deep_thread.is_alive():
            return
        _deep_thread = threading.Thread(target=worker, name="segs-llm-enrich", daemon=True)
        _deep_thread.start()


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
            "aiSummary": "",
            "aiProvider": "",
            "deepAnalysis": None,
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


def _shadow_to_ui(e: dict) -> dict:
    """Normalize a gateway shadow_enforcement row for the Audit page."""
    raw_ts = e.get("ts")
    ts_ms = None
    if isinstance(raw_ts, (int, float)):
        ts_ms = int(raw_ts if raw_ts > 1e12 else raw_ts * 1000)
    elif isinstance(raw_ts, str):
        try:
            ts_ms = int(datetime.fromisoformat(raw_ts.replace("Z", "+00:00")).timestamp() * 1000)
        except ValueError:
            ts_ms = None
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)

    verdict = e.get("verdict") or "CLEAN"
    ui_type = (
        "critical" if verdict == "MALICIOUS" else
        "serious" if verdict == "SUSPICIOUS" else
        "warning" if verdict == "LOW" else "good"
    )
    title = "Shadow decision: " + (e.get("disposition_intended") or e.get("action_taken") or verdict)
    detail = (e.get("from") or "unknown sender") + " — “" + (e.get("subject") or "(no subject)") + "”"
    if e.get("disposition_reason"):
        detail += " — " + str(e["disposition_reason"])
    return {
        "ts": ts_ms,
        "type": ui_type,
        "title": title,
        "detail": detail,
        "wazuh": bool(e.get("wazuh")),
        "kind": "gateway",
        "tag": "Gateway",
    }


def combined_audit_entries(limit: int = 500) -> list:
    """Gateway shadow log + console activity, newest first, UI-shaped."""
    from . import activity_log

    rows = [_shadow_to_ui(e) for e in shadow_log_entries()]
    rows.extend(activity_log.to_audit_ui(e) for e in activity_log.list_entries(limit=limit))
    rows.sort(key=lambda e: e.get("ts") or 0, reverse=True)
    return rows[:limit]


# In-memory cache — rebuilt at server startup and on-demand via
# POST /api/feed/refresh, not recomputed per GET request.
_cache: Optional[list] = None


def build_feed(force: bool = False, correlation_store=None) -> list:
    global _cache
    if _cache is None or force:
        combined = run_samples(correlation_store) + spool_entries()
        combined.sort(key=lambda e: e["ts"], reverse=True)
        _cache = combined
    return _cache
