"""Real-data feed for the SEGS dashboard.

Combines spool summaries under email/spool/{gmail,quarantine,rejected,released}.
Optional demo scoring of .eml files is only used when `_DEMO_EML_DIR` is set
(tests). Production API does not ship a mail corpus.

Set SEG_DASHBOARD_LLM=0 to force HeuristicProvider (tests / offline demos).
Set SEG_DASHBOARD_DEEP=0 to skip deep-agent enrichment.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Optional

from backend import disposition
from backend.config import get_settings
from workers.pipeline import content_ai, runner
from workers.pipeline.intel import LocalIOCClient
from backend.report import _ioc_context
from backend.paths import DATA_DIR, REPO_ROOT, SPOOL_DIR
from backend.stores.mail_thread import assign_thread_keys, headers_from_raw
from workers.pipeline.stage_summary import stages_for_feed
from backend.stores import ai_assess

# The feed builder always uses the offline client — live VT/AbuseIPDB calls
# are expensive (15 s throttle per call) and belong only in user-triggered
# /api/analyze, not in background feed refreshes that run at startup and on
# every feed rebuild. The intel stage in the feed will show SKIPPED/offline,
# which is correct for historical sample display.
_FEED_INTEL_CLIENT = LocalIOCClient()

_ROOT = REPO_ROOT
_DEMO_EML_DIR = None
_SPOOL_ROOT = SPOOL_DIR
_DEEP_CACHE_DIR = DATA_DIR / "deep_cache"

_WEEK_MS = 7 * 24 * 3600 * 1000

_deep_lock = threading.Lock()
_deep_thread: Optional[threading.Thread] = None


def _glm_credentials_available() -> bool:
    try:
        from cli.eml_analysis_agent import resolve_glm_credentials_path
        return resolve_glm_credentials_path().is_file()
    except Exception:
        return False


_LLM_PROVIDERS = frozenset({"glm", "gemini", "bedrock", "ollama"})


def llm_configured() -> bool:
    """True when live mail is assessed by a real model (same gate as the Gmail worker)."""
    try:
        provider = content_ai.get_default_provider()
    except Exception:
        return False
    return not isinstance(provider, (content_ai.HeuristicProvider, content_ai.NullProvider))


def has_llm_assessment(provider: str, summary: str) -> bool:
    return ai_assess.has_llm_assessment(provider, summary)


def dashboard_content_provider():
    """Content provider for dashboard-triggered pipeline runs.

    Prefers the installed LLM (GLM via Vertex) when credentials exist and
    SEG_DASHBOARD_LLM is not disabled. Honors an explicit SEG_CONTENT_PROVIDER
    if set to bedrock/gemini/glm/ollama/null. Falls back to HeuristicProvider
    offline.
    """
    s = get_settings()
    choice = (s.content_provider or "").strip().lower()
    if choice in ("bedrock", "gemini", "glm", "ollama", "null"):
        return content_ai.get_default_provider()
    if s.dashboard_llm and _glm_credentials_available():
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
        "modelId": facts.get("model_id") or "",
        "isForwarded": bool(facts.get("is_forwarded")),
        "isReply": bool(facts.get("is_reply")),
        "primaryContent": facts.get("primary_content") or "",
        "quotedContent": facts.get("quoted_or_forwarded_content") or "",
        "footerContent": facts.get("footer_content") or "",
        "footerWorthAssessing": bool(facts.get("footer_worth_assessing")),
        "footerAssessment": facts.get("footer_assessment") or "",
        "threadSummary": facts.get("thread_summary") or "",
        "threadVerdict": facts.get("thread_verdict") or "",
        "mailboxes": facts.get("mailboxes") or [],
        "recipients": facts.get("recipients") or [],
        "behavioralHits": facts.get("behavioral_hits") or [],
        "behavioralDetails": facts.get("behavioral_details") or [],
        "campaignHits": facts.get("campaign_hits") or [],
        "campaignDetails": facts.get("campaign_details") or [],
        "nluIntent": facts.get("nlu_intent") or "",
        "nluConfidence": facts.get("nlu_confidence") or 0,
        "degraded": bool(facts.get("degraded")),
        "scoreCapped": bool(facts.get("score_capped")),
        "fallbackUsed": facts.get("fallback_used") or "",
        "latencyMs": getattr(stage_result, "latency_ms", 0) or 0,
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
        "body_structure": content.get("body_structure") or {},
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
    if not get_settings().dashboard_deep:
        return None
    if not _glm_credentials_available():
        return None
    cached = load_deep_cache(raw)
    if cached:
        return cached
    try:
        from cli.eml_analysis_agent import analyze_eml_bytes
        deep = analyze_eml_bytes(raw, filename)
        summary = _deep_summary_from_analysis(deep)
        save_deep_cache(raw, summary)
        return summary
    except Exception:
        return None


def _from_parts(header: str) -> tuple:
    display, addr = parseaddr(header or "")
    addr = (addr or "").strip()
    display = (display or "").strip()
    return display or addr or "(unknown)", addr


def _to_parts(header: str, mailbox: str = "") -> tuple:
    people = [(d.strip(), a.strip()) for d, a in getaddresses([header or ""]) if a]
    if not people and mailbox:
        mb = mailbox.strip()
        people = [("", mb)] if mb else []
    addrs = [a for _, a in people]
    if not people:
        return "", "", []
    display, addr = people[0]
    return display or addr, addr, addrs


def _pipeline_result_to_entry(result, source_file: str, ts_ms: int,
                             deep: Optional[dict] = None, raw: Optional[bytes] = None) -> dict:
    display, addr = _from_parts(result.from_header or "")
    to_name, to_addr, to_addrs = _to_parts(getattr(result, "to_header", "") or "")
    verdict = result.verdict.value
    iocs = result.iocs.model_dump()
    iocs["context"] = _ioc_context(result)
    stages = {s.stage: _stage_dict(s) for s in result.stages}
    cai = stages.get("content_ai") or {}
    hdrs = headers_from_raw(raw or b"")
    return {
        "id": result.message_id or ("sample:" + source_file),
        "ts": ts_ms,
        "verdict": verdict,
        "score": result.composite_score,
        "hardOverride": result.hard_override,
        "threatClass": result.threat_class,
        "threatConfidence": result.threat_confidence,
        "fromName": display or addr or "(unknown)",
        "fromAddr": addr,
        "toName": to_name,
        "toAddr": to_addr,
        "toAddrs": to_addrs,
        "subject": result.subject or "(no subject)",
        "stages": stages,
        "reasons": result.reasons,
        "iocs": iocs,
        "status": "delivered",
        "pipelineStatus": "complete",
        "expiresAt": ts_ms + _WEEK_MS,
        "hasStageDetail": True,
        "sourceKind": "sample",
        "sourceFile": source_file,
        "aiSummary": cai.get("summary") or "",
        "aiProvider": cai.get("provider") or "",
        "aiModel": cai.get("modelId") or "",
        "aiLlmAttempted": has_llm_assessment(cai.get("provider") or "", cai.get("summary") or ""),
        "aiPending": False,
        "isForwarded": bool(cai.get("isForwarded")),
        "isReply": bool(cai.get("isReply")),
        "primaryContent": cai.get("primaryContent") or "",
        "quotedContent": cai.get("quotedContent") or "",
        "footerContent": cai.get("footerContent") or "",
        "footerWorthAssessing": bool(cai.get("footerWorthAssessing")),
        "footerAssessment": cai.get("footerAssessment") or "",
        "deepAnalysis": deep,
        "analystLabel": "",
        "analystLabelBy": "",
        "analystLabelTs": "",
        "messageId": (hdrs.get("message_id") if hdrs else "") or (result.message_id or ""),
        "inReplyTo": (hdrs.get("in_reply_to") if hdrs else "") or "",
        "references": (hdrs.get("references") if hdrs else "") or "",
        "gmailThreadId": "",
        "threadKey": "",
        "threadCount": 1,
        "threadSummary": cai.get("threadSummary") or "",
        "threadVerdict": cai.get("threadVerdict") or "",
        "fanoutCount": len((stages.get("fanout") or {}).get("mailboxes") or []),
        "fanoutMailboxes": (stages.get("fanout") or {}).get("mailboxes") or [],
        "fanoutRecipients": (stages.get("fanout") or {}).get("recipients") or [],
    }


def run_samples(correlation_store=None) -> list:
    """Score optional demo .eml files for the feed (tests / local SPA only).

    First pass uses HeuristicProvider so the dashboard can paint quickly.
    When GLM credentials are available, a background worker re-scores each
    sample with the LLM content stage and attaches deep-agent summaries
    (disk-cached under data/deep_cache/).
    """
    root = _DEMO_EML_DIR
    if root is None:
        return []
    files = sorted(root.glob("*.eml")) + sorted(root.glob("*.EML"))
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
        deep = load_deep_cache(raw) if get_settings().dashboard_deep else None
        entry = _pipeline_result_to_entry(result, eml_path.name, ts_ms, deep=deep, raw=raw)
        entries.append(entry)
        pending.append((eml_path, raw))
    assign_thread_keys(entries)
    if pending:
        s = get_settings()
        if _glm_credentials_available() and (s.dashboard_llm or s.dashboard_deep):
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
            if get_settings().dashboard_deep:
                deep = run_deep_analysis(raw, eml_path.name)
            result = None
            if use_llm:
                try:
                    result = runner.run_pipeline(
                        raw, source="file", content_provider=llm_provider,
                        intel_client=_FEED_INTEL_CLIENT,
                        correlation_store=correlation_store,
                        llm_triage=False)
                except Exception:
                    result = None
            with _deep_lock:
                if _cache is None:
                    continue
                for e in _cache:
                    if e.get("sourceKind") != "sample" or e.get("sourceFile") != eml_path.name:
                        continue
                    if result is not None:
                        prev_key = e.get("threadKey")
                        prev_count = e.get("threadCount")
                        updated = _pipeline_result_to_entry(
                            result, eml_path.name, e.get("ts") or int(time.time() * 1000),
                            deep=deep or e.get("deepAnalysis"), raw=raw)
                        e.update(updated)
                        if prev_key:
                            e["threadKey"] = prev_key
                            e["threadCount"] = prev_count
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


def _overlay_assessment(queue_id: str, full: dict, row: dict | None = None,
                        *, include_stages: bool = True) -> dict:
    """Prefer worker-written copy columns over a stale spool meta.json."""
    if row is None:
        try:
            from backend.stores.assessments import get_copy
            row = get_copy(queue_id)
        except Exception:
            row = None
    if not row:
        return full
    from backend.stores.assessments import status_of
    out = dict(full)
    if row.get("verdict"):
        out["verdict"] = row["verdict"]
    if row.get("score") is not None:
        out["score"] = row["score"]
    if row.get("disposition"):
        out["disposition"] = row["disposition"]
    if row.get("ai_summary"):
        out["ai_summary"] = row["ai_summary"]
        out["ai_provider"] = row.get("ai_provider") or out.get("ai_provider") or ""
        out["ai_model"] = row.get("ai_model") or out.get("ai_model") or ""
    if row.get("from_addr"):
        out.setdefault("from", row["from_addr"])
    if row.get("subject"):
        out.setdefault("subject", row["subject"])
    if row.get("to_addr"):
        out.setdefault("to", row["to_addr"])
    out["pipeline_status"] = status_of(row)
    if not include_stages:
        return out
    try:
        stages = json.loads(row.get("stages_json") or "{}")
    except json.JSONDecodeError:
        stages = {}
    if stages:
        merged = dict(out.get("stages") or {})
        merged.update(stages)
        out["stages"] = merged
    return out


def _norm_meta(meta: dict) -> dict:
    """Normalizes the two meta.json schemas seen on real disk data onto one
    shape — see module docstring."""
    return {
        "verdict": meta.get("verdict") or meta.get("core_verdict") or "",
        "score": meta.get("score", meta.get("core_score")),
        "disposition": meta.get("disposition") or meta.get("core_disposition") or "",
        "hard_override": meta.get("hard_override"),
        "reasons": list(meta.get("reasons") or []) if isinstance(meta.get("reasons"), (list, tuple)) else [],
        "subject": meta.get("subject", ""),
        "from": meta.get("from", ""),
        "to": meta.get("to", ""),
        "ts": meta.get("ts", ""),
        "message_id": meta.get("message_id", ""),
    }


def _thread_fields(full: dict, dest) -> dict:
    """Gmail thread id + RFC headers from meta, with an EML fallback."""
    message_id = str(full.get("message_id") or "")
    in_reply_to = str(full.get("in_reply_to") or "")
    references = str(full.get("references") or "")
    gmail_thread_id = str(full.get("gmail_thread_id") or "")
    stored = "in_reply_to" in full and "references" in full
    if not stored or not message_id:
        raw = b""
        if isinstance(dest, Path):
            eml = dest / "message.eml"
            if eml.is_file():
                try:
                    raw = eml.read_bytes()
                except OSError:
                    raw = b""
        if raw:
            try:
                rfc = headers_from_raw(raw)
            except Exception:
                rfc = {}
            message_id = message_id or rfc.get("message_id") or ""
            in_reply_to = in_reply_to or rfc.get("in_reply_to") or ""
            references = references or rfc.get("references") or ""
    return {
        "messageId": message_id,
        "inReplyTo": in_reply_to,
        "references": references,
        "gmailThreadId": gmail_thread_id,
    }


def _bucket_from_dest(dest: str) -> str:
    text = (dest or "").strip()
    parts = Path(text).parts if text else ()
    for name in ("gmail", "quarantine", "released", "rejected"):
        if name in parts:
            return name
    return "gmail"


def _meta_from_assessment(row: dict) -> dict:
    try:
        meta = json.loads(row.get("meta_json") or "{}")
    except json.JSONDecodeError:
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    if row.get("from_addr") and not meta.get("from"):
        meta["from"] = row["from_addr"]
    if row.get("subject") and not meta.get("subject"):
        meta["subject"] = row["subject"]
    if row.get("to_addr") and not meta.get("to"):
        meta["to"] = row["to_addr"]
    if row.get("mailbox") and not meta.get("mailbox"):
        meta["mailbox"] = row["mailbox"]
    if row.get("verdict") and not meta.get("verdict"):
        meta["verdict"] = row["verdict"]
    if row.get("score") is not None and meta.get("score") is None:
        meta["score"] = row["score"]
    if row.get("gmail_thread_id") and not meta.get("gmail_thread_id"):
        meta["gmail_thread_id"] = row["gmail_thread_id"]
    return meta


def _each_spool_copy(verdict_filter: str | None = None, origin: str = ""):
    """Yield (bucket, queue_id, meta, local_dir) for live mail.

    Fargate stores copies on S3 (and Postgres ``copies``). Tests still seed a
    temp directory via ``_SPOOL_ROOT``.
    """
    from backend.stores import spool as spoolmod
    from backend.stores import assessments as store

    if spoolmod.use_s3() and _SPOOL_ROOT == SPOOL_DIR:
        # Do not call iter_copies() here: that GetObject's every meta.json and
        # blocks FastAPI lifespan long enough for the ALB to fail the task.
        filt = verdict_filter or ""
        cc = origin or ""
        if store.verdicts_for_filter(filt) or cc:
            rows = store.list_feed_by_verdict_with_thread_siblings(filt, origin=cc)
        else:
            rows = store.list_feed_with_thread_siblings()
        for row in rows:
            qid = str(row.get("queue_id") or "").strip()
            if not qid:
                continue
            bkt = _bucket_from_dest(str(row.get("dest") or ""))
            yield bkt, qid, _meta_from_assessment(row), None, row
        return
    if not _SPOOL_ROOT.is_dir():
        return
    for summary in disposition.list_spool_entries(_SPOOL_ROOT):
        yield (
            summary["bucket"],
            summary["queue_id"],
            _read_full_meta(summary["path"]),
            Path(summary["path"]),
            None,
        )


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

_LIST_ORIGIN_KEYS = ("country", "country_name", "city", "ip", "network_role")


def _origin_stage_for_list(stored_stages: dict) -> dict:
    """Overview map needs country; drop the rest of stages_json from the list DTO."""
    origin = stored_stages.get("origin_ip") if isinstance(stored_stages, dict) else None
    if not isinstance(origin, dict):
        return {}
    keep = {
        key: origin[key]
        for key in _LIST_ORIGIN_KEYS
        if origin.get(key) not in ("", None, 0, False, [], {})
    }
    return {"origin_ip": keep} if keep else {}


def _ui_from_copy(bucket: str, queue_id: str, full: dict, dest_dir, *,
                  configured: bool | None = None, copy_row: dict | None = None,
                  slim: bool = False) -> dict:
    """One live-feed row from a spool/Postgres copy."""
    if configured is None:
        configured = llm_configured()
    full = _overlay_assessment(queue_id, full, row=copy_row, include_stages=not slim)
    norm = _norm_meta(full)
    ts_ms = _parse_ts_ms(norm["ts"])
    display, addr = _from_parts(norm["from"] or "")
    mailbox = (full.get("mailbox") or "").strip()
    # Always prefer the message To header. The scanned Gmail mailbox is only
    # a fallback when To is empty — otherwise SENT mail (From=support@pdax.ph,
    # To=customer) wrongly shows both columns as the mailbox.
    to_name, to_addr, to_addrs = _to_parts(norm.get("to") or "", mailbox=mailbox)
    iocs = dict(_EMPTY_IOCS)
    stored = full.get("iocs") if isinstance(full.get("iocs"), dict) else {}
    for key, val in stored.items():
        if val:
            iocs[key] = val
    if addr and not iocs.get("sender_emails"):
        iocs["sender_emails"] = [addr]
    if bucket == "gmail":
        status = "delivered"
        source_kind = "gmail"
    elif bucket == "released":
        status = "released"
        source_kind = "spool"
    elif bucket in ("quarantine", "rejected"):
        status = "held"
        source_kind = "spool"
    else:
        status = "delivered"
        source_kind = "spool"
    flags = ai_assess.feed_ai_flags(full, dest_dir, configured, source_kind)
    verdict = norm["verdict"]
    if not verdict:
        verdict = "" if (flags["aiPending"] or flags["aiTimedOut"]) else "CLEAN"
    stored_stages = stages_for_feed(full.get("stages"))
    pipeline_status = _pipeline_status(full, flags, stored_stages)
    summary = full.get("ai_summary") or ""
    if slim and len(summary) > 400:
        summary = summary[:400]
    origin_cc = ""
    if copy_row:
        origin_cc = str(
            copy_row.get("origin_cc") or copy_row.get("origin_country") or ""
        ).strip().upper()
    if not origin_cc and isinstance(full.get("stages"), dict):
        hop = (full.get("stages") or {}).get("origin_ip")
        if isinstance(hop, dict):
            origin_cc = str(hop.get("country") or "").strip().upper()
    return {
        "id": queue_id,
        "ts": ts_ms,
        "verdict": verdict,
        "score": norm["score"] if norm["score"] is not None else 0.0,
        "hardOverride": norm["hard_override"],
        "fromName": display or addr or "(unknown)",
        "fromAddr": addr,
        "toName": to_name,
        "toAddr": to_addr,
        "toAddrs": to_addrs,
        "subject": norm["subject"] or "(no subject)",
        "stages": {} if slim else stored_stages,
        "originCountry": origin_cc,
        "reasons": norm["reasons"],
        "iocs": iocs if not slim else {
            "sender_emails": iocs.get("sender_emails") or ([] if not addr else [addr]),
            "domains": [], "ips": [], "urls": [],
            "hashes_sha256": [], "authenticated_relay_senders": [], "context": {},
        },
        "status": status,
        "pipelineStatus": pipeline_status,
        "expiresAt": ts_ms + _WEEK_MS,
        "hasStageDetail": bool(stored_stages) if not slim else bool(
            stored_stages
            or origin_cc
            or (copy_row and (copy_row.get("static_done") or copy_row.get("stages_json")))
            or (isinstance(full.get("stages"), dict) and full.get("stages"))
        ),
        "sourceKind": source_kind,
        "bucket": bucket,
        "queueId": queue_id,
        "mailbox": full.get("mailbox") or "",
        "gmailLabels": full.get("gmail_labels") or [],
        "aiSummary": summary,
        "aiProvider": full.get("ai_provider") or "",
        "aiModel": full.get("ai_model") or "",
        "aiLlmAttempted": bool(full.get("ai_llm_attempted")),
        **flags,
        "isForwarded": bool(full.get("is_forwarded")),
        "isReply": bool(full.get("is_reply")),
        "primaryContent": "" if slim else (full.get("primary_content") or ""),
        "quotedContent": "" if slim else (full.get("quoted_or_forwarded_content") or ""),
        "footerContent": "" if slim else (full.get("footer_content") or ""),
        "footerWorthAssessing": bool(full.get("footer_worth_assessing")),
        "footerAssessment": "" if slim else (full.get("footer_assessment") or ""),
        "threatClass": full.get("threat_class") or "none",
        "threatConfidence": full.get("threat_confidence") or 0,
        "deepAnalysis": None,
        "analystLabel": full.get("analyst_label") or "",
        "analystLabelBy": full.get("analyst_label_by") or "",
        "analystLabelTs": full.get("analyst_label_ts") or "",
        **_thread_fields(full, dest_dir),
        "threadKey": "",
        "threadCount": 1,
        "threadSummary": full.get("thread_summary") or "",
        "threadVerdict": full.get("thread_verdict") or "",
        "fanoutCount": int(full.get("fanout_count") or 0),
        "fanoutMailboxes": full.get("fanout_mailboxes") or [],
        "fanoutRecipients": full.get("fanout_recipients") or [],
        "campaigns": [] if slim else (full.get("campaigns") or []),
    }


def spool_entries(verdict_filter: str | None = None, *, slim: bool = False,
                  origin: str = "") -> list:
    from backend.stores import assessments as store
    configured = llm_configured()
    out = [
        _ui_from_copy(bucket, queue_id, full, dest_dir, configured=configured, copy_row=row,
                      slim=slim)
        for bucket, queue_id, full, dest_dir, row in _each_spool_copy(
            verdict_filter, origin=origin)
    ]
    assign_thread_keys(out)
    wanted = store.verdicts_for_filter(verdict_filter or "")
    cc = (origin or "").strip().upper()
    if wanted or cc:
        match_ids = set()
        for e in out:
            ok_v = (not wanted) or (
                str(e.get("verdict") or "").upper() in wanted
                or str(e.get("threadVerdict") or "").upper() in wanted
            )
            ok_o = (not cc) or str(e.get("originCountry") or "").upper() == cc
            if ok_v and ok_o:
                match_ids.add(e.get("id"))
        thread_keys = {
            e.get("threadKey") for e in out if e.get("id") in match_ids and e.get("threadKey")
        }
        out = [
            e for e in out
            if e.get("id") in match_ids or (e.get("threadKey") and e.get("threadKey") in thread_keys)
        ]
    return out


def _disk_item_copies(queue_id: str) -> list[tuple]:
    if not _SPOOL_ROOT.is_dir():
        return []
    for bucket in ("gmail", "quarantine", "released", "rejected"):
        dest = _SPOOL_ROOT / bucket / queue_id
        if dest.is_dir():
            return [(bucket, queue_id, _read_full_meta(dest), dest)]
    return []


def _copy_rows_for_item(queue_id: str) -> list[dict]:
    from backend.stores import assessments as store
    row = store.get_copy(queue_id)
    if not row:
        return []
    tid = str(row.get("gmail_thread_id") or "").strip()
    mb = str(row.get("mailbox") or "").strip()
    sibs = store.copies_in_thread(tid, mb or None) if tid else []
    seen: set[str] = set()
    out: list[dict] = []
    for r in [row, *sibs]:
        q = str(r.get("queue_id") or "")
        if not q or q in seen:
            continue
        seen.add(q)
        if len(out) >= 1 + store._THREAD_SIBLING_CAP:
            break
        out.append(r)
    return out


def entries_for_queue_id(queue_id: str) -> list:
    """This copy plus mailbox thread siblings, even when it is outside the feed page."""
    qid = (queue_id or "").strip()
    if not qid:
        return []
    configured = llm_configured()
    rows = _copy_rows_for_item(qid)
    tuples: list[tuple] = []
    if rows:
        for r in rows:
            q = str(r.get("queue_id") or "")
            bkt = _bucket_from_dest(str(r.get("dest") or "")) or "gmail"
            dest_dir = None
            if _SPOOL_ROOT.is_dir():
                candidate = _SPOOL_ROOT / bkt / q
                if candidate.is_dir():
                    dest_dir = candidate
            tuples.append((bkt, q, _meta_from_assessment(r), dest_dir, r))
    else:
        tuples = [(b, q, full, d, None) for b, q, full, d in _disk_item_copies(qid)]
    if not tuples:
        return []
    out = [
        _ui_from_copy(bucket, q, full, dest_dir, configured=configured, copy_row=row)
        for bucket, q, full, dest_dir, row in tuples
    ]
    assign_thread_keys(out)
    return out


def entries_from_copy_rows(rows: list[dict]) -> list:
    """UI feed rows for spotlight hits (matching copies only, no extra siblings)."""
    configured = llm_configured()
    out = []
    for row in rows:
        qid = str(row.get("queue_id") or "").strip()
        if not qid:
            continue
        bkt = _bucket_from_dest(str(row.get("dest") or "")) or "gmail"
        dest_dir = None
        if _SPOOL_ROOT.is_dir():
            candidate = _SPOOL_ROOT / bkt / qid
            if candidate.is_dir():
                dest_dir = candidate
        out.append(
            _ui_from_copy(bkt, qid, _meta_from_assessment(row), dest_dir,
                          configured=configured, copy_row=row)
        )
    assign_thread_keys(out)
    out.sort(key=lambda e: e.get("ts") or 0, reverse=True)
    return out


def _pipeline_status(full: dict, flags: dict, stages: dict) -> str:
    """Where this copy sits in the worker graph (queued → static → ai → complete)."""
    stored = str(full.get("pipeline_status") or "").strip()
    if stored in ("error", "dead_letter", "timed_out", "queued", "static", "ai", "complete"):
        if stored == "complete" and flags.get("aiTimedOut"):
            return "timed_out"
        return stored
    if flags.get("aiTimedOut"):
        return "timed_out"
    if has_llm_assessment(full.get("ai_provider") or "", full.get("ai_summary") or ""):
        return "complete"
    if stages and any(stages.get(k) for k in ("headers", "sender", "urls", "intel", "deception")):
        return "ai"
    if flags.get("aiPending"):
        return "queued"
    return "complete"


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


# Sample corpus cache — rebuilt at server startup and POST /api/feed/refresh.
# Spool (including live Gmail scans) is re-read on every GET so the console
# shows new inbox mail without waiting for a full sample re-score.
_sample_cache: Optional[list] = None
_cache: Optional[list] = None
_feed_built_at = 0.0
_FEED_TTL_SECONDS = 2.0


def _demo_samples_enabled() -> bool:
    if _DEMO_EML_DIR is None:
        return False
    s = get_settings()
    if s.dashboard_samples:
        return True
    if (s.database_url or "").strip():
        return False
    return bool(s.serve_spa)


def warm_sample_cache(correlation_store=None) -> None:
    """Optional demo .eml scoring at boot. Live spool is listed on GET."""
    global _sample_cache
    if _sample_cache is None and _demo_samples_enabled():
        _sample_cache = run_samples(correlation_store)
    elif _sample_cache is None:
        _sample_cache = []


def build_feed(force: bool = False, correlation_store=None, *,
               verdict_filter: str = "", origin: str = "") -> list:
    global _cache, _sample_cache, _feed_built_at
    now = time.time()
    filtered = bool((verdict_filter or "").strip() or (origin or "").strip())
    if force:
        _feed_built_at = 0.0
        _cache = None
    elif not filtered and _cache is not None and (now - _feed_built_at) < _FEED_TTL_SECONDS:
        return _cache
    if _sample_cache is None:
        _sample_cache = run_samples(correlation_store) if _demo_samples_enabled() else []
    live = spool_entries(verdict_filter or None, slim=True, origin=origin or "")
    combined = live if filtered else (list(_sample_cache) + live)
    assign_thread_keys(combined)
    combined.sort(key=lambda e: e["ts"], reverse=True)
    if not filtered:
        _cache = combined
        _feed_built_at = now
        return _cache
    return combined


def build_filtered_feed(verdict_filter: str, correlation_store=None,
                        origin: str = "") -> list:
    """Overview tile / map click: copies for that filter, not the live page."""
    return build_feed(
        correlation_store=correlation_store,
        verdict_filter=verdict_filter or "",
        origin=origin or "",
    )


def _feed_thread_key(queue_id: str) -> str:
    if not queue_id or _cache is None:
        return ""
    for e in _cache:
        if e.get("queueId") == queue_id:
            return (e.get("threadKey") or "").strip()
    return ""


def candidate_unlock_keys(queue_id: str) -> set[str]:
    """Keys that identify the same conversation as *queue_id*.

    Gmail ``threadId`` is enough even when the sibling is not on the 500-row
    feed page. RFC grouping still uses the in-memory feed cache when present.
    """
    qid = (queue_id or "").strip()
    keys: set[str] = set()
    if qid:
        keys.add(f"msg:{qid}")
    from backend.stores import assessments as store
    from backend.stores.mail_thread import extract_message_ids
    row = store.get_copy(qid) or {}
    gid = str(row.get("gmail_thread_id") or "").strip()
    mailbox = str(row.get("mailbox") or "").strip().lower()
    if gid:
        keys.add(f"gmail:{gid}")
        if mailbox:
            keys.add(f"gmail:{mailbox}:{gid}")
    rfc = extract_message_ids(str(row.get("rfc_message_id") or ""))
    if rfc:
        keys.add("rfc:" + rfc[0])
    feed_key = _feed_thread_key(qid)
    if feed_key:
        keys.add(feed_key)
    return keys


def preferred_unlock_key(queue_id: str) -> str:
    """Canonical grant stored on the session after a passkey unlock."""
    keys = candidate_unlock_keys(queue_id)
    gmail_mb = sorted(k for k in keys if k.startswith("gmail:") and k.count(":") >= 2)
    if gmail_mb:
        return gmail_mb[0]
    gmail = sorted(k for k in keys if k.startswith("gmail:"))
    if gmail:
        return gmail[0]
    rfc = sorted(k for k in keys if k.startswith("rfc:"))
    if rfc:
        return rfc[0]
    if queue_id:
        return f"msg:{queue_id}"
    return "*"


def thread_key_for_queue_id(queue_id: str) -> str:
    """Thread key for a spool/Gmail queue id, or a stable singleton if unknown."""
    if not queue_id:
        return ""
    global _cache
    if _cache is None:
        build_feed()
    feed_key = _feed_thread_key(queue_id)
    if feed_key:
        return feed_key
    return preferred_unlock_key(queue_id)
