"""Compact per-stage snapshot for the SOC assessment-flow graph.

Persisted on spool/Gmail meta.json so live mail can show the same dependency
view as sample/Analyze runs (which already keep full StageResult objects).
Omits bulky facts (URL lists, attachment blobs) — scores, flags, and the
content-AI extras are enough to explain *how* the verdict was reached.
"""
from __future__ import annotations

from typing import Any


def compact_stages(result: Any) -> dict:
    """Return {stage_name: {status, score, flags, ...}} for persistence."""
    out: dict[str, dict] = {}
    for s in getattr(result, "stages", None) or []:
        name = getattr(s, "stage", None)
        if not name:
            continue
        status = getattr(s, "status", None)
        status_s = status.value if hasattr(status, "value") else str(status or "ok")
        facts = getattr(s, "facts", None) or {}
        row: dict[str, Any] = {
            "status": status_s,
            "score": float(getattr(s, "sub_score", 0) or 0),
            "flags": list(getattr(s, "red_flags", None) or []),
        }
        latency = int(getattr(s, "latency_ms", 0) or 0)
        if latency:
            row["latency_ms"] = latency
        extras = {
            "summary": facts.get("summary") or "",
            "provider": facts.get("provider") or "",
            "model_id": facts.get("model_id") or "",
            "nlu_intent": facts.get("nlu_intent") or "",
            "nlu_confidence": facts.get("nlu_confidence") or 0,
            "degraded": bool(facts.get("degraded")),
            "score_capped": bool(facts.get("score_capped")),
            "triage_escalated": bool(facts.get("triage_escalated")),
            "triage_skipped_llm": bool(facts.get("triage_skipped_llm")),
            "fallback_used": facts.get("fallback_used") or "",
            "thread_summary": facts.get("thread_summary") or "",
            "thread_verdict": facts.get("thread_verdict") or "",
            "mailboxes": facts.get("mailboxes") or [],
            "recipients": facts.get("recipients") or [],
            "ip": facts.get("ip") or "",
            "hostname": facts.get("hostname") or "",
            "org": facts.get("org") or "",
            "country": facts.get("country") or "",
            "search_summary": facts.get("search_summary") or "",
            "x_originating_ip": facts.get("x_originating_ip") or "",
            "country_name": facts.get("country_name") or "",
            "region": facts.get("region") or "",
            "city": facts.get("city") or "",
            "isp": facts.get("isp") or "",
            "asn": facts.get("asn") or "",
            "as_name": facts.get("as_name") or "",
            "timezone": facts.get("timezone") or "",
            "network_role": facts.get("network_role") or "",
            "network_role_label": facts.get("network_role_label") or "",
            "vpn": bool(facts.get("vpn")),
            "hosting": bool(facts.get("hosting")),
            "geo_mismatch": bool(facts.get("geo_mismatch")),
            "suspicion": facts.get("suspicion") or "",
            "suspicion_reason": facts.get("suspicion_reason") or "",
            "link_hops": facts.get("link_hops") or [],
            "link_hop_count": facts.get("link_hop_count") or 0,
            "profile": facts.get("profile") or {},
            "profile_delta": facts.get("profile_delta") or [],
            "profile_summary": facts.get("profile_summary") or "",
            "request_class": facts.get("request_class") or "",
            "request_history": facts.get("request_history") or {},
            "request_summary": facts.get("request_summary") or "",
            "trusted_channel": bool(facts.get("trusted_channel")),
            "campaign_hits": facts.get("campaign_hits") or [],
            "campaign_details": facts.get("campaign_details") or [],
        }
        for key, val in extras.items():
            if val in ("", 0, 0.0, False, None) or val == [] or val == {}:
                continue
            row[key] = val
        for key in ("lat", "lon"):
            val = facts.get(key)
            if isinstance(val, (int, float)):
                row[key] = float(val)
        out[str(name)] = row
    return out


def stages_for_feed(stored: Any) -> dict:
    """Normalize persisted or in-memory stage maps into the dashboard shape."""
    if not isinstance(stored, dict):
        return {}
    out: dict[str, dict] = {}
    for name, row in stored.items():
        if not isinstance(row, dict):
            continue
        try:
            score = float(row.get("score") or 0)
        except (TypeError, ValueError):
            score = 0.0
        flags = row.get("flags")
        if not isinstance(flags, list):
            flags = []
        try:
            nlu_conf = float(row.get("nlu_confidence") or row.get("nluConfidence") or 0)
        except (TypeError, ValueError):
            nlu_conf = 0.0
        out[str(name)] = {
            "status": row.get("status") or "ok",
            "score": score,
            "flags": flags,
            "summary": row.get("summary") or "",
            "provider": row.get("provider") or "",
            "modelId": row.get("modelId") or row.get("model_id") or "",
            "nluIntent": row.get("nlu_intent") or row.get("nluIntent") or "",
            "nluConfidence": nlu_conf,
            "degraded": bool(row.get("degraded")),
            "scoreCapped": bool(row.get("score_capped") or row.get("scoreCapped")),
            "fallbackUsed": row.get("fallback_used") or row.get("fallbackUsed") or "",
            "latencyMs": row.get("latency_ms") or row.get("latencyMs") or 0,
            "isForwarded": bool(row.get("isForwarded") or row.get("is_forwarded")),
            "isReply": bool(row.get("isReply") or row.get("is_reply")),
            "primaryContent": row.get("primaryContent") or row.get("primary_content") or "",
            "quotedContent": row.get("quotedContent") or row.get("quoted_or_forwarded_content") or "",
            "footerContent": row.get("footerContent") or row.get("footer_content") or "",
            "footerWorthAssessing": bool(
                row.get("footerWorthAssessing") or row.get("footer_worth_assessing")
            ),
            "footerAssessment": row.get("footerAssessment") or row.get("footer_assessment") or "",
            "threadSummary": row.get("threadSummary") or row.get("thread_summary") or "",
            "threadVerdict": row.get("threadVerdict") or row.get("thread_verdict") or "",
            "behavioralHits": row.get("behavioralHits") or row.get("behavioral_hits") or [],
            "behavioralDetails": row.get("behavioralDetails") or row.get("behavioral_details") or [],
            "campaignHits": row.get("campaignHits") or row.get("campaign_hits") or [],
            "campaignDetails": row.get("campaignDetails") or row.get("campaign_details") or [],
            "mailboxes": row.get("mailboxes") or [],
            "recipients": row.get("recipients") or [],
            "ip": row.get("ip") or "",
            "hostname": row.get("hostname") or "",
            "org": row.get("org") or "",
            "country": row.get("country") or "",
            "searchSummary": row.get("searchSummary") or row.get("search_summary") or "",
            "xOriginatingIp": row.get("xOriginatingIp") or row.get("x_originating_ip") or "",
            "countryName": row.get("countryName") or row.get("country_name") or "",
            "region": row.get("region") or "",
            "city": row.get("city") or "",
            "isp": row.get("isp") or "",
            "asn": row.get("asn") or "",
            "asName": row.get("asName") or row.get("as_name") or "",
            "timezone": row.get("timezone") or "",
            "networkRole": row.get("networkRole") or row.get("network_role") or "",
            "networkRoleLabel": row.get("networkRoleLabel") or row.get("network_role_label") or "",
            "vpn": bool(row.get("vpn")),
            "hosting": bool(row.get("hosting")),
            "geoMismatch": bool(row.get("geoMismatch") or row.get("geo_mismatch")),
            "suspicion": row.get("suspicion") or "",
            "suspicionReason": row.get("suspicionReason") or row.get("suspicion_reason") or "",
            "linkHops": row.get("linkHops") or row.get("link_hops") or [],
            "linkHopCount": row.get("linkHopCount") or row.get("link_hop_count") or 0,
            "lat": row.get("lat"),
            "lon": row.get("lon"),
            "profile": row.get("profile") or {},
            "profileDelta": row.get("profileDelta") or row.get("profile_delta") or [],
            "profileSummary": row.get("profileSummary") or row.get("profile_summary") or "",
            "requestClass": row.get("requestClass") or row.get("request_class") or "",
            "requestHistory": row.get("requestHistory") or row.get("request_history") or {},
            "requestSummary": row.get("requestSummary") or row.get("request_summary") or "",
            "trustedChannel": bool(row.get("trustedChannel") or row.get("trusted_channel")),
        }
    return out
