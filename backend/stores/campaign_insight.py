"""Campaign-level phishing-pattern assessment over already-analyzed emails.

Clustering (URL / hash / template) only groups candidates. This module reads
each member's existing LLM assessment — summary, NLU intent, findings, IOCs,
thread notes — and writes a campaign narrative: shared lure, tactics, targeting,
infrastructure, false-positive risk, and analyst actions.

Heuristic fill always runs so the console is useful without a model. When a
real content provider is configured, a second pass asks it to refine the
narrative from the same briefing (same pattern as sender-risk).
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import Counter
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, ValidationError, field_validator

_log = logging.getLogger(__name__)

_MAX_MEMBERS = 14
_STALE_SECONDS = 6 * 3600
_ATTACKS = (
    "credential_theft", "bec", "malware_delivery", "callback_scam",
    "extortion", "steal_pii", "job_scam", "ransomware", "reconnaissance",
    "mixed", "unknown",
)
_ATTACK_LABEL = {
    "credential_theft": "Credential theft",
    "bec": "Business email compromise",
    "malware_delivery": "Malware delivery",
    "callback_scam": "Callback / vishing lure",
    "extortion": "Extortion",
    "steal_pii": "PII harvesting",
    "job_scam": "Job scam",
    "ransomware": "Ransomware",
    "reconnaissance": "Reconnaissance",
    "mixed": "Mixed threat classes",
    "unknown": "Unclassified cluster",
}
_KIND_WHY = {
    "hash": "Member emails share the same attachment hash — a morphing-resistant payload pivot.",
    "url_path": "Member emails share the same landing-page path after tracking parameters are stripped.",
    "url_host": "Member emails share a non-popular URL host that is uncommon as a coincidental overlap.",
    "content": "Member emails share a near-identical body/subject fingerprint (same template, different senders or mailboxes).",
    "subj": "Member emails share a subject template after reply prefixes, numbers, and addresses are stripped.",
    "msgid": "Member emails share a Message-ID — a fan-out of the same message into several mailboxes.",
    "mixed": "Member emails share more than one pivot kind (URL, hash, template, or subject).",
}
_KIND_LABEL = {
    "hash": "shared attachment hash",
    "url_path": "shared landing URL",
    "url_host": "shared URL host",
    "content": "shared message template",
    "subj": "shared subject template",
    "msgid": "same Message-ID fan-out",
    "mixed": "mixed pivots",
}


class _CampaignLLM(BaseModel):
    title: str = ""
    attack_class: str = "unknown"
    confidence: str = "medium"
    summary: str = ""
    lure: str = ""
    patterns: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    targeting: str = ""
    infrastructure: str = ""
    why_clustered: str = ""
    false_positive_risk: str = "medium"
    false_positive_note: str = ""
    analyst_actions: list[str] = Field(default_factory=list)

    @field_validator("title", "lure", "targeting", "infrastructure",
                     "why_clustered", "false_positive_note", mode="before")
    @classmethod
    def _short(cls, v):
        return str(v or "").strip()[:800]

    @field_validator("summary", mode="before")
    @classmethod
    def _sum(cls, v):
        return str(v or "").strip()[:6000]

    @field_validator("attack_class", mode="before")
    @classmethod
    def _atk(cls, v):
        raw = str(v or "unknown").strip().lower().replace(" ", "_").replace("-", "_")
        aliases = {
            "phishing": "credential_theft",
            "credential": "credential_theft",
            "credentialharvesting": "credential_theft",
            "business_email_compromise": "bec",
            "invoice_fraud": "bec",
            "malware": "malware_delivery",
            "vishing": "callback_scam",
            "callback": "callback_scam",
            "pii": "steal_pii",
            "none": "unknown",
            "benign": "unknown",
        }
        raw = aliases.get(raw, raw)
        return raw if raw in _ATTACKS else "unknown"

    @field_validator("confidence", "false_positive_risk", mode="before")
    @classmethod
    def _lvl(cls, v):
        raw = str(v or "medium").strip().lower()
        return raw if raw in ("low", "medium", "high") else "medium"

    @field_validator("patterns", "tactics", "analyst_actions", mode="before")
    @classmethod
    def _strs(cls, v):
        if not isinstance(v, list):
            return []
        out = []
        for item in v[:12]:
            text = str(item or "").strip()
            if text:
                out.append(text[:400])
        return out


def dest_queue_id(dest: str) -> str:
    s = str(dest or "").strip()
    slash = s.find("/")
    return s[slash + 1:] if slash >= 0 else s


def cluster_hash(campaign: dict) -> str:
    blob = json.dumps(
        {
            "d": sorted(str(x) for x in (campaign.get("dests") or [])),
            "k": sorted(str(x) for x in (campaign.get("keys") or [])),
            "f": int(campaign.get("flagged") or 0),
            "m": int(campaign.get("members") or 0),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:20]


def insight_hash(campaign: dict, briefs: list[dict]) -> str:
    blob = json.dumps(
        {
            "c": cluster_hash(campaign),
            "s": [
                (
                    b.get("queue_id") or "",
                    b.get("verdict") or "",
                    (b.get("ai_summary") or "")[:160],
                    b.get("nlu_intent") or "",
                )
                for b in briefs[:_MAX_MEMBERS]
            ],
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:20]


def _parse_json(raw: Any, default):
    if isinstance(raw, (dict, list)):
        return raw
    if not raw:
        return default
    try:
        val = json.loads(raw)
    except (TypeError, ValueError):
        return default
    return val if isinstance(val, type(default)) else default


def _stages(row: dict) -> dict:
    data = _parse_json(row.get("stages_json"), {})
    return data if isinstance(data, dict) else {}


def _meta(row: dict) -> dict:
    data = _parse_json(row.get("meta_json"), {})
    return data if isinstance(data, dict) else {}


def _content_stage(stages: dict) -> dict:
    for key in ("content", "content_ai", "ai"):
        row = stages.get(key)
        if isinstance(row, dict) and row:
            return row
    return {}


def _uniq(items: list[str], limit: int = 12) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _iocs_of(meta: dict, stages: dict) -> dict:
    iocs = meta.get("iocs") if isinstance(meta.get("iocs"), dict) else {}
    intel = stages.get("intel") if isinstance(stages.get("intel"), dict) else {}
    merged = {
        "urls": list(iocs.get("urls") or intel.get("urls") or [])[:16],
        "domains": list(iocs.get("domains") or intel.get("domains") or [])[:12],
        "hashes": list(
            iocs.get("hashes_sha256") or iocs.get("hashes") or intel.get("hashes") or []
        )[:8],
        "ips": list(iocs.get("ips") or intel.get("ips") or [])[:8],
    }
    return {k: _uniq([str(x) for x in v], 12) for k, v in merged.items()}


def _findings_of(meta: dict, content: dict) -> list[str]:
    out: list[str] = []
    for key in ("investigation_findings", "findings"):
        raw = meta.get(key)
        if isinstance(raw, list):
            out.extend(str(x) for x in raw if x)
    flags = content.get("flags")
    if isinstance(flags, list):
        out.extend(str(x) for x in flags if x)
    for key in ("footer_assessment", "footerAssessment"):
        text = content.get(key)
        if text:
            out.append(str(text))
    return _uniq(out, 8)


def member_brief(row: dict, dest: str = "") -> dict:
    stages = _stages(row)
    meta = _meta(row)
    content = _content_stage(stages)
    intel = stages.get("intel") if isinstance(stages.get("intel"), dict) else {}
    iocs = _iocs_of(meta, stages)
    qid = str(row.get("queue_id") or dest_queue_id(dest) or "")
    intent = (
        content.get("nlu_intent") or content.get("nluIntent")
        or meta.get("threat_class") or row.get("threat_class") or ""
    )
    return {
        "queue_id": qid,
        "dest": dest or qid,
        "from": str(row.get("from_addr") or row.get("sender") or meta.get("from") or ""),
        "mailbox": str(row.get("mailbox") or meta.get("mailbox") or ""),
        "subject": str(row.get("subject") or meta.get("subject") or "")[:180],
        "verdict": str(row.get("verdict") or meta.get("verdict") or "").upper(),
        "threat_class": str(intent or "").strip(),
        "ai_summary": str(
            row.get("ai_summary") or content.get("summary") or meta.get("ai_summary") or ""
        )[:900],
        "nlu_intent": str(intent or "").strip(),
        "nlu_confidence": float(content.get("nlu_confidence") or content.get("nluConfidence") or 0),
        "thread_summary": str(
            content.get("thread_summary") or content.get("threadSummary") or ""
        )[:400],
        "findings": _findings_of(meta, content),
        "iocs": iocs,
        "ai_done": int(row.get("ai_done") or 0),
        "score": float(intel.get("score") or row.get("score") or 0),
    }


def _obs_brief(obs: dict) -> dict:
    return {
        "queue_id": dest_queue_id(obs.get("dest") or ""),
        "dest": obs.get("dest") or "",
        "from": obs.get("sender") or "",
        "mailbox": obs.get("mailbox") or "",
        "subject": (obs.get("subject") or "")[:180],
        "verdict": str(obs.get("verdict") or "").upper(),
        "threat_class": obs.get("threat_class") or "",
        "ai_summary": "",
        "nlu_intent": obs.get("threat_class") or "",
        "nlu_confidence": 0.0,
        "thread_summary": "",
        "findings": [],
        "iocs": {"urls": [], "domains": [], "hashes": [], "ips": []},
        "ai_done": 0,
        "score": 0.0,
    }


def load_member_briefs(campaign: dict, store=None) -> list[dict]:
    dests = [str(d) for d in (campaign.get("dests") or []) if d]
    ids = [dest_queue_id(d) for d in dests]
    copies: dict[str, dict] = {}
    try:
        from backend.stores import assessments
        for row in assessments.list_copies_by_ids(ids):
            qid = str(row.get("queue_id") or "")
            if qid:
                copies[qid] = row
    except Exception:
        _log.debug("campaign insight copy load failed", exc_info=True)

    obs_by_qid: dict[str, dict] = {}
    if store is not None:
        try:
            for row in store.obs_for_dests(dests):
                obs_by_qid[dest_queue_id(row.get("dest") or "")] = row
        except Exception:
            _log.debug("campaign insight obs load failed", exc_info=True)

    briefs: list[dict] = []
    for dest, qid in zip(dests, ids):
        if qid in copies:
            briefs.append(member_brief(copies[qid], dest))
        elif qid in obs_by_qid:
            briefs.append(_obs_brief(obs_by_qid[qid]))
        else:
            briefs.append(_obs_brief({"dest": dest}))
    briefs.sort(
        key=lambda b: (
            0 if b.get("verdict") in ("MALICIOUS", "SUSPICIOUS") else 1,
            0 if b.get("ai_summary") else 1,
            -(b.get("nlu_confidence") or 0),
        )
    )
    return briefs[:_MAX_MEMBERS]


def _majority(counter: Counter, default: str = "") -> str:
    if not counter:
        return default
    key, n = counter.most_common(1)[0]
    if not key or key in ("none", "unknown", ""):
        for k, _ in counter.most_common():
            if k and k not in ("none", "unknown"):
                return k
        return default
    return key if n else default


def _host_of(url: str) -> str:
    try:
        host = (urlparse(url).hostname or "").lower().lstrip("www.")
    except Exception:
        return ""
    return host


def _sender_domain(addr: str) -> str:
    s = str(addr or "").strip().lower()
    if "@" in s:
        return s.rsplit("@", 1)[-1]
    return s


def build_aggregates(campaign: dict, briefs: list[dict]) -> dict:
    verdicts = Counter(b.get("verdict") or "UNKNOWN" for b in briefs)
    intents = Counter(
        (b.get("nlu_intent") or b.get("threat_class") or "").strip().lower()
        for b in briefs
        if (b.get("nlu_intent") or b.get("threat_class"))
    )
    intents.pop("", None)
    senders = _uniq([b.get("from") or "" for b in briefs], 16)
    mailboxes = _uniq([b.get("mailbox") or "" for b in briefs], 16)
    sender_domains = _uniq([_sender_domain(s) for s in senders], 12)
    urls, domains, hashes, ips = [], [], [], []
    findings: list[str] = []
    summaries: list[str] = []
    for b in briefs:
        iocs = b.get("iocs") or {}
        urls.extend(iocs.get("urls") or [])
        domains.extend(iocs.get("domains") or [])
        hashes.extend(iocs.get("hashes") or [])
        ips.extend(iocs.get("ips") or [])
        findings.extend(b.get("findings") or [])
        if b.get("ai_summary"):
            summaries.append(str(b["ai_summary"]))
    url_hosts = _uniq([_host_of(u) for u in urls], 12)
    analyzed = sum(1 for b in briefs if b.get("ai_summary") or b.get("ai_done"))
    attack = _majority(intents, "unknown")
    if attack in ("none",):
        attack = "unknown"
    if len([k for k, n in intents.items() if k not in ("none", "") and n]) > 2:
        attack = "mixed"
    return {
        "verdict_mix": dict(verdicts),
        "intent_mix": dict(intents),
        "attack_class": attack if attack in _ATTACKS else "unknown",
        "senders": senders,
        "sender_domains": sender_domains,
        "mailboxes": mailboxes,
        "urls": _uniq(urls, 10),
        "url_hosts": url_hosts,
        "domains": _uniq(domains, 10),
        "hashes": _uniq(hashes, 6),
        "ips": _uniq(ips, 6),
        "findings": _uniq(findings, 10),
        "summaries": summaries[:8],
        "analyzed": analyzed,
        "members": int(campaign.get("members") or len(briefs)),
        "flagged": int(campaign.get("flagged") or 0),
        "kind": campaign.get("kind") or "",
        "pattern": campaign.get("pattern") or "",
        "keys": list(campaign.get("keys") or [])[:16],
        "subjects": list(campaign.get("subjects") or [])[:8],
    }


def _patterns_from(agg: dict, campaign: dict) -> list[str]:
    kind = agg.get("kind") or ""
    out: list[str] = []
    label = _KIND_LABEL.get(kind, kind or "shared pivot")
    pivot = str(agg.get("pattern") or "")
    cut = pivot.find(":")
    if cut > 0:
        pivot = pivot[cut + 1:]
    if pivot:
        out.append(f"Primary pivot ({label}): {pivot[:160]}")
    if len(agg.get("sender_domains") or []) >= 2:
        out.append(
            "Sender rotation across %s domains (%s) — typical of a campaign kit, not a single compromised mailbox."
            % (len(agg["sender_domains"]), ", ".join(agg["sender_domains"][:5]))
        )
    elif len(agg.get("senders") or []) >= 2:
        out.append(
            "Multiple From addresses (%s) delivering the same lure."
            % ", ".join(agg["senders"][:4])
        )
    if len(agg.get("mailboxes") or []) >= 2:
        out.append(
            "Spray across %s internal mailboxes: %s."
            % (len(agg["mailboxes"]), ", ".join(agg["mailboxes"][:6]))
        )
    if len(agg.get("urls") or []) >= 1:
        out.append("Shared or repeated landing URLs: " + "; ".join(agg["urls"][:4]))
    if agg.get("hashes"):
        out.append("Shared attachment hash(es): " + ", ".join(h[:16] + "…" for h in agg["hashes"][:3]))
    subjects = agg.get("subjects") or []
    if len(subjects) >= 2:
        out.append("Subject variants of the same template: " + " | ".join(subjects[:4]))
    elif subjects:
        out.append("Repeated subject: " + subjects[0])
    if agg.get("findings"):
        out.append("Recurring investigation notes: " + "; ".join(agg["findings"][:3]))
    return out[:10]


def _tactics_from(agg: dict, briefs: list[dict]) -> list[str]:
    blob = " ".join(
        (agg.get("summaries") or [])
        + (agg.get("findings") or [])
        + [b.get("subject") or "" for b in briefs]
    ).lower()
    checks = [
        ("credential harvest", ("password", "login", "sign in", "verify account", "credential")),
        ("urgency / deadline", ("urgent", "immediately", "within 24", "suspend", "expire")),
        ("payment / invoice", ("invoice", "wire", "payment", "bank", "remittance", "payroll")),
        ("brand impersonation", ("microsoft", "google", "docusign", "hr portal", "it helpdesk")),
        ("callback / vishing", ("call this number", "callback", "phone", "extension")),
        ("malware dropper", ("attachment", "macro", "enable content", "zip", "html smuggling")),
        ("lookalike infrastructure", ("punycode", "lookalike", "typosquat")),
    ]
    out = []
    for label, needles in checks:
        if any(n in blob for n in needles):
            out.append(label)
    if len(agg.get("sender_domains") or []) >= 2:
        out.append("infrastructure rotation")
    if int(agg.get("flagged") or 0) >= 2:
        out.append("multi-mailbox delivery")
    return _uniq(out, 8)


def _fp_risk(agg: dict) -> tuple[str, str]:
    flagged = int(agg.get("flagged") or 0)
    members = max(1, int(agg.get("members") or 1))
    kind = agg.get("kind") or ""
    if flagged == 0 and kind in ("subj", "url_host"):
        return "high", (
            "No member is flagged SUSPICIOUS or MALICIOUS, and the pivot is a weaker "
            "signal (subject or popular-adjacent host). This may be legitimate bulk mail."
        )
    if flagged == 0:
        return "medium", (
            "Members are clustered by a technical pivot but none are flagged yet. "
            "Treat as a watchlist until an assessed email confirms a lure."
        )
    if kind in ("hash", "url_path") and flagged >= 1:
        return "low", (
            "A morphing-resistant pivot (payload hash or landing path) plus at least "
            "one flagged member makes coincidental overlap unlikely."
        )
    if flagged / members >= 0.5:
        return "low", "A majority of clustered emails are already flagged by the scoring engine."
    return "medium", "Mixed verdicts in the cluster — confirm the shared pivot is the lure, not a newsletter template."


def _actions_from(agg: dict) -> list[str]:
    attack = agg.get("attack_class") or "unknown"
    actions = [
        "Open two or three member emails and compare the AI assessments — confirm the shared lure before broadcasting a warning.",
    ]
    if agg.get("urls"):
        actions.append(
            "Block or hunt the shared landing URL(s) and registrable host(s) in the secure email gateway and DNS logs: "
            + ", ".join((agg.get("url_hosts") or agg["urls"])[:4])
        )
    if agg.get("hashes"):
        actions.append("Add the shared attachment hash(es) to block / detonate lists and search the tenant for other deliveries.")
    if attack == "credential_theft":
        actions.append("If any recipient clicked, reset credentials and review sign-in logs for the targeted mailboxes.")
    elif attack == "bec":
        actions.append("Verify any payment or vendor-change request out of band. Do not use reply-to on the clustered mail.")
    elif attack in ("malware_delivery", "ransomware"):
        actions.append("Isolate endpoints that opened the attachment and submit the sample to the sandbox if not already detonated.")
    elif attack == "callback_scam":
        actions.append("Warn targeted mailboxes not to call numbers in the body; hunt the callback number across other mail.")
    if len(agg.get("mailboxes") or []) >= 2:
        actions.append(
            "Search the live feed for the other targeted mailboxes and the shared subject template to catch late deliveries."
        )
    actions.append("This cluster is reference-only: it does not change a message verdict. Use it to prioritize hunting.")
    return actions[:8]


def _title_from(agg: dict, campaign: dict) -> str:
    attack = _ATTACK_LABEL.get(agg.get("attack_class") or "", "")
    subjects = agg.get("subjects") or campaign.get("subjects") or []
    subj = str(subjects[0] if subjects else "").replace("\n", " ").strip()
    if len(subj) > 72:
        subj = subj[:69] + "…"
    kind = _KIND_LABEL.get(agg.get("kind") or "", "cluster")
    if attack and attack != "Unclassified cluster" and subj:
        return f"{attack}: {subj}"
    if subj:
        return subj
    if attack and attack != "Unclassified cluster":
        return f"{attack} via {kind}"
    return f"Email cluster via {kind}"


def heuristic_insight(campaign: dict, briefs: list[dict]) -> dict:
    agg = build_aggregates(campaign, briefs)
    patterns = _patterns_from(agg, campaign)
    tactics = _tactics_from(agg, briefs)
    fp, fp_note = _fp_risk(agg)
    analyzed = int(agg.get("analyzed") or 0)
    members = int(agg.get("members") or 0)
    flagged = int(agg.get("flagged") or 0)
    attack = agg.get("attack_class") or "unknown"
    kind_why = _KIND_WHY.get(agg.get("kind") or "", "Members share at least one clustering pivot.")
    mix_bits = [
        f"{n} {v.lower()}" for v, n in sorted(agg["verdict_mix"].items(), key=lambda kv: (-kv[1], kv[0])) if n
    ]
    intent_bits = [
        f"{n}× {_ATTACK_LABEL.get(k, k)}"
        for k, n in sorted(agg["intent_mix"].items(), key=lambda kv: (-kv[1], kv[0]))
        if k not in ("none", "")
    ]
    summary_parts = [
        (
            f"This cluster groups {members} email{'s' if members != 1 else ''} from "
            f"{len(agg['senders']) or int(campaign.get('senders') or 0)} sender"
            f"{'' if (len(agg['senders']) or 1) == 1 else 's'} into "
            f"{len(agg['mailboxes']) or int(campaign.get('mailboxes') or 0)} mailbox"
            f"{'' if (len(agg['mailboxes']) or 1) == 1 else 'es'}, linked by "
            f"{_KIND_LABEL.get(agg.get('kind') or '', 'a shared pivot')}."
        ),
        f"{flagged} of {members} member{'s' if members != 1 else ''} "
        f"{'is' if flagged == 1 else 'are'} flagged SUSPICIOUS or MALICIOUS"
        + (f" ({', '.join(mix_bits)})." if mix_bits else "."),
    ]
    if analyzed:
        summary_parts.append(
            f"{analyzed} member{'s have' if analyzed != 1 else ' has'} a per-email AI assessment; "
            "the narrative below is synthesized from those assessments, not from raw MIME alone."
        )
    else:
        summary_parts.append(
            "Per-email AI assessments are not on file yet for these members — "
            "the cluster still stands on the technical pivot and verdict mix."
        )
    if attack and attack not in ("unknown", "mixed"):
        summary_parts.append(
            f"Dominant assessed class is {_ATTACK_LABEL.get(attack, attack)}"
            + (f" ({', '.join(intent_bits[:4])})." if intent_bits else ".")
        )
    elif intent_bits:
        summary_parts.append("Assessed intent mix: " + ", ".join(intent_bits[:5]) + ".")
    if agg.get("summaries"):
        summary_parts.append("Representative email AI notes: " + " / ".join(s[:220] for s in agg["summaries"][:3]))
    if tactics:
        summary_parts.append("Recurring tactics: " + ", ".join(tactics) + ".")
    if agg.get("mailboxes"):
        summary_parts.append("Targeted mailboxes: " + ", ".join(agg["mailboxes"][:8]) + ".")
    lure = ""
    if attack == "credential_theft":
        lure = "Get the recipient to authenticate at an attacker-controlled page or form."
    elif attack == "bec":
        lure = "Get the recipient to change a payment, vendor, or payroll instruction without calling a known number."
    elif attack in ("malware_delivery", "ransomware"):
        lure = "Get the recipient to open a shared payload (attachment or link) that delivers code."
    elif attack == "callback_scam":
        lure = "Get the recipient to call a number in the body where a live operator continues the scam."
    elif agg.get("urls"):
        lure = "Drive traffic to the shared landing URL(s) clustered on this campaign."
    elif agg.get("hashes"):
        lure = "Deliver the same attachment payload to several mailboxes."
    conf = "high" if analyzed >= 2 and flagged >= 1 and fp == "low" else (
        "low" if analyzed == 0 or fp == "high" else "medium"
    )
    targeting = ""
    if agg.get("mailboxes"):
        targeting = (
            f"{len(agg['mailboxes'])} mailbox(es) in this tenant"
            + (f": {', '.join(agg['mailboxes'][:8])}" if agg["mailboxes"] else "")
            + ". Multiple mailboxes with one lure is campaign-shaped rather than a one-off."
        )
    infra_bits = []
    if agg.get("url_hosts"):
        infra_bits.append("hosts " + ", ".join(agg["url_hosts"][:6]))
    if agg.get("urls"):
        infra_bits.append("urls " + "; ".join(agg["urls"][:4]))
    if agg.get("hashes"):
        infra_bits.append("hashes " + ", ".join(h[:20] for h in agg["hashes"][:3]))
    if agg.get("sender_domains"):
        infra_bits.append("from-domains " + ", ".join(agg["sender_domains"][:6]))
    insight = {
        "lure": lure,
        "patterns": patterns,
        "tactics": tactics,
        "targeting": targeting,
        "infrastructure": "; ".join(infra_bits),
        "why_clustered": kind_why,
        "false_positive_risk": fp,
        "false_positive_note": fp_note,
        "analyst_actions": _actions_from(agg),
        "threat_mix": agg["verdict_mix"],
        "intent_mix": agg["intent_mix"],
        "shared_iocs": {
            "urls": agg["urls"],
            "hosts": agg["url_hosts"],
            "domains": agg["domains"],
            "hashes": agg["hashes"],
            "ips": agg["ips"],
        },
        "member_briefs": [
            {
                "queue_id": b.get("queue_id"),
                "from": b.get("from"),
                "mailbox": b.get("mailbox"),
                "subject": b.get("subject"),
                "verdict": b.get("verdict"),
                "intent": b.get("nlu_intent") or b.get("threat_class"),
                "summary": (b.get("ai_summary") or "")[:280],
            }
            for b in briefs[:8]
        ],
        "analyzed": analyzed,
    }
    return {
        "ai_title": _title_from(agg, campaign)[:180],
        "ai_summary": " ".join(summary_parts).strip()[:5000],
        "attack_class": attack,
        "confidence": conf,
        "insight": insight,
        "facts_hash": insight_hash(campaign, briefs),
        "ai_provider": "heuristic",
        "ai_model": "",
        "ai_assessed_at": time.time(),
    }


def _llm_json(system: str, user: str) -> tuple[dict, str]:
    from workers.pipeline import content_ai as ca

    try:
        provider = ca.get_default_provider()
    except Exception:
        return {}, ""
    if isinstance(provider, ca.HeuristicProvider):
        return {}, ""
    slots = list(getattr(provider, "_providers", None) or [provider])
    last = ""
    for slot in slots:
        generate = getattr(slot, "_generate", None)
        extract = getattr(slot, "_extract_text", None)
        get_client = getattr(slot, "_get_client", None)
        if not (generate and extract and get_client):
            continue
        model = str(getattr(slot, "model_id", "") or "")
        try:
            client = get_client()
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ]
            resp = generate(client, messages)
            text = extract(resp)
            if not text:
                last = "empty"
                continue
            parsed = json.loads(text)
            if isinstance(parsed, dict) and parsed:
                return parsed, model
        except Exception as exc:
            last = f"{type(exc).__name__}: {exc}"
            err = str(exc).lower()
            if "429" in err or "resource_exhausted" in err:
                time.sleep(1.5)
            continue
    if last:
        _log.warning("campaign insight LLM failed: %s", last)
    return {}, ""


def _system_prompt() -> str:
    return (
        "You are a senior phishing-campaign analyst at a financial-services SOC. "
        "You are given a *cluster* of emails that already share a technical pivot "
        "(landing URL, attachment hash, or template) plus each member's existing "
        "per-email AI assessment. Your job is campaign-level insight: the shared lure, "
        "tactics, targeting, infrastructure reuse, why they belong together, and what "
        "an analyst should do next. You never set or override a message verdict — that "
        "belongs to the scoring engine. Do not invent emails, URLs, hashes, or mailboxes "
        "that are not in the briefing. If members look like legitimate bulk mail, say so "
        "via false_positive_risk=high.\n"
        "Reply with JSON only:\n"
        '{"title":"short analyst title",'
        '"attack_class":"credential_theft|bec|malware_delivery|callback_scam|extortion|'
        'steal_pii|job_scam|ransomware|reconnaissance|mixed|unknown",'
        '"confidence":"low|medium|high",'
        '"summary":"8-14 sentence campaign narrative grounded in the member assessments",'
        '"lure":"one sentence: what the victim is being asked to do",'
        '"patterns":["shared tactic or pivot in plain language"],'
        '"tactics":["urgency","brand impersonation"],'
        '"targeting":"who is targeted and why that is campaign-shaped",'
        '"infrastructure":"shared hosts, URLs, hashes, sender domains from the briefing",'
        '"why_clustered":"why these emails belong together",'
        '"false_positive_risk":"low|medium|high",'
        '"false_positive_note":"when this cluster could be coincidental",'
        '"analyst_actions":["concrete next step"]}\n'
        "Ground every claim in the briefing. Prefer specific IOCs and mailbox names over generic advice."
    )


def assess_with_llm(campaign: dict, briefs: list[dict], heuristic: dict) -> dict:
    agg = build_aggregates(campaign, briefs)
    user = (
        "Heuristic draft (refine; do not drop shared IOCs or flagged counts):\n"
        + json.dumps(
            {
                "title": heuristic.get("ai_title"),
                "attack_class": heuristic.get("attack_class"),
                "confidence": heuristic.get("confidence"),
                "summary": heuristic.get("ai_summary"),
                "insight": {
                    k: (heuristic.get("insight") or {}).get(k)
                    for k in (
                        "lure", "patterns", "tactics", "targeting", "infrastructure",
                        "why_clustered", "false_positive_risk", "false_positive_note",
                        "analyst_actions",
                    )
                },
            },
            ensure_ascii=False,
        )
        + "\n\nCluster facts and per-email AI assessments:\n"
        + json.dumps(
            {
                "id": campaign.get("id"),
                "kind": campaign.get("kind"),
                "pattern": campaign.get("pattern"),
                "keys": (campaign.get("keys") or [])[:16],
                "members": campaign.get("members"),
                "flagged": campaign.get("flagged"),
                "aggregates": {
                    k: agg.get(k)
                    for k in (
                        "verdict_mix", "intent_mix", "senders", "sender_domains",
                        "mailboxes", "urls", "url_hosts", "hashes", "findings",
                        "analyzed",
                    )
                },
                "member_assessments": [
                    {
                        "from": b.get("from"),
                        "mailbox": b.get("mailbox"),
                        "subject": b.get("subject"),
                        "verdict": b.get("verdict"),
                        "intent": b.get("nlu_intent"),
                        "ai_summary": b.get("ai_summary"),
                        "findings": b.get("findings"),
                        "urls": (b.get("iocs") or {}).get("urls"),
                        "thread_summary": b.get("thread_summary"),
                    }
                    for b in briefs
                    if b.get("ai_summary") or b.get("verdict")
                ][:12],
            },
            ensure_ascii=False,
            default=str,
        )
    )
    raw, model = _llm_json(_system_prompt(), user)
    if not raw:
        return heuristic
    try:
        parsed = _CampaignLLM(**raw)
    except ValidationError:
        return heuristic
    insight = dict(heuristic.get("insight") or {})
    if parsed.lure:
        insight["lure"] = parsed.lure
    if parsed.patterns:
        insight["patterns"] = parsed.patterns
    if parsed.tactics:
        insight["tactics"] = parsed.tactics
    if parsed.targeting:
        insight["targeting"] = parsed.targeting
    if parsed.infrastructure:
        insight["infrastructure"] = parsed.infrastructure
    if parsed.why_clustered:
        insight["why_clustered"] = parsed.why_clustered
    if parsed.false_positive_risk:
        insight["false_positive_risk"] = parsed.false_positive_risk
    if parsed.false_positive_note:
        insight["false_positive_note"] = parsed.false_positive_note
    if parsed.analyst_actions:
        insight["analyst_actions"] = parsed.analyst_actions
    return {
        "ai_title": (parsed.title or heuristic.get("ai_title") or "")[:180],
        "ai_summary": parsed.summary or heuristic.get("ai_summary") or "",
        "attack_class": parsed.attack_class or heuristic.get("attack_class") or "unknown",
        "confidence": parsed.confidence or heuristic.get("confidence") or "medium",
        "insight": insight,
        "facts_hash": insight_hash(campaign, briefs),
        "ai_provider": "glm",
        "ai_model": model,
        "ai_assessed_at": time.time(),
    }


def assess_campaign(campaign: dict, store=None, *, use_llm: bool = True) -> dict:
    briefs = load_member_briefs(campaign, store)
    heuristic = heuristic_insight(campaign, briefs)
    if use_llm:
        return assess_with_llm(campaign, briefs, heuristic)
    return heuristic


def stale(stored: dict | None, campaign: dict, briefs: list[dict]) -> bool:
    if not stored or not (stored.get("ai_summary") or ""):
        return True
    if (stored.get("facts_hash") or "") != insight_hash(campaign, briefs):
        return True
    age = time.time() - float(stored.get("ai_assessed_at") or 0)
    return age > _STALE_SECONDS


def fill_heuristic(store, campaigns: list[dict] | None = None) -> int:
    """Write heuristic insight for clusters missing a narrative. Cheap; no LLM."""
    rows = campaigns if campaigns is not None else store.list_campaigns(limit=80)
    written = 0
    for cam in rows:
        if cam.get("ai_summary") and cam.get("ai_provider"):
            briefs = load_member_briefs(cam, store)
            if not stale(cam, cam, briefs):
                continue
        try:
            out = assess_campaign(cam, store, use_llm=False)
            store.put_insight(cam["id"], out)
            cam.update(_public_insight(out))
            written += 1
        except Exception:
            _log.debug("campaign heuristic fill failed for %s", cam.get("id"), exc_info=True)
    return written


_llm_available: bool | None = None


def _has_llm() -> bool:
    global _llm_available
    if _llm_available is not None:
        return _llm_available
    try:
        from workers.pipeline import content_ai as ca
        provider = ca.get_default_provider()
    except Exception:
        _llm_available = False
        return False
    _llm_available = not isinstance(provider, ca.HeuristicProvider)
    return _llm_available


def enrich_with_llm(store, *, limit: int = 4) -> dict:
    """Refresh stale clusters with the content LLM. Call after recompute."""
    if not _has_llm():
        return {"assessed": 0, "llm": 0, "pending": 0}
    rows = store.list_campaigns(limit=80)
    todo = []
    for cam in rows:
        briefs = load_member_briefs(cam, store)
        if stale(cam, cam, briefs) or (cam.get("ai_provider") or "") == "heuristic":
            # Prefer flagged clusters that already have per-email AI.
            analyzed = sum(1 for b in briefs if b.get("ai_summary"))
            todo.append((-(int(cam.get("flagged") or 0)), -analyzed, cam, briefs))
        if len(todo) >= 40:
            break
    todo.sort(key=lambda t: (t[0], t[1]))
    assessed = 0
    llm_n = 0
    for _, __, cam, _briefs in todo[: max(1, int(limit))]:
        try:
            out = assess_campaign(cam, store, use_llm=True)
            store.put_insight(cam["id"], out)
            assessed += 1
            if (out.get("ai_provider") or "") != "heuristic":
                llm_n += 1
        except Exception:
            _log.debug("campaign LLM enrich failed for %s", cam.get("id"), exc_info=True)
    return {"assessed": assessed, "llm": llm_n, "pending": len(todo)}


def _public_insight(out: dict) -> dict:
    return {
        "ai_title": out.get("ai_title") or "",
        "ai_summary": out.get("ai_summary") or "",
        "attack_class": out.get("attack_class") or "",
        "confidence": out.get("confidence") or "",
        "insight": out.get("insight") or {},
        "facts_hash": out.get("facts_hash") or "",
        "ai_provider": out.get("ai_provider") or "",
        "ai_model": out.get("ai_model") or "",
        "ai_assessed_at": float(out.get("ai_assessed_at") or 0),
    }
