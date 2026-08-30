"""Advisory sender-identity risk — volume, reciprocity, and LLM narrative.

Does not write a message verdict. Typical-behavior CLEAN/SUSPICIOUS/MALICIOUS
on the profile stays deterministic (sender_identity.assessment_of). This module
answers a different question: given send/receive volume and the rest of the
6-month picture, is this *identity* risky to trust?

The heuristic is always computed (Abnormal / Proofpoint AISS / Defender-style
signals: reciprocity, burst, targeting, request-class, infra, hostility).
When SEG_CONTENT_PROVIDER is a real model, a worker asks it to write the
analyst narrative over the same facts.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Optional

from pydantic import BaseModel, Field, ValidationError, field_validator

from workers.pipeline.correlation import BehavioralCorrelationStore, PROFILE_MIN_N
from workers.pipeline.request_class import HIGH_RISK_CLASSES, request_label
from backend.stores.sender_identity import is_protected_sender, is_role_mailbox, sender_lane

_log = logging.getLogger(__name__)

_RISKS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_STALE_SECONDS = 6 * 3600


class _SenderRiskLLM(BaseModel):
    risk: str
    score: float = 0.0
    posture: str = "unknown"
    confidence: str = "medium"
    summary: str = ""
    factors: list[dict] = Field(default_factory=list)

    @field_validator("risk", mode="before")
    @classmethod
    def _risk(cls, v):
        raw = str(v or "LOW").strip().upper()
        aliases = {"CLEAN": "LOW", "SAFE": "LOW", "MALICIOUS": "CRITICAL",
                   "SUSPICIOUS": "HIGH", "MODERATE": "MEDIUM"}
        raw = aliases.get(raw, raw)
        return raw if raw in _RISKS else "MEDIUM"

    @field_validator("score", mode="before")
    @classmethod
    def _score(cls, v):
        try:
            n = float(v)
        except (TypeError, ValueError):
            n = 0.0
        return max(0.0, min(n, 100.0))

    @field_validator("confidence", mode="before")
    @classmethod
    def _conf(cls, v):
        raw = str(v or "medium").strip().lower()
        return raw if raw in ("low", "medium", "high") else "medium"

    @field_validator("summary", mode="before")
    @classmethod
    def _sum(cls, v):
        return str(v or "").strip()[:4000]

    @field_validator("factors", mode="before")
    @classmethod
    def _fac(cls, v):
        if not isinstance(v, list):
            return []
        out = []
        for item in v[:12]:
            if not isinstance(item, dict):
                continue
            out.append({
                "code": str(item.get("code") or "factor")[:48],
                "direction": str(item.get("direction") or "context")[:24],
                "detail": str(item.get("detail") or "")[:400],
            })
        return out


def _band(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _factor(code: str, direction: str, detail: str) -> dict:
    return {"code": code, "direction": direction, "detail": detail}


def build_facts(store: BehavioralCorrelationStore, sender: str, listed: dict | None = None) -> dict:
    """Compact fact pack for heuristic + LLM. Numbers only — no verdict claim."""
    addr = (sender or "").strip().lower()
    listed = listed or {}
    vol = store.volume_for(addr)
    sent = int(vol.get("sent_count") or 0) or int(listed.get("sent_count") or listed.get("copies") or 0)
    received = int(vol.get("received_count") or listed.get("received_count") or 0)
    emails = int(listed.get("copies") or sent)
    total = sent + received
    reciprocity = round(received / total, 3) if total else 0.0
    burst = store.volume_burst(addr)
    hours = store.volume_hours(addr)
    night = sum(int(h.get("count") or 0) for h in hours if int(h.get("hour_utc") or 0) >= 22 or int(h.get("hour_utc") or 0) <= 5)
    day_n = sum(int(h.get("count") or 0) for h in hours) or 1
    lane = listed.get("lane") or sender_lane(addr)
    req = store.request_mix_for(addr)
    high_req = sum(int(r["count"]) for r in req if r.get("value") in HIGH_RISK_CLASSES)
    first = float(vol.get("first_seen") or listed.get("last_seen") or 0)
    last = float(vol.get("last_seen") or listed.get("last_seen") or 0)
    span_days = round((last - first) / 86400, 1) if first and last and last > first else 0.0
    prof = listed if listed.get("n") is not None else store.profile_for(addr)
    return {
        "sender": addr,
        "lane": lane,
        "internal": is_protected_sender(addr),
        "role_mailbox": is_role_mailbox(addr),
        "sent_count": sent,
        "received_count": received,
        "outbound_count": int(vol.get("outbound_count") or listed.get("outbound_count") or 0),
        "mailbox_targets": int(vol.get("mailbox_targets") or listed.get("mailbox_targets") or 0),
        "copies": emails,
        "reciprocity": reciprocity,
        "one_way_external": lane == "external" and sent > 0 and received == 0,
        "monitored_mailbox": received > 0 or lane in ("internal", "role"),
        "first_seen": first,
        "last_seen": last,
        "span_days": span_days,
        "days_active": int(burst.get("days_active") or 0),
        "max_day": int(burst.get("max_day") or 0),
        "avg_day": float(burst.get("avg_day") or 0),
        "night_hour_share": round(night / day_n, 3),
        "verdicts": dict(listed.get("verdicts") or {}),
        "identity_verdicts": dict(listed.get("identity_verdicts") or {}),
        "hostile_rate": float(listed.get("hostile_rate") or 0),
        "typical_assessment": listed.get("assessment") or "CLEAN",
        "baseline_n": int(prof.get("n") or 0),
        "baseline_ready": int(prof.get("n") or 0) >= PROFILE_MIN_N,
        "majority_role": prof.get("majority_role") or "",
        "vpn_rate": float(prof.get("vpn_rate") or 0),
        "countries": [c.get("value") for c in (prof.get("countries") or [])[:6] if c.get("value")],
        "asns": [a.get("value") for a in (prof.get("asns") or [])[:6] if a.get("value")],
        "spf": [s.get("value") for s in (prof.get("spf") or [])[:3] if s.get("value")],
        "dkim": [s.get("value") for s in (prof.get("dkim") or [])[:3] if s.get("value")],
        "request_mix": req,
        "high_risk_requests": high_req,
        "coverage_note": (
            "Path A polls INBOX only. received_count is mail delivered to this "
            "address when it is a monitored mailbox. sent_count is mail this "
            "From originated that we scanned. External senders with received=0 "
            "is expected — we do not see their inbox."
        ),
    }


def facts_hash(facts: dict) -> str:
    blob = json.dumps(
        {k: facts.get(k) for k in (
            "sent_count", "received_count", "mailbox_targets", "copies",
            "hostile_rate", "typical_assessment", "high_risk_requests",
            "max_day", "majority_role", "vpn_rate", "verdicts",
        )},
        sort_keys=True, default=str,
    )
    return hashlib.sha256(blob.encode()).hexdigest()[:32]


def assess_heuristic(facts: dict) -> dict:
    """Deterministic comprehensive risk from send/receive + profile facts."""
    score = 12.0
    factors: list[dict] = []
    sent = int(facts.get("sent_count") or 0)
    received = int(facts.get("received_count") or 0)
    emails = int(facts.get("copies") or sent)
    lane = facts.get("lane") or "external"
    hostile = float(facts.get("hostile_rate") or 0)
    verdicts = facts.get("verdicts") or {}
    mal = int(verdicts.get("MALICIOUS") or 0)
    sus = int(verdicts.get("SUSPICIOUS") or 0)
    targets = int(facts.get("mailbox_targets") or 0)
    ready = bool(facts.get("baseline_ready"))
    role = (facts.get("majority_role") or "").lower()
    vpn = float(facts.get("vpn_rate") or 0)
    high_req = int(facts.get("high_risk_requests") or 0)
    max_day = int(facts.get("max_day") or 0)
    avg_day = float(facts.get("avg_day") or 0)
    night = float(facts.get("night_hour_share") or 0)
    typical = facts.get("typical_assessment") or "CLEAN"

    if sent <= 0 and emails <= 0:
        factors.append(_factor("no_volume", "context",
            "No scanned emails yet — too little history to judge this identity."))
        return _pack("LOW", 8, "unknown", "low", factors, facts, "heuristic")

    if sent < 3:
        score += 16
        factors.append(_factor("new_contact", "increases_risk",
            f"Only {sent or emails} originated message(s) in the 6-month window — "
            "thin history, closer to first-contact risk than an established partner."))
    elif sent >= 20 and float(facts.get("span_days") or 0) >= 14 and hostile < 0.05:
        score -= 18
        factors.append(_factor("established_volume", "decreases_risk",
            f"{sent} originated messages over {facts.get('span_days')} days with "
            "low hostility — looks like a repeating correspondent, not a one-shot lure."))

    if facts.get("one_way_external"):
        if high_req:
            score += 18
            factors.append(_factor("one_way_high_risk_ask", "increases_risk",
                f"External identity has sent {sent} to the org and received 0 replies "
                f"we can see, while also making {high_req} payment/access/account-control "
                "asks — the BEC-shaped one-way vendor pattern."))
        else:
            score += 6
            factors.append(_factor("one_way_external", "context",
                f"External sender: {sent} sent, 0 received. For addresses we do not "
                "monitor that is normal; it is not a conversation we can prove."))
    elif lane in ("internal", "role") and received:
        score -= 8
        factors.append(_factor("mailbox_reciprocity", "decreases_risk",
            f"Monitored mailbox: sent {sent}, received {received} "
            f"(reciprocity {facts.get('reciprocity')}). Two-way traffic is the "
            "healthy pattern for an org identity."))

    if targets >= 8:
        score += 16
        factors.append(_factor("spray_targets", "increases_risk",
            f"Reached {targets} distinct mailboxes — spray / catch-all targeting "
            "rather than a single ongoing thread."))
    elif targets == 1 and sent >= 3 and (hostile >= 0.2 or high_req):
        score += 10
        factors.append(_factor("spear_target", "increases_risk",
            "Repeated mail to a single mailbox with hostility or a high-risk ask "
            "— spear-phish / VIP-focus shape."))
    elif targets:
        factors.append(_factor("mailbox_targets", "context",
            f"Delivered into {targets} monitored mailbox(es)."))

    if hostile:
        bump = min(36.0, hostile * 50)
        score += bump
        factors.append(_factor("hostile_share", "increases_risk",
            f"{round(hostile * 100, 1)}% of scored emails are SUSPICIOUS or MALICIOUS "
            f"({sus} suspicious, {mal} malicious). Typical-behavior label is {typical}."))
    if mal >= 3:
        score += 12
        factors.append(_factor("repeat_malicious", "increases_risk",
            f"{mal} malicious emails — this identity has repeated confirmed-bad mail."))

    if vpn >= 0.5 and lane == "external":
        score += 12
        factors.append(_factor("vpn_majority", "increases_risk",
            f"{round(vpn * 100)}% of CLEAN/LOW hops came from VPN/proxy — unusual "
            "for a stable vendor ESP path."))
    if role in ("cloud_hosting", "vpn_proxy") and lane == "external" and not ready:
        score += 8
        factors.append(_factor("hosting_origin", "increases_risk",
            f"Usual network role is {role} and the CLEAN/LOW baseline is not ready."))
    if role == "esp" and ready and hostile < 0.05:
        score -= 12
        factors.append(_factor("esp_baseline", "decreases_risk",
            "Ready ESP baseline with low hostility — infrastructure looks like a "
            "legitimate mail platform, not a rotating VPS."))

    auth = " ".join(str(x) for x in (facts.get("spf") or []) + (facts.get("dkim") or []))
    if any(tok in auth for tok in ("fail", "permerror", "none")):
        score += 8
        factors.append(_factor("auth_weak", "increases_risk",
            f"Auth mix includes weak SPF/DKIM results ({auth or 'unknown'})."))

    if avg_day and max_day >= 8 and max_day >= 5 * avg_day:
        score += 12
        factors.append(_factor("volume_burst", "increases_risk",
            f"Peak day {max_day} vs average {avg_day:.1f} — a burst, not a steady partner."))
    if night >= 0.7 and sent >= 5 and lane == "external" and role not in ("esp",):
        score += 6
        factors.append(_factor("off_hours", "increases_risk",
            f"{round(night * 100)}% of originated mail sits in 22:00–05:00 UTC, "
            "and this is not an ESP-shaped sender."))

    if facts.get("role_mailbox") and typical == "CLEAN":
        score -= 10
        factors.append(_factor("role_mailbox", "decreases_risk",
            "Role mailbox. Typical-behavior stays CLEAN unless identity-eligible "
            "emails themselves are hostile (quoted lures do not paint it)."))
    if typical == "MALICIOUS":
        score = max(score, 78)
        factors.append(_factor("typical_malicious", "increases_risk",
            "Deterministic typical-behavior is already MALICIOUS — AI risk cannot "
            "talk that down below CRITICAL without new evidence."))
    elif typical == "SUSPICIOUS":
        score = max(score, 42)

    countries = facts.get("countries") or []
    if countries:
        factors.append(_factor("geo", "context",
            "Usual countries: " + ", ".join(str(c) for c in countries[:4]) + "."))

    req = facts.get("request_mix") or []
    if req:
        bits = [f"{request_label(r.get('value'))} ×{r.get('count')}" for r in req[:5]]
        factors.append(_factor("request_mix", "context" if not high_req else "increases_risk",
            "Request classes: " + "; ".join(bits) + "."))

    factors.append(_factor("volume", "context",
        f"Sent {sent}, received {received}, {emails} scored emails, "
        f"{int(facts.get('days_active') or 0)} active days. "
        + str(facts.get("coverage_note") or "")))

    score = max(0.0, min(score, 100.0))
    risk = _band(score)
    if typical == "MALICIOUS":
        risk = "CRITICAL"
    posture = _posture(facts, risk)
    conf = "high" if (ready or sent >= 8) else ("medium" if sent >= 3 else "low")
    return _pack(risk, score, posture, conf, factors, facts, "heuristic")


def _posture(facts: dict, risk: str) -> str:
    if facts.get("role_mailbox"):
        return "role_mailbox"
    if facts.get("internal") or facts.get("lane") == "internal":
        return "internal_mailbox"
    if risk in ("CRITICAL", "HIGH") and int(facts.get("mailbox_targets") or 0) >= 8:
        return "spray_campaign"
    if risk in ("CRITICAL", "HIGH") and float(facts.get("hostile_rate") or 0) >= 0.5:
        return "likely_compromised"
    if facts.get("one_way_external") and int(facts.get("high_risk_requests") or 0):
        return "vendor_impersonation"
    if facts.get("one_way_external"):
        return "one_way_external"
    if int(facts.get("sent_count") or 0) < 3:
        return "new_contact"
    return "established_partner"


def _narrative(risk: str, posture: str, facts: dict, factors: list[dict]) -> str:
    sent = int(facts.get("sent_count") or 0)
    received = int(facts.get("received_count") or 0)
    addr = facts.get("sender") or "this sender"
    head = {
        "CRITICAL": f"{addr} looks risky as an identity — treat it as hostile until the mix changes.",
        "HIGH": f"{addr} is a high-risk sender: volume and context do not look like a safe partner.",
        "MEDIUM": f"{addr} is not a clean established partner. Some signals deserve an analyst look.",
        "LOW": f"{addr} looks like a low-risk correspondent on the evidence we have.",
    }.get(risk, f"{addr} sender-risk is {risk}.")
    vol = (
        f"Observed volume in the last 6 months: {sent} email(s) sent (From this address) "
        f"and {received} email(s) received into this address as a monitored mailbox."
    )
    if facts.get("one_way_external"):
        vol += (
            " Received=0 is expected for external From addresses we do not poll; "
            "it still means we cannot prove a two-way relationship."
        )
    elif facts.get("monitored_mailbox"):
        vol += " This is a mailbox we actually see both directions on (within INBOX poll limits)."
    inc = [f["detail"] for f in factors if f.get("direction") == "increases_risk"][:4]
    dec = [f["detail"] for f in factors if f.get("direction") == "decreases_risk"][:3]
    body = " ".join(inc) if inc else "No single strong risk-increasing signal dominated."
    ease = (" Mitigating: " + " ".join(dec)) if dec else ""
    close = (
        f" Posture: {posture.replace('_', ' ')}. This is advisory sender-identity risk — "
        "it does not change any message verdict."
    )
    return " ".join([head, vol, body + ease, close]).strip()


def _pack(risk, score, posture, confidence, factors, facts, provider, *,
          summary="", model_id="") -> dict:
    text = summary or _narrative(risk, posture, facts, factors)
    return {
        "risk": risk,
        "score": round(float(score), 1),
        "posture": posture,
        "confidence": confidence,
        "summary": text,
        "factors": factors,
        "provider": provider,
        "model_id": model_id or "",
        "facts_hash": facts_hash(facts),
        "assessed_at": time.time(),
        "sent_count": int(facts.get("sent_count") or 0),
        "received_count": int(facts.get("received_count") or 0),
        "mailbox_targets": int(facts.get("mailbox_targets") or 0),
        "reciprocity": float(facts.get("reciprocity") or 0),
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
        _log.warning("sender_risk LLM failed: %s", last)
    return {}, ""


def _system_prompt() -> str:
    return (
        "You are a senior email-security analyst at a financial-services SOC. "
        "You judge whether a *sender identity* is risky to trust, using send/receive "
        "volume, reciprocity, targeting, infrastructure, authentication, request class, "
        "and hostility mix. You never set or override a message verdict — that belongs "
        "to the scoring engine. Modern systems (Abnormal, Proofpoint AISS, Microsoft "
        "Defender) treat one-way external volume plus a payment/access ask as BEC-shaped; "
        "spray across many mailboxes as campaign-shaped; ready ESP baselines with low "
        "hostility as partner-shaped. Path A Gmail is INBOX-only: received_count is only "
        "populated when this address is a mailbox we poll; external received=0 is normal.\n"
        "Reply with JSON only:\n"
        '{"risk":"LOW|MEDIUM|HIGH|CRITICAL","score":0-100,'
        '"posture":"established_partner|new_contact|one_way_external|internal_mailbox|'
        'role_mailbox|likely_compromised|vendor_impersonation|spray_campaign",'
        '"confidence":"low|medium|high","summary":"4-8 sentence analyst narrative",'
        '"factors":[{"code":"snake_case","direction":"increases_risk|decreases_risk|context",'
        '"detail":"one sentence"}]}\n'
        "Ground every claim in the facts. Do not invent mail we did not observe."
    )


def assess_with_llm(facts: dict, heuristic: dict) -> dict:
    user = (
        "Heuristic draft (you may refine risk/score if the facts support it, "
        "but do not ignore hostility or typical_assessment=MALICIOUS):\n"
        + json.dumps(
            {k: heuristic.get(k) for k in ("risk", "score", "posture", "summary", "factors")},
            ensure_ascii=False,
        )
        + "\n\nObserved facts:\n"
        + json.dumps(facts, ensure_ascii=False, default=str)
    )
    raw, model = _llm_json(_system_prompt(), user)
    if not raw:
        return heuristic
    try:
        parsed = _SenderRiskLLM(**raw)
    except ValidationError:
        return heuristic
    factors = parsed.factors or heuristic.get("factors") or []
    if parsed.risk == "LOW" and (facts.get("typical_assessment") == "MALICIOUS"):
        parsed.risk = "CRITICAL"
        parsed.score = max(parsed.score, 78)
    summary = parsed.summary or heuristic.get("summary") or ""
    return _pack(
        parsed.risk, parsed.score, parsed.posture or heuristic.get("posture") or "",
        parsed.confidence, factors, facts, "glm",
        summary=summary, model_id=model,
    )


def assess_sender(store: BehavioralCorrelationStore, sender: str,
                  listed: dict | None = None, *, use_llm: bool = True) -> dict:
    facts = build_facts(store, sender, listed)
    heuristic = assess_heuristic(facts)
    if use_llm:
        return assess_with_llm(facts, heuristic)
    return heuristic


def stale(stored: Optional[dict], facts: dict) -> bool:
    if not stored:
        return True
    if (stored.get("facts_hash") or "") != facts_hash(facts):
        return True
    age = time.time() - float(stored.get("assessed_at") or 0)
    return age > _STALE_SECONDS


def ensure_assessed(store: BehavioralCorrelationStore, sender: str,
                    listed: dict | None = None, *, use_llm: bool = False) -> dict:
    """Always returns a risk payload. LLM only if use_llm and facts went stale."""
    facts = build_facts(store, sender, listed)
    stored = store.get_sender_risk(sender)
    if stored and not stale(stored, facts) and stored.get("summary"):
        stored["sent_count"] = int(facts.get("sent_count") or 0)
        stored["received_count"] = int(facts.get("received_count") or 0)
        stored["mailbox_targets"] = int(facts.get("mailbox_targets") or 0)
        stored["reciprocity"] = float(facts.get("reciprocity") or 0)
        return stored
    out = assess_sender(store, sender, listed, use_llm=use_llm)
    store.put_sender_risk(sender, out)
    return out


def risk_cycle(store: BehavioralCorrelationStore, *, limit: int = 5,
               use_llm: bool = True) -> dict:
    """Refresh the oldest/stale sender-risk rows (API worker)."""
    rows = store.list_profiles(limit=400)
    todo: list[dict] = []
    for row in rows:
        addr = row.get("sender") or ""
        if not addr:
            continue
        facts = build_facts(store, addr, row)
        stored = store.get_sender_risk(addr)
        if stale(stored, facts):
            todo.append(row)
        if len(todo) >= max(1, int(limit)):
            break
    assessed = 0
    llm_n = 0
    for row in todo:
        out = assess_sender(store, row["sender"], row, use_llm=use_llm)
        store.put_sender_risk(row["sender"], out)
        assessed += 1
        if (out.get("provider") or "") != "heuristic":
            llm_n += 1
    return {"assessed": assessed, "llm": llm_n, "pending": len(todo)}
