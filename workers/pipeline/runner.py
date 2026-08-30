"""Pipeline orchestrator. Transport-agnostic: run_pipeline(raw, source=...) is
called by the CLI/eval harness (source='file') and by the Gmail AI worker
when joined static facts are missing. Live Gmail copies normally go through
parallel workers, then content AI only. Identical detection libraries.
"""
from __future__ import annotations

import yaml

from backend.config import get_settings
from backend.models import PipelineResult, StageResult, StageStatus, Verdict, Disposition
from backend.parsed_email import ParsedEmail
from backend.paths import RULES_DETECTION, RULES_IDENTITY
from backend import disposition as disposition_mod
from backend.stores import lists as lists_mod
from backend.stores import feedback as feedback_mod
from . import headers, sender, urls, attachments, content_ai, intel, verdict, deception
from . import correlation as correlation_mod
from . import detection_rules as detection_rules_mod
from backend.stores.mail_fanout import envelope_context, stage_result as fanout_stage_result
from .origin_ip import enrich as origin_ip_enrich, stage_result as origin_ip_stage_result
from backend.stores.sender_identity import identity_skip_reason

_DETECTION_DIR = RULES_DETECTION
_IDENTITY_DIR = RULES_IDENTITY

# How far a composite score can sit from the LOW/MALICIOUS thresholds and
# still count as "confidently decided without the LLM" — see _should_escalate.
# Tune against the golden set once real production volume is known; this
# default has not been calibrated against real traffic.
_DEFAULT_TRIAGE_MARGIN = 15


def _should_escalate(result: PipelineResult, thresholds: dict, margin: float) -> bool:
    """Decides whether a case is worth spending an LLM call on.

    A hard override is already decisive — headers/sender/urls/attachments/
    intel plus the free HeuristicProvider settled it, an LLM opinion can't
    change a verdict that bypasses weighting entirely. Otherwise, escalate
    only if the composite score sits close enough to the LOW or MALICIOUS
    boundary that a deeper read could plausibly move it — comfortably-clean
    and comfortably-malicious cases don't need to spend a call confirming
    what the deterministic engine already resolved.
    """
    if result.hard_override:
        return False
    low = thresholds.get("low", 20)
    malicious = thresholds.get("malicious", 70)
    score = result.composite_score
    return (low - margin) <= score <= (malicious + margin)


def load_config():
    weights_cfg = yaml.safe_load((_DETECTION_DIR / "weights.yaml").read_text())
    protected = [l.strip() for l in (_IDENTITY_DIR / "protected_domains.txt").read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
    vips = [l.strip() for l in (_IDENTITY_DIR / "vip_names.txt").read_text().splitlines()
            if l.strip() and not l.startswith("#")]
    banned_ext = [l.strip() for l in (_DETECTION_DIR / "banned_extensions.txt").read_text().splitlines()
                  if l.strip() and not l.startswith("#")]
    policy_path = _DETECTION_DIR / "policy.yaml"
    policy_cfg = yaml.safe_load(policy_path.read_text()) if policy_path.is_file() else None
    return weights_cfg, protected, vips, policy_cfg, banned_ext


def run_pipeline(raw: bytes, source: str = "file",
                 content_provider=None, intel_client=None,
                 config=None, llm_triage=None, correlation_store=None,
                 extra_context=None) -> PipelineResult:
    weights_cfg, protected, vips, policy_cfg, banned_ext = config or load_config()
    weights = weights_cfg["weights"]
    thresholds = weights_cfg["thresholds"]
    severity_points = weights_cfg.get("forensics_severity_points")
    ai_floor_conf = (weights_cfg.get("ai_influence") or {}).get("verdict_floor_confidence")

    requested_provider = content_provider or content_ai.get_default_provider()
    ic = intel_client or intel.get_default_intel_client()
    # Local verdict-history correlation (Correlated Intelligence's standalone
    # half, see correlation.py) — off by default, same "gate behind a flag"
    # posture as SEG_LLM_TRIAGE/SEG_CONTENT_PROVIDER/SEG_INTEL_CLIENT: a
    # test run or an analyze-CLI one-off shouldn't silently write to a
    # persistent SQLite file on disk. Set SEG_CORRELATION_STORE=1 for
    # production/gateway use, where building real history across mail is the
    # point. An explicit correlation_store= argument always wins either way.
    if correlation_store is None:
        use_correlation = get_settings().correlation_store
        cs = correlation_mod.get_default_store() if use_correlation else None
    elif correlation_store is False:
        cs = None
    else:
        cs = correlation_store

    # Volume control for the paid/rate-limited AI providers: off by default so
    # the analyze CLI's existing interactive workflow (force a specific provider,
    # see what it says about *this* email) never silently skips the call you
    # asked for. Turn on for production/gateway volume, where most mail is
    # decisively clean or decisively bad from the free stages alone and
    # doesn't need an LLM call to confirm that.
    if llm_triage is None:
        llm_triage = get_settings().llm_triage
    triage_margin = float(get_settings().llm_triage_margin)
    is_llm_provider = isinstance(requested_provider,
                                  (content_ai.BedrockProvider, content_ai.GeminiProvider,
                                   content_ai.GLMProvider, content_ai.OllamaProvider))

    pe = ParsedEmail(raw)
    result = PipelineResult(
        message_id=pe.header("Message-ID"),
        source=source,
        subject=pe.header("Subject"),
        from_header=pe.header("From"),
        to_header=pe.header("To"),
    )

    def safe(stage_name, fn, *a, **kw) -> StageResult:
        try:
            return fn(*a, **kw)
        except Exception as e:            # a broken stage must not sink the pipeline
            return StageResult(stage=stage_name, status=StageStatus.ERROR,
                               red_flags=[f"stage_error:{type(e).__name__}"],
                               facts={"error": str(e)})

    h = safe("headers", headers.run, pe, protected)
    s = safe("sender", sender.run, pe, protected, vips, correlation_store=cs)
    u = safe("urls", urls.run, pe, protected)
    d = safe("deception", deception.run, pe, h.facts, u.facts)
    a = safe("attachments", attachments.run, pe, severity_points, banned_ext, policy_cfg)
    try:
        origin_facts = origin_ip_enrich(
            pe.originating_hop(),
            sender_domain=(pe.from_addr or "").split("@")[-1],
        )
    except Exception:
        origin_facts = {}
    mailbox = ""
    gmail_labels: list = []
    if isinstance(extra_context, dict):
        mailbox = str(extra_context.get("mailbox") or "")
        gmail_labels = list(extra_context.get("gmail_labels") or [])
    # Moved ahead of content_ai: intel doesn't depend on it, and the triage
    # decision below wants the full non-content picture (including any
    # threat-intel hard override) before deciding whether an LLM call earns
    # its cost. Origin facts feed per-sender profile comparison.
    i = safe(
        "intel", intel.run, pe, ic, u.facts, a.facts, cs,
        origin_facts=origin_facts, header_facts=h.facts, mailbox=mailbox,
    )

    # Enriched with the other stages' facts (Phase 7 of the TMES policy-parity
    # plan) so a real AI provider reasons over the same full picture a human
    # analyst reviewing the report would see — web reputation, malware
    # scanning/file blocking, correlated intelligence — not just subject/body
    # in isolation. content_ai.py's providers build a compact prompt summary
    # from this; see their _summarize_context().
    content_context = {"headers": h.facts, "sender": s.facts, "urls": u.facts,
                        "attachments": a.facts, "intel": i.facts,
                        "deception": d.facts,
                        "raw_headers": {"in_reply_to": pe.header("In-Reply-To"),
                                        "references": pe.header("References")}}
    if extra_context:
        content_context.update(extra_context)
    try:
        fb_match = feedback_mod.match_pe(pe)
    except Exception:
        fb_match = {}
    content_context["feedback"] = fb_match
    content_context["fanout"] = envelope_context(pe)
    if origin_facts:
        content_context["origin_ip"] = origin_facts
    if extra_context:
        extra = dict(extra_context)
        extra.pop("origin_ip", None)
        extra_fan = extra.pop("fanout", None)
        content_context.update(extra)
        if extra_fan:
            merged = dict(content_context.get("fanout") or {})
            merged.update(extra_fan)
            content_context["fanout"] = merged

    if llm_triage and is_llm_provider:
        # Pass 1: free, unlimited heuristic content pass. Cheap enough to
        # always run, and already sufficient for every hard override (the
        # regex BEC bank covers bec_pattern for the VIP+BEC combo the same
        # way the paid providers' prompt does).
        c = safe("content_ai", content_ai.run, pe, content_ai.HeuristicProvider(), content_context)
        result.stages = [h, s, u, d, a, c, i]
        result.iocs = verdict.extract_iocs(pe, result.stages)
        verdict.score_and_verdict(result, weights, thresholds, policy_cfg, ai_floor_conf)

        if _should_escalate(result, thresholds, triage_margin):
            # Pass 2: only the genuinely ambiguous middle spends a real call.
            c = safe("content_ai", content_ai.run, pe, requested_provider, content_context)
            c.facts["triage_escalated"] = True
        else:
            c.facts["triage_skipped_llm"] = True
    else:
        c = safe("content_ai", content_ai.run, pe, requested_provider, content_context)

    result.stages = [h, s, u, d, a, c, i]
    origin_st = origin_ip_stage_result(origin_facts)
    if origin_st:
        result.stages.append(origin_st)
    fanout_st = fanout_stage_result(content_context.get("fanout") or {})
    if fanout_st:
        result.stages.append(fanout_st)
        try:
            from backend.stores.gmail_coverage import offer as offer_coverage
            fan = content_context.get("fanout") or {}
            offer_coverage(
                list(fan.get("recipients") or [])
                + list(fan.get("envelope_recipients") or [])
                + list(fan.get("mailboxes") or []),
                source="fanout",
            )
        except Exception:
            pass
    result.iocs = verdict.extract_iocs(pe, result.stages)
    verdict.score_and_verdict(result, weights, thresholds, policy_cfg, ai_floor_conf)

    # Behavioral correlation write-back (see correlation.py) — called for ALL
    # emails so the behavioral baselines reflect the full mail flow, not only
    # already-caught mail. Wrapped defensively so a storage hiccup can never
    # affect the verdict already computed above.
    if cs is not None:
        try:
            url_shorteners = (u.facts or {}).get("shortener_domains", [])
            all_flags = [f for st in result.stages for f in (st.red_flags or [])]
            skip = identity_skip_reason(
                (pe.from_addr or "").lower(), mailbox, gmail_labels, all_flags,
                protected=protected,
            )
            cs.record_observation(
                sender=(pe.from_addr or "").lower(),
                originating_ips=pe.originating_ips(),
                shortener_domains=url_shorteners,
                message_id=result.message_id,
                verdict=result.verdict.value,
                identity=0 if skip else 1,
                identity_reason=skip,
            )
            snap = correlation_mod.this_copy_snapshot(
                origin_facts, h.facts, mailbox=mailbox,
                hour_utc=intel._date_hour_utc(pe),
            )
            cs.record_profile_observation(
                sender=(pe.from_addr or "").lower(),
                asn=snap.get("asn") or "",
                country=snap.get("country") or "",
                network_role=snap.get("network_role") or "",
                vpn=bool(snap.get("vpn")),
                spf=snap.get("spf") or "",
                dkim=snap.get("dkim") or "",
                mailbox=snap.get("mailbox") or "",
                hour_utc=snap.get("hour_utc"),
                verdict=result.verdict.value,
                message_id=result.message_id or "",
            )
            intel_facts = i.facts or {}
            req_cls = intel_facts.get("request_class") or ""
            if mailbox and req_cls:
                cs.record_recipient_request(
                    mailbox,
                    (pe.from_addr or "").lower(),
                    req_cls,
                    message_id=result.message_id or "",
                )
            try:
                att_n = len(((a.facts or {}).get("attachments") or []))
                if hasattr(cs, "record_copy_behavior"):
                    cs.record_copy_behavior(
                        sender=(pe.from_addr or "").lower(),
                        mailbox=mailbox,
                        message_id=result.message_id or "",
                        peers=correlation_mod.copy_peers(pe, mailbox),
                        direction=correlation_mod.copy_direction(
                            (pe.from_addr or "").lower(), mailbox, gmail_labels,
                        ),
                        request_class=req_cls,
                        hour_utc=snap.get("hour_utc"),
                        has_attachment=att_n > 0,
                        is_reply=correlation_mod.copy_is_reply(pe),
                        labels=gmail_labels,
                    )
            except Exception:
                pass
        except Exception:
            pass

    # Named detection rules — evaluated after final scoring so all stage flags
    # (including intel hits and behavioral signals) are available. Applies to
    # every pipeline path: EML upload, live feed, and gateway hold consumer.
    all_flags = [f for s in result.stages for f in (s.red_flags or [])]
    intel_facts = (i.facts or {}) if i is not None else {}
    for extra in (
        intel_facts.get("behavioral_hits") or [],
        intel_facts.get("campaign_hits") or [],
    ):
        all_flags.extend(extra)
    try:
        result.matched_rules = detection_rules_mod.match_rules(all_flags)
    except Exception:
        result.matched_rules = []

    # Post-verdict only: map CLEAN/LOW/SUSPICIOUS/MALICIOUS → gateway action.
    # Does not change the verdict; AI never writes disposition.
    disposition_mod.apply_disposition(result)

    # Allowlist / blocklist hard overrides — checked after scoring so audit log
    # retains the real risk score alongside the override reason.
    _apply_list_overrides(result, pe)
    try:
        feedback_mod.apply_learned_override(result, pe, fb_match)
    except Exception:
        pass

    return result


def _apply_list_overrides(result: PipelineResult, pe: "ParsedEmail") -> None:
    sender_addr = (pe.from_addr or "").lower().strip()
    sender_domain = sender_addr.split("@", 1)[-1] if "@" in sender_addr else ""

    def _matches(entry: dict) -> bool:
        if "address" in entry:
            return entry["address"].lower().strip() == sender_addr
        if "domain" in entry:
            d = entry["domain"].lower().strip().lstrip("@")
            return sender_domain == d or sender_domain.endswith("." + d)
        return False

    for entry in lists_mod.load_blocklist():
        if _matches(entry):
            result.hard_override = "blocklist"
            result.disposition = Disposition.QUARANTINE
            result.disposition_reason = f"Sender on blocklist: {entry.get('note') or entry.get('address') or entry.get('domain', '')}"
            return

    for entry in lists_mod.load_allowlist():
        if _matches(entry):
            result.hard_override = "allowlist"
            result.disposition = Disposition.DELIVER
            result.disposition_reason = f"Sender on allowlist: {entry.get('note') or entry.get('address') or entry.get('domain', '')}"
            return
