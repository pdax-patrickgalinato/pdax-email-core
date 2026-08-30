"""Stage 8 (IOC extraction) + Stage 9 (scoring engine / verdict).

Deterministic. The AI stage only ever contributes a weighted sub-score here;
it cannot set the verdict directly. Hard overrides handle the high-confidence
cases that should bypass weighting entirely."""
from __future__ import annotations

import re

from backend.models import IOCSet, PipelineResult, StageResult, Verdict
from backend.config import get_settings
from . import policy

# Minimum AI intent-confidence for the content stage's threat classification to
# floor the verdict up to SUSPICIOUS (see the end of score_and_verdict).
# Upward-only, so a fooled LLM can only over-quarantine, never wave a threat
# past the gate. Start high; tune down as trust in the classifier grows.
_AI_VERDICT_FLOOR_CONF_DEFAULT = 0.8

# The verdict floor is only driven by a genuine LLM's decision — not the
# offline regex HeuristicProvider (whose "confidence" is a fixed heuristic, not
# a calibrated judgment) nor the NullProvider. This keeps heuristic-only runs
# behaviourally unchanged and makes the floor mean "a real model decided this."
_AI_LLM_PROVIDERS = frozenset({"bedrock", "gemini", "glm", "ollama"})

# Live FPs were GLM labeling ordinary Google/JumpCloud/support mail as
# credential_theft / reconnaissance at ≥0.8 confidence, which used to floor
# CLEAN mail up to SUSPICIOUS. Restrict the floor to attack classes where a
# confident model call is worth the over-quarantine risk even without other
# stages lighting up.
_AI_FLOOR_INTENTS = frozenset({
    "ransomware", "extortion", "malware_delivery", "bec",
})

_URL_HOST = re.compile(r"^https?://([^/]+)", re.I)


def extract_iocs(pe, stages: list[StageResult]) -> IOCSet:
    ioc = IOCSet()
    if pe.from_addr:
        ioc.sender_emails.append(pe.from_addr)
    if pe.from_domain:
        ioc.domains.append(pe.from_domain)
    subj = pe.header("Subject")
    if subj:
        ioc.subjects.append(subj)

    # Return-Path / Reply-To / Message-ID domains — computed by the headers
    # stage but previously discarded here. These are pivotable on their own
    # (a spoofed From often shares infrastructure with its real Return-Path).
    headers_stage = next((s for s in stages if s.stage == "headers"), None)
    if headers_stage:
        for key in ("return_path_domain", "reply_to_domain", "message_id_domain"):
            d = headers_stage.facts.get(key)
            if d:
                ioc.domains.append(d)

    url_stage = next((s for s in stages if s.stage == "urls"), None)
    if url_stage:
        for rec in url_stage.facts.get("urls", []):
            if rec.get("url"):
                ioc.urls.append(rec["url"])
            if rec.get("ip"):
                ioc.ips.append(rec["ip"])
            elif rec.get("reg_domain"):
                ioc.domains.append(rec["reg_domain"])

    # Mail-transport metadata: public IPs from the Received chain, and any
    # "Authenticated sender" relay account — often the actually-compromised
    # or attacker-registered credential, distinct from the spoofed From.
    ioc.ips.extend(pe.originating_ips())
    ioc.authenticated_relay_senders.extend(pe.authenticated_relay_senders())

    att_stage = next((s for s in stages if s.stage == "attachments"), None)
    if att_stage:
        for a in att_stage.facts.get("attachments", []):
            if a.get("sha256"):
                ioc.hashes_sha256.append(a["sha256"])
        # URLs found inside a PDF/HTML attachment (app/attachment_forensics.py)
        # — pivotable the same way a URL in the email body is.
        ioc.urls.extend(att_stage.facts.get("embedded_urls", []))

    # dedupe
    ioc.sender_emails = sorted(set(ioc.sender_emails))
    ioc.domains = sorted(set(ioc.domains))
    ioc.ips = sorted(set(ioc.ips))
    ioc.urls = sorted(set(ioc.urls))
    ioc.hashes_sha256 = sorted(set(ioc.hashes_sha256))
    ioc.authenticated_relay_senders = sorted(set(ioc.authenticated_relay_senders))
    return ioc


def score_and_verdict(result: PipelineResult, weights: dict, thresholds: dict,
                      policy_cfg: dict = None, ai_floor_conf: float = None) -> None:
    result.thresholds = dict(thresholds)   # carried through so reports can show margin-to-next-verdict
    stage_by_name = {s.stage: s for s in result.stages}
    suppressed_all: list = []

    # Multi-threat classification from the AI content stage — recorded on the
    # result up front so it survives every return path below (including the
    # hard-override early returns), giving analysts the attack class the AI
    # assigned regardless of how the verdict was reached.
    content_stage = stage_by_name.get("content_ai")
    if content_stage and isinstance(content_stage.facts, dict):
        result.threat_class = content_stage.facts.get("nlu_intent") or "none"
        try:
            result.threat_confidence = float(content_stage.facts.get("nlu_confidence") or 0.0)
        except (TypeError, ValueError):
            result.threat_confidence = 0.0

    # --- hard overrides (bypass weighted scoring) -----------------------
    # Correlated Intelligence — only a real external hit (VirusTotal/
    # AbuseIPDB/LocalIOCClient, "intel_"-prefixed) is a hard override. A
    # correlation_seen_before hit (this pipeline's own verdict history,
    # workers/pipeline/correlation.py) is deliberately weighted-only — "PDAX
    # flagged this before" is lower-confidence than "known bad externally,"
    # so it's excluded here on purpose, not an oversight.
    intel = stage_by_name.get("intel")
    if (intel and any(f.startswith("intel_") for f in intel.red_flags)
            and policy.is_enabled(policy_cfg, "correlated_intelligence")):
        result.hard_override = "threat_intel_hit"
        result.verdict = Verdict.MALICIOUS
        result.composite_score = 100.0
        result.reasons = [f for f in intel.red_flags if f.startswith("intel_")]
        return

    # Web Reputation
    urls = stage_by_name.get("urls")
    atts = stage_by_name.get("attachments")
    if (urls and any(f.startswith("url_lookalike") for f in urls.red_flags)
            and policy.is_enabled(policy_cfg, "web_reputation")):
        result.hard_override = "url_lookalike_domain"
        result.verdict = Verdict.MALICIOUS
        result.composite_score = 95.0
        result.reasons = [f for f in urls.red_flags if f.startswith("url_lookalike")]
        return
    # Trusted-channel deception structure (TestFlight / service abuse):
    # authentic platform mail + foreign mega-brand lure. Auth always looks
    # clean; weighted scoring would under-weight this. Always on.
    dec = stage_by_name.get("deception")
    if dec:
        abuse_flags = [
            f for f in dec.red_flags
            if f == "deception_structure_service_abuse"
            or f.startswith("service_abuse_")
        ]
        if abuse_flags:
            # Prefer the composed flag name for hard_override when present.
            override = (
                "deception_structure_service_abuse"
                if "deception_structure_service_abuse" in abuse_flags
                else abuse_flags[0]
            )
            # Keep TestFlight-specific name when that is the only concrete alias
            # (analyst/tests already key on it).
            if "service_abuse_testflight_brand_lure" in abuse_flags:
                override = "service_abuse_testflight_brand_lure"
            result.hard_override = override
            result.verdict = Verdict.MALICIOUS
            result.composite_score = 95.0
            result.reasons = sorted(set(abuse_flags))
            return
    # File Blocking
    if (atts and any(f.startswith("banned_attachment") for f in atts.red_flags)
            and policy.is_enabled(policy_cfg, "file_blocking")):
        result.hard_override = "banned_attachment_type"
        result.verdict = Verdict.MALICIOUS
        result.composite_score = 95.0
        result.reasons = [f for f in atts.red_flags if f.startswith("banned_attachment")]
        return
    # File Blocking: a renamed/spoofed executable (declared extension doesn't
    # match the actual magic bytes, or a double-extension shape like
    # invoice.pdf.exe) is invisible to the banned_attachment override above
    # since that one only keys off the *declared* extension — this closes
    # that gap using app/attachment_forensics.py's findings (wired in by
    # attachments.py, Phase 1/2 of the TMES policy-parity plan).
    if (atts and any(f.startswith("spoofed_attachment_type") or f.startswith("double_extension_executable")
                      for f in atts.red_flags)
            and policy.is_enabled(policy_cfg, "file_blocking")):
        result.hard_override = "spoofed_or_double_extension_attachment"
        result.verdict = Verdict.MALICIOUS
        result.composite_score = 95.0
        result.reasons = [f for f in atts.red_flags
                          if f.startswith("spoofed_attachment_type") or f.startswith("double_extension_executable")]
        return

    # ClamAV confirmed malicious signature — treated the same as a VirusTotal
    # FOUND hit: deterministic, low false-positive rate, authoritative enough
    # to bypass weighted scoring unconditionally. Gated by virtual_analyzer
    # so teams can suppress it via policy.yaml if clamd is not yet deployed.
    if (atts and any(f == "sandbox_clam_found" for f in (atts.red_flags or []))
            and policy.is_enabled(policy_cfg, "virtual_analyzer")):
        result.hard_override = "clam_malicious"
        result.verdict = Verdict.MALICIOUS
        result.composite_score = 100.0
        result.reasons = [f for f in atts.red_flags if f == "sandbox_clam_found"]
        return

    # Sender lookalike and BEC+VIP impersonation are sender-identity/content
    # signals, not owned by any of the 6 TMES categories (see policy.py's
    # module docstring) — always on, never gated by policy_cfg.
    sender = stage_by_name.get("sender")
    if sender and any(f.startswith("lookalike_of") for f in sender.red_flags):
        result.hard_override = "sender_lookalike_domain"
        result.verdict = Verdict.MALICIOUS
        result.composite_score = 95.0
        result.reasons = [f for f in sender.red_flags if f.startswith("lookalike_of")]
        return

    content = stage_by_name.get("content_ai")
    # BEC combination: VIP-name impersonation + payment/gift-card language is a
    # high-loss pattern that averaging would bury. Treat co-occurrence as an
    # override, not a sum. (VASP-specific: BEC is the top financial-loss class.)
    if (sender and any(f.startswith("vip_name_spoof") for f in sender.red_flags)
            and content and "bec_pattern" in content.red_flags):
        result.hard_override = "bec_vip_impersonation"
        result.verdict = Verdict.MALICIOUS
        result.composite_score = 90.0
        result.reasons = [f for f in sender.red_flags if f.startswith("vip_name_spoof")] + ["bec_pattern"]
        return

    # --- weighted composite ---------------------------------------------
    # max-plus blend: dominant signal + damped contribution of the rest, so
    # several independent weak-to-moderate signals reinforce instead of being
    # averaged toward zero by the stages that (legitimately) found nothing.
    #
    # Policy gating here is stage-level, not per-flag: if every one of a
    # stage's red_flags belongs to a disabled category (i.e. nothing "ungated"
    # or enabled-category survives the filter), that stage contributes 0 —
    # same as if it had legitimately found nothing. A stage that mixes a
    # disabled-category flag with an active one (e.g. attachments.py mixing
    # file_blocking + malware_scanning findings) keeps its full sub_score
    # conservatively rather than guessing a per-flag point split; Phases 1/2
    # add real per-category score decomposition to attachments.py once there
    # are enough distinct malware_scanning findings to make that split
    # meaningful (see the TMES policy-parity plan).
    all_flags: list[str] = []
    contributions: list[float] = []
    for name, w in weights.items():
        st = stage_by_name.get(name)
        if not st:
            continue
        active, suppressed = policy.filter_flags(st.red_flags, policy_cfg)
        suppressed_all.extend(suppressed)
        if st.red_flags and not active:
            continue   # everything this stage found belongs to a disabled category
        contributions.append((st.sub_score / 100.0) * (w / max(weights.values())) * 100.0)
        all_flags.extend(active)

    contributions.sort(reverse=True)
    if contributions:
        dominant = contributions[0]
        rest = sum(contributions[1:]) * 0.5          # damped reinforcement
        composite = round(min(dominant + rest, 100.0), 1)
    else:
        composite = 0.0
    result.composite_score = composite
    # Suppressed-by-disabled-category flags stay visible (tagged) rather than
    # silently vanishing — an analyst reading the report should be able to
    # see what a disabled policy category *would* have caught. See
    # backend/policy/detection/policy.yaml and workers/pipeline/policy.py.
    result.reasons = sorted(set(all_flags)) + sorted(
        f"policy_suppressed:{f}" for f in set(suppressed_all))

    if composite >= thresholds["malicious"]:
        result.verdict = Verdict.MALICIOUS
    elif composite >= thresholds["suspicious"]:
        result.verdict = Verdict.SUSPICIOUS
    elif composite >= thresholds["low"]:
        result.verdict = Verdict.LOW
    else:
        result.verdict = Verdict.CLEAN

    # AI decision as an upward-only verdict floor: a high-confidence threat
    # classification from the content stage guarantees at least SUSPICIOUS
    # (quarantine), even when the weighted math landed lower. This makes the
    # AI's *decision* (its classification, not just its number) a direct factor
    # in the final verdict — but strictly upward: it never lowers a verdict and
    # never reaches MALICIOUS/reject on the model's word alone, so a fooled LLM
    # can only over-quarantine, never let a threat through. Hard overrides
    # returned earlier and are unaffected.
    _content_provider = (content_stage.facts.get("provider")
                         if content_stage and isinstance(content_stage.facts, dict) else None)
    if (result.threat_class and result.threat_class != "none"
            and _content_provider in _AI_LLM_PROVIDERS):
        # Precedence: env override > backend/policy/detection/weights.yaml (ai_floor_conf) > default.
        try:
            env_floor = get_settings().ai_verdict_floor_conf
            if env_floor is not None:
                floor_conf = float(env_floor)
            elif ai_floor_conf is not None:
                floor_conf = float(ai_floor_conf)
            else:
                floor_conf = _AI_VERDICT_FLOOR_CONF_DEFAULT
        except (TypeError, ValueError):
            floor_conf = _AI_VERDICT_FLOOR_CONF_DEFAULT
        if (result.threat_class in _AI_FLOOR_INTENTS
                and result.threat_confidence >= floor_conf
                and result.verdict in (Verdict.CLEAN, Verdict.LOW)):
            result.verdict = Verdict.SUSPICIOUS
            result.reasons.append(
                f"ai_verdict_floor:{result.threat_class}:{result.threat_confidence:.2f}")

    # First-contact URL-only body: GLM (and humans) often treat a real brand
    # host as "no hostile intent." The shape itself is the tell — no ask, no
    # thread, new sender. Floor to SUSPICIOUS, never MALICIOUS.
    intel_flags = list((intel.red_flags if intel else None) or [])
    content_flags = list((content.red_flags if content else None) or [])
    if (
        "first_time_sender" in intel_flags
        and "minimal_body_with_link_only" in content_flags
        and result.verdict in (Verdict.CLEAN, Verdict.LOW)
    ):
        result.verdict = Verdict.SUSPICIOUS
        result.reasons.append("first_contact_link_only")
