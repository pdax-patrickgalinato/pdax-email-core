"""Stage 8 (IOC extraction) + Stage 9 (scoring engine / verdict).

Deterministic. The AI stage only ever contributes a weighted sub-score here;
it cannot set the verdict directly. Hard overrides handle the high-confidence
cases that should bypass weighting entirely."""
from __future__ import annotations

import re

from ..models import IOCSet, PipelineResult, StageResult, Verdict
from . import policy

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
                      policy_cfg: dict = None) -> None:
    result.thresholds = dict(thresholds)   # carried through so reports can show margin-to-next-verdict
    stage_by_name = {s.stage: s for s in result.stages}
    suppressed_all: list = []

    # --- hard overrides (bypass weighted scoring) -----------------------
    # Correlated Intelligence — only a real external hit (VirusTotal/
    # AbuseIPDB/LocalIOCClient, "intel_"-prefixed) is a hard override. A
    # correlation_seen_before hit (this pipeline's own verdict history,
    # app/pipeline/correlation.py) is deliberately weighted-only — "PDAX
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
    # rules/policy.yaml and app/pipeline/policy.py.
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
