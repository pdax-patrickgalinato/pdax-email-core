"""Pipeline orchestrator. Transport-agnostic: run_pipeline(raw, source=...) is
called by the POC (source='gmail_api'), the gateway hold consumer
(source='smtp_hold'), and the CLI/eval harness (source='file'). Identical
detection logic across all three — this is why the POC code is not throwaway."""
from __future__ import annotations

import os
from pathlib import Path
import yaml

from ..models import PipelineResult, StageResult, StageStatus, Verdict
from ..parsed_email import ParsedEmail
from .. import disposition as disposition_mod
from . import headers, sender, urls, attachments, content_ai, intel, verdict
from . import correlation as correlation_mod

_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"

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
    weights_cfg = yaml.safe_load((_RULES_DIR / "weights.yaml").read_text())
    protected = [l.strip() for l in (_RULES_DIR / "protected_domains.txt").read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
    vips = [l.strip() for l in (_RULES_DIR / "vip_names.txt").read_text().splitlines()
            if l.strip() and not l.startswith("#")]
    banned_ext = [l.strip() for l in (_RULES_DIR / "banned_extensions.txt").read_text().splitlines()
                  if l.strip() and not l.startswith("#")]
    policy_path = _RULES_DIR / "policy.yaml"
    policy_cfg = yaml.safe_load(policy_path.read_text()) if policy_path.is_file() else None
    return weights_cfg, protected, vips, policy_cfg, banned_ext


def run_pipeline(raw: bytes, source: str = "file",
                 content_provider=None, intel_client=None,
                 config=None, llm_triage=None, correlation_store=None) -> PipelineResult:
    weights_cfg, protected, vips, policy_cfg, banned_ext = config or load_config()
    weights = weights_cfg["weights"]
    thresholds = weights_cfg["thresholds"]
    severity_points = weights_cfg.get("forensics_severity_points")

    requested_provider = content_provider or content_ai.get_default_provider()
    ic = intel_client or intel.get_default_intel_client()
    # Local verdict-history correlation (Correlated Intelligence's standalone
    # half, see correlation.py) — off by default, same "gate behind a flag"
    # posture as SEG_LLM_TRIAGE/SEG_CONTENT_PROVIDER/SEG_INTEL_CLIENT: a
    # test run or an analyze.py one-off shouldn't silently write to a
    # persistent SQLite file on disk. Set SEG_CORRELATION_STORE=1 for
    # production/gateway use, where building real history across mail is the
    # point. An explicit correlation_store= argument always wins either way.
    if correlation_store is None:
        use_correlation = os.environ.get("SEG_CORRELATION_STORE", "").strip().lower() in ("1", "true", "yes")
        cs = correlation_mod.get_default_store() if use_correlation else None
    elif correlation_store is False:
        cs = None
    else:
        cs = correlation_store

    # Volume control for the paid/rate-limited AI providers: off by default so
    # `analyze.py`'s existing interactive workflow (force a specific provider,
    # see what it says about *this* email) never silently skips the call you
    # asked for. Turn on for production/gateway volume, where most mail is
    # decisively clean or decisively bad from the free stages alone and
    # doesn't need an LLM call to confirm that.
    if llm_triage is None:
        llm_triage = os.environ.get("SEG_LLM_TRIAGE", "").strip().lower() in ("1", "true", "yes")
    triage_margin = float(os.environ.get("SEG_LLM_TRIAGE_MARGIN", _DEFAULT_TRIAGE_MARGIN))
    is_llm_provider = isinstance(requested_provider,
                                  (content_ai.BedrockProvider, content_ai.GeminiProvider,
                                   content_ai.GLMProvider, content_ai.OllamaProvider))

    pe = ParsedEmail(raw)
    result = PipelineResult(
        message_id=pe.header("Message-ID"),
        source=source,
        subject=pe.header("Subject"),
        from_header=pe.header("From"),
    )

    def safe(stage_name, fn, *a, **kw) -> StageResult:
        try:
            return fn(*a, **kw)
        except Exception as e:            # a broken stage must not sink the pipeline
            return StageResult(stage=stage_name, status=StageStatus.ERROR,
                               red_flags=[f"stage_error:{type(e).__name__}"],
                               facts={"error": str(e)})

    h = safe("headers", headers.run, pe)
    s = safe("sender", sender.run, pe, protected, vips)
    u = safe("urls", urls.run, pe, protected)
    a = safe("attachments", attachments.run, pe, severity_points, banned_ext, policy_cfg)
    # Moved ahead of content_ai: intel doesn't depend on it, and the triage
    # decision below wants the full non-content picture (including any
    # threat-intel hard override) before deciding whether an LLM call earns
    # its cost.
    i = safe("intel", intel.run, pe, ic, u.facts, a.facts, cs)

    # Enriched with the other stages' facts (Phase 7 of the TMES policy-parity
    # plan) so a real AI provider reasons over the same full picture a human
    # analyst reviewing the report would see — web reputation, malware
    # scanning/file blocking, correlated intelligence — not just subject/body
    # in isolation. content_ai.py's providers build a compact prompt summary
    # from this; see their _summarize_context().
    content_context = {"headers": h.facts, "sender": s.facts, "urls": u.facts,
                        "attachments": a.facts, "intel": i.facts,
                        "raw_headers": {"in_reply_to": pe.header("In-Reply-To"),
                                        "references": pe.header("References")}}

    if llm_triage and is_llm_provider:
        # Pass 1: free, unlimited heuristic content pass. Cheap enough to
        # always run, and already sufficient for every hard override (the
        # regex BEC bank covers bec_pattern for the VIP+BEC combo the same
        # way the paid providers' prompt does).
        c = safe("content_ai", content_ai.run, pe, content_ai.HeuristicProvider(), content_context)
        result.stages = [h, s, u, a, c, i]
        result.iocs = verdict.extract_iocs(pe, result.stages)
        verdict.score_and_verdict(result, weights, thresholds, policy_cfg)

        if _should_escalate(result, thresholds, triage_margin):
            # Pass 2: only the genuinely ambiguous middle spends a real call.
            c = safe("content_ai", content_ai.run, pe, requested_provider, content_context)
            c.facts["triage_escalated"] = True
        else:
            c.facts["triage_skipped_llm"] = True
    else:
        c = safe("content_ai", content_ai.run, pe, requested_provider, content_context)

    result.stages = [h, s, u, a, c, i]
    result.iocs = verdict.extract_iocs(pe, result.stages)
    verdict.score_and_verdict(result, weights, thresholds, policy_cfg)

    # Write path for local correlation (see correlation.py) — only after the
    # verdict is final, and only SUSPICIOUS/MALICIOUS (record.record() itself
    # also enforces this; checked here too to skip the call entirely on the
    # common CLEAN/LOW case). Wrapped defensively so a storage hiccup can
    # never affect the verdict already computed above.
    if cs is not None and result.verdict.value in ("SUSPICIOUS", "MALICIOUS"):
        try:
            cs.record(
                verdict=result.verdict.value, message_id=result.message_id,
                domains=result.iocs.domains, ips=result.iocs.ips,
                urls=result.iocs.urls, hashes=result.iocs.hashes_sha256,
                senders=result.iocs.sender_emails,
            )
        except Exception:
            pass   # correlation history is an enhancement, never load-bearing

    # Post-verdict only: map CLEAN/LOW/SUSPICIOUS/MALICIOUS → gateway action.
    # Does not change the verdict; AI never writes disposition.
    disposition_mod.apply_disposition(result)
    return result
