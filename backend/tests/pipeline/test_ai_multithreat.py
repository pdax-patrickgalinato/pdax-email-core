"""Tests for the multi-threat AI changes:

  * threat classification (nlu_intent) surfaces on PipelineResult.threat_class
  * the AI decision acts as an upward-only verdict floor (Change 4)
  * the gateway consumer's Tier-2 deep analysis is gated on verdict (Change 2)

All deterministic — no network, no real LLM. The content stage is driven by a
tiny fake provider (for pipeline-level tests) or by hand-built StageResults
(for the verdict-floor unit tests).
"""
import os
from email.mime.text import MIMEText
from pathlib import Path

from backend.models import PipelineResult, StageResult, Verdict
from workers.pipeline import runner, verdict as verdict_mod

# --- helpers -----------------------------------------------------------------

class _FakeProvider:
    """Returns a chosen content score + threat classification, like a real
    provider's (score, findings, facts) contract."""
    def __init__(self, score=0.0, intent="none", conf=0.0):
        self.score, self.intent, self.conf = score, intent, conf

    def analyze(self, subject, body, context):
        # Report as an LLM provider ("glm") so the verdict floor — which is
        # gated to genuine LLM decisions — applies in these tests.
        findings, facts = [], {"provider": "glm"}
        if self.intent and self.intent != "none":
            findings.append(f"nlu_intent:{self.intent}")
            facts["nlu_intent"] = self.intent
            facts["nlu_confidence"] = self.conf
        return self.score, findings, facts

def _benign_eml():
    msg = MIMEText("Hello, please find the notes from today's meeting attached.")
    msg["From"] = "colleague@pdax.ph"
    msg["To"] = "me@pdax.ph"
    msg["Subject"] = "Meeting notes"
    msg["Message-ID"] = "<benign@pdax.ph>"
    return msg.as_bytes()

def _cfg():
    weights_cfg, *_ = runner.load_config()
    return weights_cfg["weights"], weights_cfg["thresholds"]

# --- threat_class surfacing --------------------------------------------------

def test_threat_class_surfaces_on_result():
    result = run_pipeline_fake(intent="ransomware", conf=0.95, score=0.0)
    assert result.threat_class == "ransomware"
    assert result.threat_confidence >= 0.9

def run_pipeline_fake(intent, conf, score):
    return runner.run_pipeline(
        _benign_eml(), source="file",
        content_provider=_FakeProvider(score=score, intent=intent, conf=conf),
        correlation_store=False,
    )

# --- verdict floor (Change 4) ------------------------------------------------

def test_ai_floor_raises_clean_to_suspicious():
    # Benign email, zero content score → would be CLEAN, but a high-confidence
    # ransomware classification floors it up to SUSPICIOUS (quarantine).
    os.environ.pop("SEG_AI_VERDICT_FLOOR_CONF", None)
    result = run_pipeline_fake(intent="ransomware", conf=0.9, score=0.0)
    assert result.verdict == Verdict.SUSPICIOUS
    assert any(r.startswith("ai_verdict_floor:ransomware:") for r in result.reasons)

def test_ai_floor_not_applied_below_confidence():
    result = run_pipeline_fake(intent="ransomware", conf=0.5, score=0.0)
    assert result.verdict in (Verdict.CLEAN, Verdict.LOW)
    assert not any(r.startswith("ai_verdict_floor:") for r in result.reasons)

def test_ai_floor_never_lowers_a_malicious_hard_override():
    # Hard override (threat-intel hit) → MALICIOUS; a low-confidence, low-score
    # content classification must NOT pull it down. Floor is upward-only.
    weights, thresholds = _cfg()
    result = PipelineResult(stages=[
        StageResult(stage="intel", red_flags=["intel_domain:evil.example"]),
        StageResult(stage="content_ai", sub_score=0.0,
                    facts={"nlu_intent": "reconnaissance", "nlu_confidence": 0.99}),
    ])
    verdict_mod.score_and_verdict(result, weights, thresholds, policy_cfg=None)
    assert result.verdict == Verdict.MALICIOUS
    assert result.hard_override == "threat_intel_hit"
    # classification is still recorded even on the hard-override path
    assert result.threat_class == "reconnaissance"

def test_floor_gated_to_llm_provider():
    # Same high-confidence ransomware classification: an LLM provider floors the
    # verdict up to SUSPICIOUS; the offline heuristic provider does not.
    weights, thresholds = _cfg()

    def _mk(provider):
        return PipelineResult(stages=[
            StageResult(stage="content_ai", sub_score=0.0,
                        facts={"provider": provider, "nlu_intent": "ransomware",
                               "nlu_confidence": 0.95}),
        ])

    r_llm = _mk("glm")
    verdict_mod.score_and_verdict(r_llm, weights, thresholds)
    r_heur = _mk("heuristic")
    verdict_mod.score_and_verdict(r_heur, weights, thresholds)
    assert r_llm.verdict == Verdict.SUSPICIOUS
    assert r_heur.verdict == Verdict.CLEAN
    # Both still record the classification for analyst visibility.
    assert r_llm.threat_class == "ransomware" and r_heur.threat_class == "ransomware"

def test_ai_floor_env_override_disables_by_raising_threshold():
    os.environ["SEG_AI_VERDICT_FLOOR_CONF"] = "0.99"
    try:
        result = run_pipeline_fake(intent="bec", conf=0.9, score=0.0)
        assert result.verdict in (Verdict.CLEAN, Verdict.LOW)
    finally:
        os.environ.pop("SEG_AI_VERDICT_FLOOR_CONF", None)


def test_ai_floor_skips_soft_intents_like_credential_theft():
    # GLM often tags authenticated Google/support mail as credential_theft at
    # high confidence. That must not floor CLEAN mail up to SUSPICIOUS.
    os.environ.pop("SEG_AI_VERDICT_FLOOR_CONF", None)
    result = run_pipeline_fake(intent="credential_theft", conf=0.95, score=0.0)
    assert result.verdict in (Verdict.CLEAN, Verdict.LOW)
    assert not any(r.startswith("ai_verdict_floor:") for r in result.reasons)
    assert result.threat_class == "credential_theft"


# --- Tier-2 deep analysis gating (Change 2) ----------------------------------

def _load_hold_consumer():
    from workers.pipeline import deep_analysis
    return deep_analysis

def test_deep_analysis_skipped_for_clean():
    hc = _load_hold_consumer()
    r = PipelineResult(verdict=Verdict.CLEAN)
    hc.maybe_deep_analyze(b"raw bytes", "x.eml", r)
    assert r.deep_analysis is None

def test_deep_analysis_runs_for_flagged():
    # Mock the agent so no real LLM call is made (there may be a
    # credentials.json in the repo root that would trigger a live call).
    hc = _load_hold_consumer()
    import cli.eml_analysis_agent as agent
    orig_analyze, orig_resolve = agent.analyze_eml_bytes, agent.resolve_glm_credentials_path
    agent.analyze_eml_bytes = lambda raw, fn, credentials_path=None: {
        "markdown": "# deep report", "analysis": {"threat_assessment": {"risk_level": "HIGH"}},
        "playbook": ["isolate host"], "model": "fake-model"}
    agent.resolve_glm_credentials_path = lambda: Path(__file__)  # any existing file
    try:
        for v in (Verdict.SUSPICIOUS, Verdict.MALICIOUS):
            r = PipelineResult(verdict=v)
            hc.maybe_deep_analyze(b"raw bytes", "x.eml", r)
            assert r.deep_analysis is not None
            assert r.deep_analysis["status"] == "ok"
            assert r.deep_analysis["markdown"] == "# deep report"
    finally:
        agent.analyze_eml_bytes, agent.resolve_glm_credentials_path = orig_analyze, orig_resolve

def test_deep_analysis_unavailable_without_credentials():
    hc = _load_hold_consumer()
    import cli.eml_analysis_agent as agent
    orig_resolve = agent.resolve_glm_credentials_path
    agent.resolve_glm_credentials_path = lambda: Path("/nonexistent/creds.json")
    try:
        r = PipelineResult(verdict=Verdict.MALICIOUS)
        hc.maybe_deep_analyze(b"raw bytes", "x.eml", r)
        assert r.deep_analysis["status"] == "unavailable"
    finally:
        agent.resolve_glm_credentials_path = orig_resolve

