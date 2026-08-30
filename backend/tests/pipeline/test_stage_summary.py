"""Compact stage snapshots for the assessment-flow graph."""
from backend.models import StageResult, StageStatus
from workers.pipeline.stage_summary import compact_stages, stages_for_feed


def test_compact_stages_keeps_scores_flags_and_ai_extras():
    result = type("R", (), {"stages": [
        StageResult(stage="headers", status=StageStatus.OK, sub_score=12.0,
                    red_flags=["spf_fail"], latency_ms=4),
        StageResult(stage="content_ai", status=StageStatus.OK, sub_score=40.0,
                    red_flags=["urgency_language"], facts={
                        "provider": "glm", "summary": "Asks for a password reset.",
                        "nlu_intent": "credential_theft", "nlu_confidence": 0.9,
                        "score_capped": True, "degraded": False,
                    }, latency_ms=1800),
    ]})()
    snap = compact_stages(result)
    assert snap["headers"]["score"] == 12.0
    assert snap["headers"]["flags"] == ["spf_fail"]
    assert snap["headers"]["latency_ms"] == 4
    assert snap["content_ai"]["provider"] == "glm"
    assert snap["content_ai"]["nlu_intent"] == "credential_theft"
    assert snap["content_ai"]["score_capped"] is True
    assert "degraded" not in snap["content_ai"]


def test_compact_stages_keeps_campaign_extras():
    result = type("R", (), {"stages": [
        StageResult(stage="intel", status=StageStatus.OK, sub_score=0,
                    facts={"campaign_hits": ["campaign_hash:cam-abc:3"],
                           "campaign_details": [{"id": "cam-abc", "kind": "hash"}]}),
    ]})()
    snap = compact_stages(result)
    assert snap["intel"]["campaign_hits"] == ["campaign_hash:cam-abc:3"]
    assert snap["intel"]["campaign_details"][0]["id"] == "cam-abc"
    assert compact_stages(type("R", (), {})()) == {}
    assert compact_stages(None) == {}


def test_stages_for_feed_normalizes_snake_and_camel():
    ui = stages_for_feed({
        "urls": {"status": "ok", "score": 33, "flags": ["url_lookalike_domain"],
                 "model_id": "x", "nlu_intent": "none"},
    })
    assert ui["urls"]["score"] == 33.0
    assert ui["urls"]["modelId"] == "x"
    assert ui["urls"]["nluIntent"] == "none"
    ui2 = stages_for_feed({"origin_ip": {"status": "ok", "score": 0, "lat": 14.55, "lon": 121.03, "country": "PH"}})
    assert ui2["origin_ip"]["lat"] == 14.55
    assert ui2["origin_ip"]["lon"] == 121.03
    ui3 = stages_for_feed({
        "intel": {"status": "ok", "score": 18, "request_class": "payment_request",
                  "request_summary": "first time", "trusted_channel": True,
                  "campaign_hits": ["campaign_hash:cam-abc:3"],
                  "campaign_details": [{"id": "cam-abc", "kind": "hash", "members": 3}]},
    })
    assert ui3["intel"]["requestClass"] == "payment_request"
    assert ui3["intel"]["requestSummary"] == "first time"
    assert ui3["intel"]["trustedChannel"] is True
    assert ui3["intel"]["campaignHits"] == ["campaign_hash:cam-abc:3"]
    assert ui3["intel"]["campaignDetails"][0]["id"] == "cam-abc"
    assert stages_for_feed(None) == {}
    assert stages_for_feed("nope") == {}
