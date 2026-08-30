"""Unit tests for named detection-rule matching."""
from __future__ import annotations

from workers.pipeline.detection_rules import match_rules


def _rule(**kwargs):
    base = {
        "id": "r1",
        "name": "Rule",
        "description": "desc",
        "severity": "medium",
        "tags": [],
        "requires": [],
        "requires_any": [],
    }
    base.update(kwargs)
    return base


def test_requires_all_flags():
    rules = [_rule(id="bec", requires=["bec_pattern", "vip_name_spoof:CEO"])]
    assert match_rules(["bec_pattern"], rules) == []
    hit = match_rules(["bec_pattern", "vip_name_spoof:CEO"], rules)
    assert [r["id"] for r in hit] == ["bec"]


def test_requires_any():
    rules = [_rule(id="nlu", requires_any=["nlu_intent:bec", "bec_pattern"])]
    assert match_rules(["urgency_language"], rules) == []
    assert match_rules(["nlu_intent:bec"], rules)[0]["id"] == "nlu"


def test_prefix_match_on_intel_flags():
    rules = [_rule(id="intel", requires=["intel_domain"])]
    hit = match_rules(["intel_domain:evil.example"], rules)
    assert hit[0]["id"] == "intel"


def test_severity_sort_critical_first():
    rules = [
        _rule(id="low", severity="low", requires=["a"]),
        _rule(id="crit", severity="critical", requires=["a"]),
        _rule(id="high", severity="high", requires=["a"]),
    ]
    ids = [r["id"] for r in match_rules(["a"], rules)]
    assert ids == ["crit", "high", "low"]
