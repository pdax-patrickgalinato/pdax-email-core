"""Named detection rule matching — SEGS equivalent of Sublime Security's
'Matched Feed Rules'. Rules are defined in rules/detection_rules.yaml and
evaluated against the union of all stage red_flags after scoring.

Each matched rule surfaces in PipelineResult.matched_rules as:
  {"id": str, "name": str, "description": str, "severity": str, "tags": list}
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)
_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "detection_rules.yaml"
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_rules() -> list[dict]:
    """Load detection rules from YAML. Returns [] on file/parse errors."""
    try:
        import yaml
        data = yaml.safe_load(_RULES_PATH.read_text(encoding="utf-8"))
        return data.get("rules", []) if isinstance(data, dict) else []
    except Exception as exc:
        _log.warning("detection_rules: failed to load %s: %s", _RULES_PATH, exc)
        return []


def match_rules(all_flags: list[str], rules: Optional[list[dict]] = None) -> list[dict]:
    """Return matched detection rules, sorted critical → high → medium → low.

    all_flags: flat list of every red_flag emitted across all pipeline stages.
    rules: pre-loaded rule list (loads from disk if None).
    """
    if rules is None:
        rules = load_rules()

    flag_set = set(all_flags)
    matched: list[dict] = []

    for rule in rules:
        requires = rule.get("requires") or []
        requires_any = rule.get("requires_any") or []

        # All listed flags must be present.
        if requires and not all(_flag_matches(f, flag_set) for f in requires):
            continue
        # At least one listed flag must be present (if the list is non-empty).
        if requires_any and not any(_flag_matches(f, flag_set) for f in requires_any):
            continue

        matched.append({
            "id": rule.get("id", ""),
            "name": rule.get("name", ""),
            "description": rule.get("description", "").strip(),
            "severity": rule.get("severity", "medium"),
            "tags": rule.get("tags") or [],
        })

    matched.sort(key=lambda r: _SEVERITY_ORDER.get(r["severity"], 9))
    return matched


def _flag_matches(pattern: str, flag_set: set[str]) -> bool:
    """Check if a rule condition pattern matches any flag in the set.

    Exact match: 'first_time_sender' matches only that exact flag.
    Prefix match: 'behavioral_shared_shortener' matches
                  'behavioral_shared_shortener:bit.ly:3'.
    """
    if pattern in flag_set:
        return True
    # Prefix match — pattern without ':' suffix matches any flag that starts with it.
    prefix = pattern if pattern.endswith(":") else pattern + ":"
    return any(f.startswith(prefix) for f in flag_set)
