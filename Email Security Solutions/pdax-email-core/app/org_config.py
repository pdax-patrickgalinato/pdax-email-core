"""Organization identity loader — Phase 13 (white-labeling). Separate from
app/pipeline/runner.py::load_config() since org identity isn't a scoring
input the way weights.yaml/policy.yaml are; it's metadata consumed by
content_ai.py's system prompt and (server/) the dashboard's branding.
"""
from __future__ import annotations

from pathlib import Path

import yaml

_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
_ORG_PATH = _RULES_DIR / "org.yaml"

_DEFAULTS = {
    "display_name": "the organization",
    "regulator_context": "a regulated organization",
}


def load_org_config() -> dict:
    """Never raises — a missing/malformed rules/org.yaml degrades to
    generic placeholder text rather than breaking the content-AI providers
    that depend on this, same "never let a rules file typo take a stage
    down" posture as runner.py::load_config()'s severity_points fallback."""
    if not _ORG_PATH.is_file():
        return dict(_DEFAULTS)
    try:
        raw = yaml.safe_load(_ORG_PATH.read_text()) or {}
    except yaml.YAMLError:
        return dict(_DEFAULTS)
    org = raw.get("organization", {}) if isinstance(raw, dict) else {}
    return {
        "display_name": org.get("display_name", _DEFAULTS["display_name"]),
        "regulator_context": org.get("regulator_context") or _DEFAULTS["regulator_context"],
    }
