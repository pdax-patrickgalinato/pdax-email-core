"""Policy read/write API — Phase 11 of the dashboard-overhaul plan.

GET is a plain read of rules/policy.yaml, re-shaped to match what
dashboard/build_policy_data.py used to export (so the frontend only needs a
fetch() swap, not a new response shape).

PUT does NOT use yaml.safe_dump() for the write — a full re-dump would
silently delete the file's header comment block (lines 1-19), which
documents real operator-facing semantics (suppress-not-block). Instead this
does a targeted line-scan rewrite that only touches the one category's
`enabled:` line, leaving every comment and the rest of the file byte-for-byte
untouched.

app/pipeline/policy.py itself stays read-only (matches its own docstring
framing) — this router is the only place in the codebase with a rules/
write path, keeping the detection core free of I/O side effects.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import activity_log
from ..auth_store import User
from ..deps import require_role
from app.pipeline import policy as policy_mod

router = APIRouter(prefix="/api")

_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _ROOT / "rules" / "policy.yaml"

_DISPLAY_NAMES = {
    "advanced_spam_protection": "Advanced Spam Protection",
    "malware_scanning": "Malware Scanning",
    "file_blocking": "File Blocking",
    "web_reputation": "Web Reputation",
    "virtual_analyzer": "Virtual Analyzer",
    "correlated_intelligence": "Correlated Intelligence",
}


class PolicyUpdate(BaseModel):
    category: str
    enabled: bool


def _read_policy_cfg() -> dict:
    if not _POLICY_PATH.is_file():
        return {}
    return yaml.safe_load(_POLICY_PATH.read_text()) or {}


def _policy_response(raw_cfg: dict) -> dict:
    categories = [
        {"key": key, "label": _DISPLAY_NAMES.get(key, key), "enabled": policy_mod.is_enabled(raw_cfg, key)}
        for key in policy_mod.ALL_CATEGORIES
    ]
    category_flag_match = {
        cat: {"exact": sorted(match["exact"]), "prefix": sorted(match["prefix"])}
        for cat, match in policy_mod.CATEGORY_FLAG_MATCH.items()
    }
    return {
        "categories": categories,
        "categoryFlagMatch": category_flag_match,
        "allCategories": list(policy_mod.ALL_CATEGORIES),
    }


@router.get("/policy")
def get_policy(_=Depends(require_role("admin", "analyst", "viewer"))):
    return _policy_response(_read_policy_cfg())


def _rewrite_category_enabled(text: str, category: str, enabled: bool) -> str:
    """Flips only `<category>:\\n    enabled: <bool>` — a targeted rewrite,
    not a full yaml.safe_dump(), so every comment survives untouched."""
    pattern = re.compile(
        r"(^  " + re.escape(category) + r":\n    enabled: )(true|false)(\s*(?:#.*)?$)",
        re.MULTILINE,
    )
    new_value = "true" if enabled else "false"
    new_text, n = pattern.subn(lambda m: m.group(1) + new_value + m.group(3), text)
    if n == 0:
        raise ValueError(f"category {category!r} not found in {_POLICY_PATH}")
    return new_text


@router.put("/policy")
def put_policy(body: PolicyUpdate, admin: User = Depends(require_role("admin"))):
    if body.category not in policy_mod.ALL_CATEGORIES:
        raise HTTPException(status_code=422, detail=f"unknown category: {body.category!r}")
    if not _POLICY_PATH.is_file():
        raise HTTPException(status_code=500, detail="rules/policy.yaml is missing")

    original = _POLICY_PATH.read_text()
    try:
        updated = _rewrite_category_enabled(original, body.category, body.enabled)
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Validate the rewrite actually parses to the intended value before
    # writing — never leave the file in a state where the regex "succeeded"
    # syntactically but produced invalid/wrong YAML.
    parsed = yaml.safe_load(updated)
    if policy_mod.is_enabled(parsed, body.category) != body.enabled:
        raise HTTPException(status_code=500, detail="policy rewrite validation failed — no changes written")

    _POLICY_PATH.write_text(updated)
    state = "enabled" if body.enabled else "disabled"
    activity_log.record(
        "policy_update", actor=admin.username, actor_role=admin.role,
        detail=f"{body.category} {state}",
        meta={"category": body.category, "enabled": body.enabled},
    )
    return _policy_response(parsed)
