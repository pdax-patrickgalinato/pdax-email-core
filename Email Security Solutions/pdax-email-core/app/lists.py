"""Shared list loaders for freemail / impersonation brands / trusted platforms.

rules/*.txt and trusted_platforms.yaml are the tunable source of truth —
pipeline stages (headers, sender, deception) all read through here so we do
not maintain three copies of FREEMAIL or brand tokens.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

_RULES_DIR = Path(__file__).resolve().parents[1] / "rules"

# Fallback if rules/freemail_domains.txt is missing (dev/partial checkout).
_DEFAULT_FREEMAIL = frozenset({
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me",
    "protonmail.com", "aol.com", "icloud.com", "yandex.com", "mail.com",
    "live.com", "msn.com", "me.com", "mac.com",
})


def _lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


@lru_cache(maxsize=1)
def freemail_domains() -> frozenset:
    rows = _lines(_RULES_DIR / "freemail_domains.txt")
    return frozenset(d.lower().rstrip(".") for d in rows) if rows else _DEFAULT_FREEMAIL


@lru_cache(maxsize=1)
def impersonation_brands() -> list[str]:
    return [b.lower() for b in _lines(_RULES_DIR / "impersonation_brands.txt")]


@lru_cache(maxsize=1)
def trusted_platforms() -> list[dict]:
    path = _RULES_DIR / "trusted_platforms.yaml"
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    platforms = data.get("platforms") or []
    out = []
    for p in platforms:
        if not isinstance(p, dict) or not p.get("id"):
            continue
        out.append({
            "id": str(p["id"]),
            "from_domains": [d.lower().rstrip(".") for d in (p.get("from_domains") or [])],
            "link_hosts": [h.lower().rstrip(".") for h in (p.get("link_hosts") or [])],
            "owned_brand_tokens": [t.lower().strip() for t in (p.get("owned_brand_tokens") or [])],
        })
    return out


def clear_lists_cache() -> None:
    """Test helper — reload after monkeypatching rules paths (if ever needed)."""
    freemail_domains.cache_clear()
    impersonation_brands.cache_clear()
    trusted_platforms.cache_clear()
