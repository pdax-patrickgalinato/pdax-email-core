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


def _load_list_file(path: Path) -> list[dict]:
    """Load an allowlist/blocklist YAML; return entries list (empty on error)."""
    try:
        if not path.is_file():
            return []
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return [e for e in (data.get("entries") or []) if isinstance(e, dict)]
    except Exception:
        return []


def load_allowlist() -> list[dict]:
    """Return current allowlist entries (not cached — reads fresh per call)."""
    return _load_list_file(_RULES_DIR / "allowlist.yaml")


def load_blocklist() -> list[dict]:
    """Return current blocklist entries (not cached — reads fresh per call)."""
    return _load_list_file(_RULES_DIR / "blocklist.yaml")


def _save_list_file(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    import re
    name = path.stem  # "allowlist" or "blocklist"
    header = (
        f"# SEGS {name.capitalize()} — written by the dashboard API.\n"
        f"# Changes take effect on the next email processed (no restart needed).\n"
    )
    lines = [header, "entries:"]
    for e in entries:
        lines.append(f"  - address: {e['address']!r}" if "address" in e
                     else f"  - domain: {e['domain']!r}")
        if e.get("note"):
            lines.append(f"    note: {e['note']!r}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def clear_lists_cache() -> None:
    """Test helper — reload after monkeypatching rules paths (if ever needed)."""
    freemail_domains.cache_clear()
    impersonation_brands.cache_clear()
    trusted_platforms.cache_clear()
