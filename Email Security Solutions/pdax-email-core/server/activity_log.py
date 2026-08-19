"""Append-only activity audit log for dashboard user / admin actions.

Complements gateway/spool/shadow_logs/shadow_enforcement.jsonl (pipeline
disposition decisions). This file records who did what in the SEGS console:
login/logout, user CRUD, password resets, quarantine actions, Analyze uploads,
policy toggles.

Storage: data/activity_audit.jsonl (gitignored via data/). Never raises into
request handlers — a logging failure must not break the primary action.
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_DEFAULT_PATH = Path(__file__).resolve().parent.parent / "data" / "activity_audit.jsonl"
_lock = threading.Lock()
_MAX_READ = 2000  # newest-first cap for API responses

# action -> (ui type for icon, human title prefix)
_ACTION_META = {
    "setup": ("accent", "First-run setup"),
    "login": ("good", "Signed in"),
    "login_failed": ("warning", "Failed sign-in"),
    "logout": ("good", "Signed out"),
    "user_create": ("accent", "User created"),
    "user_delete": ("serious", "User deleted"),
    "password_reset": ("accent", "Password reset"),
    "quarantine_release": ("good", "Quarantine release"),
    "quarantine_keep_blocked": ("critical", "Kept blocked"),
    "quarantine_reevaluate": ("warning", "Re-evaluated"),
    "quarantine_download": ("warning", "EML downloaded"),
    "analyze_eml": ("accent", "Deep analysis"),
    "policy_update": ("accent", "Policy changed"),
}


def _path(path: Optional[Path] = None) -> Path:
    return Path(path) if path else _DEFAULT_PATH


def record(
    action: str,
    *,
    actor: str = "",
    actor_role: str = "",
    detail: str = "",
    meta: Optional[dict] = None,
    path: Optional[Path] = None,
) -> None:
    """Append one activity event. Swallows I/O errors."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "ts_epoch": time.time(),
        "action": action,
        "actor": actor or "(anonymous)",
        "actor_role": actor_role or "",
        "detail": detail or "",
        "meta": meta or {},
    }
    try:
        p = _path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with _lock:
            with p.open("a", encoding="utf-8") as f:
                f.write(line)
    except Exception:
        pass


def list_entries(path: Optional[Path] = None, limit: int = _MAX_READ) -> list[dict]:
    """Newest-first activity events (raw JSONL rows)."""
    p = _path(path)
    if not p.is_file():
        return []
    rows: list[dict] = []
    try:
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue
    except Exception:
        return []
    rows.sort(key=lambda e: float(e.get("ts_epoch") or 0), reverse=True)
    return rows[: max(1, int(limit))]


def to_audit_ui(entry: dict) -> dict[str, Any]:
    """Shape an activity row for the dashboard Audit log page."""
    action = entry.get("action") or "activity"
    ui_type, title_base = _ACTION_META.get(action, ("accent", action.replace("_", " ").title()))
    actor = entry.get("actor") or "(anonymous)"
    role = entry.get("actor_role") or ""
    who = f"{actor}" + (f" ({role})" if role else "")
    detail_bits = [who]
    if entry.get("detail"):
        detail_bits.append(str(entry["detail"]))
    ts_ms = int(float(entry.get("ts_epoch") or time.time()) * 1000)
    return {
        "ts": ts_ms,
        "type": ui_type,
        "title": title_base,
        "detail": " — ".join(detail_bits),
        "wazuh": False,
        "kind": "activity",
        "action": action,
        "actor": actor,
        "tag": "Activity",
    }
