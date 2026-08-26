"""Admin-only enforcement mode toggle — GET/PUT /api/enforcement.

Reads and writes rules/enforcement_mode.yaml so the gateway's disposition
layer picks up the change on the next email without a process restart.
The detection and monitoring pipeline always runs regardless of mode;
only the blocking action is gated.

  shadow     — monitor-only: score, log, never block (safe for live testing)
  quarantine — hold SUSPICIOUS and MALICIOUS mail in spool/quarantine/
  reject     — hard-reject MALICIOUS (requires allow_reject_on_malicious in
               rules/disposition.yaml; downgraded to quarantine otherwise)
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import activity_log
from ..auth_store import User
from ..deps import require_role

router = APIRouter(prefix="/api")

_ENFORCE_FILE = Path(__file__).resolve().parents[2] / "rules" / "enforcement_mode.yaml"
_VALID_MODES = ("shadow", "quarantine", "reject")


def _read_mode() -> dict:
    try:
        if _ENFORCE_FILE.is_file():
            data = yaml.safe_load(_ENFORCE_FILE.read_text()) or {}
            return {
                "mode": data.get("mode", "shadow"),
                "updated_by": data.get("updated_by", "system"),
                "updated_at": data.get("updated_at", ""),
            }
    except Exception:
        pass
    return {"mode": "shadow", "updated_by": "system", "updated_at": ""}


def _write_mode(mode: str, actor: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    _ENFORCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _ENFORCE_FILE.write_text(
        f"# Runtime enforcement mode — written by PUT /api/enforcement (admin only).\n"
        f"# Values: shadow | quarantine | reject\n"
        f"mode: {mode}\n"
        f"updated_by: {actor}\n"
        f"updated_at: \"{now}\"\n",
        encoding="utf-8",
    )


class EnforcementUpdate(BaseModel):
    mode: str


@router.get("/enforcement")
def get_enforcement(user: User = Depends(require_role("admin"))):
    """Return current runtime enforcement mode."""
    return _read_mode()


@router.put("/enforcement")
def set_enforcement(body: EnforcementUpdate, user: User = Depends(require_role("admin"))):
    """Set enforcement mode. Detection and monitoring always run; only blocking changes."""
    mode = body.mode.strip().lower()
    if mode not in _VALID_MODES:
        raise HTTPException(
            status_code=422,
            detail=f"mode must be one of: {', '.join(_VALID_MODES)}",
        )
    old = _read_mode().get("mode", "shadow")
    _write_mode(mode, user.username)
    activity_log.record(
        "enforcement_mode_change",
        actor=user.username,
        actor_role=user.role,
        detail=f"Enforcement mode changed: {old} → {mode}",
        meta={"old_mode": old, "new_mode": mode},
    )
    return {"mode": mode, "previous": old, "updated_by": user.username}
