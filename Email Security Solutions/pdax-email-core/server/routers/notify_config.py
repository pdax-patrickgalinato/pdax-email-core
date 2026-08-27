"""Admin-only quarantine notification config — GET/PUT /api/notify-config.

Reads and writes rules/notify_config.yaml. The SMTP password is write-only:
the GET response never returns it (masked to asterisks). The PUT endpoint
accepts an empty smtp_pass to preserve the existing stored value, so the UI
can update other fields without requiring the admin to re-enter the password.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

import yaml
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import activity_log
from ..auth_store import User
from ..deps import require_role

router = APIRouter(prefix="/api")

_CONFIG_FILE = Path(__file__).resolve().parents[2] / "rules" / "notify_config.yaml"
_VALID_THRESHOLDS = ("SUSPICIOUS", "MALICIOUS")


def _read_config() -> dict:
    try:
        if _CONFIG_FILE.is_file():
            data = yaml.safe_load(_CONFIG_FILE.read_text()) or {}
            return {
                "enabled": bool(data.get("enabled", False)),
                "smtp_host": str(data.get("smtp_host", "")),
                "smtp_port": int(data.get("smtp_port", 587)),
                "smtp_user": str(data.get("smtp_user", "")),
                "from_addr": str(data.get("from_addr", "segs-alerts@pdax.ph")),
                "threshold": str(data.get("threshold", "SUSPICIOUS")),
                "updated_by": str(data.get("updated_by", "system")),
                "updated_at": str(data.get("updated_at", "")),
            }
    except Exception:
        pass
    return {
        "enabled": False, "smtp_host": "", "smtp_port": 587,
        "smtp_user": "", "from_addr": "segs-alerts@pdax.ph",
        "threshold": "SUSPICIOUS", "updated_by": "system", "updated_at": "",
    }


def _write_config(cfg: dict, actor: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(
        "# SEGS quarantine receiver notification — written by PUT /api/notify-config.\n"
        "# SMTP password is read from SEGS_NOTIFY_SMTP_PASS env var (never stored here).\n"
        f"enabled: {str(cfg['enabled']).lower()}\n"
        f"smtp_host: {cfg['smtp_host']!r}\n"
        f"smtp_port: {cfg['smtp_port']}\n"
        f"smtp_user: {cfg['smtp_user']!r}\n"
        f"from_addr: {cfg['from_addr']!r}\n"
        f"threshold: {cfg['threshold']}\n"
        f'updated_by: "{actor}"\n'
        f'updated_at: "{now}"\n',
        encoding="utf-8",
    )


class NotifyConfigUpdate(BaseModel):
    enabled: bool
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    from_addr: str = "segs-alerts@pdax.ph"
    threshold: Literal["SUSPICIOUS", "MALICIOUS"] = "SUSPICIOUS"


@router.get("/notify-config")
def get_notify_config(user: User = Depends(require_role("admin"))):
    cfg = _read_config()
    # SMTP password is env-only — never returned; show presence indicator
    import os
    cfg["smtp_pass_set"] = bool(os.environ.get("SEGS_NOTIFY_SMTP_PASS", "").strip())
    return cfg


@router.put("/notify-config")
def set_notify_config(body: NotifyConfigUpdate, user: User = Depends(require_role("admin"))):
    cfg = {
        "enabled": body.enabled,
        "smtp_host": body.smtp_host.strip(),
        "smtp_port": body.smtp_port,
        "smtp_user": body.smtp_user.strip(),
        "from_addr": body.from_addr.strip() or "segs-alerts@pdax.ph",
        "threshold": body.threshold,
    }
    _write_config(cfg, user.username)
    activity_log.record(
        "notify_config_change",
        actor=user.username,
        actor_role=user.role,
        detail=f"Quarantine notification {'enabled' if body.enabled else 'disabled'}, "
               f"host={body.smtp_host or '(none)'}, threshold={body.threshold}",
        meta={"enabled": body.enabled, "threshold": body.threshold},
    )
    return {"enabled": body.enabled, "threshold": body.threshold, "updated_by": user.username}
