"""Admin-only Slack alerting config — GET/PUT /api/slack-config.

Reads and writes rules/slack_config.yaml. Changes are picked up by
hold_consumer.py on the next email without a restart.
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

_CONFIG_FILE = Path(__file__).resolve().parents[2] / "rules" / "slack_config.yaml"
_VALID_THRESHOLDS = ("SUSPICIOUS", "MALICIOUS")


def _read_config() -> dict:
    try:
        if _CONFIG_FILE.is_file():
            data = yaml.safe_load(_CONFIG_FILE.read_text()) or {}
            return {
                "enabled": bool(data.get("enabled", False)),
                "webhook_url": str(data.get("webhook_url", "")),
                "threshold": str(data.get("threshold", "SUSPICIOUS")),
                "updated_by": str(data.get("updated_by", "system")),
                "updated_at": str(data.get("updated_at", "")),
            }
    except Exception:
        pass
    return {"enabled": False, "webhook_url": "", "threshold": "SUSPICIOUS",
            "updated_by": "system", "updated_at": ""}


def _write_config(enabled: bool, webhook_url: str, threshold: str, actor: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(
        f"# SEGS Slack alerting configuration — written by PUT /api/slack-config.\n"
        f"enabled: {str(enabled).lower()}\n"
        f"webhook_url: {webhook_url!r}\n"
        f"threshold: {threshold}\n"
        f"updated_by: {actor}\n"
        f"updated_at: \"{now}\"\n",
        encoding="utf-8",
    )


class SlackConfigUpdate(BaseModel):
    enabled: bool
    webhook_url: str = ""
    threshold: Literal["SUSPICIOUS", "MALICIOUS"] = "SUSPICIOUS"


@router.get("/slack-config")
def get_slack_config(user: User = Depends(require_role("admin"))):
    cfg = _read_config()
    # Mask webhook URL — show only last 6 chars for security
    url = cfg.get("webhook_url", "")
    cfg["webhook_url_masked"] = ("…" + url[-6:]) if len(url) > 6 else ("*" * len(url))
    return cfg


@router.put("/slack-config")
def set_slack_config(body: SlackConfigUpdate, user: User = Depends(require_role("admin"))):
    old = _read_config()
    url = body.webhook_url.strip()
    # If blank URL submitted, keep the existing one (UI masks it)
    if not url and old.get("webhook_url"):
        url = old["webhook_url"]
    _write_config(body.enabled, url, body.threshold, user.username)
    activity_log.record(
        "slack_config_change",
        actor=user.username,
        actor_role=user.role,
        detail=f"Slack alerting {'enabled' if body.enabled else 'disabled'}, threshold={body.threshold}",
        meta={"enabled": body.enabled, "threshold": body.threshold},
    )
    return {"enabled": body.enabled, "threshold": body.threshold, "updated_by": user.username}
