"""Admin-only JumpCloud SSO config — GET/PUT /api/sso-config.

Stores OIDC application values so the SOC can prepare a JumpCloud connection
from the console. Live enforcement still requires SEG_SSO_PROVIDER=alb_oidc
and the ALB authenticate-oidc action (see docs/jumpcloud-sso.md). The client
secret is write-only.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import activity_log
from ..auth_store import User
from ..deps import require_role
from backend.config import get_settings
from backend.paths import RULES_RUNTIME

router = APIRouter(prefix="/api")

_CONFIG_FILE = RULES_RUNTIME / "sso_config.yaml"

JUMPCLOUD_ISSUER = "https://oauth.id.jumpcloud.com"
JUMPCLOUD_AUTHORIZE = "https://oauth.id.jumpcloud.com/oauth2/v1/authorize"
JUMPCLOUD_TOKEN = "https://oauth.id.jumpcloud.com/oauth2/v1/token"
JUMPCLOUD_USERINFO = "https://oauth.id.jumpcloud.com/oauth2/v1/userinfo"
_REDIRECT_PATH = "/oauth2/idpresponse"
_VALID_ROLES = ("viewer", "analyst", "admin")


def _https_url(value: str, field: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise HTTPException(status_code=400, detail=f"{field} must be an https URL")
    return value.rstrip("/")


def _defaults() -> dict:
    return {
        "enabled": False,
        "provider": "jumpcloud",
        "issuer": JUMPCLOUD_ISSUER,
        "authorization_endpoint": JUMPCLOUD_AUTHORIZE,
        "token_endpoint": JUMPCLOUD_TOKEN,
        "userinfo_endpoint": JUMPCLOUD_USERINFO,
        "client_id": "",
        "client_secret": "",
        "allowed_domains": "pdax.ph",
        "default_role": "viewer",
        "updated_by": "system",
        "updated_at": "",
    }


def _read_config() -> dict:
    cfg = _defaults()
    try:
        if _CONFIG_FILE.is_file():
            import yaml

            data = yaml.safe_load(_CONFIG_FILE.read_text()) or {}
            if isinstance(data, dict):
                for key in cfg:
                    if key in data and data[key] is not None:
                        cfg[key] = data[key]
                cfg["enabled"] = bool(cfg.get("enabled"))
                cfg["provider"] = "jumpcloud"
                if str(cfg.get("default_role") or "") not in _VALID_ROLES:
                    cfg["default_role"] = "viewer"
    except Exception:
        return _defaults()
    return cfg


def _write_config(cfg: dict, actor: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(
        "# SEGS JumpCloud SSO — written by PUT /api/sso-config.\n"
        f"enabled: {str(cfg['enabled']).lower()}\n"
        "provider: jumpcloud\n"
        f"issuer: {cfg['issuer']!r}\n"
        f"authorization_endpoint: {cfg['authorization_endpoint']!r}\n"
        f"token_endpoint: {cfg['token_endpoint']!r}\n"
        f"userinfo_endpoint: {cfg['userinfo_endpoint']!r}\n"
        f"client_id: {cfg['client_id']!r}\n"
        f"client_secret: {cfg['client_secret']!r}\n"
        f"allowed_domains: {cfg['allowed_domains']!r}\n"
        f"default_role: {cfg['default_role']}\n"
        f'updated_by: "{actor}"\n'
        f'updated_at: "{now}"\n',
        encoding="utf-8",
    )


def _redirect_uri() -> str:
    origin = (get_settings().public_origin or "").strip().rstrip("/")
    if not origin:
        return _REDIRECT_PATH
    return origin + _REDIRECT_PATH


def _public_payload(cfg: dict) -> dict:
    secret = str(cfg.get("client_secret") or "")
    env = get_settings()
    live = env.sso_provider.strip().lower() == "alb_oidc"
    issuer = str(cfg.get("issuer") or JUMPCLOUD_ISSUER)
    return {
        "enabled": bool(cfg.get("enabled")),
        "live": live,
        "provider": "jumpcloud",
        "issuer": issuer,
        "authorization_endpoint": str(cfg.get("authorization_endpoint") or JUMPCLOUD_AUTHORIZE),
        "token_endpoint": str(cfg.get("token_endpoint") or JUMPCLOUD_TOKEN),
        "userinfo_endpoint": str(cfg.get("userinfo_endpoint") or JUMPCLOUD_USERINFO),
        "client_id": str(cfg.get("client_id") or ""),
        "client_secret_set": bool(secret) or bool(env.oidc_client_secret.strip()),
        "client_secret_masked": ("…" + secret[-4:]) if len(secret) > 4 else ("*" * len(secret)),
        "redirect_uri": _redirect_uri(),
        "discovery_url": issuer.rstrip("/") + "/.well-known/openid-configuration",
        "allowed_domains": str(cfg.get("allowed_domains") or "pdax.ph"),
        "default_role": str(cfg.get("default_role") or "viewer"),
        "updated_by": str(cfg.get("updated_by") or ""),
        "updated_at": str(cfg.get("updated_at") or ""),
        "env_provider": env.sso_provider.strip(),
    }


class SsoConfigUpdate(BaseModel):
    enabled: bool = False
    issuer: str = JUMPCLOUD_ISSUER
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    client_id: str = ""
    client_secret: str = ""
    allowed_domains: str = "pdax.ph"
    default_role: Literal["viewer", "analyst", "admin"] = "viewer"


@router.get("/sso-config")
def get_sso_config(user: User = Depends(require_role("admin"))):
    return _public_payload(_read_config())


@router.put("/sso-config")
def set_sso_config(body: SsoConfigUpdate, user: User = Depends(require_role("admin"))):
    old = _read_config()
    issuer = _https_url(body.issuer or JUMPCLOUD_ISSUER, "issuer") or JUMPCLOUD_ISSUER
    authorize = _https_url(body.authorization_endpoint, "authorization_endpoint") or (
        JUMPCLOUD_AUTHORIZE if issuer == JUMPCLOUD_ISSUER else old.get("authorization_endpoint") or ""
    )
    token = _https_url(body.token_endpoint, "token_endpoint") or (
        JUMPCLOUD_TOKEN if issuer == JUMPCLOUD_ISSUER else old.get("token_endpoint") or ""
    )
    userinfo = _https_url(body.userinfo_endpoint, "userinfo_endpoint") or (
        JUMPCLOUD_USERINFO if issuer == JUMPCLOUD_ISSUER else old.get("userinfo_endpoint") or ""
    )
    client_id = body.client_id.strip()
    secret = body.client_secret.strip()
    if not secret and old.get("client_secret"):
        secret = str(old["client_secret"])
    domains = ",".join(
        part.strip().lower().lstrip("@")
        for part in (body.allowed_domains or "").split(",")
        if part.strip()
    ) or "pdax.ph"
    if body.enabled and not client_id:
        raise HTTPException(status_code=400, detail="client_id is required when SSO is enabled")
    if body.enabled and not secret:
        raise HTTPException(status_code=400, detail="client_secret is required when SSO is enabled")
    cfg = {
        "enabled": body.enabled,
        "issuer": issuer,
        "authorization_endpoint": authorize,
        "token_endpoint": token,
        "userinfo_endpoint": userinfo,
        "client_id": client_id,
        "client_secret": secret,
        "allowed_domains": domains,
        "default_role": body.default_role,
    }
    _write_config(cfg, user.username)
    activity_log.record(
        "sso_config_change",
        actor=user.username,
        actor_role=user.role,
        detail="JumpCloud SSO {state}, issuer={issuer}".format(
            state="enabled" if body.enabled else "disabled",
            issuer=issuer,
        ),
        meta={"enabled": body.enabled, "provider": "jumpcloud"},
    )
    saved = _read_config()
    saved["updated_by"] = user.username
    return _public_payload(saved)
