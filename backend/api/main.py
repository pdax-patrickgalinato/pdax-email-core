"""FastAPI application factory for the SEGS API + web console.

    uvicorn backend.api.main:app --reload

Serves `/api/*` from the routers below. The React console (`web-console/dist`)
is mounted last so it does not shadow API routes.
"""
from __future__ import annotations

import os
import stat
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.paths import DATA_DIR, SPOOL_DIR, WEB_CONSOLE_DIST
from backend.config import get_settings
from workers.pipeline import runner
from workers.pipeline import correlation as correlation_mod
from . import deps, feed_builder
from .routers import auth as auth_router
from .routers import policy as policy_router
from .routers import feed as feed_router
from .routers import analyze as analyze_router
from .routers import enforcement as enforcement_router
from .routers import lists as lists_router
from .routers import slack_config as slack_config_router
from .routers import notify_config as notify_config_router
from .routers import sso_config as sso_config_router
from .routers import scim as scim_router
from .routers import feedback as feedback_router
from .routers import org as org_router
from .routers import passkeys as passkeys_router
from .routers import sender_profiles as sender_profiles_router
from .routers import campaigns as campaigns_router
from .routers import ingest as ingest_router
from .routers import workers as workers_router
from .security import MaxBodySizeMiddleware, SecurityHeadersMiddleware, SSOMiddleware
from . import wazuh_shipper
import workers as workers_mod

_config = None


def _harden_tree(root: Path) -> None:
    """Recursively restrict a directory tree to owner-only (dirs 700, files
    600). Best-effort — never crashes startup on a permission error."""
    if not root.is_dir():
        return
    try:
        os.chmod(root, stat.S_IRWXU)  # 700
        for p in root.rglob("*"):
            try:
                if p.is_dir():
                    os.chmod(p, stat.S_IRWXU)  # 700
                elif p.is_file():
                    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)  # 600
            except OSError:
                continue
    except OSError:
        pass


def _harden_data_dir() -> None:
    """Restrict sensitive on-disk state to owner-only on startup — prevents
    other local users from reading the credentials database, the audit log,
    or quarantined email content in the spool. Runs every boot so files the
    mail-processing pipeline creates at runtime are re-locked here."""
    _harden_tree(DATA_DIR)
    _harden_tree(SPOOL_DIR)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    global _config
    _harden_data_dir()
    _config = runner.load_config()
    cs = correlation_mod.get_default_store()
    deps.set_correlation_store(cs)
    feed_builder.warm_sample_cache(correlation_store=cs)
    wazuh_shipper.start_shipper()
    workers_mod.set_process("api")
    # Follow-up jobs drain the sqlite queue the receiver LLM worker writes.
    # Do not start Gmail poll / LLM here — those belong to the receiver.
    workers_mod.start_profile_worker()
    workers_mod.start_campaign_worker()
    workers_mod.start_sender_risk_worker()
    try:
        from backend.stores.gmail_coverage import seed_from_copies
        seed_from_copies()
    except Exception:
        pass
    yield


def get_config():
    """Returns the (weights_cfg, protected, vips, policy_cfg, banned_ext)
    tuple loaded at startup. Routers call this rather than re-reading
    backend/policy YAML on every request — except policy.yaml, which
    Phase 11's GET /api/policy re-reads fresh on every call since it's
    meant to reflect the latest write immediately within the same process."""
    return _config


def create_app() -> FastAPI:
    application = FastAPI(
        title="SEGS API",
        version="1.0.0",
        description=(
            "Secure Email Gateway Suite HTTP API. Authenticate with a stateful JWT "
            "(``Authorization: Bearer``) or the ``seg_session`` cookie. "
            "SCIM 2.0 is at ``/scim/v2``. Interactive ``/docs`` is not served; "
            "the contract is ``docs/openapi.yaml`` and is what API Gateway imports."
        ),
        lifespan=_lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        servers=[
            {
                "url": "/",
                "description": "Same origin as the SOC console (CloudFront)",
            }
        ],
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "Authorization"],
    )
    application.add_middleware(SSOMiddleware)
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(MaxBodySizeMiddleware)

    @application.get("/api/health", tags=["health"])
    def health():
        return {"status": "ok"}

    application.include_router(auth_router.router)
    application.include_router(passkeys_router.router)
    application.include_router(org_router.router)
    application.include_router(policy_router.router)
    application.include_router(feed_router.router)
    application.include_router(analyze_router.router)
    application.include_router(enforcement_router.router)
    application.include_router(ingest_router.router)
    application.include_router(lists_router.router)
    application.include_router(slack_config_router.router)
    application.include_router(notify_config_router.router)
    application.include_router(sso_config_router.router)
    application.include_router(scim_router.router)
    application.include_router(feedback_router.router)
    application.include_router(sender_profiles_router.router)
    application.include_router(campaigns_router.router)
    application.include_router(workers_router.router)

    dist = WEB_CONSOLE_DIST
    if not get_settings().serve_spa:
        @application.get("/")
        def api_root():
            return {"service": "segs-api"}
    elif (dist / "index.html").is_file():
        assets = dist / "assets"
        if assets.is_dir():
            application.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

        @application.get("/{full_path:path}")
        def spa_fallback(full_path: str):
            if full_path == "api" or full_path.startswith("api/"):
                return JSONResponse({"detail": "not found"}, status_code=404)
            if full_path == "scim" or full_path.startswith("scim/"):
                return JSONResponse({"detail": "not found"}, status_code=404)
            if full_path:
                candidate = dist / full_path
                try:
                    candidate.resolve().relative_to(dist.resolve())
                except ValueError:
                    return FileResponse(dist / "index.html")
                if candidate.is_file():
                    return FileResponse(candidate)
            return FileResponse(dist / "index.html")
    else:
        @application.get("/")
        def spa_missing():
            return {
                "error": "web console is not built",
                "hint": "cd web-console && npm install && npm run build",
            }

    return application


app = create_app()
