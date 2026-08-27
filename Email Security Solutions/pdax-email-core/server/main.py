"""FastAPI app entry point. Run from the repo root (pdax-email-core/):

    uvicorn server.main:app --reload

Mounts dashboard/ as static files (index.html stays one file — no
templating engine; the dashboard already renders everything client-side via
fetch() calls to the API routers below) and registers the API routers as
each phase lands (auth: Phase 10, policy: Phase 11, feed: Phase 12).
"""
from __future__ import annotations

import os
import stat
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app import org_config
from app.pipeline import runner
from app.pipeline import correlation as correlation_mod
from . import deps, feed_builder
from .routers import auth as auth_router
from .routers import policy as policy_router
from .routers import feed as feed_router
from .routers import analyze as analyze_router
from .routers import enforcement as enforcement_router
from .routers import lists as lists_router
from .routers import slack_config as slack_config_router
from .routers import notify_config as notify_config_router
from .security import MaxBodySizeMiddleware, SecurityHeadersMiddleware, SSOMiddleware

_ROOT = Path(__file__).resolve().parent.parent
_DASHBOARD_DIR = _ROOT / "dashboard"

# Loaded once at startup — the same config every run_pipeline() call in this
# process uses (matches runner.run_pipeline()'s own "load once, reuse"
# expectation when config= is passed explicitly rather than re-read per call).
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
    _harden_tree(_ROOT / "data")
    _harden_tree(_ROOT / "gateway" / "spool")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    global _config
    _harden_data_dir()
    _config = runner.load_config()
    cs = correlation_mod.get_default_store()
    deps.set_correlation_store(cs)
    feed_builder.build_feed(correlation_store=cs)
    yield


app = FastAPI(
    title="Secure Email Gateway Dashboard",
    lifespan=_lifespan,
    # Disable interactive API docs in production — they enumerate every
    # route, schema, and parameter for unauthenticated visitors.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# CORS: same-origin only — this is a local admin console, not a public API.
# allow_origins=[] means no cross-origin requests are permitted.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type"],
)

# JumpCloud SSO gate (no-op when SEG_SSO_PROVIDER is unset; see docs/JUMPCLOUD_SSO.md).
app.add_middleware(SSOMiddleware)

# Security response headers on every reply.
app.add_middleware(SecurityHeadersMiddleware)

# Global request body size cap — prevents memory exhaustion from oversized bodies.
app.add_middleware(MaxBodySizeMiddleware)


def get_config():
    """Returns the (weights_cfg, protected, vips, policy_cfg, banned_ext)
    tuple loaded at startup. Routers call this rather than re-reading
    rules/*.yaml/*.txt on every request — except rules/policy.yaml, which
    Phase 11's GET /api/policy re-reads fresh on every call since it's
    meant to reflect the latest write immediately within the same process."""
    return _config


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/org")
def org(_=Depends(deps.get_current_user)):
    """Organization identity (rules/org.yaml) — requires a valid session.
    Branding info is returned only to authenticated dashboard users, not to
    unauthenticated visitors performing reconnaissance."""
    return org_config.load_org_config()


app.include_router(auth_router.router)
app.include_router(policy_router.router)
app.include_router(feed_router.router)
app.include_router(analyze_router.router)
app.include_router(enforcement_router.router)
app.include_router(lists_router.router)
app.include_router(slack_config_router.router)
app.include_router(notify_config_router.router)


# Static dashboard last — catches everything not matched by an API route
# above it, same reason StaticFiles mounts always go last in FastAPI apps.
app.mount("/", StaticFiles(directory=str(_DASHBOARD_DIR), html=True), name="dashboard")
