"""FastAPI app entry point. Run from the repo root (pdax-email-core/):

    uvicorn server.main:app --reload

Mounts dashboard/ as static files (index.html stays one file — no
templating engine; the dashboard already renders everything client-side via
fetch() calls to the API routers below) and registers the API routers as
each phase lands (auth: Phase 10, policy: Phase 11, feed: Phase 12).
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import org_config
from app.pipeline import runner
from . import feed_builder
from .routers import auth as auth_router
from .routers import policy as policy_router
from .routers import feed as feed_router

_ROOT = Path(__file__).resolve().parent.parent
_DASHBOARD_DIR = _ROOT / "dashboard"

# Loaded once at startup — the same config every run_pipeline() call in this
# process uses (matches runner.run_pipeline()'s own "load once, reuse"
# expectation when config= is passed explicitly rather than re-read per call).
_config = None


@asynccontextmanager
async def _lifespan(app: FastAPI):
    global _config
    _config = runner.load_config()
    feed_builder.build_feed()   # runs the heuristic-only pipeline over samples/ once at boot
    yield


app = FastAPI(title="Secure Email Gateway Dashboard", lifespan=_lifespan)


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
def org():
    """Organization identity (rules/org.yaml, Phase 13 white-labeling) — the
    dashboard fetches this to render its branding instead of a hardcoded
    company name, so deploying this for a different organization is a
    config edit, not a code change."""
    return org_config.load_org_config()


app.include_router(auth_router.router)
app.include_router(policy_router.router)
app.include_router(feed_router.router)


# Static dashboard last — catches everything not matched by an API route
# above it, same reason StaticFiles mounts always go last in FastAPI apps.
app.mount("/", StaticFiles(directory=str(_DASHBOARD_DIR), html=True), name="dashboard")
