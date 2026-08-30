"""Unit tests for server/main.py — Phase 9 (backend foundation) of the
dashboard-overhaul plan. Uses starlette's TestClient (ships with FastAPI;
httpx is the only extra dependency, dev/test-only).

Run: python3 -m pytest tests/test_server_foundation.py
     (or python3 tests/test_server_foundation.py)
"""

import pytest
from starlette.testclient import TestClient

from backend.api.main import app, get_config
from backend.paths import WEB_CONSOLE_DIST

_SPA_BUILT = (WEB_CONSOLE_DIST / "index.html").is_file()

def test_health_endpoint():
    with TestClient(app) as client:
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


def test_serve_spa_disabled_exposes_api_root(monkeypatch):
    monkeypatch.setenv("SEG_SERVE_SPA", "0")
    from backend.api.main import create_app

    with TestClient(create_app()) as client:
        r = client.get("/")
        assert r.status_code == 200
        assert r.json() == {"service": "segs-api"}
        assert client.get("/api/health").json() == {"status": "ok"}

def test_config_loaded_on_startup():
    with TestClient(app) as client:
        client.get("/api/health")  # triggers the lifespan startup
        weights_cfg, protected, vips, policy_cfg, banned_ext = get_config()
        assert "weights" in weights_cfg
        assert "thresholds" in weights_cfg
        assert isinstance(protected, list)

@pytest.mark.skipif(not _SPA_BUILT, reason="web-console/dist not built (npm run build)")
def test_dashboard_index_served():
    with TestClient(app) as client:
        r = client.get("/index.html")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "<title>" in r.text

@pytest.mark.skipif(not _SPA_BUILT, reason="web-console/dist not built (npm run build)")
def test_dashboard_root_serves_index():
    with TestClient(app) as client:
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

@pytest.mark.skipif(not _SPA_BUILT, reason="web-console/dist not built (npm run build)")
def test_spa_client_routes_serve_index():
    with TestClient(app) as client:
        for path in ("/overview", "/quarantine", "/analyze", "/senders", "/campaigns", "/workers", "/audit", "/settings",
                     "/mail/gmail-abc123"):
            r = client.get(path)
            assert r.status_code == 200, path
            assert "text/html" in r.headers["content-type"]
            assert "<div id=\"app\">" in r.text or "<title>" in r.text
    with TestClient(app) as client:
        r = client.get("/flag_descriptions_data.js")
        assert r.status_code == 200
        assert "window.SEG_FLAG_DESCRIPTIONS" in r.text

def test_org_endpoint_requires_auth():
    with TestClient(app) as client:
        r = client.get("/api/org")
        assert r.status_code == 401

def test_org_config_has_required_fields():
    """org_config module always returns display_name, regulator_context, and context_notes."""
    from backend.stores import org_config
    body = org_config.load_org_config()
    assert "display_name" in body
    assert "regulator_context" in body
    assert "context_notes" in body
    assert isinstance(body["context_notes"], list)

