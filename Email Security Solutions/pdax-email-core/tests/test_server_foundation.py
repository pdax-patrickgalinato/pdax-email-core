"""Unit tests for server/main.py — Phase 9 (backend foundation) of the
dashboard-overhaul plan. Uses starlette's TestClient (ships with FastAPI;
httpx is the only extra dependency, dev/test-only).

Run: python3 -m pytest tests/test_server_foundation.py
     (or python3 tests/test_server_foundation.py)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from starlette.testclient import TestClient

from server.main import app, get_config


def test_health_endpoint():
    with TestClient(app) as client:
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


def test_config_loaded_on_startup():
    with TestClient(app) as client:
        client.get("/api/health")  # triggers the lifespan startup
        weights_cfg, protected, vips, policy_cfg, banned_ext = get_config()
        assert "weights" in weights_cfg
        assert "thresholds" in weights_cfg
        assert isinstance(protected, list)


def test_dashboard_index_served():
    with TestClient(app) as client:
        r = client.get("/index.html")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "<title>" in r.text


def test_dashboard_root_serves_index():
    with TestClient(app) as client:
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]


def test_flag_descriptions_js_served():
    with TestClient(app) as client:
        r = client.get("/flag_descriptions_data.js")
        assert r.status_code == 200
        assert "window.SEG_FLAG_DESCRIPTIONS" in r.text


def test_org_endpoint_returns_display_name():
    with TestClient(app) as client:
        r = client.get("/api/org")
        assert r.status_code == 200
        body = r.json()
        assert "display_name" in body
        assert "regulator_context" in body


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); passed += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
