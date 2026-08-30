"""GET/PUT /api/ingest — pause Gmail fetch without stopping assessment."""
from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI
from starlette.testclient import TestClient

from backend.api.auth_store import AuthStore
from backend.stores import ingest_control
from backend.tests.conftest import TEST_PASSWORD


def _client(role: str = "admin"):
    from backend.api.routers import ingest as ingest_module
    import backend.api.deps as deps_module

    store = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = store
    user = store.create_user("testuser", TEST_PASSWORD, role)
    app = FastAPI()
    app.include_router(ingest_module.router)
    client = TestClient(app)
    token = store.create_session(user.id)
    client.cookies.set("seg_session", token)
    return client


def test_ingest_defaults_to_fetch_on():
    client = _client()
    r = client.get("/api/ingest")
    assert r.status_code == 200
    assert r.json()["gmail_fetch"] is True


def test_admin_can_pause_and_resume_gmail_fetch():
    client = _client("admin")
    r = client.put("/api/ingest", json={"gmail_fetch": False})
    assert r.status_code == 200
    body = r.json()
    assert body["gmail_fetch"] is False
    assert body["updated_by"] == "testuser"
    assert ingest_control.gmail_fetch_enabled() is False

    r = client.put("/api/ingest", json={"gmail_fetch": True})
    assert r.status_code == 200
    assert r.json()["gmail_fetch"] is True
    assert ingest_control.gmail_fetch_enabled() is True


def test_analyst_cannot_pause_gmail_fetch():
    client = _client("analyst")
    r = client.put("/api/ingest", json={"gmail_fetch": False})
    assert r.status_code == 403
    assert ingest_control.gmail_fetch_enabled() is True


def test_unauthenticated_ingest_is_rejected():
    from backend.api.routers import ingest as ingest_module

    app = FastAPI()
    app.include_router(ingest_module.router)
    with TestClient(app) as client:
        assert client.get("/api/ingest").status_code == 401
        assert client.put("/api/ingest", json={"gmail_fetch": False}).status_code == 401
