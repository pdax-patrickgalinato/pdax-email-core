"""API tests for GET /api/org and admin CRUD of organizational context notes.

Uses an isolated temp org.yaml — never mutates the real project file.

Run: python3 -m pytest backend/tests/server/test_org_api.py
"""
import tempfile
from pathlib import Path

from fastapi import FastAPI
from starlette.testclient import TestClient

from backend.stores import org_config
from backend.api.auth_store import AuthStore
from backend.paths import RULES_IDENTITY
from backend.tests.conftest import TEST_PASSWORD


def _client_as(role: str, tmp_org_path: Path):
    from backend.api.routers import org as org_module
    import backend.api.deps as deps_module

    org_config._ORG_PATH = tmp_org_path

    store = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = store
    user = store.create_user("testuser", TEST_PASSWORD, role)

    app = FastAPI()
    app.include_router(org_module.router)
    client = TestClient(app)

    token = store.create_session(user.id)
    client.cookies.set("seg_session", token)
    return client


def _tmp_org() -> Path:
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text(
        'organization:\n'
        '  display_name: ""\n'
        '  regulator_context: "a BSP-regulated crypto exchange"\n'
        '  context_notes: []\n'
    )
    return tmp


def _restore():
    org_config._ORG_PATH = RULES_IDENTITY / "org.yaml"


def test_get_org_includes_context_notes():
    tmp = _tmp_org()
    try:
        client = _client_as("viewer", tmp)
        r = client.get("/api/org")
        assert r.status_code == 200
        body = r.json()
        assert "display_name" in body
        assert "regulator_context" in body
        assert body["context_notes"] == []
    finally:
        _restore()


def test_viewer_cannot_add_context_403():
    tmp = _tmp_org()
    try:
        client = _client_as("viewer", tmp)
        r = client.post("/api/org/context", json={"text": "PDAX is a crypto exchange"})
        assert r.status_code == 403
    finally:
        _restore()


def test_analyst_cannot_add_context_403():
    tmp = _tmp_org()
    try:
        client = _client_as("analyst", tmp)
        r = client.post("/api/org/context", json={"text": "PDAX is a crypto exchange"})
        assert r.status_code == 403
    finally:
        _restore()


def test_admin_add_and_remove_context_persists():
    tmp = _tmp_org()
    try:
        client = _client_as("admin", tmp)
        r = client.post(
            "/api/org/context",
            json={"text": "support@pdax.ph is the customer-support inbox where clients raise concerns."},
        )
        assert r.status_code == 201, r.text
        added = r.json()["added"]
        assert added["text"].startswith("support@pdax.ph")
        notes = r.json()["context_notes"]
        assert len(notes) == 1

        r2 = client.get("/api/org")
        assert r2.json()["context_notes"][0]["id"] == added["id"]

        r3 = client.delete(f"/api/org/context/{added['id']}")
        assert r3.status_code == 200
        assert r3.json()["context_notes"] == []
    finally:
        _restore()


def test_admin_can_update_context():
    tmp = _tmp_org()
    try:
        client = _client_as("admin", tmp)
        added = client.post(
            "/api/org/context",
            json={"text": "support@pdax.ph is a shared inbox"},
        ).json()["added"]
        r = client.patch(
            f"/api/org/context/{added['id']}",
            json={"text": "support@pdax.ph is the customer-support inbox"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["updated"]["id"] == added["id"]
        assert "customer-support" in r.json()["updated"]["text"]
        notes = client.get("/api/org").json()["context_notes"]
        assert len(notes) == 1
        assert notes[0]["text"] == r.json()["updated"]["text"]
    finally:
        _restore()


def test_update_missing_context_404():
    tmp = _tmp_org()
    try:
        client = _client_as("admin", tmp)
        r = client.patch("/api/org/context/doesnotexist", json={"text": "new text"})
        assert r.status_code == 404
    finally:
        _restore()


def test_admin_duplicate_context_409():
    tmp = _tmp_org()
    try:
        client = _client_as("admin", tmp)
        body = {"text": "PDAX is a Philippine-based crypto exchange"}
        assert client.post("/api/org/context", json=body).status_code == 201
        r = client.post("/api/org/context", json=body)
        assert r.status_code == 409
    finally:
        _restore()


def test_remove_missing_context_404():
    tmp = _tmp_org()
    try:
        client = _client_as("admin", tmp)
        r = client.delete("/api/org/context/doesnotexist")
        assert r.status_code == 404
    finally:
        _restore()
