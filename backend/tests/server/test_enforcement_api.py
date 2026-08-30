"""Enforcement API is observe-only: Gmail Path A never holds or rejects mail."""
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from backend.api.auth_store import AuthStore


def _admin_client(tmp: Path) -> TestClient:
    from fastapi import FastAPI
    from backend.api.routers import enforcement as enf
    import backend.api.deps as deps_module

    enf._ENFORCE_FILE = tmp / "enforcement_mode.yaml"
    store = AuthStore(db_path=tmp / "users.sqlite3")
    deps_module._store = store
    user = store.create_user("admin", "Password123!", "admin")
    app = FastAPI()
    app.include_router(enf.router)
    client = TestClient(app)
    client.cookies.set("seg_session", store.create_session(user.id))
    return client


def test_enforcement_rejects_quarantine_and_reject():
    tmp = Path(tempfile.mkdtemp())
    client = _admin_client(tmp)
    r = client.put("/api/enforcement", json={"mode": "quarantine"})
    assert r.status_code == 409
    r = client.put("/api/enforcement", json={"mode": "reject"})
    assert r.status_code == 409
    r = client.put("/api/enforcement", json={"mode": "shadow"})
    assert r.status_code == 200
    assert r.json()["mode"] == "shadow"
