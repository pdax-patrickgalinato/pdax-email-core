"""GET/PUT /api/sso-config — JumpCloud OIDC settings for the console."""
from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI
from starlette.testclient import TestClient

from backend.api.auth_store import AuthStore
from backend.tests.conftest import TEST_PASSWORD


def _client(tmp_path: Path, monkeypatch, role: str = "admin"):
    from backend.api.routers import sso_config as sso_module
    import backend.api.deps as deps_module

    monkeypatch.setattr(sso_module, "_CONFIG_FILE", tmp_path / "sso_config.yaml")
    store = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = store
    user = store.create_user("testuser", TEST_PASSWORD, role)
    app = FastAPI()
    app.include_router(sso_module.router)
    client = TestClient(app)
    token = store.create_session(user.id)
    client.cookies.set("seg_session", token)
    return client


def test_sso_defaults_are_jumpcloud(tmp_path, monkeypatch):
    monkeypatch.setenv("SEG_PUBLIC_ORIGIN", "https://segs.example")
    client = _client(tmp_path, monkeypatch)
    r = client.get("/api/sso-config")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is False
    assert body["live"] is False
    assert body["provider"] == "jumpcloud"
    assert body["issuer"] == "https://oauth.id.jumpcloud.com"
    assert body["redirect_uri"] == "https://segs.example/oauth2/idpresponse"
    assert "secret" not in body
    assert body["client_secret_set"] is False


def test_admin_can_save_jumpcloud_oidc(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    r = client.put(
        "/api/sso-config",
        json={
            "enabled": True,
            "issuer": "https://oauth.id.jumpcloud.com",
            "client_id": "jc-app-id",
            "client_secret": "super-secret-value",
            "allowed_domains": "PDAX.ph, segs.example",
            "default_role": "analyst",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    assert body["client_id"] == "jc-app-id"
    assert body["client_secret_set"] is True
    assert "super-secret-value" not in str(body)
    assert body["allowed_domains"] == "pdax.ph,segs.example"
    assert body["default_role"] == "analyst"
    assert body["authorization_endpoint"].startswith("https://oauth.id.jumpcloud.com")

    again = client.get("/api/sso-config").json()
    assert again["client_id"] == "jc-app-id"
    assert again["enabled"] is True


def test_blank_secret_keeps_stored_value(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.put(
        "/api/sso-config",
        json={"enabled": True, "client_id": "id-1", "client_secret": "keep-me"},
    )
    r = client.put("/api/sso-config", json={"enabled": True, "client_id": "id-1", "client_secret": ""})
    assert r.status_code == 200
    assert r.json()["client_secret_set"] is True


def test_enable_without_client_id_is_rejected(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    r = client.put("/api/sso-config", json={"enabled": True, "client_id": "", "client_secret": "x"})
    assert r.status_code == 400


def test_http_issuer_is_rejected(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    r = client.put("/api/sso-config", json={"enabled": False, "issuer": "http://evil.example"})
    assert r.status_code == 400


def test_live_flag_follows_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SEG_SSO_PROVIDER", "alb_oidc")
    client = _client(tmp_path, monkeypatch)
    assert client.get("/api/sso-config").json()["live"] is True


def test_analyst_cannot_read_sso_config(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, role="analyst")
    assert client.get("/api/sso-config").status_code == 403
    assert client.put("/api/sso-config", json={"enabled": False}).status_code == 403


def test_unauthenticated_sso_config_is_rejected():
    from backend.api.routers import sso_config as sso_module

    app = FastAPI()
    app.include_router(sso_module.router)
    with TestClient(app) as client:
        assert client.get("/api/sso-config").status_code == 401
