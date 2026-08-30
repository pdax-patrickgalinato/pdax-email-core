"""SCIM 2.0 user/group provisioning."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from backend.api.auth_store import AuthStore


def _tmp_store() -> AuthStore:
    tmp = Path(tempfile.mkstemp(suffix=".sqlite3")[1])
    return AuthStore(db_path=tmp)


def _client(store: AuthStore, monkeypatch) -> TestClient:
    monkeypatch.setenv("SEG_SCIM_BEARER_TOKEN", "scim-test-token")
    from fastapi import FastAPI
    from backend.api.routers import scim as scim_module
    import backend.api.deps as deps_module

    deps_module._store = store
    scim_module._store = store
    app = FastAPI()
    app.include_router(scim_module.router)
    return TestClient(app)


def test_scim_requires_bearer(monkeypatch):
    client = _client(_tmp_store(), monkeypatch)
    r = client.get("/scim/v2/Users")
    assert r.status_code == 401
    assert "Bearer" in r.headers.get("www-authenticate", "")


def test_scim_create_filter_and_groups(monkeypatch):
    store = _tmp_store()
    client = _client(store, monkeypatch)
    headers = {
        "Authorization": "Bearer scim-test-token",
        "Content-Type": "application/scim+json",
    }
    created = client.post(
        "/scim/v2/Users",
        headers=headers,
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "jc.user",
            "externalId": "jumpcloud-1",
            "displayName": "JC User",
            "emails": [{"value": "jc.user@pdax.ph", "primary": True}],
            "roles": [{"value": "analyst"}],
            "active": True,
        },
    )
    assert created.status_code == 201
    body = created.json()
    assert body["userName"] == "jc.user"
    assert body["id"]
    assert created.headers.get("content-type", "").startswith("application/scim+json")

    listed = client.get(
        '/scim/v2/Users?filter=userName eq "jc.user"',
        headers=headers,
    )
    assert listed.status_code == 200
    assert listed.json()["totalResults"] == 1

    groups = client.get("/scim/v2/Groups", headers=headers)
    assert groups.status_code == 200
    names = {g["displayName"] for g in groups.json()["Resources"]}
    assert names == {"admin", "analyst", "viewer"}
    analyst = next(g for g in groups.json()["Resources"] if g["id"] == "analyst")
    assert any(m["display"] == "jc.user" for m in analyst["members"])

    sp = client.get("/scim/v2/ServiceProviderConfig", headers=headers)
    assert sp.status_code == 200
    assert sp.json()["filter"]["supported"] is True

    patched = client.patch(
        f"/scim/v2/Users/{body['id']}",
        headers=headers,
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
    )
    assert patched.status_code == 200
    assert patched.json()["active"] is False
