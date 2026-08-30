"""GET /api/campaigns — authenticated campaign clusters."""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from starlette.testclient import TestClient

from backend.api.auth_store import AuthStore


def _client():
    from fastapi import FastAPI
    from backend.api.routers import campaigns as campaigns_module
    import backend.api.deps as deps_module

    auth = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = auth
    user = auth.create_user("testuser", "Password123!", "analyst")
    app = FastAPI()
    app.include_router(campaigns_module.router)
    client = TestClient(app)
    token = auth.create_session(user.id)
    client.cookies.set("seg_session", token)
    return client


def test_campaigns_requires_auth():
    from fastapi import FastAPI
    from backend.api.routers import campaigns as campaigns_module

    app = FastAPI()
    app.include_router(campaigns_module.router)
    with TestClient(app) as client:
        assert client.get("/api/campaigns").status_code == 401


def test_campaigns_empty_shape():
    with patch("backend.api.routers.campaigns.get_default_store") as store:
        store = store.return_value
        store.list_campaigns.return_value = []
        client = _client()
        body = client.get("/api/campaigns").json()
    assert body["campaigns"] == []
    assert body["total"] == 0
    assert body["flagged"] == 0


def test_campaigns_lists_clusters():
    with patch("backend.api.routers.campaigns.get_default_store") as store:
        store = store.return_value
        store.list_campaigns.return_value = [{
            "id": "cam-abc", "kind": "hash", "members": 3, "senders": 2,
            "mailboxes": 2, "flagged": 2, "pattern": "hash:aa",
            "ai_title": "Shared malware payload",
            "ai_summary": "Three emails share one attachment hash.",
            "attack_class": "malware_delivery",
            "confidence": "high",
        }]
        store.get_campaign.return_value = {
            "id": "cam-abc", "kind": "hash", "members": 3, "senders": 2,
            "mailboxes": 2, "flagged": 2, "pattern": "hash:aa",
            "ai_title": "Shared malware payload",
            "ai_summary": "Three emails share one attachment hash.",
            "attack_class": "malware_delivery",
            "insight": {"lure": "Open the attached bonus letter."},
        }
        client = _client()
        body = client.get("/api/campaigns").json()
        detail = client.get("/api/campaigns/by-id", params={"id": "cam-abc"}).json()
    assert body["total"] == 1
    assert body["flagged"] == 1
    assert body["campaigns"][0]["id"] == "cam-abc"
    assert body["campaigns"][0]["ai_title"] == "Shared malware payload"
    assert detail["id"] == "cam-abc"
    assert detail["insight"]["lure"]
