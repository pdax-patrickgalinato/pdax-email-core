"""API tests for GET /api/sender-profiles."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from backend.api.auth_store import AuthStore
from workers.pipeline.correlation import BehavioralCorrelationStore, PROFILE_MIN_N


def _client(role="analyst", store=None):
    from fastapi import FastAPI
    from backend.api.routers import sender_profiles as profiles_module
    import backend.api.deps as deps_module

    auth = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = auth
    deps_module.set_correlation_store(store)
    user = auth.create_user("testuser", "Password123!", role)
    app = FastAPI()
    app.include_router(profiles_module.router)
    client = TestClient(app)
    token = auth.create_session(user.id)
    client.cookies.set("seg_session", token)
    return client


def _profile_store():
    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    return BehavioralCorrelationStore(db_path=path), path


def test_sender_profiles_requires_auth():
    from fastapi import FastAPI
    from backend.api.routers import sender_profiles as profiles_module

    app = FastAPI()
    app.include_router(profiles_module.router)
    with TestClient(app) as client:
        assert client.get("/api/sender-profiles").status_code == 401


def test_list_and_detail_profiles():
    store, path = _profile_store()
    try:
        sender = "alice@yahoo.com"
        for _ in range(PROFILE_MIN_N):
            store.record_profile_observation(
                sender, asn="AS26101", country="US", network_role="esp",
                vpn=False, verdict="CLEAN",
            )
        store.record_profile_observation(
            "bob@example.com", asn="AS16509", country="IE",
            network_role="cloud_hosting", vpn=False, verdict="LOW",
        )
        client = _client(store=store)
        listed = client.get("/api/sender-profiles").json()
        assert listed["min_n"] == PROFILE_MIN_N
        addrs = [s["sender"] for s in listed["senders"]]
        assert "alice@yahoo.com" in addrs
        alice = next(s for s in listed["senders"] if s["sender"] == "alice@yahoo.com")
        assert alice["n"] == PROFILE_MIN_N
        assert alice["ready"] is True
        assert alice["majority_role"] == "esp"
        assert alice["assessment"] == "CLEAN"
        assert listed["assessment"]["CLEAN"] >= 1

        ready = client.get("/api/sender-profiles", params={"ready": True}).json()
        assert all(s["ready"] for s in ready["senders"])
        assert "bob@example.com" not in [s["sender"] for s in ready["senders"]]

        q = client.get("/api/sender-profiles", params={"q": "alice"}).json()
        assert [s["sender"] for s in q["senders"]] == ["alice@yahoo.com"]

        detail = client.get(
            "/api/sender-profiles/by-address", params={"sender": "Alice@Yahoo.com"}
        ).json()
        assert detail["ready"] is True
        assert detail["profile"]["n"] == PROFILE_MIN_N
        assert len(detail["observations"]) == PROFILE_MIN_N
        assert "Sender profile" in (detail["summary"] or "")
        assert detail["assessment"] == "CLEAN"

        store.record_copy_behavior(
            sender=sender,
            mailbox="jan@pdax.ph",
            message_id="<api-vol@x>",
            peers=["jan@pdax.ph"],
            request_class="other",
            hour_utc=14,
        )
        detail2 = client.get(
            "/api/sender-profiles/by-address", params={"sender": "Alice@Yahoo.com"}
        ).json()
        assert detail2["sent_count"] >= 1
        assert any(p["value"] == "jan@pdax.ph" for p in (detail2.get("sent_to") or []))
        assert detail2["hours"]
        assert "sent_count" in detail
        assert "received_count" in detail
        assert detail["ai_summary"]
        assert detail["ai_risk"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    finally:
        os.unlink(path)


def test_list_includes_malicious_only_sender():
    store, path = _profile_store()
    try:
        store.record_observation(
            "phish@evil.example", ["9.9.9.9"], [], verdict="MALICIOUS", message_id="x1",
        )
        client = _client(store=store)
        listed = client.get("/api/sender-profiles").json()
        assert listed["assessment"]["MALICIOUS"] == 1
        row = next(s for s in listed["senders"] if s["sender"] == "phish@evil.example")
        assert row["assessment"] == "MALICIOUS"
        assert row["copies"] == 1
    finally:
        os.unlink(path)


def test_list_empty_when_store_missing():
    client = _client(store=None)
    body = client.get("/api/sender-profiles").json()
    assert body["senders"] == []
    assert body["total"] == 0
