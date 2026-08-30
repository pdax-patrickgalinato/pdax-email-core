"""Passkeys: store + HTTP register/assert options, mocked verify, content unlock."""
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
from pathlib import Path

from fastapi import FastAPI
from starlette.testclient import TestClient

from backend.api.auth_store import AuthStore


def _tmp_store() -> AuthStore:
    return AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))


def _client(store: AuthStore) -> TestClient:
    from backend.api.routers import auth as auth_module
    from backend.api.routers import passkeys as passkeys_module
    import backend.api.deps as deps_module

    auth_module._store = store
    deps_module._store = store
    user = store.create_user("admin", "Password123!", "admin")
    app = FastAPI()
    app.include_router(auth_module.router)
    app.include_router(passkeys_module.router)
    client = TestClient(app)
    token = store.create_session(user.id)
    client.cookies.set("seg_session", token)
    return client


def test_passkey_store_unlock_and_count():
    store = _tmp_store()
    user = store.create_user("alice", "Password123!", "admin")
    token = store.create_session(user.id)
    assert store.passkey_count(user.id) == 0
    assert store.is_content_unlocked(token) is False
    store.add_passkey(user.id, "cred-aaa", "pubkey-aaa", 0, "Laptop")
    assert store.passkey_count(user.id) == 1
    store.unlock_content(token, "rfc:<a@x>")
    assert store.is_content_unlocked(token) is True
    assert store.is_content_unlocked(token, "rfc:<a@x>") is True
    assert store.is_content_unlocked(token, "rfc:<b@x>") is False
    store.unlock_content(token)
    assert store.is_content_unlocked(token, "rfc:<b@x>") is True
    store.lock_content(token)
    assert store.is_content_unlocked(token) is False
    store.delete_all_sessions_for_user(user.id)
    assert store.is_content_unlocked(token) is False


def test_me_reports_locked_until_passkey():
    client = _client(_tmp_store())
    me = client.get("/api/auth/me").json()
    assert me["username"] == "admin"
    assert me["passkey_count"] == 0
    assert me["content_unlocked"] is False


def test_register_options_returns_webauthn_public_key():
    client = _client(_tmp_store())
    r = client.post("/api/auth/passkeys/register/options")
    assert r.status_code == 200
    body = r.json()
    assert body["challenge"]
    assert body["rp"]["id"] == "testserver"
    assert body["user"]["name"] == "admin"


def test_assert_options_without_passkey_400():
    client = _client(_tmp_store())
    r = client.post("/api/auth/passkeys/assert/options")
    assert r.status_code == 400


def test_loopback_ip_uses_localhost_rpid():
    from starlette.requests import Request
    from backend.api.routers.passkeys import _rp_origin

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/auth/passkeys/register/options",
        "raw_path": b"/api/auth/passkeys/register/options",
        "query_string": b"",
        "headers": [(b"host", b"127.0.0.1:8765")],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8765),
    }
    rp_id, origins = _rp_origin(Request(scope))
    assert rp_id == "localhost"
    assert "http://localhost:8765" in origins
    assert "http://127.0.0.1:8765" in origins


def test_cloudfront_viewer_origin_not_alb_rpid():
    from starlette.requests import Request
    from backend.api.routers.passkeys import _rp_origin

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/auth/passkeys/register/options",
        "raw_path": b"/api/auth/passkeys/register/options",
        "query_string": b"",
        "headers": [
            (b"host", b"internal-segs-prod-api-123.ap-southeast-1.elb.amazonaws.com"),
            (b"origin", b"https://dgtbdm3x6793c.cloudfront.net"),
            (b"cloudfront-forwarded-proto", b"https"),
        ],
        "client": ("10.80.0.10", 12345),
        "server": ("10.80.1.20", 8765),
    }
    rp_id, origins = _rp_origin(Request(scope))
    assert rp_id == "dgtbdm3x6793c.cloudfront.net"
    assert "https://dgtbdm3x6793c.cloudfront.net" in origins
    assert not any("elb.amazonaws.com" in o for o in origins)


def test_register_options_uses_origin_header_behind_alb():
    client = _client(_tmp_store())
    r = client.post(
        "/api/auth/passkeys/register/options",
        headers={
            "Origin": "https://dgtbdm3x6793c.cloudfront.net",
            "Host": "internal-segs-prod-api-123.ap-southeast-1.elb.amazonaws.com",
        },
    )
    assert r.status_code == 200
    assert r.json()["rp"]["id"] == "dgtbdm3x6793c.cloudfront.net"


def test_save_challenge_can_be_replaced():
    store = _tmp_store()
    user = store.create_user("alice", "Password123!", "admin")
    token = store.create_session(user.id)
    store.save_challenge(token, "aaa", "register")
    store.save_challenge(token, "bbb", "register")
    assert store.pop_challenge(token, "register") == "bbb"
    assert store.pop_challenge(token, "register") is None


@patch("backend.api.routers.passkeys.verify_registration_response")
def test_register_does_not_unlock_content_by_default(mock_verify):
    mock_verify.return_value = SimpleNamespace(
        credential_id=b"cred-bytes-1",
        credential_public_key=b"pubkey-bytes-1",
        sign_count=0,
    )
    client = _client(_tmp_store())
    assert client.post("/api/auth/passkeys/register/options").status_code == 200
    r = client.post("/api/auth/passkeys/register", json={
        "credential": {
            "id": "cred", "rawId": "cred", "type": "public-key",
            "response": {"clientDataJSON": "x", "attestationObject": "y"},
        },
        "name": "Laptop",
    })
    assert r.status_code == 200
    assert r.json()["content_unlocked"] is False
    me = client.get("/api/auth/me").json()
    assert me["passkey_count"] == 1
    assert me["content_unlocked"] is False
    listed = client.get("/api/auth/passkeys").json()["passkeys"]
    assert listed[0]["name"] == "Laptop"


@patch("backend.api.routers.passkeys.verify_registration_response")
def test_register_can_one_shot_unlock(mock_verify):
    mock_verify.return_value = SimpleNamespace(
        credential_id=b"cred-bytes-1b",
        credential_public_key=b"pubkey-bytes-1b",
        sign_count=0,
    )
    client = _client(_tmp_store())
    assert client.post("/api/auth/passkeys/register/options").status_code == 200
    r = client.post("/api/auth/passkeys/register", json={
        "credential": {
            "id": "cred", "rawId": "cred", "type": "public-key",
            "response": {"clientDataJSON": "x", "attestationObject": "y"},
        },
        "name": "Laptop",
        "unlock": True,
    })
    assert r.status_code == 200
    assert r.json()["content_unlocked"] is True
    assert client.get("/api/auth/me").json()["content_unlocked"] is True


@patch("backend.api.routers.passkeys.verify_authentication_response")
def test_assert_unlocks_after_register(mock_verify):
    from webauthn.helpers import bytes_to_base64url

    store = _tmp_store()
    client = _client(store)
    users = client.get("/api/users").json()
    admin_id = next(u["id"] for u in users if u["username"] == "admin")
    cred_id = bytes_to_base64url(b"cred-bytes-2")
    store.add_passkey(admin_id, cred_id, bytes_to_base64url(b"pubkey-2"), 1, "Key")
    mock_verify.return_value = SimpleNamespace(new_sign_count=2)
    assert client.post("/api/auth/passkeys/assert/options").status_code == 200
    r = client.post("/api/auth/passkeys/assert", json={
        "credential": {
            "id": cred_id, "rawId": cred_id, "type": "public-key",
            "response": {"clientDataJSON": "x", "authenticatorData": "y", "signature": "z"},
        }
    })
    assert r.status_code == 200
    assert r.json()["content_unlocked"] is True
    assert r.json()["thread_key"] == "*"
    me = client.get("/api/auth/me").json()
    assert me["content_unlocked"] is True


@patch("backend.api.routers.passkeys.verify_authentication_response")
@patch("backend.api.routers.passkeys.feed_builder.preferred_unlock_key", return_value="rfc:<root@x>")
def test_assert_unlocks_named_thread(mock_thread, mock_verify):
    from webauthn.helpers import bytes_to_base64url

    store = _tmp_store()
    client = _client(store)
    users = client.get("/api/users").json()
    admin_id = next(u["id"] for u in users if u["username"] == "admin")
    cred_id = bytes_to_base64url(b"cred-bytes-3")
    store.add_passkey(admin_id, cred_id, bytes_to_base64url(b"pubkey-3"), 1, "Key")
    mock_verify.return_value = SimpleNamespace(new_sign_count=2)
    assert client.post("/api/auth/passkeys/assert/options").status_code == 200
    r = client.post("/api/auth/passkeys/assert", json={
        "credential": {
            "id": cred_id, "rawId": cred_id, "type": "public-key",
            "response": {"clientDataJSON": "x", "authenticatorData": "y", "signature": "z"},
        },
        "queue_id": "q1",
    })
    assert r.status_code == 200
    assert r.json()["thread_key"] == "rfc:<root@x>"
    token = client.cookies.get("seg_session")
    assert store.is_content_unlocked(token, "rfc:<root@x>") is True
    assert store.is_content_unlocked(token, "rfc:<other@x>") is False
    mock_thread.assert_called_once_with("q1")
    lock = client.post("/api/auth/passkeys/lock")
    assert lock.status_code == 200
    assert store.is_content_unlocked(token, "rfc:<root@x>") is False


def test_delete_passkey():
    store = _tmp_store()
    client = _client(store)
    users = client.get("/api/users").json()
    admin_id = next(u["id"] for u in users if u["username"] == "admin")
    pk_id = store.add_passkey(admin_id, "cid", "pk", 0, "Old")
    r = client.delete(f"/api/auth/passkeys/{pk_id}")
    assert r.status_code == 200
    assert store.passkey_count(admin_id) == 0
