"""Unit tests for server/auth_store.py + backend/api/routers/auth.py — Phase 10
(RBAC / user management) of the dashboard-overhaul plan. Uses an isolated
temp-file SQLite DB per test — never the real project data/ directory.

Run: python3 -m pytest tests/test_server_auth.py
     (or python3 tests/test_server_auth.py)
"""
import tempfile
from pathlib import Path

from starlette.testclient import TestClient

from backend.api.auth_store import AuthStore

def _tmp_store() -> AuthStore:
    tmp = Path(tempfile.mkstemp(suffix=".sqlite3")[1])
    return AuthStore(db_path=tmp)

def _client_with_store(store: AuthStore) -> TestClient:
    """Builds a fresh FastAPI app instance wired to an isolated auth store,
    rather than reusing server.main.app's module-level singleton store —
    keeps every test's user/session data fully isolated."""
    from fastapi import FastAPI
    from backend.api.routers import auth as auth_module

    auth_module._store = store   # the router module's module-level store
    import backend.api.deps as deps_module
    deps_module._store = store   # get_current_user/require_role resolve via this

    app = FastAPI()
    app.include_router(auth_module.router)
    return TestClient(app)

# --- AuthStore directly -------------------------------------------------------

def test_password_hash_never_stored_plaintext():
    store = _tmp_store()
    user = store.create_user("alice", "Correct-horse1!", "admin")
    conn = store._connect()
    row = conn.execute("SELECT password_hash FROM users WHERE id=?", (user.id,)).fetchone()
    conn.close()
    assert "correct horse" not in row[0]

def test_verify_password_correct_and_incorrect():
    store = _tmp_store()
    store.create_user("bob", "Hunter22222!", "viewer")
    assert store.verify_password("bob", "Hunter22222!") is not None
    assert store.verify_password("bob", "wrong-password") is None
    assert store.verify_password("nobody", "whatever1") is None

def test_disabled_user_cannot_authenticate():
    store = _tmp_store()
    user = store.create_user("carol", "Password123!", "analyst")
    store.set_user_disabled(user.id, True)
    assert store.verify_password("carol", "Password123!") is None

def test_session_create_resolve_delete():
    store = _tmp_store()
    user = store.create_user("dave", "Password123!", "admin")
    token = store.create_session(user.id)
    resolved = store.resolve_session(token)
    assert resolved is not None
    assert resolved.username == "dave"
    store.delete_session(token)
    assert store.resolve_session(token) is None

def test_delete_all_sessions_for_user_logs_out_everywhere():
    store = _tmp_store()
    user = store.create_user("erin", "Password123!", "admin")
    t1, t2 = store.create_session(user.id), store.create_session(user.id)
    store.delete_all_sessions_for_user(user.id)
    assert store.resolve_session(t1) is None
    assert store.resolve_session(t2) is None

def test_invalid_role_rejected():
    store = _tmp_store()
    try:
        store.create_user("frank", "Password123!", "superuser")
        assert False, "expected ValueError"
    except ValueError:
        pass

# --- HTTP layer ----------------------------------------------------------------

def test_setup_status_reports_needs_setup():
    client = _client_with_store(_tmp_store())
    r = client.get("/api/setup/status")
    assert r.json() == {"needs_setup": True}

def test_setup_creates_admin_and_sets_cookie():
    client = _client_with_store(_tmp_store())
    r = client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"
    assert r.json()["token_type"] == "Bearer"
    assert r.json()["access_token"].count(".") == 2
    assert "seg_session" in r.cookies

def test_setup_disabled_after_first_user():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    r = client.post("/api/setup", json={"username": "second", "password": "Password123!"})
    assert r.status_code == 404

def test_login_wrong_password_401():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    r = client.post("/api/auth/login", json={"username": "admin", "password": "nope12345"})
    assert r.status_code == 401

def test_me_requires_auth():
    client = _client_with_store(_tmp_store())
    r = client.get("/api/auth/me")
    assert r.status_code == 401

def test_me_returns_current_user_after_login():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    assert r.json()["username"] == "admin"

def test_logout_clears_session():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    client.post("/api/auth/logout")
    r = client.get("/api/auth/me")
    assert r.status_code == 401

def test_login_starts_passkey_mfa_without_session():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Password123!"})
    assert r.status_code == 200
    body = r.json()
    assert body["mfa"] == "webauthn"
    assert body["mode"] in ("enroll", "assert")
    assert body["login_token"]
    assert "options" in body
    me = client.get("/api/auth/me")
    assert me.status_code == 401


def test_bearer_jwt_authenticates():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    users = client.get("/api/users").json()
    admin_id = next(u["id"] for u in users if u["username"] == "admin")
    token = store.create_session(admin_id)
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["username"] == "admin"
    assert r.headers.get("www-authenticate") is None


def test_viewer_cannot_list_users_403():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    viewer = store.create_user("viewbob", "Password123!", "viewer")
    client.cookies.set("seg_session", store.create_session(viewer.id))
    r = client.get("/api/users")
    assert r.status_code == 403

def test_admin_can_create_and_list_users():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    r = client.post("/api/users", json={"username": "newanalyst", "password": "Password123!", "role": "analyst"})
    assert r.status_code == 200
    r2 = client.get("/api/users")
    usernames = [u["username"] for u in r2.json()]
    assert "newanalyst" in usernames
    assert "admin" in usernames

def test_admin_cannot_delete_own_account():
    store = _tmp_store()
    client = _client_with_store(store)
    r = client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    me = client.get("/api/auth/me").json()
    users = client.get("/api/users").json()
    admin_id = next(u["id"] for u in users if u["username"] == "admin")
    r = client.delete(f"/api/users/{admin_id}")
    assert r.status_code == 400

def test_response_bodies_never_leak_password_hash():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    r = client.get("/api/users")
    for u in r.json():
        assert "password_hash" not in u
        assert "salt" not in u

def test_set_password_updates_hash_and_revokes_sessions():
    store = _tmp_store()
    user = store.create_user("bob", "Oldpassword1!", "analyst")
    token = store.create_session(user.id)
    assert store.resolve_session(token) is not None
    store.set_password(user.id, "Newpassword9!")
    assert store.verify_password("bob", "Oldpassword1!") is None
    assert store.verify_password("bob", "Newpassword9!") is not None
    assert store.resolve_session(token) is None

def test_admin_can_reset_any_user_password():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    client.post("/api/users", json={"username": "alice", "password": "Password123!", "role": "viewer"})
    users = client.get("/api/users").json()
    alice_id = next(u["id"] for u in users if u["username"] == "alice")
    r = client.post(f"/api/users/{alice_id}/password", json={"password": "Brandnew99!"})
    assert r.status_code == 200
    assert store.verify_password("alice", "Password123!") is None
    assert store.verify_password("alice", "Brandnew99!") is not None

def test_analyst_cannot_reset_password_403():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
    store.create_user("ana", "Password123!", "analyst")
    users = client.get("/api/users").json()
    admin_id = next(u["id"] for u in users if u["username"] == "admin")
    ana = store.get_user_by_username("ana")
    client.cookies.set("seg_session", store.create_session(ana.id))
    r = client.post(f"/api/users/{admin_id}/password", json={"password": "hackedpass1"})
    assert r.status_code == 403
    assert store.verify_password("admin", "Password123!") is not None


def test_user_can_change_own_password_and_keep_session():
    store = _tmp_store()
    client = _client_with_store(store)
    admin = store.create_user("admin", "Password123!", "admin")
    client.cookies.set("seg_session", store.create_session(admin.id))
    other = store.create_session(admin.id)
    r = client.post(
        "/api/auth/password",
        json={"current_password": "Password123!", "new_password": "Brandnew99!"},
    )
    assert r.status_code == 200
    assert store.verify_password("admin", "Password123!") is None
    assert store.verify_password("admin", "Brandnew99!") is not None
    assert store.resolve_session(other) is None
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "admin"
    assert "id" in me.json()


def test_change_password_rejects_wrong_current():
    store = _tmp_store()
    client = _client_with_store(store)
    admin = store.create_user("admin", "Password123!", "admin")
    client.cookies.set("seg_session", store.create_session(admin.id))
    r = client.post(
        "/api/auth/password",
        json={"current_password": "not-the-password", "new_password": "Brandnew99!"},
    )
    assert r.status_code == 401
    assert store.verify_password("admin", "Password123!") is not None


def test_analyst_can_change_own_password():
    store = _tmp_store()
    client = _client_with_store(store)
    ana = store.create_user("ana", "Password123!", "analyst")
    client.cookies.set("seg_session", store.create_session(ana.id))
    r = client.post(
        "/api/auth/password",
        json={"current_password": "Password123!", "new_password": "Analyst99!"},
    )
    assert r.status_code == 200
    assert store.verify_password("ana", "Analyst99!") is not None
    assert client.get("/api/auth/me").json()["username"] == "ana"

def test_login_and_user_admin_write_activity_audit():
    """Activity events land in an isolated audit JSONL path."""
    from backend.api import activity_log

    path = Path(tempfile.mkdtemp()) / "activity_audit.jsonl"
    orig = activity_log._DEFAULT_PATH
    activity_log._DEFAULT_PATH = path
    try:
        store = _tmp_store()
        client = _client_with_store(store)
        client.post("/api/setup", json={"username": "admin", "password": "Password123!"})
        client.post("/api/auth/logout")
        client.post("/api/auth/login", json={"username": "admin", "password": "Password123!"})
        token = store.create_session(store.get_user_by_username("admin").id)
        client.cookies.set("seg_session", token)
        client.post("/api/users", json={"username": "bob", "password": "Password123!", "role": "viewer"})
        entries = activity_log.list_entries(path=path)
        actions = [e["action"] for e in entries]
        assert "setup" in actions
        assert "login_mfa" in actions
        assert "logout" in actions
        assert "user_create" in actions
        ui = [activity_log.to_audit_ui(e) for e in entries]
        assert all(u["kind"] == "activity" and u["tag"] == "Activity" for u in ui)
    finally:
        activity_log._DEFAULT_PATH = orig

