"""Unit tests for server/auth_store.py + server/routers/auth.py — Phase 10
(RBAC / user management) of the dashboard-overhaul plan. Uses an isolated
temp-file SQLite DB per test — never the real project data/ directory.

Run: python3 -m pytest tests/test_server_auth.py
     (or python3 tests/test_server_auth.py)
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from starlette.testclient import TestClient

from server.auth_store import AuthStore


def _tmp_store() -> AuthStore:
    tmp = Path(tempfile.mkstemp(suffix=".sqlite3")[1])
    return AuthStore(db_path=tmp)


def _client_with_store(store: AuthStore) -> TestClient:
    """Builds a fresh FastAPI app instance wired to an isolated auth store,
    rather than reusing server.main.app's module-level singleton store —
    keeps every test's user/session data fully isolated."""
    from fastapi import FastAPI
    from server.routers import auth as auth_module

    auth_module._store = store   # the router module's module-level store
    import server.deps as deps_module
    deps_module._store = store   # get_current_user/require_role resolve via this

    app = FastAPI()
    app.include_router(auth_module.router)
    return TestClient(app)


# --- AuthStore directly -------------------------------------------------------

def test_password_hash_never_stored_plaintext():
    store = _tmp_store()
    user = store.create_user("alice", "correct horse battery staple", "admin")
    conn = store._connect()
    row = conn.execute("SELECT password_hash FROM users WHERE id=?", (user.id,)).fetchone()
    conn.close()
    assert "correct horse" not in row[0]


def test_verify_password_correct_and_incorrect():
    store = _tmp_store()
    store.create_user("bob", "hunter22222", "viewer")
    assert store.verify_password("bob", "hunter22222") is not None
    assert store.verify_password("bob", "wrong-password") is None
    assert store.verify_password("nobody", "whatever1") is None


def test_disabled_user_cannot_authenticate():
    store = _tmp_store()
    user = store.create_user("carol", "password123", "analyst")
    store.set_user_disabled(user.id, True)
    assert store.verify_password("carol", "password123") is None


def test_session_create_resolve_delete():
    store = _tmp_store()
    user = store.create_user("dave", "password123", "admin")
    token = store.create_session(user.id)
    resolved = store.resolve_session(token)
    assert resolved is not None
    assert resolved.username == "dave"
    store.delete_session(token)
    assert store.resolve_session(token) is None


def test_delete_all_sessions_for_user_logs_out_everywhere():
    store = _tmp_store()
    user = store.create_user("erin", "password123", "admin")
    t1, t2 = store.create_session(user.id), store.create_session(user.id)
    store.delete_all_sessions_for_user(user.id)
    assert store.resolve_session(t1) is None
    assert store.resolve_session(t2) is None


def test_invalid_role_rejected():
    store = _tmp_store()
    try:
        store.create_user("frank", "password123", "superuser")
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
    r = client.post("/api/setup", json={"username": "admin", "password": "password123"})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"
    assert "seg_session" in r.cookies


def test_setup_disabled_after_first_user():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "password123"})
    r = client.post("/api/setup", json={"username": "second", "password": "password123"})
    assert r.status_code == 404


def test_login_wrong_password_401():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "password123"})
    r = client.post("/api/auth/login", json={"username": "admin", "password": "nope12345"})
    assert r.status_code == 401


def test_me_requires_auth():
    client = _client_with_store(_tmp_store())
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_me_returns_current_user_after_login():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "password123"})
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    assert r.json()["username"] == "admin"


def test_logout_clears_session():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "password123"})
    client.post("/api/auth/logout")
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_viewer_cannot_list_users_403():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "password123"})
    store.create_user("viewbob", "password123", "viewer")
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "viewbob", "password": "password123"})
    r = client.get("/api/users")
    assert r.status_code == 403


def test_admin_can_create_and_list_users():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "password123"})
    r = client.post("/api/users", json={"username": "newanalyst", "password": "password123", "role": "analyst"})
    assert r.status_code == 200
    r2 = client.get("/api/users")
    usernames = [u["username"] for u in r2.json()]
    assert "newanalyst" in usernames
    assert "admin" in usernames


def test_admin_cannot_delete_own_account():
    store = _tmp_store()
    client = _client_with_store(store)
    r = client.post("/api/setup", json={"username": "admin", "password": "password123"})
    me = client.get("/api/auth/me").json()
    users = client.get("/api/users").json()
    admin_id = next(u["id"] for u in users if u["username"] == "admin")
    r = client.delete(f"/api/users/{admin_id}")
    assert r.status_code == 400


def test_response_bodies_never_leak_password_hash():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "password123"})
    r = client.get("/api/users")
    for u in r.json():
        assert "password_hash" not in u
        assert "salt" not in u


def test_set_password_updates_hash_and_revokes_sessions():
    store = _tmp_store()
    user = store.create_user("bob", "oldpassword1", "analyst")
    token = store.create_session(user.id)
    assert store.resolve_session(token) is not None
    store.set_password(user.id, "newpassword9")
    assert store.verify_password("bob", "oldpassword1") is None
    assert store.verify_password("bob", "newpassword9") is not None
    assert store.resolve_session(token) is None


def test_admin_can_reset_any_user_password():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "password123"})
    client.post("/api/users", json={"username": "alice", "password": "password123", "role": "viewer"})
    users = client.get("/api/users").json()
    alice_id = next(u["id"] for u in users if u["username"] == "alice")
    r = client.post(f"/api/users/{alice_id}/password", json={"password": "brandnew99"})
    assert r.status_code == 200
    assert store.verify_password("alice", "password123") is None
    assert store.verify_password("alice", "brandnew99") is not None


def test_analyst_cannot_reset_password_403():
    store = _tmp_store()
    client = _client_with_store(store)
    client.post("/api/setup", json={"username": "admin", "password": "password123"})
    store.create_user("ana", "password123", "analyst")
    users = client.get("/api/users").json()
    admin_id = next(u["id"] for u in users if u["username"] == "admin")
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "ana", "password": "password123"})
    r = client.post(f"/api/users/{admin_id}/password", json={"password": "hackedpass1"})
    assert r.status_code == 403
    assert store.verify_password("admin", "password123") is not None


def test_login_and_user_admin_write_activity_audit():
    """Activity events land in an isolated audit JSONL path."""
    from server import activity_log

    path = Path(tempfile.mkdtemp()) / "activity_audit.jsonl"
    orig = activity_log._DEFAULT_PATH
    activity_log._DEFAULT_PATH = path
    try:
        store = _tmp_store()
        client = _client_with_store(store)
        client.post("/api/setup", json={"username": "admin", "password": "password123"})
        client.post("/api/auth/logout")
        client.post("/api/auth/login", json={"username": "admin", "password": "password123"})
        client.post("/api/users", json={"username": "bob", "password": "password123", "role": "viewer"})
        entries = activity_log.list_entries(path=path)
        actions = [e["action"] for e in entries]
        assert "setup" in actions
        assert "login" in actions
        assert "logout" in actions
        assert "user_create" in actions
        ui = [activity_log.to_audit_ui(e) for e in entries]
        assert all(u["kind"] == "activity" and u["tag"] == "Activity" for u in ui)
    finally:
        activity_log._DEFAULT_PATH = orig


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); passed += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
