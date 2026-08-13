"""Unit tests for server/routers/policy.py — Phase 11 (policy write-back
API) of the dashboard-overhaul plan. Uses an isolated temp-file copy of
rules/policy.yaml — never mutates the real project file.

Run: python3 -m pytest tests/test_server_policy_api.py
     (or python3 tests/test_server_policy_api.py)
"""
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from starlette.testclient import TestClient

from app.pipeline import runner
from server.auth_store import AuthStore

_REAL_POLICY_PATH = Path(__file__).resolve().parents[1] / "rules" / "policy.yaml"


def _tmp_policy_copy() -> Path:
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    shutil.copy(_REAL_POLICY_PATH, tmp)
    return tmp


def _client_as(role: str, tmp_policy_path: Path):
    """Wires an isolated FastAPI app: a temp auth store (with one user of
    the given role, already logged in) + server/routers/policy.py pointed
    at an isolated policy.yaml copy, never the real project file."""
    from fastapi import FastAPI
    from server.routers import policy as policy_module
    import server.deps as deps_module

    policy_module._POLICY_PATH = tmp_policy_path

    store = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = store
    user = store.create_user("testuser", "password123", role)

    app = FastAPI()
    app.include_router(policy_module.router)
    client = TestClient(app)

    token = store.create_session(user.id)
    client.cookies.set("seg_session", token)
    return client


def test_get_policy_reflects_real_file_defaults():
    tmp = _tmp_policy_copy()
    client = _client_as("viewer", tmp)
    r = client.get("/api/policy")
    assert r.status_code == 200
    cats = {c["key"]: c["enabled"] for c in r.json()["categories"]}
    assert cats["virtual_analyzer"] is False
    assert cats["malware_scanning"] is True


def test_viewer_cannot_write_policy_403():
    tmp = _tmp_policy_copy()
    client = _client_as("viewer", tmp)
    r = client.put("/api/policy", json={"category": "web_reputation", "enabled": False})
    assert r.status_code == 403


def test_analyst_cannot_write_policy_403():
    tmp = _tmp_policy_copy()
    client = _client_as("analyst", tmp)
    r = client.put("/api/policy", json={"category": "web_reputation", "enabled": False})
    assert r.status_code == 403


def test_admin_toggle_persists_to_disk():
    tmp = _tmp_policy_copy()
    client = _client_as("admin", tmp)
    r = client.put("/api/policy", json={"category": "web_reputation", "enabled": False})
    assert r.status_code == 200
    cats = {c["key"]: c["enabled"] for c in r.json()["categories"]}
    assert cats["web_reputation"] is False

    # Re-read from disk independently — confirms it's a real write, not an
    # in-memory-only response.
    on_disk = tmp.read_text()
    assert "web_reputation:\n    enabled: false" in on_disk


def test_comment_header_survives_round_trip():
    tmp = _tmp_policy_copy()
    original = tmp.read_text()
    client = _client_as("admin", tmp)
    client.put("/api/policy", json={"category": "advanced_spam_protection", "enabled": False})
    updated = tmp.read_text()
    # Every comment line from the original file is still present verbatim.
    original_comments = [l for l in original.splitlines() if l.strip().startswith("#")]
    for line in original_comments:
        assert line in updated


def test_toggle_reflected_in_a_real_pipeline_run():
    tmp = _tmp_policy_copy()
    client = _client_as("admin", tmp)
    client.put("/api/policy", json={"category": "web_reputation", "enabled": False})

    # Independent of the API/server entirely: load config the same way
    # runner.run_pipeline() does, from the now-modified file, and confirm
    # the CLI-equivalent path reflects the change (tests/test_policy.py's
    # own _run_with_policy pattern, reused here).
    weights_cfg, protected, vips, _, banned_ext = runner.load_config()
    import yaml
    policy_cfg = yaml.safe_load(tmp.read_text())
    fixtures = Path(__file__).resolve().parents[1] / "samples" / "fixtures"
    raw = (fixtures / "phish_lookalike.eml").read_bytes()
    result = runner.run_pipeline(raw, source="test",
                                 config=(weights_cfg, protected, vips, policy_cfg, banned_ext))
    assert result.hard_override != "url_lookalike_domain"


def test_unknown_category_422():
    tmp = _tmp_policy_copy()
    client = _client_as("admin", tmp)
    r = client.put("/api/policy", json={"category": "not_a_real_category", "enabled": True})
    assert r.status_code == 422


def test_toggle_all_six_categories_independently():
    tmp = _tmp_policy_copy()
    client = _client_as("admin", tmp)
    from app.pipeline import policy as policy_mod
    for cat in policy_mod.ALL_CATEGORIES:
        r = client.put("/api/policy", json={"category": cat, "enabled": False})
        assert r.status_code == 200, cat
        cats = {c["key"]: c["enabled"] for c in r.json()["categories"]}
        assert cats[cat] is False, cat
        r2 = client.put("/api/policy", json={"category": cat, "enabled": True})
        assert r2.json()["categories"]
        cats2 = {c["key"]: c["enabled"] for c in r2.json()["categories"]}
        assert cats2[cat] is True, cat


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); passed += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
