"""Unit tests for server/feed_builder.py + server/routers/feed.py — Phase
12 (real-data feed) of the dashboard-overhaul plan. Uses a temp spool root
and temp auth store — never touches the real gateway/spool/ or data/.

Run: python3 -m pytest tests/test_server_feed_api.py
     (or python3 tests/test_server_feed_api.py)
"""
import json
import os
import sys
import tempfile
from pathlib import Path

# Keep unit tests offline — never call live GLM during CI/local suite.
os.environ["SEG_DASHBOARD_LLM"] = "0"
os.environ["SEG_DASHBOARD_DEEP"] = "0"

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from starlette.testclient import TestClient

from app.pipeline import runner
from app.models import Verdict
from server import feed_builder
from server.auth_store import AuthStore

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _ROOT / "samples" / "fixtures"


def _tmp_spool() -> Path:
    return Path(tempfile.mkdtemp())


def _seed_entry(spool_root: Path, bucket: str, queue_id: str, meta: dict,
                eml_bytes: bytes = b"From: a@b.com\nSubject: x\n\nbody"):
    d = spool_root / bucket / queue_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "message.eml").write_bytes(eml_bytes)
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")


def _client_as(role: str, spool_root: Path):
    from fastapi import FastAPI
    from server.routers import feed as feed_module
    import server.deps as deps_module

    feed_module._SPOOL_ROOT = spool_root
    feed_builder._SPOOL_ROOT = spool_root
    feed_builder._cache = None   # force a fresh build against the temp root

    store = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = store
    user = store.create_user("testuser", "password123", role)

    app = FastAPI()
    app.include_router(feed_module.router)
    client = TestClient(app)
    token = store.create_session(user.id)
    client.cookies.set("seg_session", token)
    return client


# --- feed_builder unit-level ---------------------------------------------------

def test_norm_meta_handles_local_quarantine_client_schema():
    norm = feed_builder._norm_meta({"verdict": "MALICIOUS", "score": 95.0,
                                     "disposition": "QUARANTINE", "subject": "s", "from": "a@b.com"})
    assert norm["verdict"] == "MALICIOUS"
    assert norm["score"] == 95.0


def test_norm_meta_handles_internal_inbox_test_schema():
    # The real on-disk shape written by gateway/internal_inbox_test.py —
    # confirmed by reading an actual meta.json on disk during planning.
    norm = feed_builder._norm_meta({"core_verdict": "CLEAN", "core_score": 15.0,
                                     "core_disposition": "DELIVER", "subject": "s", "from": "a@b.com"})
    assert norm["verdict"] == "CLEAN"
    assert norm["score"] == 15.0
    assert norm["disposition"] == "DELIVER"


def test_norm_meta_prefers_standard_schema_when_both_present():
    norm = feed_builder._norm_meta({"verdict": "LOW", "core_verdict": "CLEAN"})
    assert norm["verdict"] == "LOW"


def test_spool_entries_reads_both_schemas_from_disk():
    root = _tmp_spool()
    _seed_entry(root, "quarantine", "std_schema", {
        "verdict": "SUSPICIOUS", "score": 50.0, "disposition": "QUARANTINE",
        "subject": "Standard schema", "from": "std@example.com", "ts": "2026-08-13T00:00:00+00:00",
    })
    _seed_entry(root, "quarantine", "legacy_schema", {
        "core_verdict": "MALICIOUS", "core_score": 90.0, "core_disposition": "QUARANTINE",
        "subject": "Legacy schema", "from": "legacy@example.com", "ts": "2026-08-13T00:00:00+00:00",
    })
    feed_builder._SPOOL_ROOT = root
    entries = feed_builder.spool_entries()
    by_id = {e["id"]: e for e in entries}
    assert by_id["std_schema"]["verdict"] == "SUSPICIOUS"
    assert by_id["std_schema"]["score"] == 50.0
    assert by_id["legacy_schema"]["verdict"] == "MALICIOUS"
    assert by_id["legacy_schema"]["score"] == 90.0
    assert by_id["legacy_schema"]["hasStageDetail"] is False


def test_spool_entries_empty_when_no_spool_dir():
    feed_builder._SPOOL_ROOT = Path(tempfile.mkdtemp()) / "does_not_exist"
    assert feed_builder.spool_entries() == []


def test_shadow_log_entries_parses_jsonl():
    root = _tmp_spool()
    (root / "shadow_logs").mkdir(parents=True)
    (root / "shadow_logs" / "shadow_enforcement.jsonl").write_text(
        '{"ts": "2026-08-13T00:00:00Z", "verdict": "MALICIOUS"}\n'
        '{"ts": "2026-08-13T00:01:00Z", "verdict": "CLEAN"}\n'
        "not valid json\n",   # malformed line skipped, not fatal
        encoding="utf-8",
    )
    feed_builder._SPOOL_ROOT = root
    entries = feed_builder.shadow_log_entries()
    assert len(entries) == 2
    assert entries[0]["verdict"] == "MALICIOUS"


def test_run_samples_matches_direct_pipeline_call():
    feed_builder._SAMPLES_DIR = _FIXTURES   # use the small, fast fixture set for this check
    entries = feed_builder.run_samples()
    by_file = {e["sourceFile"]: e for e in entries}
    assert "phish_lookalike.eml" in by_file
    assert by_file["phish_lookalike.eml"]["verdict"] == "MALICIOUS"
    assert by_file["phish_lookalike.eml"]["hasStageDetail"] is True

    direct = runner.run_pipeline(
        (_FIXTURES / "phish_lookalike.eml").read_bytes(), source="file")
    assert by_file["phish_lookalike.eml"]["verdict"] == direct.verdict.value
    feed_builder._SAMPLES_DIR = _ROOT / "samples"   # restore for other tests


def test_run_samples_excludes_fixtures_when_pointed_at_real_samples_dir():
    feed_builder._SAMPLES_DIR = _ROOT / "samples"
    files = sorted(feed_builder._SAMPLES_DIR.glob("*.eml"))
    assert all("fixtures" not in str(f) for f in files)


# --- HTTP layer: role gating --------------------------------------------------

def test_viewer_can_read_feed_and_audit():
    root = _tmp_spool()
    client = _client_as("viewer", root)
    assert client.get("/api/feed").status_code == 200
    assert client.get("/api/audit").status_code == 200


def test_viewer_cannot_release_403():
    root = _tmp_spool()
    _seed_entry(root, "quarantine", "q1", {"verdict": "SUSPICIOUS", "score": 50, "subject": "x", "from": "a@b.com"})
    client = _client_as("viewer", root)
    r = client.post("/api/quarantine/q1/release")
    assert r.status_code == 403


def test_viewer_cannot_download_403():
    root = _tmp_spool()
    _seed_entry(root, "quarantine", "q1", {"verdict": "SUSPICIOUS", "score": 50, "subject": "x", "from": "a@b.com"})
    client = _client_as("viewer", root)
    r = client.get("/api/quarantine/q1/download")
    assert r.status_code == 403


def test_analyst_can_release_and_it_moves_on_disk():
    root = _tmp_spool()
    _seed_entry(root, "quarantine", "q1", {"verdict": "SUSPICIOUS", "score": 50, "subject": "x", "from": "a@b.com"})
    client = _client_as("analyst", root)
    r = client.post("/api/quarantine/q1/release")
    assert r.status_code == 200
    assert r.json()["bucket"] == "released"
    assert not (root / "quarantine" / "q1").exists()
    assert (root / "released" / "q1").exists()


def test_analyst_can_keep_blocked_and_it_moves_on_disk():
    root = _tmp_spool()
    _seed_entry(root, "quarantine", "q1", {"verdict": "MALICIOUS", "score": 95, "subject": "x", "from": "a@b.com"})
    client = _client_as("analyst", root)
    r = client.post("/api/quarantine/q1/keep-blocked")
    assert r.status_code == 200
    assert r.json()["bucket"] == "rejected"
    assert (root / "rejected" / "q1").exists()


def test_analyst_can_download_real_eml_bytes():
    root = _tmp_spool()
    _seed_entry(root, "quarantine", "q1", {"verdict": "SUSPICIOUS", "score": 50, "subject": "x", "from": "a@b.com"},
               eml_bytes=b"From: real@sender.com\nSubject: real test\n\nreal body content")
    client = _client_as("analyst", root)
    r = client.get("/api/quarantine/q1/download")
    assert r.status_code == 200
    assert b"real body content" in r.content


def test_release_missing_entry_404():
    root = _tmp_spool()
    client = _client_as("admin", root)
    r = client.post("/api/quarantine/nonexistent/release")
    assert r.status_code == 404


def test_reevaluate_uses_dashboard_provider_and_updates_meta():
    root = _tmp_spool()
    raw = (_FIXTURES / "phish_lookalike.eml").read_bytes()
    _seed_entry(root, "quarantine", "q1",
               {"verdict": "CLEAN", "score": 0, "subject": "old", "from": "a@b.com"},
               eml_bytes=raw)
    client = _client_as("analyst", root)
    r = client.post("/api/quarantine/q1/reevaluate")
    assert r.status_code == 200
    body = r.json()
    assert body["reeval"]["new_verdict"] == "MALICIOUS"   # phish_lookalike always hard-overrides
    meta = json.loads((root / "quarantine" / "q1" / "meta.json").read_text())
    assert meta["verdict"] == "MALICIOUS"


def test_feed_refresh_rebuilds_cache():
    root = _tmp_spool()
    feed_builder._SAMPLES_DIR = _FIXTURES
    client = _client_as("viewer", root)
    r1 = client.get("/api/feed").json()
    r2 = client.post("/api/feed/refresh").json()
    assert len(r1["entries"]) == len(r2["entries"])
    feed_builder._SAMPLES_DIR = _ROOT / "samples"


def test_audit_merges_gateway_shadow_and_activity():
    root = _tmp_spool()
    (root / "shadow_logs").mkdir(parents=True)
    (root / "shadow_logs" / "shadow_enforcement.jsonl").write_text(
        '{"ts": "2026-08-13T00:00:00Z", "verdict": "MALICIOUS",'
        ' "from": "a@b.com", "subject": "phish"}\n',
        encoding="utf-8",
    )
    feed_builder._SPOOL_ROOT = root

    from server import activity_log
    path = Path(tempfile.mkdtemp()) / "activity_audit.jsonl"
    orig = activity_log._DEFAULT_PATH
    activity_log._DEFAULT_PATH = path
    try:
        activity_log.record("login", actor="admin", actor_role="admin", detail="Session started")
        client = _client_as("admin", root)
        entries = client.get("/api/audit").json()["entries"]
        kinds = {e.get("kind") for e in entries}
        assert "gateway" in kinds
        assert "activity" in kinds
        assert any(e.get("tag") == "Activity" for e in entries)
        assert any(e.get("tag") == "Gateway" for e in entries)
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
