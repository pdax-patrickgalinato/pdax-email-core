"""API tests for analyst benign labels and pack export/import."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

os.environ.setdefault("SEG_DASHBOARD_LLM", "0")
os.environ.setdefault("SEG_DASHBOARD_DEEP", "0")

from starlette.testclient import TestClient

from backend.api.auth_store import AuthStore
from backend.tests.conftest import TEST_PASSWORD


def _seed_gmail(spool: Path, queue_id: str) -> None:
    d = spool / "gmail" / queue_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "message.eml").write_bytes(
        b"From: ok@pdax.ph\nTo: jan@pdax.ph\nSubject: All good\n\nThanks\n"
    )
    (d / "meta.json").write_text(json.dumps({
        "verdict": "LOW", "score": 22.0, "subject": "All good",
        "from": "ok@pdax.ph", "mailbox": "jan@pdax.ph",
        "gmail_message_id": "mid1",
    }), encoding="utf-8")


def _client(tmp_path: Path):
    from fastapi import FastAPI
    from backend.api.routers import feedback as fb_mod
    from backend.api import feed_builder
    import backend.api.deps as deps_module
    from backend.stores import feedback as feedback_store

    spool = tmp_path / "spool"
    db = tmp_path / "fb.sqlite3"
    pack = tmp_path / "good_indicators.json"
    _seed_gmail(spool, "gmail-abc")

    fb_mod._SPOOL_ROOT = spool
    feed_builder._SPOOL_ROOT = spool
    feed_builder._cache = None
    feed_builder._sample_cache = []

    orig_record = feedback_store.record_benign
    orig_remove = feedback_store.remove_label
    orig_load = feedback_store.load_pack
    orig_import = feedback_store.import_pack

    def record_benign(**kwargs):
        kwargs["db_path"] = db
        kwargs["pack_file"] = pack
        return orig_record(**kwargs)

    def remove_label(queue_id, **kwargs):
        kwargs["db_path"] = db
        kwargs["pack_file"] = pack
        return orig_remove(queue_id, **kwargs)

    def load_pack(path=None):
        return orig_load(pack if pack.is_file() else path)

    def import_pack(body, **kwargs):
        kwargs["db_path"] = db
        kwargs["pack_file"] = pack
        return orig_import(body, **kwargs)

    feedback_store.record_benign = record_benign
    feedback_store.remove_label = remove_label
    feedback_store.load_pack = load_pack
    feedback_store.import_pack = import_pack

    store = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = store
    user = store.create_user("analyst1", TEST_PASSWORD, "analyst")
    admin = store.create_user("admin1", TEST_PASSWORD, "admin")

    app = FastAPI()
    app.include_router(fb_mod.router)
    client = TestClient(app)
    return client, store, user, admin, pack


def test_mark_benign_patches_meta_and_pack(tmp_path):
    client, store, user, _admin, pack = _client(tmp_path)
    token = store.create_session(user.id)
    client.cookies.set("seg_session", token)
    r = client.post("/api/feedback/benign", json={"queue_id": "gmail-abc"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["label"] == "benign"
    assert any(i["value"] == "ok@pdax.ph" for i in body["indicators"])
    meta = json.loads((tmp_path / "spool" / "gmail" / "gmail-abc" / "meta.json").read_text())
    assert meta["analyst_label"] == "benign"
    loaded = json.loads(pack.read_text())
    assert loaded["indicators"]


def test_export_and_import(tmp_path):
    client, store, user, admin, pack = _client(tmp_path)
    token = store.create_session(user.id)
    client.cookies.set("seg_session", token)
    assert client.post("/api/feedback/benign", json={"queue_id": "gmail-abc"}).status_code == 200
    exported = client.get("/api/feedback/export").json()
    assert exported["indicators"]

    admin_token = store.create_session(admin.id)
    client.cookies.set("seg_session", admin_token)
    r = client.post("/api/feedback/import", json={"pack": exported})
    assert r.status_code == 200, r.text
    assert r.json()["indicators"]


def test_viewer_cannot_label(tmp_path):
    client, store, _user, _admin, _pack = _client(tmp_path)
    viewer = store.create_user("view1", TEST_PASSWORD, "viewer")
    client.cookies.set("seg_session", store.create_session(viewer.id))
    r = client.post("/api/feedback/benign", json={"queue_id": "gmail-abc"})
    assert r.status_code == 403
