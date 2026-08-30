"""GET /api/workers — authenticated worker snapshot."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from starlette.testclient import TestClient

from backend.api.auth_store import AuthStore


def _client(role="analyst"):
    from fastapi import FastAPI
    from backend.api.routers import workers as workers_module
    import backend.api.deps as deps_module

    auth = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = auth
    user = auth.create_user("testuser", "Password123!", role)
    app = FastAPI()
    app.include_router(workers_module.router)
    client = TestClient(app)
    token = auth.create_session(user.id)
    client.cookies.set("seg_session", token)
    return client


def test_workers_requires_auth():
    from fastapi import FastAPI
    from backend.api.routers import workers as workers_module

    app = FastAPI()
    app.include_router(workers_module.router)
    with TestClient(app) as client:
        assert client.get("/api/workers").status_code == 401


def test_workers_snapshot_shape():
    os.environ["SEG_PROFILE_WORKER"] = "0"
    os.environ["SEG_INCONCLUSIVE_RETRY"] = "0"
    with patch("backend.api.routers.workers.probe_receiver", return_value={
        "process": "gmail_receiver",
        "reachable": False,
        "error": "connection refused",
        "events": [],
    }):
        client = _client()
        body = client.get("/api/workers").json()
    assert "api" in body
    assert "receiver" in body
    assert body["receiver"]["reachable"] is False
    assert "profile" in body["api"]
    assert "inconclusive_retry" in body["api"]
    assert "campaign" in body["api"]
    assert "ops" in body
    assert "spool" in body["ops"]
    assert "config" in body["ops"]
    assert body["ops"]["gmail_fetch"] is True
    assert "queues" in body
    assert body["queues"]["static"]["waiting"] == 0
    assert body["receiver"]["static"]["queue_waiting"] == 0
    assert isinstance(body["events"], list)


def test_workers_merges_receiver_events():
    with patch("backend.api.routers.workers.probe_receiver", return_value={
        "process": "gmail_receiver",
        "reachable": True,
        "users": 7,
        "profile": {"alive": True, "enabled": True},
        "inconclusive_retry": {"alive": True, "last_stats": {"queued": 2}},
        "gmail_poll": {"alive": True, "last_stats": {"processed": 3, "mailboxes": 7}},
        "events": [{"ts": 9, "process": "gmail_receiver", "worker": "gmail_poll",
                    "ok": True, "summary": "scanned 3 messages"}],
    }):
        client = _client()
        body = client.get("/api/workers").json()
    assert body["receiver"]["reachable"] is True
    assert body["receiver"]["users"] == 7
    assert any(e.get("summary") == "scanned 3 messages" for e in body["events"])


def test_merge_standalone_worker_heartbeats():
    from backend.api.routers.workers import merge_standalone_workers

    receiver = {
        "process": "gmail_receiver",
        "reachable": False,
        "source": "probe",
        "error": "connection refused",
        "events": [],
    }
    api = {
        "process": "api",
        "reachable": True,
        "profile": {"alive": False, "enabled": True},
        "campaign": {"alive": False, "enabled": True},
        "sender_risk": {"alive": False, "enabled": True},
        "events": [],
    }
    processes = {
        "gmail_poll": {
            "process": "gmail_poll",
            "heartbeat_age_seconds": 2.5,
            "gmail_poll": {
                "alive": True, "running": False, "last_finished_at": 1,
                "last_stats": {"mailboxes": 4, "processed": 2},
            },
        },
        "content_ai": {
            "process": "content_ai",
            "gmail_llm": {"alive": True, "last_stats": {"queued": 1}},
        },
        "static": {
            "process": "static",
            "static": {"alive": True, "last_finished_at": 1},
        },
        "profile": {
            "process": "profile",
            "profile": {"alive": True, "enabled": True, "cycles": 3},
        },
    }
    rec, local = merge_standalone_workers(receiver, api, processes)
    assert rec["reachable"] is True
    assert rec["source"] == "heartbeat"
    assert rec["gmail_poll"]["alive"] is True
    assert rec["users"] == 4
    assert rec["gmail_llm"]["alive"] is True
    assert rec["static"]["alive"] is True
    assert rec["heartbeat_age_seconds"] == 2.5
    assert local["profile"]["alive"] is True
    assert rec["profile"]["cycles"] == 3


def test_merge_combined_sender_process_fills_both_slots():
    from backend.api.routers.workers import merge_standalone_workers

    rec, local = merge_standalone_workers(
        {"process": "gmail_receiver", "reachable": False},
        {"profile": {"alive": False}, "sender_risk": {"alive": False}},
        {
            "sender": {
                "process": "sender",
                "source": "probe",
                "profile": {"alive": True, "enabled": True, "cycles": 4},
                "sender_risk": {"alive": True, "enabled": True, "cycles": 2},
            },
        },
    )
    assert local["profile"]["alive"] is True
    assert local["sender_risk"]["alive"] is True
    assert rec["profile"]["cycles"] == 4
    assert rec["sender_risk"]["cycles"] == 2


def test_merge_leaves_live_http_receiver_alone():
    from backend.api.routers.workers import merge_standalone_workers

    receiver = {
        "process": "gmail_receiver",
        "reachable": True,
        "source": "probe",
        "gmail_poll": {"alive": True, "last_stats": {"mailboxes": 9}},
        "users": 9,
    }
    rec, _local = merge_standalone_workers(receiver, {}, {
        "gmail_poll": {
            "gmail_poll": {"alive": True, "last_stats": {"mailboxes": 1}},
        },
    })
    assert rec["source"] == "probe"
    assert rec["users"] == 9
    assert rec["gmail_poll"]["last_stats"]["mailboxes"] == 9


def test_merge_ilb_probe_sets_source_probe():
    from backend.api.routers.workers import merge_standalone_workers

    rec, _local = merge_standalone_workers(
        {"process": "gmail_receiver", "reachable": False, "source": "probe", "error": "refused"},
        {},
        {
            "gmail_poll": {
                "process": "gmail_poll",
                "source": "probe",
                "gmail_poll": {"alive": True, "last_finished_at": 1, "last_stats": {"mailboxes": 3}},
            },
        },
    )
    assert rec["reachable"] is True
    assert rec["source"] == "probe"
    assert rec["gmail_poll"]["alive"] is True
    assert rec["users"] == 3


def test_probe_split_workers_empty_without_base(monkeypatch):
    from backend.api.routers import workers as workers_router

    monkeypatch.delenv("SEG_WORKER_HEALTH_BASE_URL", raising=False)
    assert workers_router.probe_split_workers() == {}


def test_probe_receiver_skips_localhost_when_ilb_configured(monkeypatch):
    from backend.api.routers import workers as workers_router

    monkeypatch.setenv("SEG_WORKER_HEALTH_BASE_URL", "http://workers.internal")
    out = workers_router.probe_receiver()
    assert out["source"] == "skipped"
    assert out["reachable"] is False


def test_workers_api_prefers_ilb_probe():
    from backend.api.routers import workers as workers_router

    with patch("backend.api.routers.workers.probe_receiver", return_value={
        "process": "gmail_receiver",
        "reachable": False,
        "source": "probe",
        "error": "connection refused",
        "events": [],
    }), patch("backend.api.routers.workers.probe_split_workers", return_value={
        "gmail_poll": {
            "process": "gmail_poll",
            "source": "probe",
            "gmail_poll": {
                "alive": True, "last_finished_at": 1,
                "last_stats": {"mailboxes": 5, "processed": 2},
            },
        },
        "static": {
            "process": "static",
            "source": "probe",
            "static": {"alive": True, "last_finished_at": 1},
        },
    }):
        client = _client()
        body = client.get("/api/workers").json()
    assert body["receiver"]["reachable"] is True
    assert body["receiver"]["source"] == "probe"
    assert body["receiver"]["gmail_poll"]["alive"] is True
    assert body["receiver"]["users"] == 5
    assert body["processes"]["static"]["static"]["alive"] is True


def test_probe_falls_back_to_heartbeat(tmp_path, monkeypatch):
    import workers as workers_mod
    from backend.api.routers import workers as workers_router

    monkeypatch.setattr(workers_mod.runtime, "HEARTBEAT_DIR", tmp_path)
    (tmp_path / "gmail_receiver.json").write_text(
        '{"process":"gmail_receiver","profile":{"alive":true,"enabled":true},'
        '"inconclusive_retry":{"alive":true},"gmail_poll":{"alive":true,'
        '"last_stats":{"mailboxes":7,"processed":3}},'
        '"events":[{"ts":1,"summary":"from heartbeat","ok":true,'
        '"process":"gmail_receiver","worker":"gmail_poll"}]}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        workers_router,
        "_http_probe",
        lambda url, timeout=0.8: {
            "process": "gmail_receiver",
            "reachable": False,
            "source": "probe",
            "error": "connection refused",
        },
    )
    out = workers_router.probe_receiver()
    assert out["source"] == "heartbeat"
    assert out["reachable"] is True
    assert out["profile"]["alive"] is True
    assert out["events"][0]["summary"] == "from heartbeat"


def test_queue_snapshot_counts_jobs_and_pipeline():
    from workers import jobs, followup
    from backend.stores import assessments as store
    from backend.api.routers.workers import attach_queues, attach_queues_to_processes, queue_snapshot

    jobs.put("static", "/tmp/static-a")
    jobs.put("static", "/tmp/static-b")
    jobs.put("content_ai", "/tmp/ai-a")
    jobs.put("thread_ai", "thread-1")
    followup._put("campaign", dest="/tmp/camp")
    followup._put("profile", dest="/tmp/camp")
    followup._put("sender_risk", sender="alice@example.com")
    store.upsert_copy("q1")
    store.upsert_copy("s1", status=store.STATIC)
    store.upsert_copy("a1", status=store.AI)
    store.upsert_copy("a2", status=store.AI)
    store.upsert_copy("t1", status=store.TIMED_OUT)

    q = queue_snapshot()
    assert q["static"]["waiting"] == 2
    assert q["static"]["running"] == 1
    assert q["content_ai"]["waiting"] == 1
    assert q["content_ai"]["running"] == 1
    assert q["thread_ai"]["waiting"] == 1
    assert q["campaign"]["waiting"] == 1
    assert q["profile"]["waiting"] == 1
    assert q["sender_risk"]["waiting"] == 1
    assert q["retry"]["waiting"] == 1
    assert q["poll"]["waiting"] == 1
    assert q["pipeline"]["queued"] == 1
    assert q["pipeline"]["ai"] == 2
    assert q["intel"]["waiting"] == 0
    assert q["alerts"] == []

    rec, api = attach_queues(
        {"static": {"alive": True, "running": True}, "gmail_llm": {"alive": True}},
        {},
        q,
    )
    assert rec["static"]["queue_waiting"] == 2
    assert rec["static"]["queue_running"] == 1
    assert rec["gmail_llm"]["queue_waiting"] == 1
    assert rec["gmail_llm"]["queue_running"] == 1
    assert api["campaign"]["queue_waiting"] == 1

    procs = attach_queues_to_processes(
        {
            "static": {"process": "static", "source": "probe", "reachable": True, "static": {"alive": True}},
            "content_ai": {"process": "content_ai", "source": "probe", "gmail_llm": {"alive": True}},
            "sender": {
                "process": "sender",
                "source": "probe",
                "profile": {"alive": True},
                "sender_risk": {"alive": True},
            },
        },
        q,
    )
    assert procs["static"]["static"]["queue_waiting"] == 2
    assert procs["content_ai"]["gmail_llm"]["queue_waiting"] == 1
    assert procs["sender"]["profile"]["queue_waiting"] == 1
    assert procs["sender"]["sender_risk"]["queue_waiting"] == 1


def test_queue_snapshot_sqs_running_is_in_flight_not_pipeline_residual(monkeypatch):
    from backend.stores import assessments as store
    from backend.api.routers.workers import queue_snapshot

    store.upsert_copy("a1", status=store.AI)
    store.upsert_copy("a2", status=store.AI)
    store.upsert_copy("a3", status=store.AI)
    monkeypatch.setattr("workers.sqs.use_sqs", lambda: True)
    monkeypatch.setattr(
        "workers.jobs.pending_counts",
        lambda: {"static": 0, "content_ai": 80, "thread_ai": 0, "intel": 0},
    )
    monkeypatch.setattr(
        "backend.api.routers.workers.followup_pending_counts",
        lambda: {"campaign": 12, "profile": 0, "sender_risk": 0},
    )
    monkeypatch.setattr(
        "workers.jobs.queue_stats",
        lambda: {
            "static": {"waiting": 0, "claimed": 0, "stale": 0, "oldest_claim_age": 0},
            "content_ai": {"waiting": 80, "claimed": 1, "stale": 0, "oldest_claim_age": 0},
            "thread_ai": {"waiting": 0, "claimed": 0, "stale": 0, "oldest_claim_age": 0},
            "intel": {"waiting": 0, "claimed": 0, "stale": 0, "oldest_claim_age": 0},
            "campaign": {"waiting": 12, "claimed": 2, "stale": 0, "oldest_claim_age": 0},
        },
    )
    q = queue_snapshot()
    assert q["content_ai"]["waiting"] == 80
    assert q["content_ai"]["running"] == 1
    assert q["campaign"]["waiting"] == 12
    assert q["campaign"]["running"] == 2
    assert q["pipeline"]["ai"] == 3


def test_queue_snapshot_sqs_idle_is_zero_not_status_minus_queue(monkeypatch):
    from backend.stores import assessments as store
    from backend.api.routers.workers import queue_snapshot

    store.upsert_copy("a1", status=store.AI)
    store.upsert_copy("a2", status=store.AI)
    monkeypatch.setattr("workers.sqs.use_sqs", lambda: True)
    monkeypatch.setattr(
        "workers.jobs.pending_counts",
        lambda: {"static": 0, "content_ai": 0, "thread_ai": 0, "intel": 0},
    )
    monkeypatch.setattr(
        "workers.jobs.queue_stats",
        lambda: {
            "static": {"waiting": 0, "claimed": 0, "stale": 0, "oldest_claim_age": 0},
            "content_ai": {"waiting": 0, "claimed": 0, "stale": 0, "oldest_claim_age": 0},
            "thread_ai": {"waiting": 0, "claimed": 0, "stale": 0, "oldest_claim_age": 0},
            "intel": {"waiting": 0, "claimed": 0, "stale": 0, "oldest_claim_age": 0},
        },
    )
    q = queue_snapshot()
    assert q["content_ai"]["running"] == 0


def test_queue_snapshot_alerts_dead_letter():
    from backend.stores import assessments as store
    from backend.api.routers.workers import queue_snapshot

    store.upsert_copy("dead-1", status=store.DEAD_LETTER)
    q = queue_snapshot()
    assert q["pipeline"]["dead_letter"] == 1
    assert any(a.get("code") == "dead_letter" for a in q["alerts"])


def test_processor_down_alerts_when_queue_has_work():
    from workers import jobs
    from backend.api.routers.workers import queue_snapshot, _processor_down_alerts

    jobs.put("static", "/tmp/static-orphaned")
    jobs.put("content_ai", "/tmp/ai-orphaned")
    q = queue_snapshot()
    alerts = _processor_down_alerts(q, {"reachable": False}, {})
    codes = {a["code"] for a in alerts}
    assert "static_worker_down" in codes
    assert "content_ai_worker_down" in codes
    live = _processor_down_alerts(
        q,
        {"static": {"alive": True}, "gmail_llm": {"alive": True}},
        {},
    )
    assert live == []


def test_workers_api_includes_queue_depths():
    from workers import jobs
    from backend.stores import assessments as store

    jobs.put("static", "/tmp/static-live")
    store.upsert_copy("live-static", status=store.STATIC)
    with patch("backend.api.routers.workers.probe_receiver", return_value={
        "process": "gmail_receiver",
        "reachable": False,
        "error": "connection refused",
        "events": [],
    }):
        client = _client()
        body = client.get("/api/workers").json()
    assert body["queues"]["static"]["waiting"] == 1
    assert body["queues"]["static"]["running"] == 1
    assert body["receiver"]["static"]["queue_waiting"] == 1
    assert body["receiver"]["static"]["queue_running"] == 1
    assert body["api"]["static"]["queue_waiting"] == 1


def test_workers_api_stamps_queue_depth_on_split_process():
    from workers import jobs

    jobs.put("content_ai", "/tmp/ai-live")
    with patch("backend.api.routers.workers.probe_receiver", return_value={
        "process": "gmail_receiver",
        "reachable": False,
        "error": "connection refused",
        "events": [],
    }), patch("backend.api.routers.workers.probe_split_workers", return_value={
        "content_ai": {
            "process": "content_ai",
            "source": "probe",
            "reachable": True,
            "gmail_llm": {"alive": True, "enabled": True},
        },
    }):
        client = _client()
        body = client.get("/api/workers").json()
    assert body["queues"]["content_ai"]["waiting"] == 1
    assert body["processes"]["content_ai"]["gmail_llm"]["queue_waiting"] == 1
    assert body["processes"]["content_ai"]["gmail_llm"]["queue_waiting"] == body["queues"]["content_ai"]["waiting"]


def test_ssl_context_only_for_https():
    from backend.api.routers import workers as workers_router

    assert workers_router._ssl_context_for("http://workers.internal/static/health") is None
    ctx = workers_router._ssl_context_for("https://workers.internal/static/health")
    assert ctx is not None
    assert ctx.minimum_version.name == "TLSv1_2"