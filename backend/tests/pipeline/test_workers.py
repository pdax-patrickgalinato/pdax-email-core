"""Background sender-profile ingest and inconclusive LLM retry."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from backend.stores import ai_assess
import workers
from workers.pipeline.correlation import BehavioralCorrelationStore
from backend.stores.sender_profile_ingest import ingest_spool_profiles


def _dest(root: Path, qid: str, meta: dict, eml: bytes = b"From: a@b.com\n\nHi\n") -> Path:
    d = root / "gmail" / qid
    d.mkdir(parents=True)
    (d / "message.eml").write_bytes(eml)
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return d


def test_ingest_learns_clean_skips_malicious_and_duplicates(tmp_path):
    store = BehavioralCorrelationStore(db_path=tmp_path / "beh.sqlite3")
    spool = tmp_path / "spool"
    _dest(spool, "gmail-clean", {
        "from": "alice@yahoo.com", "verdict": "CLEAN", "message_id": "<c@x>",
        "mailbox": "jan@pdax.ph",
        "to": "jan@pdax.ph",
        "subject": "hello",
        "stages": {"origin_ip": {"asn": "AS1", "country": "US", "network_role": "esp", "ip": "1.1.1.1"}},
    })
    _dest(spool, "gmail-bad", {
        "from": "evil@x.com", "verdict": "MALICIOUS", "message_id": "<m@x>",
        "mailbox": "jan@pdax.ph",
        "to": "jan@pdax.ph",
        "stages": {"origin_ip": {"asn": "AS9", "country": "NL", "network_role": "vpn_proxy", "ip": "9.9.9.9"}},
    })
    first = ingest_spool_profiles(store, spool, limit=20)
    assert first["inserted"] == 1
    assert store.profile_for("alice@yahoo.com")["n"] == 1
    assert store.profile_for("evil@x.com")["n"] == 0
    alice = store.behavior_for("alice@yahoo.com")
    assert alice["volume"]["sent_count"] >= 1
    assert "jan@pdax.ph" in {p["value"] for p in alice["sent_to"]}
    evil = store.behavior_for("evil@x.com")
    assert evil["volume"]["sent_count"] >= 1
    second = ingest_spool_profiles(store, spool, limit=20)
    assert second["inserted"] == 0


def test_ingest_marks_sent_lure_identity_ineligible(tmp_path):
    store = BehavioralCorrelationStore(db_path=tmp_path / "beh.sqlite3")
    spool = tmp_path / "spool"
    store.record_observation(
        "support@pdax.ph", ["8.8.8.8"], [], verdict="MALICIOUS",
        message_id="<sent-lure@pdax.ph>",
    )
    _dest(spool, "gmail-sent", {
        "from": "support@pdax.ph",
        "verdict": "MALICIOUS",
        "message_id": "<sent-lure@pdax.ph>",
        "mailbox": "support@pdax.ph",
        "gmail_labels": ["SENT"],
        "reasons": ["forwarded_lure"],
        "stages": {"content_ai": {"flags": ["forwarded_lure"], "nlu_intent": "bec"}},
    })
    out = ingest_spool_profiles(store, spool, limit=20)
    assert out["identity_updated"] >= 1
    row = next(r for r in store.list_profiles() if r["sender"] == "support@pdax.ph")
    assert row["assessment"] == "CLEAN"
    assert row["verdicts"]["MALICIOUS"] == 1


def test_dests_inconclusive_skips_pending_and_respects_cap(tmp_path, monkeypatch):
    monkeypatch.setenv("SEG_LLM_ASSESS_TIMEOUT_SECONDS", "120")
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY", "1")
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY_MAX", "2")
    spool = tmp_path / "spool"
    now = time.time()
    _dest(spool, "gmail-pending", {
        "ai_provider": "heuristic", "ai_summary": "",
        "ai_queued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "ai_timed_out": False,
    })
    _dest(spool, "gmail-done", {
        "ai_provider": "glm", "ai_summary": "Looks fine.",
        "ai_timed_out": True,
    })
    timed = _dest(spool, "gmail-stale", {
        "ai_provider": "heuristic", "ai_summary": "",
        "ai_timed_out": True,
        "ai_auto_retry_count": 0,
    })
    capped = _dest(spool, "gmail-capped", {
        "ai_provider": "heuristic", "ai_summary": "",
        "ai_timed_out": True,
        "ai_auto_retry_count": 2,
        "ai_auto_retry_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 3600)),
    })
    found = ai_assess.dests_inconclusive(spool, limit=10, now=now, max_retries=2)
    names = {p.name for p in found}
    assert "gmail-stale" in names
    assert "gmail-pending" not in names
    assert "gmail-done" not in names
    assert "gmail-capped" not in names

    queued = workers.retry_inconclusive_cycle(lambda d: None, spool_root=spool, limit=10)
    assert "gmail-stale" in queued
    meta = json.loads((timed / "meta.json").read_text())
    assert meta["ai_retry_requested"] is True
    assert meta["ai_timed_out"] is False
    assert meta["ai_auto_retry_count"] == 1
    _ = capped


def test_dests_inconclusive_oldest_first(tmp_path, monkeypatch):
    monkeypatch.setenv("SEG_LLM_ASSESS_TIMEOUT_SECONDS", "120")
    spool = tmp_path / "spool"
    now = time.time()
    _dest(spool, "gmail-newer", {
        "ai_provider": "heuristic", "ai_summary": "",
        "ai_timed_out": True,
        "ai_queued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 600)),
        "ai_auto_retry_count": 0,
    })
    _dest(spool, "gmail-older", {
        "ai_provider": "heuristic", "ai_summary": "",
        "ai_timed_out": True,
        "ai_queued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 3600)),
        "ai_auto_retry_count": 0,
    })
    found = ai_assess.dests_inconclusive(spool, limit=1, now=now, max_retries=12)
    assert [p.name for p in found] == ["gmail-older"]


def test_dests_inconclusive_honors_backoff(tmp_path, monkeypatch):
    monkeypatch.setenv("SEG_LLM_ASSESS_TIMEOUT_SECONDS", "120")
    spool = tmp_path / "spool"
    now = time.time()
    _dest(spool, "gmail-hot", {
        "ai_provider": "heuristic", "ai_summary": "",
        "ai_timed_out": True,
        "ai_auto_retry_count": 1,
        "ai_auto_retry_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 10)),
    })
    _dest(spool, "gmail-ready", {
        "ai_provider": "heuristic", "ai_summary": "",
        "ai_timed_out": True,
        "ai_auto_retry_count": 1,
        "ai_auto_retry_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 120)),
    })
    found = ai_assess.dests_inconclusive(spool, limit=10, now=now, max_retries=12)
    assert [p.name for p in found] == ["gmail-ready"]


def test_auto_retry_cooldown_is_short(monkeypatch):
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY", "1")
    assert ai_assess._auto_retry_cooldown_seconds(0) == 0.0
    assert ai_assess._auto_retry_cooldown_seconds(1) == 30.0
    assert ai_assess._auto_retry_cooldown_seconds(2) == 60.0
    assert ai_assess._auto_retry_cooldown_seconds(6) == 10 * 60


def test_profile_cycle_records_status(tmp_path):
    store = BehavioralCorrelationStore(db_path=tmp_path / "beh.sqlite3")
    spool = tmp_path / "spool"
    _dest(spool, "gmail-clean", {
        "from": "alice@yahoo.com", "verdict": "CLEAN", "message_id": "<c@x>",
        "mailbox": "jan@pdax.ph",
        "stages": {"origin_ip": {"asn": "AS1", "country": "US", "network_role": "esp", "ip": "1.1.1.1"}},
    })
    stats = workers.profile_cycle(store, spool, limit=20)
    assert stats["inserted"] == 1
    snap = workers.worker_status()
    assert snap["profile"]["last_ok"] is True
    assert snap["profile"]["last_stats"]["inserted"] == 1
    assert snap["profile"]["cycles"] >= 1
    assert any("learned" in (e.get("summary") or "") for e in snap["events"])


def test_retry_cycle_records_queued(tmp_path, monkeypatch):
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY", "1")
    monkeypatch.setenv("SEG_LLM_ASSESS_TIMEOUT_SECONDS", "120")
    spool = tmp_path / "spool"
    now = time.time()
    _dest(spool, "gmail-stale", {
        "ai_provider": "heuristic", "ai_summary": "",
        "ai_timed_out": True,
        "ai_auto_retry_count": 0,
    })
    queued = workers.retry_inconclusive_cycle(lambda d: None, spool_root=spool, limit=10)
    assert "gmail-stale" in queued
    snap = workers.worker_status()
    assert snap["inconclusive_retry"]["last_stats"]["queued"] == 1
    assert "gmail-stale" in snap["inconclusive_retry"]["last_queued"]


def test_retry_cycle_skips_already_queued(tmp_path, monkeypatch):
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY", "1")
    monkeypatch.setenv("SEG_LLM_ASSESS_TIMEOUT_SECONDS", "120")
    spool = tmp_path / "spool"
    dest = _dest(spool, "gmail-stale", {
        "ai_provider": "heuristic", "ai_summary": "",
        "ai_timed_out": True,
        "ai_auto_retry_count": 0,
    })
    hit = []
    queued = workers.retry_inconclusive_cycle(
        hit.append, spool_root=spool, limit=10, already_queued=lambda d: True,
    )
    assert queued == []
    assert hit == []
    meta = json.loads((dest / "meta.json").read_text())
    assert int(meta.get("ai_auto_retry_count") or 0) == 0


def test_workers_disabled_by_default_in_tests():
    os.environ["SEG_PROFILE_WORKER"] = "0"
    os.environ["SEG_INCONCLUSIVE_RETRY"] = "0"
    os.environ["SEG_CAMPAIGN_WORKER"] = "0"
    os.environ["SEG_SENDER_RISK_WORKER"] = "0"
    assert workers.start_profile_worker() is None
    assert workers.start_inconclusive_retry_worker(lambda d: None) is None
    assert workers.start_campaign_worker() is None
    assert workers.start_sender_risk_worker() is None


def test_start_profile_worker_thread(monkeypatch, tmp_path):
    monkeypatch.setenv("SEG_PROFILE_WORKER", "1")
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY", "0")
    monkeypatch.setattr(workers.runtime, "HEARTBEAT_DIR", tmp_path)
    monkeypatch.setattr(workers.runtime, "spool", lambda: tmp_path / "spool")
    workers.stop_workers()
    workers.set_process("api")
    t = workers.start_profile_worker()
    try:
        assert t is not None and t.is_alive()
        snap = workers.worker_status()
        assert snap["profile"]["alive"] is True
        assert snap["profile"]["enabled"] is True
        hb = workers.load_heartbeat("api", max_age=60)
        assert hb is not None
        assert hb["profile"]["alive"] is True
    finally:
        workers.stop_workers()


def test_dedicated_process_reports_slot_alive(monkeypatch, tmp_path):
    monkeypatch.setattr(workers.runtime, "HEARTBEAT_DIR", tmp_path)
    workers.stop_workers()
    workers.set_process("gmail_poll")
    try:
        snap = workers.worker_status()
        assert snap["process"] == "gmail_poll"
        assert snap["gmail_poll"]["alive"] is True
        assert snap["profile"]["alive"] is False
        workers.set_process("content_ai")
        monkeypatch.setattr("workers.content_ai.llm_configured", lambda: False)
        snap = workers.worker_status()
        # Heuristic/offline provider does not start LLM drain threads.
        assert snap["gmail_llm"]["alive"] is False
        workers.set_process("static")
        assert workers.worker_status()["static"]["alive"] is True
        workers.set_process("thread_ai")
        assert workers.worker_status()["thread_ai"]["alive"] is True
        workers.set_process("sender")
        snap = workers.worker_status()
        assert snap["profile"]["alive"] is True
        assert snap["sender_risk"]["alive"] is True
        assert snap["gmail_poll"]["alive"] is False
    finally:
        workers.set_process("unknown")
        workers.stop_workers()


def test_heartbeat_db_roundtrip(tmp_path, monkeypatch):
    from backend.db import connect
    from workers import runtime

    db_path = tmp_path / "heartbeats.sqlite3"
    monkeypatch.setattr(runtime, "is_postgres", lambda: True)
    monkeypatch.setattr(
        runtime, "db_connect",
        lambda *a, **k: connect(db_path, schema=runtime._HEARTBEAT_SCHEMA),
    )
    monkeypatch.setattr(runtime, "HEARTBEAT_DIR", tmp_path / "no-files")
    runtime.set_process("gmail_poll")
    runtime.persist_heartbeat()
    hb = runtime.load_heartbeat("gmail_poll", max_age=60)
    assert hb is not None
    assert hb["source"] == "heartbeat"
    assert hb["gmail_poll"]["alive"] is True
    all_hb = runtime.load_all_heartbeats()
    assert "gmail_poll" in all_hb
    assert all_hb["gmail_poll"]["gmail_poll"]["alive"] is True


def test_heartbeat_prefers_fresher_db_row(tmp_path, monkeypatch):
    from backend.db import connect
    from workers import runtime

    db_path = tmp_path / "heartbeats.sqlite3"
    files = tmp_path / "files"
    files.mkdir()
    stale = files / "gmail_poll.json"
    stale.write_text(
        '{"process":"gmail_poll","gmail_poll":{"alive":false,"cycles":1}}',
        encoding="utf-8",
    )
    past = time.time() - 45
    os.utime(stale, (past, past))
    conn = connect(db_path, schema=runtime._HEARTBEAT_SCHEMA)
    runtime._upsert_heartbeat_row(
        conn, "gmail_poll",
        {"process": "gmail_poll", "gmail_poll": {"alive": True, "cycles": 9}},
        time.time(),
    )
    conn.close()
    monkeypatch.setattr(runtime, "is_postgres", lambda: True)
    monkeypatch.setattr(
        runtime, "db_connect",
        lambda *a, **k: connect(db_path, schema=runtime._HEARTBEAT_SCHEMA),
    )
    monkeypatch.setattr(runtime, "HEARTBEAT_DIR", files)
    hb = runtime.load_heartbeat("gmail_poll", max_age=60)
    assert hb["gmail_poll"]["cycles"] == 9
    assert hb["gmail_poll"]["alive"] is True


def test_health_server_skips_receiver_and_unknown():
    from workers import health, runtime
    health.stop_health_server()
    runtime.set_process("unknown")
    assert health.start_health_server(port=0) is None
    runtime.set_process("gmail_receiver")
    assert health.start_health_server(port=0) is None
    runtime.set_process("api")
    assert health.start_health_server(port=0) is None


def test_health_server_serves_status(monkeypatch):
    import json
    import urllib.error
    import urllib.request
    from workers import health, runtime

    health.stop_health_server()
    runtime.set_process("gmail_poll")
    srv = health.start_health_server(port=0)
    assert srv is not None
    port = health.listen_port()
    try:
        body = None
        for _ in range(30):
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/health", timeout=1
                ) as resp:
                    assert resp.status == 200
                    body = json.loads(resp.read().decode("utf-8"))
                    break
            except OSError:
                time.sleep(0.05)
        assert body is not None
        assert body["ok"] is True
        assert body["process"] == "gmail_poll"
        assert body["gmail_poll"]["alive"] is True
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/gmail_poll/health", timeout=1
        ) as resp:
            prefixed = json.loads(resp.read().decode("utf-8"))
        assert prefixed["ok"] is True
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/static/health", timeout=1)
        assert err.value.code == 404
        from backend.api.routers import workers as workers_router
        probed = workers_router.probe_split_workers(
            base=f"http://127.0.0.1:{port}", timeout=1,
        )
        assert probed["gmail_poll"]["gmail_poll"]["alive"] is True
        assert "static" not in probed
    finally:
        health.stop_health_server()
        runtime.set_process("unknown")


def test_sender_health_serves_profile_and_risk_aliases():
    import json
    import urllib.request
    from workers import health, runtime

    health.stop_health_server()
    runtime.set_process("sender")
    srv = health.start_health_server(port=0)
    assert srv is not None
    port = health.listen_port()
    try:
        body = None
        for _ in range(30):
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/health", timeout=1
                ) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                    break
            except OSError:
                time.sleep(0.05)
        assert body["process"] == "sender"
        assert body["profile"]["alive"] is True
        assert body["sender_risk"]["alive"] is True
        for path in ("/sender/health", "/profile/health", "/sender_risk/health"):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=1) as resp:
                assert json.loads(resp.read().decode("utf-8"))["ok"] is True
    finally:
        health.stop_health_server()
        runtime.set_process("unknown")

