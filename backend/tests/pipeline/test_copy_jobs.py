"""Static checks then AI."""
from __future__ import annotations

import json
from pathlib import Path

from backend.stores import assessments as store
from workers.copy_jobs import finished


def test_jobs_queue_is_durable(tmp_path):
    from workers import jobs
    dest = tmp_path / "gmail-x"
    dest.mkdir()
    jobs.put("static", dest)
    jobs.put("static", dest)
    assert jobs.pending_count("static") == 1
    got = jobs.take("static")
    assert Path(got).name == "gmail-x"
    assert jobs.take("static") is None


def test_static_process_iterates_attachments(tmp_path, monkeypatch):
    from email.mime.application import MIMEApplication
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from workers.static import process

    msg = MIMEMultipart()
    msg["From"] = "a@example.com"
    msg["To"] = "b@pdax.ph"
    msg["Subject"] = "file"
    msg.attach(MIMEText("hi"))
    part = MIMEApplication(b"hello", _subtype="octet-stream")
    part.add_header("Content-Disposition", "attachment", filename="note.txt")
    msg.attach(part)
    dest = tmp_path / "gmail-att"
    dest.mkdir()
    (dest / "message.eml").write_bytes(msg.as_bytes())
    (dest / "meta.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr("workers.copy_jobs.finished", lambda *a, **k: None)
    monkeypatch.setattr("workers.static.record_stages", lambda *a, **k: None)
    process(dest)
    row = store.get_copy("gmail-att")
    assert row is not None
    assert row["status"] == store.STATIC


def test_static_finished_enqueues_ai(tmp_path, monkeypatch):
    dest = tmp_path / "gmail" / "gmail-x"
    dest.mkdir(parents=True)
    (dest / "message.eml").write_bytes(b"From: a@b.com\n\nHi\n")
    (dest / "meta.json").write_text(json.dumps({"queue_id": "gmail-x"}), encoding="utf-8")
    store.upsert_copy("gmail-x", dest=str(dest))
    queued = []
    monkeypatch.setattr("workers.content_ai.llm_configured", lambda: True)
    monkeypatch.setattr("workers.content_ai.enqueue", queued.append)
    finished(dest, "static")
    assert queued == [dest]
    row = store.get_copy("gmail-x")
    assert store.static_complete(row)
    assert row["status"] == store.AI
    from workers import jobs
    assert jobs.pending_count("intel") == 0


def test_static_finished_is_complete_without_llm(tmp_path, monkeypatch):
    dest = tmp_path / "gmail" / "gmail-y"
    dest.mkdir(parents=True)
    store.upsert_copy("gmail-y", dest=str(dest))
    monkeypatch.setattr("workers.content_ai.llm_configured", lambda: False)
    monkeypatch.setattr("workers.content_ai.enqueue", lambda dest: None)
    finished(dest, "static")
    assert store.get_copy("gmail-y")["status"] == store.COMPLETE


def test_jobs_lease_reclaims_stale_claim(tmp_path, monkeypatch):
    from workers import jobs
    monkeypatch.setenv("SEG_JOB_LEASE_SECONDS", "30")
    dest = tmp_path / "gmail-lease"
    dest.mkdir()
    jobs.put("static", dest)
    first = jobs.take("static")
    assert Path(first).name == "gmail-lease"
    assert jobs.take("static") is None
    import sqlite3
    conn = sqlite3.connect(str(jobs.db_path()))
    conn.execute("UPDATE jobs SET claimed_at = 1 WHERE kind = 'static'")
    conn.commit()
    conn.close()
    again = jobs.take("static")
    assert Path(again).name == "gmail-lease"
    jobs.ack("static", dest)
    assert jobs.take("static") is None


def test_jobs_reclaim_claim_from_dead_pid(tmp_path, monkeypatch):
    from workers import jobs
    dest = tmp_path / "gmail-orphan"
    dest.mkdir()
    jobs.put("static", dest)
    first = jobs.take("static", claimant="99999999:static-0")
    assert Path(first).name == "gmail-orphan"
    monkeypatch.setenv("SEG_JOB_LEASE_SECONDS", "1800")
    again = jobs.take("static")
    assert Path(again).name == "gmail-orphan"
    jobs.ack("static", dest)


def test_static_unreadable_eml_is_terminal(tmp_path):
    from workers.static import process
    dest = tmp_path / "gmail-bad"
    dest.mkdir()
    (dest / "meta.json").write_text("{}", encoding="utf-8")
    process(dest)
    row = store.get_copy("gmail-bad")
    assert row["status"] == store.DEAD_LETTER
    assert "unreadable" in (row.get("last_error") or "")


def test_recover_deadlocks_requeues_static(tmp_path, monkeypatch):
    import workers.copy_jobs as copy_jobs
    from workers import jobs

    dest = tmp_path / "gmail-deadlock"
    dest.mkdir()
    (dest / "message.eml").write_bytes(b"From: a@b.com\n\nHi\n")
    store.upsert_copy(
        "gmail-deadlock", dest=str(dest), static_done=0,
        status=store.ERROR, last_error="deadlock detected",
    )
    monkeypatch.setattr("backend.stores.spool.use_s3", lambda: False)
    n = copy_jobs.recover_deadlocks(10)
    assert n == 1
    assert store.get_copy("gmail-deadlock")["status"] == store.QUEUED
    got = jobs.take("static")
    assert Path(got).name == "gmail-deadlock"


def test_static_skips_when_already_complete(tmp_path, monkeypatch):
    from workers.static import process

    dest = tmp_path / "gmail-done"
    dest.mkdir()
    (dest / "message.eml").write_bytes(b"From: a@b.com\n\nHi\n")
    (dest / "meta.json").write_text("{}", encoding="utf-8")
    store.upsert_copy("gmail-done", dest=str(dest), static_done=1, status=store.AI)
    acked = []
    ran = []
    monkeypatch.setattr("workers.copy_jobs.ack", lambda kind, d: acked.append(d))
    monkeypatch.setattr("workers.static._process_locked", lambda *a, **k: ran.append(True))
    process(dest)
    assert acked == [dest]
    assert ran == []


def test_static_defers_when_lock_held(tmp_path, monkeypatch):
    from workers.static import process

    dest = tmp_path / "gmail-busy"
    dest.mkdir()
    (dest / "message.eml").write_bytes(b"From: a@b.com\n\nHi\n")
    (dest / "meta.json").write_text("{}", encoding="utf-8")
    store.upsert_copy("gmail-busy", dest=str(dest), static_done=0, status=store.QUEUED)
    assert store.try_lock("static:gmail-busy", "other-task", ttl_seconds=60) is True
    deferred = []
    ran = []
    monkeypatch.setattr("workers.copy_jobs.defer", lambda kind, d: deferred.append(d))
    monkeypatch.setattr("workers.static._process_locked", lambda *a, **k: ran.append(True))
    process(dest)
    assert deferred == [dest]
    assert ran == []


def test_reuse_fanout_copies_sibling_assessment(tmp_path):
    from workers.content_ai import _reuse_fanout
    src = tmp_path / "gmail-src"
    dst = tmp_path / "gmail-dst"
    for d, qid in ((src, "gmail-src"), (dst, "gmail-dst")):
        d.mkdir()
        (d / "message.eml").write_bytes(b"From: a@b.com\nMessage-ID: <same@x>\n\nHi\n")
        (d / "meta.json").write_text(json.dumps({
            "queue_id": qid, "message_id": "<same@x>",
        }), encoding="utf-8")
    store.upsert_copy(
        "gmail-src", dest=str(src), rfc_message_id="<same@x>",
        ai_done=1, ai_provider="glm", ai_summary="Phish.", ai_model="glm-5.2",
        verdict="SUSPICIOUS", score=40, status=store.COMPLETE,
        stages_json=json.dumps({"content_ai": {"summary": "Phish.", "provider": "glm"}}),
    )
    store.upsert_copy("gmail-dst", dest=str(dst), rfc_message_id="<same@x>")
    meta = json.loads((dst / "meta.json").read_text(encoding="utf-8"))
    assert _reuse_fanout(dst, meta) is True
    row = store.get_copy("gmail-dst")
    assert row["ai_summary"] == "Phish."
    assert row["ai_provider"] == "glm"
    assert row["status"] == store.COMPLETE


def test_fail_dead_letters_after_max_attempts(tmp_path, monkeypatch):
    from workers import jobs
    from workers.copy_jobs import fail

    dest = tmp_path / "gmail-retry"
    dest.mkdir()
    monkeypatch.setenv("SEG_JOB_MAX_ATTEMPTS", "2")
    store.upsert_copy("gmail-retry", dest=str(dest))
    jobs.put("static", dest)
    jobs.take("static")
    fail(dest, "static", "boom")
    assert store.get_copy("gmail-retry")["status"] == store.ERROR
    assert jobs.pending_count("static") == 1
    jobs.take("static")
    fail(dest, "static", "boom again")
    assert store.get_copy("gmail-retry")["status"] == store.DEAD_LETTER
    assert jobs.take("static") is None


def test_thread_ai_ready_requires_two_assessed_copies(tmp_path):
    store.upsert_copy(
        "gmail-a", dest=str(tmp_path / "a"), gmail_thread_id="thr-1", ai_done=1,
    )
    assert store.thread_ai_ready("thr-1") is False
    store.upsert_copy(
        "gmail-b", dest=str(tmp_path / "b"), gmail_thread_id="thr-1", ai_done=1,
    )
    assert store.thread_ai_ready("thr-1") is True


def test_list_awaiting_thread_ai():
    store.upsert_copy("gmail-a", gmail_thread_id="t1", ai_done=1, thread_ai_done=0, status=store.COMPLETE)
    store.upsert_copy("gmail-b", gmail_thread_id="t1", ai_done=1, thread_ai_done=0, status=store.COMPLETE)
    store.upsert_copy("gmail-c", gmail_thread_id="t2", ai_done=1, thread_ai_done=0, status=store.COMPLETE)
    store.upsert_copy("gmail-d", gmail_thread_id="t3", ai_done=0, status=store.AI)
    store.upsert_copy("gmail-e", gmail_thread_id="t3", ai_done=1, status=store.COMPLETE)
    assert store.list_awaiting_thread_ai(10) == ["t1"]


def test_list_missing_thread_id_prefers_assessed():
    store.upsert_copy("gmail-old", gmail_thread_id="", ai_done=1, status=store.COMPLETE)
    store.upsert_copy("gmail-new", gmail_thread_id="", ai_done=0, status=store.AI)
    store.upsert_copy("gmail-ok", gmail_thread_id="t1", ai_done=1, status=store.COMPLETE)
    missing = [r["queue_id"] for r in store.list_missing_thread_id(10)]
    assert missing[0] == "gmail-old"
    assert "gmail-new" in missing
    assert "gmail-ok" not in missing


def test_content_ai_worker_reenqueues_on_retry(tmp_path, monkeypatch):
    from workers import content_ai as cai

    dest = tmp_path / "gmail-x"
    dest.mkdir()
    queued = []
    n = {"n": 0}

    def wait_for(kind):
        n["n"] += 1
        if n["n"] == 1:
            return dest
        cai.runtime.stop.set()
        return None

    monkeypatch.setattr(cai.copy_jobs, "wait_for", wait_for)
    monkeypatch.setattr(cai, "enrich", lambda d: "retry")
    monkeypatch.setattr(cai, "enqueue", queued.append)
    monkeypatch.setattr(cai.jobs, "ack", lambda *a, **k: None)
    cai._worker()
    assert queued == [dest]


def test_content_ai_worker_survives_retry_bookkeeping_failure(tmp_path, monkeypatch):
    from workers import content_ai as cai

    cai.runtime.stop.clear()
    dest = {"queue_id": "gmail-x", "bucket": "gmail"}
    n = {"n": 0}

    def wait_for(kind):
        n["n"] += 1
        if n["n"] == 1:
            return dest
        cai.runtime.stop.set()
        return None

    monkeypatch.setattr(cai.copy_jobs, "wait_for", wait_for)
    monkeypatch.setattr(cai, "enrich", lambda d: (_ for _ in ()).throw(TypeError("resolve")))
    monkeypatch.setattr(cai, "_retry_or_dead", lambda *a, **k: (_ for _ in ()).throw(TypeError("meta.json")))
    monkeypatch.setattr(cai, "enqueue", lambda d: None)
    acked = []
    monkeypatch.setattr(cai.copy_jobs, "ack", lambda kind, d: acked.append(d))
    cai._worker()
    assert acked == [dest]


def test_content_ai_worker_skips_enrich_when_claim_lost(monkeypatch):
    from workers import content_ai as cai

    cai.runtime.stop.clear()
    dest = {"queue_id": "gmail-dup", "bucket": "gmail"}
    n = {"n": 0}
    enriched = []

    def wait_for(kind):
        n["n"] += 1
        if n["n"] == 1:
            return dest
        cai.runtime.stop.set()
        return None

    monkeypatch.setattr(cai.copy_jobs, "wait_for", wait_for)
    monkeypatch.setattr(cai.store, "try_claim_ai", lambda *a, **k: False)
    monkeypatch.setattr(cai, "enrich", lambda d: enriched.append(d) or "ok")
    acked = []
    monkeypatch.setattr(cai.copy_jobs, "ack", lambda kind, d: acked.append(d))
    cai._worker()
    assert acked == [dest]
    assert enriched == []


def test_enqueue_pending_skips_when_backfill_lock_held(monkeypatch):
    from workers import content_ai as cai

    assert store.try_lock("content_ai_backfill", "other-task", ttl_seconds=60) is True
    monkeypatch.setattr(cai, "llm_configured", lambda: True)
    queued = []
    monkeypatch.setattr(cai, "enqueue", queued.append)
    store.upsert_copy(
        "gmail-x", dest="/tmp/x", static_done=1, ai_done=0, status=store.AI,
    )
    assert cai.enqueue_pending(limit=10) == 0
    assert queued == []


def test_enqueue_pending_s3_uses_payloads(monkeypatch):
    from backend.stores import spool
    from workers import content_ai as cai

    queued = []
    monkeypatch.setattr(cai, "llm_configured", lambda: True)
    monkeypatch.setattr(cai, "enqueue", queued.append)
    monkeypatch.setattr(cai, "already_queued", lambda dest: False)
    monkeypatch.setattr(spool, "use_s3", lambda: True)
    monkeypatch.setattr(spool, "read_meta", lambda dest: {"ai_provider": "", "ai_summary": ""})
    store.upsert_copy(
        "gmail-x",
        dest=json.dumps(spool.payload("gmail-x")),
        static_done=1,
        ai_done=0,
        status=store.AI,
    )
    n = cai.enqueue_pending(limit=10)
    assert n == 1
    assert spool.dest_name(queued[0]) == "gmail-x"


def test_enqueue_pending_skips_when_sqs_has_work(monkeypatch):
    from workers import content_ai as cai

    monkeypatch.setattr(cai, "llm_configured", lambda: True)
    monkeypatch.setattr("workers.sqs.use_sqs", lambda: True)
    monkeypatch.setattr(cai.jobs, "pending_count", lambda kind="": 10)
    queued = []
    monkeypatch.setattr(cai, "enqueue", queued.append)
    assert cai.enqueue_pending(limit=10) == 0
    assert queued == []


def test_thread_ai_enqueue_pending_and_process(monkeypatch):
    from backend.stores import spool
    from workers import thread_ai as tai

    queued = []
    monkeypatch.setattr(tai.copy_jobs, "put", lambda kind, tid: queued.append(tid))
    store.upsert_copy(
        "gmail-a", dest=json.dumps(spool.payload("gmail-a")),
        gmail_thread_id="thr-9", ai_done=1, verdict="CLEAN", status=store.COMPLETE,
    )
    store.upsert_copy(
        "gmail-b", dest=json.dumps(spool.payload("gmail-b")),
        gmail_thread_id="thr-9", ai_done=1, verdict="SUSPICIOUS", status=store.COMPLETE,
    )
    metas = {
        "gmail-a": {
            "gmail_thread_id": "thr-9", "from": "a@x", "subject": "Hi",
            "verdict": "CLEAN", "ts": "1",
        },
        "gmail-b": {
            "gmail_thread_id": "thr-9", "from": "b@x", "subject": "Re: Hi",
            "verdict": "SUSPICIOUS", "ts": "2",
        },
    }
    written = []
    monkeypatch.setattr(spool, "use_s3", lambda: True)
    monkeypatch.setattr(
        spool, "read_meta",
        lambda dest: dict(metas.get(spool.dest_name(dest)) or {}),
    )
    monkeypatch.setattr(
        spool, "write_meta",
        lambda dest, meta: written.append((spool.dest_name(dest), dict(meta))),
    )
    assert tai.enqueue_pending(limit=10) == 1
    assert queued == ["thr-9"]
    tai.process("thr-9")
    assert store.get_copy("gmail-a")["thread_ai_done"] == 1
    assert store.get_copy("gmail-b")["thread_ai_done"] == 1
    assert any((m[1].get("thread_verdict") == "SUSPICIOUS") for m in written)


def test_thread_ai_skips_when_already_done(monkeypatch):
    from workers import thread_ai as tai

    store.upsert_copy(
        "gmail-a", gmail_thread_id="thr-done", ai_done=1, thread_ai_done=1, status=store.COMPLETE,
    )
    store.upsert_copy(
        "gmail-b", gmail_thread_id="thr-done", ai_done=1, thread_ai_done=1, status=store.COMPLETE,
    )
    acked = []
    ran = []
    monkeypatch.setattr(tai.copy_jobs, "ack", lambda kind, d: acked.append(d))
    monkeypatch.setattr(tai, "_process_locked", lambda *a, **k: ran.append(True))
    tai.process("thr-done")
    assert acked == ["thr-done"]
    assert ran == []


def test_thread_ai_defers_when_lock_held(monkeypatch):
    from workers import thread_ai as tai

    store.upsert_copy(
        "gmail-a", gmail_thread_id="thr-busy", ai_done=1, thread_ai_done=0, status=store.COMPLETE,
    )
    store.upsert_copy(
        "gmail-b", gmail_thread_id="thr-busy", ai_done=1, thread_ai_done=0, status=store.COMPLETE,
    )
    assert store.try_lock("thread_ai:thr-busy", "other-task", ttl_seconds=60) is True
    deferred = []
    ran = []
    monkeypatch.setattr(tai.copy_jobs, "defer", lambda kind, d: deferred.append(d))
    monkeypatch.setattr(tai, "_process_locked", lambda *a, **k: ran.append(True))
    tai.process("thr-busy")
    assert deferred == ["thr-busy"]
    assert ran == []


def test_thread_ai_hydrates_empty_gmail_thread_id(monkeypatch):
    from backend.stores import spool
    from workers import thread_ai as tai

    queued = []
    monkeypatch.setattr(tai.copy_jobs, "put", lambda kind, tid: queued.append(tid))
    store.upsert_copy(
        "gmail-a", dest=json.dumps(spool.payload("gmail-a")),
        gmail_thread_id="", ai_done=1, verdict="CLEAN", status=store.COMPLETE,
    )
    store.upsert_copy(
        "gmail-b", dest=json.dumps(spool.payload("gmail-b")),
        gmail_thread_id="", ai_done=1, verdict="LOW", status=store.COMPLETE,
    )
    metas = {
        "gmail-a": {"gmail_thread_id": "thr-hydrate"},
        "gmail-b": {"gmail_thread_id": "thr-hydrate"},
    }
    monkeypatch.setattr(spool, "use_s3", lambda: True)
    monkeypatch.setattr(
        spool, "read_meta",
        lambda dest: dict(metas.get(spool.dest_name(dest)) or {}),
    )
    assert tai.enqueue_pending(limit=10) == 1
    assert queued == ["thr-hydrate"]
    assert store.get_copy("gmail-a")["gmail_thread_id"] == "thr-hydrate"
    assert store.get_copy("gmail-b")["gmail_thread_id"] == "thr-hydrate"


def test_enqueue_incomplete_skips_s3_head(tmp_path, monkeypatch):
    from workers import copy_jobs

    dest = tmp_path / "gmail-wait"
    dest.mkdir()
    (dest / "message.eml").write_bytes(b"From: a@b.com\n\nHi\n")
    store.upsert_copy("gmail-wait", dest=str(dest), static_done=0, status=store.QUEUED)
    queued = []
    monkeypatch.setattr(copy_jobs.spool, "use_s3", lambda: True)
    monkeypatch.setattr(
        copy_jobs.spool, "exists",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("poll/static must not HeadObject")),
    )
    monkeypatch.setattr(copy_jobs.spool, "payload", lambda qid, bucket="gmail": {"queue_id": qid, "bucket": bucket})
    monkeypatch.setattr(copy_jobs, "put", lambda kind, dest: queued.append((kind, dest)))
    assert copy_jobs.enqueue_incomplete(limit=10) == 1
    assert queued == [("static", {"queue_id": "gmail-wait", "bucket": "gmail"})]


def test_enqueue_incomplete_skips_when_sqs_has_work(monkeypatch):
    from workers import copy_jobs

    store.upsert_copy("gmail-wait", static_done=0, status=store.QUEUED)
    queued = []
    monkeypatch.setattr("workers.sqs.use_sqs", lambda: True)
    monkeypatch.setattr(copy_jobs.jobs, "pending_count", lambda kind="": 12)
    monkeypatch.setattr(copy_jobs, "put", lambda kind, dest: queued.append((kind, dest)))
    assert copy_jobs.enqueue_incomplete(limit=10) == 0
    assert queued == []
