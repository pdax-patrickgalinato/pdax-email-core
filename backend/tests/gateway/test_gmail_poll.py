"""Gmail outbound poll — cursor store and mailbox scan (no Pub/Sub push)."""
from __future__ import annotations

import json
from pathlib import Path

from workers import receiver as gr


class _FakeHistory:
    def __init__(self, payload):
        self._payload = payload

    def list(self, **kwargs):
        return self

    def execute(self):
        return self._payload


class _FakeUsers:
    def __init__(self, profile_history_id, history_payload, inbox_ids=None):
        self.profile_history_id = profile_history_id
        self.history_payload = history_payload
        self.inbox_ids = inbox_ids or []
        self.history_calls = []
        self.list_calls = []

    def getProfile(self, userId):
        hid = self.profile_history_id

        class _P:
            def execute(_self):
                return {"historyId": hid}
        return _P()

    def history(self):
        parent = self

        class _H:
            def list(_self, **kwargs):
                parent.history_calls.append(kwargs)
                return _FakeHistory(parent.history_payload)
        return _H()

    def messages(self):
        parent = self

        class _M:
            def list(_self, **kwargs):
                parent.list_calls.append(kwargs)
                payload = {"messages": [{"id": i} for i in parent.inbox_ids]}
                return _FakeHistory(payload)
        return _M()


class _FakeService:
    def __init__(self, users):
        self._users = users

    def users(self):
        return self._users


def test_first_poll_seeds_recent_inbox_then_sets_cursor(tmp_path: Path):
    db = tmp_path / "cursors.sqlite3"
    users = _FakeUsers("100", {"historyId": "100", "history": []}, inbox_ids=["m-old"])
    scanned = []
    out = gr.poll_mailbox(
        "a@pdax.ph",
        service=_FakeService(users),
        scan=lambda u, m: scanned.append(m) or {"verdict": "CLEAN", "action": "read-only"},
        db_path=db,
    )
    assert out["initialized"] is True
    assert out["processed"] == 1
    assert scanned == ["m-old"]
    assert gr.get_cursor("a@pdax.ph", db_path=db) == "100"
    assert users.history_calls == []
    assert users.list_calls[0]["labelIds"] == ["INBOX"]


def test_first_poll_empty_inbox_still_initializes(tmp_path: Path):
    db = tmp_path / "cursors.sqlite3"
    users = _FakeUsers("100", {"historyId": "100", "history": []}, inbox_ids=[])
    scanned = []
    out = gr.poll_mailbox(
        "a@pdax.ph",
        service=_FakeService(users),
        scan=lambda u, m: scanned.append(m) or {"verdict": "CLEAN", "action": "read-only"},
        db_path=db,
    )
    assert out["initialized"] is True
    assert out["processed"] == 0
    assert scanned == []
    assert gr.get_cursor("a@pdax.ph", db_path=db) == "100"


def test_second_poll_scans_new_inbox_messages(tmp_path: Path):
    db = tmp_path / "cursors.sqlite3"
    gr.set_cursor("a@pdax.ph", "100", db_path=db)
    history = {
        "historyId": "120",
        "history": [
            {"messagesAdded": [{"message": {"id": "m1"}}, {"message": {"id": "m2"}}]},
        ],
    }
    users = _FakeUsers("120", history)
    scanned = []

    def scan(user, msg_id):
        scanned.append(msg_id)
        return {"verdict": "CLEAN", "action": "none"}

    out = gr.poll_mailbox(
        "a@pdax.ph",
        service=_FakeService(users),
        scan=scan,
        db_path=db,
    )
    assert out["processed"] == 2
    assert scanned == ["m1", "m2"]
    assert gr.get_cursor("a@pdax.ph", db_path=db) == "120"
    assert users.history_calls[0]["startHistoryId"] == "100"

    out2 = gr.poll_mailbox(
        "a@pdax.ph",
        service=_FakeService(users),
        scan=scan,
        db_path=db,
    )
    assert out2["processed"] == 0


def test_label_names_are_read_from_gmail(tmp_path: Path):
    class _Labels:
        def list(self, userId):
            return self

        def execute(self):
            return {"labels": [
                {"id": "INBOX", "name": "INBOX"},
                {"id": "Label_1", "name": "Newsletters"},
            ]}

    class _Users:
        def labels(self):
            return _Labels()

    class _Svc:
        def users(self):
            return _Users()

    names = gr._label_names(_Svc(), "a@pdax.ph", ["INBOX", "Label_1", "UNREAD"])
    assert names == ["INBOX", "Newsletters", "UNREAD"]


def test_persist_gmail_scan_writes_console_copy(tmp_path: Path):
    from types import SimpleNamespace

    from backend.models import Verdict

    result = SimpleNamespace(
        verdict=Verdict.LOW,
        disposition=SimpleNamespace(value="LOG"),
        composite_score=12.0,
        hard_override=None,
        reasons=["bulk_sender"],
        subject="Hello",
        from_header="News <news@example.com>",
        message_id="<mid@example.com>",
    )
    qid = gr.persist_gmail_scan(
        "jan.almazora@pdax.ph", "abc123",
        b"From: a\nMessage-ID: <mid@example.com>\nIn-Reply-To: <parent@example.com>\n\nbody",
        result,
        ["INBOX", "UNREAD"], spool_root=tmp_path,
        gmail_thread_id="thread-xyz",
    )
    dest = tmp_path / "gmail" / qid
    assert (dest / "message.eml").is_file()
    meta = json.loads((dest / "meta.json").read_text())
    assert meta["mailbox"] == "jan.almazora@pdax.ph"
    assert meta["verdict"] == "LOW"
    assert meta["gmail_labels"] == ["INBOX", "UNREAD"]
    assert "to" in meta
    assert meta["ai_summary"] == ""
    assert meta["ai_llm_attempted"] is False
    assert meta.get("ai_queued_at")
    assert meta["gmail_thread_id"] == "thread-xyz"
    assert meta["in_reply_to"] == "<parent@example.com>"


def test_persist_gmail_pending_skips_pipeline(tmp_path: Path):
    qid = gr.persist_gmail_pending(
        "jan.almazora@pdax.ph", "abc-pending",
        b"From: News <news@example.com>\nSubject: Hello\nTo: jan@pdax.ph\n\nbody",
        ["INBOX", "UNREAD"], spool_root=tmp_path,
        gmail_thread_id="thread-xyz",
    )
    dest = tmp_path / "gmail" / qid
    meta = json.loads((dest / "meta.json").read_text())
    assert meta["verdict"] == ""
    assert meta["score"] is None
    assert meta["subject"] == "Hello"
    assert "news@example.com" in meta["from"].lower()
    assert meta["to"] == "jan@pdax.ph"
    assert meta["gmail_labels"] == ["INBOX", "UNREAD"]
    assert meta["gmail_thread_id"] == "thread-xyz"
    assert meta.get("ai_queued_at")
    assert meta["ai_provider"] == ""
    assert (dest / "message.eml").is_file()
    from backend.stores import assessments as store
    row = store.get_copy(qid)
    assert row is not None
    assert row["status"] == store.QUEUED
    store.set_status(qid, store.STATIC)
    gr.persist_gmail_pending(
        "jan.almazora@pdax.ph", "abc-pending",
        b"From: News <news@example.com>\nSubject: Hello\nTo: jan@pdax.ph\n\nbody",
        ["INBOX", "UNREAD"], spool_root=tmp_path,
        gmail_thread_id="thread-xyz",
    )
    assert store.get_copy(qid)["status"] == store.STATIC


def test_scan_message_does_not_run_pipeline(tmp_path: Path, monkeypatch):
    import base64
    from workers import gmail as gmail_mod

    raw = b"From: News <news@example.com>\nSubject: Hello\nTo: jan@pdax.ph\n\nbody\n"
    queued = []

    class _Messages:
        def get(self, **kwargs):
            class _E:
                def execute(_self):
                    return {
                        "raw": base64.urlsafe_b64encode(raw).decode().rstrip("="),
                        "labelIds": ["INBOX"],
                        "threadId": "thr-1",
                    }
            return _E()

    class _Labels:
        def list(self, userId):
            return self

        def execute(self):
            return {"labels": [{"id": "INBOX", "name": "INBOX"}]}

    class _Users:
        def messages(self):
            return _Messages()

        def labels(self):
            return _Labels()

    class _Svc:
        def users(self):
            return _Users()

    monkeypatch.setenv("SEG_QUARANTINE_ROOT", str(tmp_path))
    monkeypatch.setattr(gmail_mod, "build_gmail_service", lambda user: _Svc())
    monkeypatch.setattr("workers.copy_jobs.enqueue_static", queued.append)

    def _boom(*a, **k):
        raise AssertionError("poll must not run the pipeline")

    monkeypatch.setattr("workers.pipeline.runner.run_pipeline", _boom)
    out = gmail_mod.scan_message("jan@pdax.ph", "mid-1")
    assert out["action"] == "queued"
    assert out["verdict"] == ""
    dest = tmp_path / "gmail" / out["queue_id"]
    meta = json.loads((dest / "meta.json").read_text())
    assert meta["verdict"] == ""
    assert meta["subject"] == "Hello"
    assert queued == [dest]


def test_scan_message_skips_dead_letter(tmp_path: Path, monkeypatch):
    import base64
    from workers import gmail as gmail_mod
    from backend.stores import assessments as store

    raw = b"From: a@b.com\nSubject: x\n\nbody\n"
    queued = []

    class _Messages:
        def get(self, **kwargs):
            class _E:
                def execute(_self):
                    return {
                        "raw": base64.urlsafe_b64encode(raw).decode().rstrip("="),
                        "labelIds": ["INBOX"],
                        "threadId": "thr-1",
                    }
            return _E()

    class _Labels:
        def list(self, userId):
            return self

        def execute(self):
            return {"labels": [{"id": "INBOX", "name": "INBOX"}]}

    class _Users:
        def messages(self):
            return _Messages()

        def labels(self):
            return _Labels()

    class _Svc:
        def users(self):
            return _Users()

    monkeypatch.setenv("SEG_QUARANTINE_ROOT", str(tmp_path))
    monkeypatch.setattr(gmail_mod, "build_gmail_service", lambda user: _Svc())
    monkeypatch.setattr("workers.copy_jobs.enqueue_static", queued.append)
    qid = gmail_mod._gmail_queue_id("mid-dead")
    store.upsert_copy(qid, dest=str(tmp_path / "gmail" / qid), status=store.DEAD_LETTER)
    out = gmail_mod.scan_message("jan@pdax.ph", "mid-dead")
    assert out["action"] == "queued"
    assert queued == []
    assert store.get_copy(qid)["status"] == store.DEAD_LETTER


def test_persist_gmail_scan_stores_content_ai(tmp_path: Path):
    from types import SimpleNamespace

    from backend.models import StageResult, StageStatus, Verdict

    result = SimpleNamespace(
        verdict=Verdict.CLEAN,
        disposition=SimpleNamespace(value="LOG"),
        composite_score=4.0,
        hard_override=None,
        reasons=[],
        subject="Hello",
        from_header="News <news@example.com>",
        to_header="jan@pdax.ph",
        message_id="<mid@example.com>",
        threat_class="none",
        threat_confidence=0.1,
        stages=[
            StageResult(
                stage="content_ai",
                status=StageStatus.OK,
                sub_score=8.0,
                facts={"provider": "glm", "model_id": "deepseek-ai/deepseek-r1-0528-maas",
                       "summary": "Looks like a routine newsletter.",
                       "is_forwarded": False, "footer_worth_assessing": False,
                       "primary_content": "Welcome to the list.",
                       "thread_summary": "Single-message thread, no hijack.",
                       "thread_verdict": "CLEAN"},
            ),
        ],
    )
    qid = gr.persist_gmail_scan(
        "jan.almazora@pdax.ph", "abc123", b"From: a\n\nbody", result,
        ["INBOX"], spool_root=tmp_path,
    )
    meta = json.loads((tmp_path / "gmail" / qid / "meta.json").read_text())
    assert meta["ai_summary"] == "Looks like a routine newsletter."
    assert meta["ai_provider"] == "glm"
    assert meta["ai_model"] == "deepseek-ai/deepseek-r1-0528-maas"
    assert meta["ai_llm_attempted"] is True
    assert meta["threat_class"] == "none"
    assert meta["is_forwarded"] is False
    assert meta["primary_content"] == "Welcome to the list."
    assert meta["thread_summary"] == "Single-message thread, no hijack."
    assert meta["thread_verdict"] == "CLEAN"
    assert "content_ai" in meta["stages"]
    assert meta["stages"]["content_ai"]["score"] == 8.0
    assert meta["stages"]["content_ai"]["provider"] == "glm"
    from backend.stores import assessments as store
    assert store.get_copy(qid)["status"] == store.COMPLETE


class _StubLLM:
    def analyze(self, subject, body, context):
        return 8.0, [], {"provider": "glm", "summary": "Benign operational mail."}


def test_enrich_gmail_dest_writes_llm_summary(tmp_path: Path, monkeypatch):
    from types import SimpleNamespace

    from backend.models import Verdict

    result = SimpleNamespace(
        verdict=Verdict.CLEAN,
        disposition=SimpleNamespace(value="LOG"),
        composite_score=3.0,
        hard_override=None,
        reasons=[],
        subject="Hello",
        from_header="a@example.com",
        to_header="",
        message_id="<mid@example.com>",
    )
    qid = gr.persist_gmail_scan(
        "jan.almazora@pdax.ph", "mid1", b"From: a@example.com\nSubject: Hello\n\nbody",
        result, ["INBOX"], spool_root=tmp_path,
    )
    dest = tmp_path / "gmail" / qid
    monkeypatch.setattr(gr, "_llm_configured", lambda: True)
    monkeypatch.setattr(gr._content_ai, "get_default_provider", lambda: _StubLLM())
    gr._enrich_gmail_dest(dest)
    meta = json.loads((dest / "meta.json").read_text())
    assert meta["ai_provider"] == "glm"
    assert "Benign" in meta["ai_summary"]
    assert meta["ai_llm_attempted"] is True


def test_enrich_gmail_dest_passes_thread_transcript(tmp_path: Path, monkeypatch):
    from types import SimpleNamespace

    from backend.models import StageResult, StageStatus, Verdict

    heuristic = SimpleNamespace(
        verdict=Verdict.CLEAN,
        disposition=SimpleNamespace(value="LOG"),
        composite_score=3.0,
        hard_override=None,
        reasons=[],
        subject="Invoice",
        from_header="alice@pdax.ph",
        to_header="",
        message_id="<root@x>",
        threat_class="none",
        threat_confidence=0.0,
        stages=[],
    )
    gr.persist_gmail_scan(
        "jan@pdax.ph", "root-mid",
        b"From: alice@pdax.ph\nSubject: Invoice\n\nPlease see attached.\n",
        heuristic, ["INBOX"], spool_root=tmp_path, gmail_thread_id="thr-9",
    )
    qid = gr.persist_gmail_scan(
        "jan@pdax.ph", "reply-mid",
        b"From: phish@evil.test\nSubject: Re: Invoice\n\nWire today.\n",
        heuristic, ["INBOX"], spool_root=tmp_path, gmail_thread_id="thr-9",
    )
    dest = tmp_path / "gmail" / qid
    captured = []
    llm_result = SimpleNamespace(
        verdict=Verdict.SUSPICIOUS,
        disposition=SimpleNamespace(value="LOG"),
        composite_score=50.0,
        hard_override=None,
        reasons=[],
        subject="Re: Invoice",
        from_header="phish@evil.test",
        to_header="",
        message_id="<reply@x>",
        threat_class="bec",
        threat_confidence=0.8,
        stages=[
            StageResult(
                stage="content_ai",
                status=StageStatus.OK,
                sub_score=50.0,
                facts={
                    "provider": "glm",
                    "summary": "Payment redirect on a real thread.",
                    "thread_summary": "Clean invoice then hijack.",
                    "thread_verdict": "SUSPICIOUS",
                },
            ),
        ],
    )

    def fake_run(raw, extra_context=None):
        captured.append(extra_context)
        return llm_result

    monkeypatch.setattr("workers.content_ai._run_llm_pipeline", fake_run)
    gr._enrich_gmail_dest(dest)
    assert captured and captured[0] and captured[0].get("thread")
    transcript = captured[0]["thread"]["transcript"]
    assert "CURRENT MESSAGE" in transcript
    assert "alice@pdax.ph" in transcript
    root_meta = json.loads((tmp_path / "gmail" / "gmail-root-mid" / "meta.json").read_text())
    assert root_meta["thread_verdict"] == "SUSPICIOUS"
    assert "hijack" in root_meta["thread_summary"].lower()


def test_enrich_gmail_dest_marks_timeout(tmp_path: Path, monkeypatch):
    from types import SimpleNamespace

    from backend.models import Verdict

    result = SimpleNamespace(
        verdict=Verdict.CLEAN,
        disposition=SimpleNamespace(value="LOG"),
        composite_score=3.0,
        hard_override=None,
        reasons=[],
        subject="Hello",
        from_header="a@example.com",
        to_header="",
        message_id="<mid-timeout@example.com>",
        stages=[],
    )
    qid = gr.persist_gmail_scan(
        "jan.almazora@pdax.ph", "mid-timeout", b"From: a@example.com\nSubject: Hello\n\nbody",
        result, ["INBOX"], spool_root=tmp_path,
    )
    dest = tmp_path / "gmail" / qid
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY", "0")
    monkeypatch.setattr("workers.content_ai._assess_from_joined", lambda *_a, **_k: result)
    gr._enrich_gmail_dest(dest)
    out = json.loads((dest / "meta.json").read_text())
    assert out["ai_timed_out"] is True


def test_enrich_gmail_dest_auto_retries_after_timeout(tmp_path: Path, monkeypatch):
    from types import SimpleNamespace

    from backend.models import Verdict

    result = SimpleNamespace(
        verdict=Verdict.CLEAN,
        disposition=SimpleNamespace(value="LOG"),
        composite_score=3.0,
        hard_override=None,
        reasons=[],
        subject="Hello",
        from_header="a@example.com",
        to_header="",
        message_id="<mid-autoretry@example.com>",
    )
    qid = gr.persist_gmail_scan(
        "jan.almazora@pdax.ph", "mid-autoretry", b"From: a@example.com\nSubject: Hello\n\nbody",
        result, ["INBOX"], spool_root=tmp_path,
    )
    dest = tmp_path / "gmail" / qid
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY", "1")

    def _timeout(*_a, **_k):
        raise TimeoutError("slot hung")

    monkeypatch.setattr("workers.content_ai._assess_from_joined", _timeout)
    outcome = gr._enrich_gmail_dest(dest)
    out = json.loads((dest / "meta.json").read_text())
    assert outcome == "retry"
    assert out["ai_timed_out"] is False
    assert out["ai_retry_requested"] is True
    assert out["ai_auto_retry_count"] == 1


def test_enrich_gmail_dest_runs_after_display_wait_expires(tmp_path: Path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace

    from backend.models import Verdict

    result = SimpleNamespace(
        verdict=Verdict.CLEAN,
        disposition=SimpleNamespace(value="LOG"),
        composite_score=3.0,
        hard_override=None,
        reasons=[],
        subject="Hello",
        from_header="a@example.com",
        to_header="",
        message_id="<mid1@example.com>",
    )
    qid = gr.persist_gmail_scan(
        "jan.almazora@pdax.ph", "mid1", b"From: a@example.com\nSubject: Hello\n\nbody",
        result, ["INBOX"], spool_root=tmp_path,
    )
    dest = tmp_path / "gmail" / qid
    meta = json.loads((dest / "meta.json").read_text())
    meta["ai_queued_at"] = (datetime.now(timezone.utc) - timedelta(minutes=3)).isoformat()
    meta["ai_timed_out"] = True
    (dest / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    monkeypatch.setattr(gr, "_llm_configured", lambda: True)
    monkeypatch.setattr(gr._content_ai, "get_default_provider", lambda: _StubLLM())
    gr._enrich_gmail_dest(dest)
    out = json.loads((dest / "meta.json").read_text())
    assert "Benign" in out["ai_summary"]
    assert out.get("ai_timed_out") is False


def test_needs_llm_assessment_skips_completed():
    assert gr._needs_llm_assessment({"ai_provider": "heuristic"}) is True
    assert gr._needs_llm_assessment({"ai_provider": "glm"}) is True
    assert gr._needs_llm_assessment({
        "ai_provider": "glm", "ai_summary": "Looks benign.",
    }) is False
    assert gr._needs_llm_assessment({
        "ai_llm_attempted": True, "ai_provider": "heuristic",
        "ai_summary": "Bulk newsletter.",
    }) is True
    assert gr._needs_llm_assessment({
        "ai_llm_attempted": True, "ai_provider": "glm", "ai_summary": "",
    }) is True


def test_needs_llm_assessment_times_out():
    from datetime import datetime, timedelta, timezone
    old = (datetime.now(timezone.utc) - timedelta(minutes=3)).isoformat()
    assert gr._needs_llm_assessment({
        "ai_provider": "heuristic", "ai_queued_at": old,
    }) is False
    assert gr._needs_llm_assessment({
        "ai_provider": "heuristic", "ai_queued_at": old, "ai_retry_requested": True,
    }) is True
    fresh = datetime.now(timezone.utc).isoformat()
    assert gr._needs_llm_assessment({
        "ai_provider": "heuristic", "ai_queued_at": fresh,
    }) is True


def test_enqueue_pending_includes_timed_out_oldest_first(tmp_path: Path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    queued = []
    monkeypatch.setattr("workers.content_ai.llm_configured", lambda: True)
    monkeypatch.setattr("workers.content_ai.already_queued", lambda dest: False)
    monkeypatch.setattr("workers.content_ai.enqueue", queued.append)
    gmail = tmp_path / "gmail"
    gmail.mkdir()
    old = datetime.now(timezone.utc) - timedelta(hours=2)
    newer = datetime.now(timezone.utc) - timedelta(minutes=10)
    for qid, ts in (("gmail-old", old), ("gmail-mid", newer)):
        dest = gmail / qid
        dest.mkdir()
        (dest / "message.eml").write_bytes(b"From: a@x\n\nbody\n")
        (dest / "meta.json").write_text(json.dumps({
            "ai_provider": "heuristic", "ai_summary": "",
            "ai_timed_out": True,
            "ai_queued_at": ts.isoformat(),
        }), encoding="utf-8")
    live = gmail / "gmail-live"
    live.mkdir()
    (live / "message.eml").write_bytes(b"From: a@x\n\nbody\n")
    (live / "meta.json").write_text(json.dumps({
        "ai_provider": "heuristic", "ai_summary": "",
        "ai_queued_at": datetime.now(timezone.utc).isoformat(),
    }), encoding="utf-8")
    n = gr.enqueue_pending_gmail_llm(spool_root=tmp_path, limit=10)
    assert n == 3
    assert queued[0].name == "gmail-live"
    assert [p.name for p in queued[1:]] == ["gmail-old", "gmail-mid"]


def test_poll_all_skips_when_previous_cycle_running(tmp_path: Path, monkeypatch):
    import threading

    from workers import gmail as gmail_io

    started = threading.Event()
    release = threading.Event()
    calls = []

    def slow_poll(user, db_path=None):
        calls.append(user)
        started.set()
        assert release.wait(timeout=3)
        return {"user": user, "processed": 0}

    monkeypatch.setattr(gmail_io, "_monitored_users", lambda: ["a@pdax.ph"])
    monkeypatch.setattr(gmail_io, "poll_mailbox", slow_poll)
    t = threading.Thread(
        target=lambda: gmail_io.poll_all_mailboxes(db_path=tmp_path / "c.db"),
        daemon=True,
    )
    t.start()
    assert started.wait(timeout=3)
    assert gmail_io.poll_all_mailboxes(db_path=tmp_path / "c.db") == []
    release.set()
    t.join(timeout=3)
    assert not t.is_alive()
    assert calls == ["a@pdax.ph"]


def test_poll_cycle_records_elapsed_and_mailbox_count(tmp_path: Path, monkeypatch):
    import workers as workers_mod
    from workers import gmail as gmail_io

    seen = []

    def fake_poll(user, db_path=None):
        seen.append(user)
        return {"user": user, "processed": 1}

    monkeypatch.setattr(gmail_io, "_monitored_users", lambda: ["a@pdax.ph", "b@pdax.ph"])
    monkeypatch.setattr(gmail_io, "poll_mailbox", fake_poll)
    monkeypatch.setattr(gmail_io, "_POLL_WORKERS", 1)
    backfill = []
    monkeypatch.setattr(
        "workers.copy_jobs.enqueue_incomplete",
        lambda limit=50: backfill.append("static") or 0,
    )
    monkeypatch.setattr(
        "workers.content_ai.enqueue_pending",
        lambda limit=50: backfill.append("llm") or 0,
    )
    out = workers_mod.poll_cycle(tmp_path / "c.db")
    assert [r["user"] for r in out] == ["a@pdax.ph", "b@pdax.ph"]
    assert seen == ["a@pdax.ph", "b@pdax.ph"]
    assert backfill == []
    stats = workers_mod.worker_status()["gmail_poll"]["last_stats"]
    assert stats["mailboxes"] == 2
    assert stats["processed"] == 2
    assert stats["static_queued"] == 2
    assert stats["llm_queued"] == 0
    assert "elapsed_seconds" in stats


def test_poll_unlocked_skips_non_workspace_mailboxes(tmp_path: Path, monkeypatch):
    from workers import gmail as gmail_io

    seen = []
    monkeypatch.setenv("SEG_GMAIL_DOMAIN", "pdax.ph")
    monkeypatch.setattr(
        gmail_io, "_monitored_users",
        lambda: ["jan@pdax.ph", "ops@fireblocks.com", "me@gmail.com"],
    )
    monkeypatch.setattr(
        gmail_io, "_poll_one_mailbox",
        lambda user, db_path: seen.append(user) or {"user": user, "processed": 0},
    )
    monkeypatch.setattr(gmail_io, "_POLL_WORKERS", 1)
    out = gmail_io.poll_unlocked(db_path=tmp_path / "c.db")
    assert [r["user"] for r in out] == ["jan@pdax.ph"]
    assert seen == ["jan@pdax.ph"]


def test_poll_cycle_skips_gmail_when_fetch_paused(tmp_path: Path, monkeypatch):
    import workers as workers_mod
    from backend.stores import ingest_control

    ingest_control.set_gmail_fetch(False, actor="tester")
    polled = []
    enqueued = []

    monkeypatch.setattr(
        "workers.gmail.poll_unlocked",
        lambda db_path=None: polled.append(db_path) or [],
    )
    monkeypatch.setattr(
        "workers.copy_jobs.enqueue_incomplete",
        lambda limit=50: enqueued.append("static") or 4,
    )
    monkeypatch.setattr(
        "workers.content_ai.enqueue_pending",
        lambda limit=50: enqueued.append("llm") or 2,
    )
    out = workers_mod.poll_cycle(tmp_path / "c.db")
    assert out == []
    assert polled == []
    assert enqueued == []
    stats = workers_mod.worker_status()["gmail_poll"]["last_stats"]
    assert stats["paused"] is True
    assert stats["mailboxes"] == 0
    assert stats["processed"] == 0
    assert stats["static_queued"] == 0
    assert stats["llm_queued"] == 0


def test_enrich_queues_campaign_and_sender_followup(tmp_path: Path, monkeypatch):
    from types import SimpleNamespace

    from backend.models import Verdict
    from workers.followup import pending_counts, take_campaign, take_profiles, take_senders

    result = SimpleNamespace(
        verdict=Verdict.CLEAN,
        disposition=SimpleNamespace(value="LOG"),
        composite_score=3.0,
        hard_override=None,
        reasons=[],
        subject="Hello",
        from_header="vendor@acme.example",
        to_header="jan@pdax.ph",
        message_id="<followup@example.com>",
    )
    qid = gr.persist_gmail_scan(
        "jan@pdax.ph", "followup-mid",
        b"From: vendor@acme.example\nSubject: Hello\n\nbody",
        result, ["INBOX"], spool_root=tmp_path,
    )
    dest = tmp_path / "gmail" / qid
    monkeypatch.setattr(gr._content_ai, "get_default_provider", lambda: _StubLLM())
    gr._enrich_gmail_dest(dest)
    counts = pending_counts()
    assert counts["campaign"] == 1
    assert counts["profile"] == 1
    assert counts["sender_risk"] == 1
    assert take_campaign(5) == [dest]
    assert take_profiles(5) == [dest]
    assert take_senders(5) == ["vendor@acme.example"]


def test_history_list_follows_next_page_token(tmp_path: Path):
    db = tmp_path / "cursors.sqlite3"
    gr.set_cursor("a@pdax.ph", "100", db_path=db)
    pages = [
        {
            "historyId": "130",
            "nextPageToken": "p2",
            "history": [{"messagesAdded": [{"message": {"id": "m1"}}]}],
        },
        {
            "historyId": "130",
            "history": [{"messagesAdded": [{"message": {"id": "m2"}}]}],
        },
    ]

    class _Paging(_FakeUsers):
        def history(self):
            parent = self

            class _H:
                def list(_self, **kwargs):
                    parent.history_calls.append(kwargs)
                    token = kwargs.get("pageToken")
                    return _FakeHistory(pages[1] if token == "p2" else pages[0])
            return _H()

    users = _Paging("130", pages[0])
    scanned = []
    out = gr.poll_mailbox(
        "a@pdax.ph",
        service=_FakeService(users),
        scan=lambda u, m: scanned.append(m) or {"verdict": "CLEAN", "action": "queued"},
        db_path=db,
    )
    assert scanned == ["m1", "m2"]
    assert out["processed"] == 2
    assert users.history_calls[0].get("pageToken") is None
    assert users.history_calls[1]["pageToken"] == "p2"
    assert gr.get_cursor("a@pdax.ph", db_path=db) == "130"


def test_expired_history_reseeds_inbox(tmp_path: Path):
    db = tmp_path / "cursors.sqlite3"
    gr.set_cursor("a@pdax.ph", "100", db_path=db)

    class _Gone(_FakeUsers):
        def history(self):
            parent = self

            class _H:
                def list(_self, **kwargs):
                    parent.history_calls.append(kwargs)

                    class _Boom:
                        def execute(_s):
                            raise Exception("HttpError 404 : requested history id is invalid")
                    return _Boom()
            return _H()

    users = _Gone("200", {}, inbox_ids=["m-seed"])
    scanned = []
    out = gr.poll_mailbox(
        "a@pdax.ph",
        service=_FakeService(users),
        scan=lambda u, m: scanned.append(m) or {"verdict": "CLEAN", "action": "queued"},
        db_path=db,
    )
    assert out.get("reseeded") is True
    assert scanned == ["m-seed"]
    assert gr.get_cursor("a@pdax.ph", db_path=db) == "200"


def test_transient_history_error_keeps_cursor(tmp_path: Path):
    db = tmp_path / "cursors.sqlite3"
    gr.set_cursor("a@pdax.ph", "100", db_path=db)

    class _Down(_FakeUsers):
        def history(self):
            parent = self

            class _H:
                def list(_self, **kwargs):
                    parent.history_calls.append(kwargs)

                    class _Boom:
                        def execute(_s):
                            raise Exception("503 Service Unavailable")
                    return _Boom()
            return _H()

    users = _Down("999", {})
    out = gr.poll_mailbox(
        "a@pdax.ph",
        service=_FakeService(users),
        scan=lambda u, m: {"verdict": "CLEAN"},
        db_path=db,
    )
    assert out["processed"] == 0
    assert "error" in out
    assert gr.get_cursor("a@pdax.ph", db_path=db) == "100"


def test_persist_pending_keeps_retry_state(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SEG_QUARANTINE_ROOT", str(tmp_path))
    from workers import gmail as gmail_io
    dest = tmp_path / "gmail" / "gmail-abc"
    dest.mkdir(parents=True)
    (dest / "message.eml").write_bytes(b"From: a@b.com\nMessage-ID: <1@x>\n\nHi\n")
    (dest / "meta.json").write_text(json.dumps({
        "ai_auto_retry_count": 3,
        "ai_queued_at": "2026-01-01T00:00:00+00:00",
        "ai_summary": "",
        "ai_provider": "",
    }), encoding="utf-8")
    qid = gmail_io.persist_gmail_pending(
        "u@pdax.ph", "abc",
        b"From: a@b.com\nMessage-ID: <1@x>\n\nHi\n",
        ["INBOX"], spool_root=tmp_path,
    )
    meta = json.loads((tmp_path / "gmail" / qid / "meta.json").read_text(encoding="utf-8"))
    assert meta["ai_auto_retry_count"] == 3
    assert meta["ai_queued_at"] == "2026-01-01T00:00:00+00:00"

