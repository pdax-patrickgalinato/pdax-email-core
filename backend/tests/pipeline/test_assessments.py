"""Pipeline status on assessment copies: queued → static → ai → complete."""
from __future__ import annotations

import time

from backend.stores import assessments as store


def test_advance_status_never_regresses():
    assert store.advance_status(store.QUEUED, store.STATIC) == store.STATIC
    assert store.advance_status(store.STATIC, store.QUEUED) == store.STATIC
    assert store.advance_status(store.STATIC, store.AI) == store.AI
    assert store.advance_status(store.AI, store.QUEUED) == store.AI
    assert store.advance_status(store.AI, store.TIMED_OUT) == store.TIMED_OUT
    assert store.advance_status(store.TIMED_OUT, store.AI) == store.AI
    assert store.advance_status(store.COMPLETE, store.QUEUED) == store.COMPLETE
    assert store.advance_status(store.COMPLETE, store.AI) == store.COMPLETE
    assert store.advance_status(store.TIMED_OUT, store.COMPLETE) == store.COMPLETE


def test_upsert_sets_queued_then_advances():
    store.upsert_copy("gmail-a", dest="/tmp/a")
    assert store.status_of(store.get_copy("gmail-a")) == store.QUEUED
    store.set_status("gmail-a", store.STATIC)
    assert store.get_copy("gmail-a")["status"] == store.STATIC
    store.upsert_copy("gmail-a", status=store.QUEUED)
    assert store.get_copy("gmail-a")["status"] == store.STATIC
    store.upsert_copy("gmail-a", static_done=1, status=store.AI)
    assert store.get_copy("gmail-a")["status"] == store.AI
    store.upsert_copy("gmail-a", ai_done=1, status=store.COMPLETE)
    assert store.get_copy("gmail-a")["status"] == store.COMPLETE


def test_status_of_derives_from_flags_when_blank():
    assert store.status_of(None) == store.QUEUED
    assert store.status_of({"static_done": 1, "ai_done": 0}) == store.AI
    assert store.status_of({"ai_done": 1}) == store.COMPLETE
    assert store.status_of({"status": store.STATIC, "static_done": 0}) == store.STATIC


def test_timeout_and_retry_update_status(tmp_path):
    from backend.stores import ai_assess

    dest = tmp_path / "gmail-z"
    dest.mkdir()
    (dest / "meta.json").write_text("{}", encoding="utf-8")
    store.upsert_copy("gmail-z", dest=str(dest), status=store.AI)
    ai_assess.mark_timed_out(dest)
    assert store.get_copy("gmail-z")["status"] == store.TIMED_OUT
    ai_assess.prepare_retry(dest, auto=True)
    assert store.get_copy("gmail-z")["status"] == store.AI


def test_prepare_retry_accepts_sqs_payload(monkeypatch):
    from backend.stores import ai_assess, spool

    stored = {"ai_auto_retry_count": 1}
    monkeypatch.setattr(spool, "read_meta", lambda dest: dict(stored))

    def write_meta(dest, meta):
        stored.clear()
        stored.update(meta)

    monkeypatch.setattr(spool, "write_meta", write_meta)
    dest = spool.payload("gmail-x")
    meta = ai_assess.prepare_retry(dest, auto=True)
    assert meta["ai_retry_requested"] is True
    assert meta["ai_auto_retry_count"] == 2


def test_wait_started_at_accepts_sqs_payload():
    from backend.stores import ai_assess, spool

    ts = ai_assess.wait_started_at({}, dest=spool.payload("gmail-x"))
    assert ts > 0


def test_status_counts():
    store.upsert_copy("a")
    store.upsert_copy("b", status=store.STATIC)
    store.upsert_copy("c", status=store.AI)
    store.upsert_copy("d", status=store.TIMED_OUT)
    store.upsert_copy("e", status=store.COMPLETE)
    counts = store.status_counts()
    assert counts[store.QUEUED] == 1
    assert counts[store.STATIC] == 1
    assert counts[store.AI] == 1
    assert counts[store.TIMED_OUT] == 1
    assert counts[store.COMPLETE] == 1
    assert counts[store.ERROR] == 0
    assert counts[store.DEAD_LETTER] == 0


def test_overview_stats_is_not_clipped_to_feed_limit():
    for i in range(store.FEED_LIST_LIMIT + 80):
        store.upsert_copy(
            f"gmail-{i}",
            status=store.AI,
            static_done=1,
            ai_done=0,
            verdict="",
        )
    store.upsert_copy(
        "gmail-clean",
        status=store.COMPLETE,
        ai_done=1,
        verdict="CLEAN",
    )
    store.upsert_copy(
        "gmail-mal",
        status=store.COMPLETE,
        ai_done=1,
        verdict="MALICIOUS",
    )
    listed = store.list_feed()
    assert len(listed) == store.FEED_LIST_LIMIT
    stats = store.overview_stats()
    assert stats["total"] == store.FEED_LIST_LIMIT + 82
    assert stats["pending"] == store.FEED_LIST_LIMIT + 80
    assert stats["clean"] == 1
    assert stats["malicious"] == 1
    assert stats["aiPendingTotal"] == store.FEED_LIST_LIMIT + 80
    assert stats["feedLimit"] == store.FEED_LIST_LIMIT
    assert stats["assessed"] == 2
    assert stats["hourly"]


def test_overview_stats_includes_mail_older_than_24h():
    store.upsert_copy(
        "gmail-old-mal", status=store.COMPLETE, ai_done=1, verdict="MALICIOUS",
    )
    store.upsert_copy(
        "gmail-new-clean", status=store.COMPLETE, ai_done=1, verdict="CLEAN",
    )
    conn = store._connect()
    try:
        conn.execute(
            "UPDATE copies SET updated_at = ? WHERE queue_id = ?",
            (time.time() - 5 * 86400, "gmail-old-mal"),
        )
        conn.commit()
    finally:
        conn.close()
    stats = store.overview_stats()
    assert stats["windowSeconds"] == 0
    assert stats["malicious"] == 1
    assert stats["clean"] == 1
    assert stats["total"] == 2
    clipped = store.overview_stats(since_seconds=86400)
    assert clipped["malicious"] == 0
    assert clipped["clean"] == 1
    assert {r["queue_id"] for r in store.list_feed_by_verdict("malicious")} == {
        "gmail-old-mal"
    }


def test_overview_stats_counts_all_time_mailboxes_and_assessments(monkeypatch):
    monkeypatch.setattr(
        "backend.stores.gmail_coverage.snapshot",
        lambda: {"polling": 0, "configured": 0, "discovered": 0, "skipped": 0},
    )
    store.upsert_copy(
        "gmail-jan-1", mailbox="jan@pdax.ph", status=store.COMPLETE,
        ai_done=1, verdict="CLEAN",
    )
    store.upsert_copy(
        "gmail-jan-2", mailbox="JAN@pdax.ph", status=store.COMPLETE,
        ai_done=1, verdict="LOW",
    )
    store.upsert_copy(
        "gmail-support", mailbox="support@pdax.ph", status=store.AI, ai_done=0,
    )
    store.upsert_copy(
        "gmail-legal", mailbox="legal@pdax.ph", status=store.COMPLETE,
        ai_done=1, verdict="SUSPICIOUS", thread_ai_done=1,
    )
    store.upsert_copy(
        "gmail-blank", mailbox="  ", status=store.COMPLETE,
        ai_done=1, verdict="CLEAN",
    )
    conn = store._connect()
    try:
        conn.execute(
            "UPDATE copies SET updated_at = ? WHERE queue_id = ?",
            (time.time() - 40 * 86400, "gmail-legal"),
        )
        conn.commit()
    finally:
        conn.close()
    stats = store.overview_stats()
    assert stats["windowSeconds"] == 0
    assert stats["total"] == 5
    assert stats["assessed"] == 4
    assert stats["threadAssessed"] == 1
    assert stats["mailboxes"] == 3
    assert stats["inboxesMonitored"] == 3
    clipped = store.overview_stats(since_seconds=86400)
    assert clipped["mailboxes"] == 2
    assert clipped["total"] == 4
    assert clipped["assessed"] == 3


def test_overview_stats_cache_skips_repeat_scan_within_ttl():
    store.upsert_copy(
        "gmail-cached", status=store.COMPLETE, ai_done=1, verdict="CLEAN",
    )
    first = store.overview_stats()
    assert first["total"] == 1
    store.upsert_copy(
        "gmail-later", status=store.COMPLETE, ai_done=1, verdict="MALICIOUS",
    )
    cached = store.overview_stats()
    assert cached["total"] == 1
    assert cached["malicious"] == 0
    store.reset()
    store.upsert_copy(
        "gmail-cached", status=store.COMPLETE, ai_done=1, verdict="CLEAN",
    )
    store.upsert_copy(
        "gmail-later", status=store.COMPLETE, ai_done=1, verdict="MALICIOUS",
    )
    fresh = store.overview_stats()
    assert fresh["total"] == 2
    assert fresh["malicious"] == 1


def test_overview_snapshot_matches_live_counts_and_origin_filter():
    """Tiles, map rollup, and ?origin= share one SQL expression over all copies."""
    import json
    from backend.stores.overview import (
        compute_overview_stats,
        origin_country_sql,
        refresh_overview_stats,
    )

    store.upsert_copy(
        "gmail-ph-1",
        status=store.COMPLETE,
        ai_done=1,
        verdict="MALICIOUS",
        disposition="QUARANTINE",
        mailbox="jan@pdax.ph",
        stages_json=json.dumps({
            "origin_ip": {
                "country": "PH", "country_name": "Philippines",
                "city": "Makati", "lat": 14.55, "lon": 121.03,
            },
        }),
    )
    store.upsert_copy(
        "gmail-ph-2",
        status=store.COMPLETE,
        ai_done=1,
        verdict="CLEAN",
        mailbox="support@pdax.ph",
        origin_country="PH",
        origin_name="Philippines",
        origin_city="Quezon City",
        origin_lat=14.7,
        origin_lon=121.0,
    )
    store.upsert_copy(
        "gmail-sg",
        status=store.COMPLETE,
        ai_done=1,
        verdict="SUSPICIOUS",
        mailbox="legal@pdax.ph",
        origin_country="SG",
        origin_name="Singapore",
        origin_lat=1.35,
        origin_lon=103.82,
    )
    store.upsert_copy(
        "gmail-pending",
        status=store.AI,
        ai_done=0,
        mailbox="jan@pdax.ph",
    )
    live = compute_overview_stats(since_seconds=0)
    snap = refresh_overview_stats(since_seconds=0)
    read = store.overview_stats()
    for key in (
        "total", "pending", "clean", "low", "suspicious", "malicious",
        "assessed", "threadAssessed", "mailboxes", "quarantined", "held",
        "aiPendingTotal",
    ):
        assert snap[key] == live[key], key
        assert read[key] == live[key], key
    assert live["total"] == 4
    assert live["assessed"] == 3
    assert live["malicious"] == 1
    assert live["clean"] == 1
    assert live["suspicious"] == 1
    assert live["quarantined"] == 1
    assert live["held"] == 1
    assert live["mailboxes"] == 3
    assert live["origin"]["located"] == 3
    ph = next(c for c in live["origin"]["countries"] if c["country"] == "PH")
    sg = next(c for c in live["origin"]["countries"] if c["country"] == "SG")
    assert ph["count"] == 2
    assert sg["count"] == 1
    assert ph["worst"] == "MALICIOUS"
    listed = store.list_feed()
    assert len(listed) <= store.FEED_LIST_LIMIT
    assert live["total"] > len(listed) or live["total"] == 4
    ph_rows = store.list_feed_page(origin="PH", limit=store.FEED_FILTER_LIMIT)
    assert {r["queue_id"] for r in ph_rows} == {"gmail-ph-1", "gmail-ph-2"}
    assert all((r.get("origin_cc") or r.get("origin_country")) == "PH" for r in ph_rows)
    conn = store._connect()
    try:
        n = conn.execute(
            "SELECT COUNT(*) AS n FROM copies WHERE " + origin_country_sql() + " = ?",
            ("PH",),
        ).fetchone()["n"]
    finally:
        conn.close()
    assert int(n) == ph["count"] == 2


def test_overview_snapshot_stale_falls_back_to_recompute():
    from backend.stores.overview import STALE_SECONDS, refresh_overview_stats

    store.upsert_copy("gmail-a", status=store.COMPLETE, ai_done=1, verdict="CLEAN")
    first = refresh_overview_stats(since_seconds=0)
    assert first["total"] == 1
    store.upsert_copy("gmail-b", status=store.COMPLETE, ai_done=1, verdict="MALICIOUS")
    cached = store.overview_stats()
    assert cached["total"] == 1
    conn = store._connect()
    try:
        conn.execute(
            "UPDATE overview_stats SET computed_at = ? WHERE key = ?",
            (time.time() - STALE_SECONDS - 5, "all"),
        )
        conn.commit()
    finally:
        conn.close()
    fresh = store.overview_stats()
    assert fresh["total"] == 2
    assert fresh["malicious"] == 1


def test_copies_in_thread_scopes_mailbox_and_dedupes_message_id():
    store.upsert_copy(
        "gmail-a", gmail_thread_id="thr-1", mailbox="jan@pdax.ph",
        gmail_message_id="m1", ai_done=1,
    )
    store.upsert_copy(
        "gmail-a-dup", gmail_thread_id="thr-1", mailbox="jan@pdax.ph",
        gmail_message_id="m1", ai_done=1,
    )
    store.upsert_copy(
        "gmail-b", gmail_thread_id="thr-1", mailbox="jan@pdax.ph",
        gmail_message_id="m2", ai_done=1,
    )
    store.upsert_copy(
        "gmail-other", gmail_thread_id="thr-1", mailbox="other@pdax.ph",
        gmail_message_id="m3", ai_done=1,
    )
    jan = store.copies_in_thread("thr-1", mailbox="jan@pdax.ph")
    assert {r["queue_id"] for r in jan} == {"gmail-a-dup", "gmail-b"}
    all_mb = store.copies_in_thread("thr-1")
    assert {r["queue_id"] for r in all_mb} == {"gmail-a-dup", "gmail-b", "gmail-other"}


def test_list_feed_with_thread_siblings_includes_older_turns(monkeypatch):
    monkeypatch.setattr(store, "FEED_LIST_LIMIT", 8)
    store.upsert_copy(
        "gmail-old",
        gmail_thread_id="thr-keep",
        mailbox="jan@pdax.ph",
        gmail_message_id="m-old",
    )
    for i in range(12):
        store.upsert_copy(
            f"gmail-noise-{i}",
            gmail_thread_id=f"noise-{i}",
            mailbox="other@pdax.ph",
        )
    store.upsert_copy(
        "gmail-new",
        gmail_thread_id="thr-keep",
        mailbox="jan@pdax.ph",
        gmail_message_id="m-new",
    )
    page = store.list_feed(limit=8)
    ids = {r["queue_id"] for r in page}
    assert "gmail-new" in ids
    assert "gmail-old" not in ids
    expanded = store.list_feed_with_thread_siblings()
    ids = {r["queue_id"] for r in expanded}
    assert "gmail-new" in ids
    assert "gmail-old" in ids


def test_awaiting_ai_and_assessed_sibling(tmp_path):
    store.upsert_copy(
        "gmail-a", dest=str(tmp_path / "a"), rfc_message_id="<m@x>",
        static_done=1, ai_done=1, ai_provider="glm", ai_summary="ok",
        status=store.COMPLETE,
    )
    store.upsert_copy(
        "gmail-b", dest=str(tmp_path / "b"), rfc_message_id="<m@x>",
        static_done=1, ai_done=0, status=store.AI,
    )
    store.upsert_copy(
        "gmail-c", dest=str(tmp_path / "c"), static_done=0, status=store.STATIC,
    )
    store.upsert_copy(
        "gmail-d", dest=str(tmp_path / "d"), static_done=0, status=store.QUEUED,
    )
    waiting = store.list_awaiting_ai(10)
    assert {r["queue_id"] for r in waiting} == {"gmail-b"}
    sib = store.find_assessed_sibling("<m@x>", "gmail-b")
    assert sib["queue_id"] == "gmail-a"
    assert [r["queue_id"] for r in store.list_incomplete_static(10)] == ["gmail-d"]


def test_try_claim_ai_is_exclusive():
    store.upsert_copy("gmail-x", static_done=1, ai_done=0, status=store.AI)
    assert store.try_claim_ai("gmail-x", "task-a") is True
    assert store.try_claim_ai("gmail-x", "task-b") is False
    row = store.get_copy("gmail-x")
    assert row["ai_claimed_by"] == "task-a"
    store.release_ai_claim("gmail-x")
    assert store.try_claim_ai("gmail-x", "task-b") is True


def test_try_claim_ai_rejects_complete_and_dead_letter():
    store.upsert_copy("gmail-done", ai_done=1, status=store.COMPLETE)
    store.upsert_copy("gmail-dead", static_done=1, ai_done=0, status=store.DEAD_LETTER)
    assert store.try_claim_ai("gmail-done", "t") is False
    assert store.try_claim_ai("gmail-dead", "t") is False


def test_try_claim_ai_expires():
    store.upsert_copy("gmail-x", static_done=1, ai_done=0, status=store.AI)
    assert store.try_claim_ai("gmail-x", "task-a", lease_seconds=30) is True
    import time
    with store._lock:
        conn = store._connect()
        try:
            conn.execute(
                "UPDATE ai_claims SET claimed_at = ? WHERE queue_id = ?",
                (time.time() - 120, "gmail-x"),
            )
            conn.commit()
        finally:
            conn.close()
    assert store.try_claim_ai("gmail-x", "task-b", lease_seconds=30) is True
    assert store.get_copy("gmail-x")["ai_claimed_by"] == "task-b"


def test_list_awaiting_ai_hides_active_claim():
    store.upsert_copy("gmail-free", dest="/tmp/a", static_done=1, ai_done=0, status=store.AI)
    store.upsert_copy("gmail-busy", dest="/tmp/b", static_done=1, ai_done=0, status=store.AI)
    assert store.try_claim_ai("gmail-busy", "task-a") is True
    waiting = {r["queue_id"] for r in store.list_awaiting_ai(10)}
    assert waiting == {"gmail-free"}


def test_try_lock_is_exclusive():
    assert store.try_lock("content_ai_backfill", "a", ttl_seconds=60) is True
    assert store.try_lock("content_ai_backfill", "b", ttl_seconds=60) is False
    store.release_lock("content_ai_backfill", "a")
    assert store.try_lock("content_ai_backfill", "b", ttl_seconds=60) is True


def test_error_does_not_requeue_as_incomplete_static():
    store.upsert_copy("gmail-err", static_done=0, status=store.ERROR, last_error="boom")
    assert store.list_incomplete_static(10) == []


def test_recover_deadlock_copies_resets_error_and_ignores_other_failures():
    store.upsert_copy(
        "gmail-dead", static_done=0, status=store.DEAD_LETTER,
        last_error="psycopg.errors.DeadlockDetected: deadlock detected",
    )
    store.upsert_copy(
        "gmail-static-dead", static_done=1, status=store.ERROR,
        last_error="deadlock detected",
    )
    store.upsert_copy("gmail-boom", static_done=0, status=store.ERROR, last_error="boom")
    recovered = {r["queue_id"]: r for r in store.recover_deadlock_copies(10)}
    assert set(recovered) == {"gmail-dead", "gmail-static-dead"}
    assert recovered["gmail-dead"]["status"] == store.QUEUED
    assert recovered["gmail-static-dead"]["status"] == store.AI
    assert store.get_copy("gmail-dead")["last_error"] == ""
    assert store.get_copy("gmail-boom")["status"] == store.ERROR
    assert store.recover_deadlock_copies(10) == []


def test_in_progress_static_is_not_incomplete():
    store.upsert_copy("gmail-run", static_done=0, status=store.STATIC)
    store.upsert_copy("gmail-ai", static_done=0, status=store.AI)
    store.upsert_copy("gmail-wait", static_done=0, status=store.QUEUED)
    assert [r["queue_id"] for r in store.list_incomplete_static(10)] == ["gmail-wait"]


def test_legacy_db_backfills_status(tmp_path):
    import sqlite3

    path = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE copies (
            queue_id TEXT PRIMARY KEY,
            dest TEXT NOT NULL DEFAULT '',
            mailbox TEXT NOT NULL DEFAULT '',
            gmail_message_id TEXT NOT NULL DEFAULT '',
            gmail_thread_id TEXT NOT NULL DEFAULT '',
            from_addr TEXT NOT NULL DEFAULT '',
            subject TEXT NOT NULL DEFAULT '',
            to_addr TEXT NOT NULL DEFAULT '',
            verdict TEXT NOT NULL DEFAULT '',
            score REAL,
            disposition TEXT NOT NULL DEFAULT 'LOG',
            ai_provider TEXT NOT NULL DEFAULT '',
            ai_summary TEXT NOT NULL DEFAULT '',
            ai_model TEXT NOT NULL DEFAULT '',
            identity_done INTEGER NOT NULL DEFAULT 0,
            reputation_done INTEGER NOT NULL DEFAULT 0,
            static_done INTEGER NOT NULL DEFAULT 0,
            sandbox_done INTEGER NOT NULL DEFAULT 0,
            ai_done INTEGER NOT NULL DEFAULT 0,
            thread_ai_done INTEGER NOT NULL DEFAULT 0,
            stages_json TEXT NOT NULL DEFAULT '{}',
            meta_json TEXT NOT NULL DEFAULT '{}',
            updated_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO copies (queue_id, static_done, ai_done, updated_at) VALUES (?, 1, 0, 1)",
        ("gmail-mid",),
    )
    conn.execute(
        "INSERT INTO copies (queue_id, static_done, ai_done, updated_at) VALUES (?, 1, 1, 1)",
        ("gmail-done",),
    )
    conn.commit()
    conn.close()
    store.set_db_path(path)
    assert store.get_copy("gmail-mid")["status"] == store.AI
    assert store.get_copy("gmail-done")["status"] == store.COMPLETE


def test_list_ai_done_payloads_skips_unassessed():
    store.upsert_copy("gmail-wait", dest="gmail/gmail-wait", ai_done=0)
    store.upsert_copy(
        "gmail-done",
        dest='{"queue_id":"gmail-done","bucket":"gmail"}',
        ai_done=1,
        status=store.COMPLETE,
    )
    rows = store.list_ai_done_payloads(limit=10)
    assert [r["queue_id"] for r in rows] == ["gmail-done"]
    assert rows[0]["bucket"] == "gmail"


def test_list_feed_by_verdict_includes_copies_past_the_live_page(monkeypatch):
    monkeypatch.setattr(store, "FEED_LIST_LIMIT", 2)
    store.upsert_copy(
        "gmail-mal-old",
        dest="gmail/gmail-mal-old",
        mailbox="jan@pdax.ph",
        status=store.COMPLETE,
        ai_done=1,
        verdict="MALICIOUS",
        gmail_thread_id="thr-mal",
        gmail_message_id="m-mal",
    )
    store.upsert_copy(
        "gmail-mal-sib",
        dest="gmail/gmail-mal-sib",
        mailbox="jan@pdax.ph",
        status=store.COMPLETE,
        ai_done=1,
        verdict="CLEAN",
        gmail_thread_id="thr-mal",
        gmail_message_id="m-sib",
    )
    store.upsert_copy("gmail-clean-a", status=store.COMPLETE, ai_done=1, verdict="CLEAN")
    store.upsert_copy("gmail-clean-b", status=store.COMPLETE, ai_done=1, verdict="CLEAN")
    listed = {r["queue_id"] for r in store.list_feed(limit=store.FEED_LIST_LIMIT)}
    assert "gmail-mal-old" not in listed
    mal = store.list_feed_by_verdict("malicious")
    assert {r["queue_id"] for r in mal} == {"gmail-mal-old"}
    expanded = store.list_feed_by_verdict_with_thread_siblings("malicious")
    assert {r["queue_id"] for r in expanded} == {"gmail-mal-old", "gmail-mal-sib"}
