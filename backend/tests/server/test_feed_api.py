"""Unit tests for server/feed_builder.py + backend/api/routers/feed.py — Phase
12 (real-data feed) of the dashboard-overhaul plan. Uses a temp spool root
and temp auth store — never touches the real email/spool/ or data/.

Run: python3 -m pytest tests/test_server_feed_api.py
     (or python3 tests/test_server_feed_api.py)
"""
import json
import os
import tempfile
from pathlib import Path

# Keep unit tests offline — never call live GLM during CI/local suite.
os.environ["SEG_DASHBOARD_LLM"] = "0"
os.environ["SEG_DASHBOARD_DEEP"] = "0"

from starlette.testclient import TestClient

from workers.pipeline import runner
from backend.models import Verdict
from backend.api import feed_builder
from backend.api.auth_store import AuthStore
from backend.paths import TEST_EML_DIR

_FIXTURES = TEST_EML_DIR

def _tmp_spool() -> Path:
    return Path(tempfile.mkdtemp())

def _seed_entry(spool_root: Path, bucket: str, queue_id: str, meta: dict,
                eml_bytes: bytes = b"From: a@b.com\nSubject: x\n\nbody"):
    d = spool_root / bucket / queue_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "message.eml").write_bytes(eml_bytes)
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")

def _client_as(role: str, spool_root: Path, *, unlock_content: bool = False):
    from fastapi import FastAPI
    from backend.api.routers import feed as feed_module
    import backend.api.deps as deps_module

    feed_module._SPOOL_ROOT = spool_root
    feed_builder._SPOOL_ROOT = spool_root
    feed_builder._cache = None
    feed_builder._sample_cache = None
    feed_builder._feed_built_at = 0.0

    store = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = store
    user = store.create_user("testuser", "Password123!", role)

    app = FastAPI()
    app.include_router(feed_module.router)
    client = TestClient(app)
    token = store.create_session(user.id)
    if unlock_content:
        store.unlock_content(token)
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


def test_norm_meta_coerces_non_list_reasons():
    assert feed_builder._norm_meta({"reasons": "spf_pass"})["reasons"] == []
    assert feed_builder._norm_meta({"reasons": ["spf_pass"]})["reasons"] == ["spf_pass"]

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


def test_spool_entries_includes_gmail_scans():
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-abc", {
        "verdict": "CLEAN", "score": 3.0, "disposition": "LOG",
        "subject": "Welcome", "from": "Boss <boss@pdax.ph>",
        "ts": "2026-08-28T00:00:00+00:00",
        "mailbox": "jan.almazora@pdax.ph",
        "gmail_labels": ["INBOX"],
        "ai_summary": "Looks like a routine welcome note.",
        "ai_provider": "glm",
        "ai_model": "deepseek-ai/deepseek-r1-0528-maas",
        "threat_class": "none",
        "threat_confidence": 0.2,
    })
    feed_builder._SPOOL_ROOT = root
    entries = feed_builder.spool_entries()
    assert len(entries) == 1
    e = entries[0]
    assert e["sourceKind"] == "gmail"
    assert e["status"] == "delivered"
    assert e["pipelineStatus"] == "complete"
    assert e["mailbox"] == "jan.almazora@pdax.ph"
    assert e["toAddr"] == "jan.almazora@pdax.ph"
    assert e["fromAddr"] == "boss@pdax.ph"
    assert e["subject"] == "Welcome"
    assert e["aiSummary"] == "Looks like a routine welcome note."
    assert e["aiProvider"] == "glm"
    assert e["aiModel"] == "deepseek-ai/deepseek-r1-0528-maas"
    assert e["aiPending"] is False
    assert e["aiLlmAttempted"] is False  # not set in this seed meta


def test_spool_entries_exposes_persisted_stages():
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-flow", {
        "verdict": "SUSPICIOUS", "score": 51.0, "disposition": "LOG",
        "subject": "Reset", "from": "it@evil.test",
        "ai_summary": "Credential-harvest wording.",
        "ai_provider": "glm",
        "stages": {
            "headers": {"status": "ok", "score": 5, "flags": []},
            "content_ai": {
                "status": "ok", "score": 42, "flags": ["credential_request"],
                "summary": "Credential-harvest wording.",
                "provider": "glm", "nlu_intent": "credential_theft",
                "nlu_confidence": 0.86,
            },
        },
    })
    feed_builder._SPOOL_ROOT = root
    e = feed_builder.spool_entries()[0]
    assert e["hasStageDetail"] is True
    assert e["stages"]["content_ai"]["score"] == 42.0
    assert e["stages"]["content_ai"]["nluIntent"] == "credential_theft"
    assert e["stages"]["headers"]["score"] == 5.0


def test_feed_list_omits_mail_body_and_full_stages():
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-slim", {
        "verdict": "CLEAN", "score": 1.0, "disposition": "LOG",
        "subject": "Slim list", "from": "a@b.com",
        "primary_content": "SECRET BODY SHOULD NOT SHIP",
        "stages": {
            "headers": {"status": "ok", "score": 5, "flags": []},
            "origin_ip": {"country": "PH", "city": "Makati", "ip": "1.2.3.4"},
        },
    })
    client = _client_as("viewer", root)
    body = client.get("/api/feed").json()
    e = next(x for x in body["entries"] if x["id"] == "gmail-slim")
    assert e["primaryContent"] == ""
    assert e["quotedContent"] == ""
    assert e["footerContent"] == ""
    assert "headers" not in (e.get("stages") or {})
    assert "origin_ip" not in (e.get("stages") or {})
    assert e["originCountry"] == "PH"
    assert e["hasStageDetail"] is True
    assert e["subject"] == "Slim list"


def test_feed_item_keeps_mail_body_and_full_stages():
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-fat", {
        "verdict": "CLEAN", "score": 1.0, "disposition": "LOG",
        "subject": "Fat item", "from": "a@b.com",
        "primary_content": "SECRET BODY ON DETAIL",
        "stages": {
            "headers": {"status": "ok", "score": 5, "flags": []},
            "origin_ip": {"country": "PH", "city": "Makati", "ip": "1.2.3.4"},
        },
    })
    client = _client_as("viewer", root)
    e = client.get("/api/feed/item/gmail-fat").json()["entries"][0]
    assert e["primaryContent"] == "SECRET BODY ON DETAIL"
    assert e["stages"]["headers"]["score"] == 5.0
    assert e["stages"]["origin_ip"]["country"] == "PH"


def test_feed_origin_query_filters_list_without_clipping_tiles():
    from backend.stores import assessments as store

    store.upsert_copy(
        "gmail-ph", status=store.COMPLETE, ai_done=1, verdict="CLEAN",
        origin_country="PH", origin_lat=14.6, origin_lon=121.0,
        stages_json=json.dumps({"origin_ip": {"country": "PH", "lat": 14.6, "lon": 121.0}}),
    )
    store.upsert_copy(
        "gmail-sg", status=store.COMPLETE, ai_done=1, verdict="MALICIOUS",
        origin_country="SG", origin_lat=1.3, origin_lon=103.8,
    )
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-ph", {
        "verdict": "CLEAN", "score": 1.0, "from": "a@b.com", "subject": "PH",
        "stages": {"origin_ip": {"country": "PH"}},
    })
    _seed_entry(root, "gmail", "gmail-sg", {
        "verdict": "MALICIOUS", "score": 90.0, "from": "b@b.com", "subject": "SG",
        "stages": {"origin_ip": {"country": "SG"}},
    })
    client = _client_as("viewer", root)
    body = client.get("/api/feed?origin=PH").json()
    ids = {e["id"] for e in body["entries"]}
    assert ids == {"gmail-ph"}
    assert body["stats"]["total"] == 2
    assert body["stats"]["malicious"] == 1
    assert body["stats"]["origin"]["located"] == 2
    ph = next(c for c in body["stats"]["origin"]["countries"] if c["country"] == "PH")
    assert ph["count"] == 1


def test_force_refresh_does_not_rescore_sample_cache(monkeypatch):
    hits = []
    monkeypatch.setattr(feed_builder, "run_samples", lambda *a, **k: hits.append(1) or [])
    monkeypatch.setattr(feed_builder, "spool_entries", lambda *a, **k: [])
    feed_builder._sample_cache = [{"id": "demo", "ts": 1, "verdict": "CLEAN"}]
    feed_builder._cache = [{"id": "stale", "ts": 0, "verdict": "CLEAN"}]
    feed_builder.build_feed(force=True)
    assert hits == []
    assert feed_builder._sample_cache[0]["id"] == "demo"


def test_heuristic_gmail_is_pending_when_llm_configured(monkeypatch):
    monkeypatch.setattr(feed_builder, "llm_configured", lambda: True)
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-pending", {
        "verdict": "LOW", "score": 8.0, "disposition": "LOG",
        "subject": "Still scanning", "from": "a@b.com",
        "ai_summary": "Heuristic content findings: none",
        "ai_provider": "heuristic",
        "ai_llm_attempted": False,
    })
    feed_builder._SPOOL_ROOT = root
    e = feed_builder.spool_entries()[0]
    assert e["aiPending"] is True
    assert e["aiLlmAttempted"] is False
    monkeypatch.setattr(feed_builder, "llm_configured", lambda: False)
    assert feed_builder.spool_entries()[0]["aiPending"] is False


def test_pending_gmail_without_verdict_is_not_clean(monkeypatch):
    monkeypatch.setattr(feed_builder, "llm_configured", lambda: True)
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-awaiting", {
        "verdict": "", "score": None, "disposition": "LOG",
        "subject": "Awaiting AI", "from": "a@b.com",
        "ai_summary": "", "ai_provider": "",
        "ai_llm_attempted": False,
    })
    feed_builder._SPOOL_ROOT = root
    e = feed_builder.spool_entries()[0]
    assert e["aiPending"] is True
    assert e["verdict"] == ""
    assert e["pipelineStatus"] == "queued"


def test_spool_pipeline_status_follows_assessment_row(monkeypatch):
    from backend.stores import assessments as store
    monkeypatch.setattr(feed_builder, "llm_configured", lambda: True)
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-static", {
        "verdict": "", "score": None, "disposition": "LOG",
        "subject": "Checking", "from": "a@b.com",
        "ai_summary": "", "ai_provider": "",
    })
    store.upsert_copy("gmail-static", dest=str(root / "gmail" / "gmail-static"), status=store.STATIC)
    feed_builder._SPOOL_ROOT = root
    e = feed_builder.spool_entries()[0]
    assert e["pipelineStatus"] == "static"
    store.upsert_copy("gmail-static", static_done=1, status=store.AI)
    assert feed_builder.spool_entries()[0]["pipelineStatus"] == "ai"


def test_stale_heuristic_gmail_is_timed_out(monkeypatch):
    from datetime import datetime, timedelta, timezone
    monkeypatch.setattr(feed_builder, "llm_configured", lambda: True)
    root = _tmp_spool()
    queued = (datetime.now(timezone.utc) - timedelta(minutes=3)).isoformat()
    _seed_entry(root, "gmail", "gmail-stale", {
        "verdict": "LOW", "score": 8.0, "disposition": "LOG",
        "subject": "Stuck", "from": "a@b.com",
        "ai_summary": "Heuristic content findings: none",
        "ai_provider": "heuristic",
        "ai_queued_at": queued,
    })
    feed_builder._SPOOL_ROOT = root
    e = feed_builder.spool_entries()[0]
    assert e["aiPending"] is False
    assert e["aiTimedOut"] is True
    assert e["aiQueuedAt"]
    assert e["pipelineStatus"] == "timed_out"


def test_feed_payload_includes_queue_fields():
    root = _tmp_spool()
    client = _client_as("viewer", root)
    body = client.get("/api/feed").json()
    assert "entries" in body
    assert isinstance(body["llmConfigured"], bool)
    assert body["aiPendingCount"] == max(
        body["stats"]["aiPendingTotal"],
        sum(1 for e in body["entries"] if e.get("aiPending")),
    )
    assert body["aiTimedOutCount"] == max(
        body["stats"]["aiTimedOutTotal"],
        sum(1 for e in body["entries"] if e.get("aiTimedOut")),
    )
    assert "total" in body["stats"]
    assert isinstance(body["stats"].get("inboxesMonitored"), int)
    assert isinstance(body["stats"].get("assessed"), int)
    assert body["llmAssessTimeoutSeconds"] >= 15
    r2 = client.post("/api/feed/refresh").json()
    assert "llmConfigured" in r2
    assert "aiPendingCount" in r2
    assert "aiTimedOutCount" in r2


def test_feed_returns_entries_when_overview_stats_fails(monkeypatch):
    from backend.stores import assessments as store

    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-keep", {
        "verdict": "CLEAN", "score": 1.0, "disposition": "LOG",
        "subject": "Still listed", "from": "a@b.com",
        "ts": "2026-08-30T00:00:00+00:00",
    })

    def boom(**_kwargs):
        raise RuntimeError("full table scan")

    monkeypatch.setattr(store, "overview_stats", boom)
    client = _client_as("viewer", root)
    body = client.get("/api/feed").json()
    assert "gmail-keep" in {e["id"] for e in body["entries"]}
    assert body["stats"]["total"] == 0
    assert body["stats"]["hourly"] == []
    assert body["stats"]["assessed"] == 0
    assert body["stats"]["mailboxes"] == 0


def test_feed_inboxes_use_historical_mailboxes_not_only_current_poll(monkeypatch):
    from backend.stores import assessments as store

    store.upsert_copy(
        "gmail-a", mailbox="jan@pdax.ph", status=store.COMPLETE,
        ai_done=1, verdict="CLEAN",
    )
    store.upsert_copy(
        "gmail-b", mailbox="JAN@pdax.ph", status=store.COMPLETE,
        ai_done=1, verdict="CLEAN",
    )
    store.upsert_copy(
        "gmail-c", mailbox="support@pdax.ph", status=store.COMPLETE,
        ai_done=1, verdict="SUSPICIOUS", thread_ai_done=1,
    )
    monkeypatch.setattr(
        "backend.stores.gmail_coverage.snapshot",
        lambda: {"polling": 1, "configured": 1, "discovered": 0, "skipped": 0},
    )
    root = _tmp_spool()
    client = _client_as("viewer", root)
    stats = client.get("/api/feed").json()["stats"]
    assert stats["total"] == 3
    assert stats["assessed"] == 3
    assert stats["threadAssessed"] == 1
    assert stats["mailboxes"] == 2
    assert stats["inboxesPolling"] == 1
    assert stats["inboxesMonitored"] == 2

    monkeypatch.setattr(
        "backend.stores.gmail_coverage.snapshot",
        lambda: {"polling": 9, "configured": 3, "discovered": 6, "skipped": 0},
    )
    wider = client.get("/api/feed").json()["stats"]
    assert wider["inboxesPolling"] == 9
    assert wider["inboxesMonitored"] == 9


def test_feed_stats_count_copies_beyond_entry_page():
    from backend.stores import assessments as store

    n = store.FEED_LIST_LIMIT + 25
    for i in range(n):
        store.upsert_copy(f"gmail-{i}", status=store.AI, static_done=1, ai_done=0)
    root = _tmp_spool()
    client = _client_as("viewer", root)
    body = client.get("/api/feed").json()
    assert body["stats"]["total"] == n
    assert body["stats"]["aiPendingTotal"] == n
    assert body["aiPendingCount"] == n
    assert body["stats"]["feedLimit"] == store.FEED_LIST_LIMIT


def test_feed_item_returns_copy_outside_list_page():
    from backend.stores import assessments as store

    store.upsert_copy(
        "gmail-old-keep",
        dest="gmail/gmail-old-keep",
        mailbox="jan@pdax.ph",
        from_addr="old@b.com",
        subject="Aged off the feed",
        verdict="SUSPICIOUS",
        score=40.0,
        status=store.COMPLETE,
        static_done=1,
        ai_done=1,
        gmail_thread_id="thr-old",
        meta_json=json.dumps({
            "from": "old@b.com",
            "subject": "Aged off the feed",
            "verdict": "SUSPICIOUS",
            "score": 40.0,
            "gmail_thread_id": "thr-old",
            "mailbox": "jan@pdax.ph",
            "ts": "2026-08-01T00:00:00+00:00",
        }),
    )
    store.upsert_copy(
        "gmail-old-sib",
        dest="gmail/gmail-old-sib",
        mailbox="jan@pdax.ph",
        from_addr="old@b.com",
        subject="Re: Aged off the feed",
        verdict="CLEAN",
        score=2.0,
        status=store.COMPLETE,
        static_done=1,
        ai_done=1,
        gmail_thread_id="thr-old",
        meta_json=json.dumps({
            "from": "old@b.com",
            "subject": "Re: Aged off the feed",
            "verdict": "CLEAN",
            "score": 2.0,
            "gmail_thread_id": "thr-old",
            "mailbox": "jan@pdax.ph",
            "ts": "2026-08-01T01:00:00+00:00",
        }),
    )
    root = _tmp_spool()
    client = _client_as("viewer", root)
    missing = client.get("/api/feed/item/gmail-missing")
    assert missing.status_code == 404
    r = client.get("/api/feed/item/gmail-old-keep")
    assert r.status_code == 200
    ids = {e["id"] for e in r.json()["entries"]}
    assert ids == {"gmail-old-keep", "gmail-old-sib"}
    by_id = {e["id"]: e for e in r.json()["entries"]}
    assert by_id["gmail-old-keep"]["subject"] == "Aged off the feed"
    assert by_id["gmail-old-keep"]["verdict"] == "SUSPICIOUS"


def test_feed_item_reads_disk_copy_without_postgres_row():
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-disk-only", {
        "verdict": "CLEAN", "score": 3.0, "disposition": "LOG",
        "subject": "On disk only", "from": "a@b.com",
        "ts": "2026-08-30T00:00:00+00:00",
    })
    client = _client_as("viewer", root)
    r = client.get("/api/feed/item/gmail-disk-only")
    assert r.status_code == 200
    assert r.json()["entries"][0]["subject"] == "On disk only"


def test_has_llm_assessment():
    assert feed_builder.has_llm_assessment("glm", "Looks benign.") is True
    assert feed_builder.has_llm_assessment("heuristic", "Heuristic content findings") is False
    assert feed_builder.has_llm_assessment("glm", "") is False
    assert feed_builder.has_llm_assessment("GLM", "  ok  ") is True


def test_spool_entries_groups_gmail_thread_and_rfc_reply():
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-root", {
        "verdict": "CLEAN", "score": 2.0, "disposition": "LOG",
        "subject": "Invoice", "from": "a@pdax.ph",
        "ts": "2026-08-28T00:00:00+00:00",
        "mailbox": "jan@pdax.ph",
        "gmail_thread_id": "thr-1",
        "message_id": "<root@pdax.ph>",
        "in_reply_to": "",
        "references": "",
    })
    _seed_entry(root, "gmail", "gmail-reply", {
        "verdict": "SUSPICIOUS", "score": 48.0, "disposition": "LOG",
        "subject": "Re: Invoice", "from": "phish@evil.test",
        "ts": "2026-08-28T01:00:00+00:00",
        "mailbox": "jan@pdax.ph",
        "gmail_thread_id": "thr-1",
        "message_id": "<reply@evil.test>",
        "in_reply_to": "<root@pdax.ph>",
        "references": "<root@pdax.ph>",
    })
    _seed_entry(root, "gmail", "gmail-other", {
        "verdict": "CLEAN", "score": 1.0, "disposition": "LOG",
        "subject": "Unrelated", "from": "b@pdax.ph",
        "ts": "2026-08-28T02:00:00+00:00",
        "mailbox": "jan@pdax.ph",
        "gmail_thread_id": "thr-2",
        "message_id": "<other@pdax.ph>",
        "in_reply_to": "",
        "references": "",
    })
    feed_builder._SPOOL_ROOT = root
    entries = feed_builder.spool_entries()
    by_id = {e["id"]: e for e in entries}
    assert by_id["gmail-root"]["threadKey"] == by_id["gmail-reply"]["threadKey"]
    assert by_id["gmail-root"]["threadCount"] == 2
    assert by_id["gmail-other"]["threadKey"] != by_id["gmail-root"]["threadKey"]
    assert by_id["gmail-other"]["threadCount"] == 1
    assert by_id["gmail-root"]["gmailThreadId"] == "thr-1"


def test_spool_entries_exposes_thread_assessment():
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-root", {
        "verdict": "CLEAN", "score": 4.0, "disposition": "LOG",
        "subject": "Invoice", "from": "alice@pdax.ph",
        "ts": "2026-08-28T00:00:00+00:00",
        "mailbox": "jan@pdax.ph",
        "gmail_thread_id": "thr-1",
        "thread_summary": "Clean opener, then a payment-redirect reply.",
        "thread_verdict": "SUSPICIOUS",
    })
    _seed_entry(root, "gmail", "gmail-reply", {
        "verdict": "LOW", "score": 30.0, "disposition": "LOG",
        "subject": "Re: Invoice", "from": "phish@evil.test",
        "ts": "2026-08-28T01:00:00+00:00",
        "mailbox": "jan@pdax.ph",
        "gmail_thread_id": "thr-1",
        "thread_summary": "Clean opener, then a payment-redirect reply.",
        "thread_verdict": "SUSPICIOUS",
    })
    feed_builder._SPOOL_ROOT = root
    entries = feed_builder.spool_entries()
    by_id = {e["id"]: e for e in entries}
    assert by_id["gmail-root"]["threadVerdict"] == "SUSPICIOUS"
    assert "payment-redirect" in by_id["gmail-reply"]["threadSummary"]


def test_spool_entries_groups_rfc_reply_from_eml_headers():
    root = _tmp_spool()
    _seed_entry(root, "quarantine", "q-root", {
        "verdict": "LOW", "score": 22.0, "disposition": "QUARANTINE",
        "subject": "Reset", "from": "it@vendor.com",
        "ts": "2026-08-28T00:00:00+00:00",
    }, eml_bytes=(
        b"From: it@vendor.com\n"
        b"Message-ID: <ticket@vendor.com>\n"
        b"Subject: Reset\n\nplease reset\n"
    ))
    _seed_entry(root, "quarantine", "q-reply", {
        "verdict": "MALICIOUS", "score": 80.0, "disposition": "QUARANTINE",
        "subject": "Re: Reset", "from": "it@vend0r.com",
        "ts": "2026-08-28T00:10:00+00:00",
    }, eml_bytes=(
        b"From: it@vend0r.com\n"
        b"Message-ID: <phish@evil>\n"
        b"In-Reply-To: <ticket@vendor.com>\n"
        b"References: <ticket@vendor.com>\n"
        b"Subject: Re: Reset\n\nclick here\n"
    ))
    feed_builder._SPOOL_ROOT = root
    entries = feed_builder.spool_entries()
    by_id = {e["id"]: e for e in entries}
    assert by_id["q-root"]["threadKey"] == by_id["q-reply"]["threadKey"]
    assert by_id["q-root"]["threadCount"] == 2
    assert by_id["q-root"]["threadKey"].startswith("rfc:")


def test_gmail_sent_uses_to_header_not_mailbox():
    # SENT mail in the support mailbox must show the real To (customer),
    # not overwrite To with the scanned mailbox (which made From and To
    # both look like support@pdax.ph).
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-sent-1", {
        "verdict": "CLEAN", "score": 2.0, "disposition": "LOG",
        "subject": "Re: your ticket",
        "from": "PDAX Support <support@pdax.ph>",
        "to": "syphercris@gmail.com",
        "ts": "2026-08-28T00:00:00+00:00",
        "mailbox": "support@pdax.ph",
        "gmail_labels": ["SENT"],
        "ai_summary": "Support reply.",
        "ai_provider": "glm",
        "is_forwarded": False,
        "footer_worth_assessing": False,
        "primary_content": "Thanks for writing in.",
    })
    feed_builder._SPOOL_ROOT = root
    entries = feed_builder.spool_entries()
    assert len(entries) == 1
    e = entries[0]
    assert e["fromAddr"] == "support@pdax.ph"
    assert e["toAddr"] == "syphercris@gmail.com"
    assert e["toAddr"] != e["fromAddr"]
    assert e["mailbox"] == "support@pdax.ph"
    assert e["primaryContent"] == "Thanks for writing in."
    assert e["isForwarded"] is False

def test_spool_entries_empty_when_no_spool_dir():
    feed_builder._SPOOL_ROOT = Path(tempfile.mkdtemp()) / "does_not_exist"
    assert feed_builder.spool_entries() == []


def test_spool_entries_reads_s3_and_assessment_copies(monkeypatch):
    from backend.paths import SPOOL_DIR
    from backend.stores import assessments as store
    from backend.stores import spool as spoolmod

    feed_builder._SPOOL_ROOT = SPOOL_DIR
    monkeypatch.setattr(spoolmod, "use_s3", lambda: True)

    def _fail_iter(*_a, **_k):
        raise AssertionError("S3 GetObject listing must not run on the feed path")

    monkeypatch.setattr(spoolmod, "iter_copies", _fail_iter)
    store.upsert_copy(
        "gmail-db",
        dest="/opt/segs/email/spool/gmail/gmail-db",
        from_addr="db@pdax.ph",
        subject="From Postgres",
        mailbox="jan.almazora@pdax.ph",
        meta_json='{"ts":"2026-08-29T01:00:00+00:00","from":"db@pdax.ph","subject":"From Postgres","mailbox":"jan.almazora@pdax.ph"}',
    )
    entries = feed_builder.spool_entries()
    by_id = {e["id"]: e for e in entries}
    assert by_id["gmail-db"]["subject"] == "From Postgres"
    assert by_id["gmail-db"]["fromAddr"] == "db@pdax.ph"
    assert by_id["gmail-db"]["sourceKind"] == "gmail"


def test_s3_feed_does_not_refetch_each_copy(monkeypatch):
    from backend.paths import SPOOL_DIR
    from backend.stores import assessments as store
    from backend.stores import spool as spoolmod

    feed_builder._SPOOL_ROOT = SPOOL_DIR
    monkeypatch.setattr(spoolmod, "use_s3", lambda: True)
    monkeypatch.setattr(spoolmod, "iter_copies", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("no iter")))
    store.upsert_copy(
        "gmail-nplus1",
        dest="/opt/segs/email/spool/gmail/gmail-nplus1",
        from_addr="n1@pdax.ph",
        subject="No extra get_copy",
        verdict="CLEAN",
        score=2.0,
        status=store.COMPLETE,
        ai_done=1,
        meta_json='{"ts":"2026-08-30T01:00:00+00:00","from":"n1@pdax.ph","subject":"No extra get_copy"}',
    )

    def _boom(*_a, **_k):
        raise AssertionError("feed must use the list_feed row, not get_copy per copy")

    monkeypatch.setattr(store, "get_copy", _boom)
    entries = feed_builder.spool_entries()
    by_id = {e["id"]: e for e in entries}
    assert by_id["gmail-nplus1"]["subject"] == "No extra get_copy"
    assert by_id["gmail-nplus1"]["verdict"] == "CLEAN"


def test_feed_verdict_query_returns_malicious_off_the_live_page(monkeypatch):
    from backend.paths import SPOOL_DIR
    from backend.stores import assessments as store
    from backend.stores import spool as spoolmod

    monkeypatch.setattr(spoolmod, "use_s3", lambda: True)
    monkeypatch.setattr(
        spoolmod, "iter_copies",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("no iter")),
    )
    monkeypatch.setattr(store, "FEED_LIST_LIMIT", 2)
    store.upsert_copy(
        "gmail-mal-off",
        dest="/opt/segs/email/spool/gmail/gmail-mal-off",
        from_addr="phish@evil.example",
        subject="Wire now",
        verdict="MALICIOUS",
        score=92.0,
        status=store.COMPLETE,
        ai_done=1,
        meta_json=(
            '{"verdict":"MALICIOUS","from":"phish@evil.example",'
            '"subject":"Wire now","ts":"2026-08-30T01:00:00+00:00"}'
        ),
    )
    for i in range(store.FEED_LIST_LIMIT):
        store.upsert_copy(
            f"gmail-c-{i}",
            dest=f"/opt/segs/email/spool/gmail/gmail-c-{i}",
            status=store.COMPLETE,
            ai_done=1,
            verdict="CLEAN",
            meta_json='{"verdict":"CLEAN","ts":"2026-08-30T02:00:00+00:00"}',
        )
    client = _client_as("viewer", SPOOL_DIR)
    live_ids = {e["id"] for e in client.get("/api/feed").json()["entries"]}
    assert "gmail-mal-off" not in live_ids
    body = client.get("/api/feed?verdict=malicious").json()
    ids = {e["id"] for e in body["entries"]}
    assert "gmail-mal-off" in ids
    mal = next(e for e in body["entries"] if e["id"] == "gmail-mal-off")
    assert mal["verdict"] == "MALICIOUS"
    assert mal["subject"] == "Wire now"

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
    feed_builder._DEMO_EML_DIR = _FIXTURES
    entries = feed_builder.run_samples()
    by_file = {e["sourceFile"]: e for e in entries}
    assert "phish-lookalike.eml" in by_file
    assert by_file["phish-lookalike.eml"]["verdict"] == "MALICIOUS"
    assert by_file["phish-lookalike.eml"]["status"] == "delivered"
    assert by_file["phish-lookalike.eml"]["hasStageDetail"] is True
    assert by_file["phish-lookalike.eml"]["fromAddr"]
    assert by_file["phish-lookalike.eml"]["toAddr"] == "user@example.com"

    direct = runner.run_pipeline(
        (_FIXTURES / "phish-lookalike.eml").read_bytes(), source="file")
    assert by_file["phish-lookalike.eml"]["verdict"] == direct.verdict.value
    feed_builder._DEMO_EML_DIR = None

def test_run_samples_is_empty_without_a_demo_dir():
    feed_builder._DEMO_EML_DIR = None
    assert feed_builder.run_samples() == []

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

def test_analyst_download_requires_passkey_unlock():
    root = _tmp_spool()
    _seed_entry(root, "quarantine", "q1", {"verdict": "SUSPICIOUS", "score": 50, "subject": "x", "from": "a@b.com"},
               eml_bytes=b"From: real@sender.com\nSubject: real test\n\nreal body content")
    client = _client_as("analyst", root)
    r = client.get("/api/quarantine/q1/download")
    assert r.status_code == 403
    assert r.json()["detail"] == "passkey_required"


def test_analyst_can_download_real_eml_bytes():
    root = _tmp_spool()
    _seed_entry(root, "quarantine", "q1", {"verdict": "SUSPICIOUS", "score": 50, "subject": "x", "from": "a@b.com"},
               eml_bytes=b"From: real@sender.com\nSubject: real test\n\nreal body content")
    client = _client_as("analyst", root, unlock_content=True)
    r = client.get("/api/quarantine/q1/download")
    assert r.status_code == 200
    assert b"real body content" in r.content
    r2 = client.get("/api/quarantine/q1/download")
    assert r2.status_code == 200
    assert b"real body content" in r2.content


def test_download_unlock_covers_thread_siblings_only():
    root = _tmp_spool()
    _seed_entry(root, "quarantine", "q1",
                {"verdict": "SUSPICIOUS", "score": 50, "subject": "hello", "from": "a@b.com"},
                eml_bytes=b"Message-ID: <root@pdax.ph>\nSubject: hello\n\nroot body")
    _seed_entry(root, "quarantine", "q2",
                {"verdict": "SUSPICIOUS", "score": 50, "subject": "Re: hello", "from": "a@b.com"},
                eml_bytes=b"Message-ID: <reply@pdax.ph>\nIn-Reply-To: <root@pdax.ph>\nSubject: Re: hello\n\nreply body")
    _seed_entry(root, "quarantine", "q3",
                {"verdict": "LOW", "score": 20, "subject": "other", "from": "c@d.com"},
                eml_bytes=b"Message-ID: <other@pdax.ph>\nSubject: other\n\nother body")
    client = _client_as("analyst", root)
    feed_builder._cache = None
    thread_key = feed_builder.thread_key_for_queue_id("q1")
    other_key = feed_builder.thread_key_for_queue_id("q3")
    assert thread_key == feed_builder.thread_key_for_queue_id("q2")
    assert thread_key != other_key
    import backend.api.deps as deps_module
    token = client.cookies.get("seg_session")
    deps_module.get_auth_store().unlock_content(token, thread_key)
    assert client.get("/api/quarantine/q1/download").status_code == 200
    assert client.get("/api/quarantine/q2/download").status_code == 200
    r3 = client.get("/api/quarantine/q3/download")
    assert r3.status_code == 403
    assert r3.json()["detail"] == "passkey_required"


def test_download_reads_from_spool_store(tmp_path):
    from backend.stores import spool
    spool.set_root(tmp_path)
    try:
        spool.put_eml("gmail-z", b"From: z@pdax.ph\nSubject: z\n\nspool body\n", "gmail")
        empty = _tmp_spool()
        client = _client_as("analyst", empty, unlock_content=True)
        r = client.get("/api/quarantine/gmail-z/download")
        assert r.status_code == 200
        assert b"spool body" in r.content
    finally:
        spool.set_root(None)


def test_unlock_covers_gmail_thread_outside_feed_cache():
    from backend.stores import assessments as store
    import backend.api.deps as deps_module

    store.upsert_copy(
        "gmail-a", dest="gmail/gmail-a", mailbox="jan@pdax.ph",
        gmail_thread_id="thr-99", rfc_message_id="<a@x>",
    )
    store.upsert_copy(
        "gmail-b", dest="gmail/gmail-b", mailbox="jan@pdax.ph",
        gmail_thread_id="thr-99", rfc_message_id="<b@x>",
    )
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-a",
                {"verdict": "CLEAN", "score": 2, "subject": "hello", "from": "a@b.com"},
                eml_bytes=b"From: a@b.com\nSubject: hello\n\nroot body")
    _seed_entry(root, "gmail", "gmail-b",
                {"verdict": "CLEAN", "score": 2, "subject": "Re: hello", "from": "a@b.com"},
                eml_bytes=b"From: a@b.com\nSubject: Re: hello\n\nreply body")
    client = _client_as("analyst", root)
    feed_builder._cache = []
    key = feed_builder.preferred_unlock_key("gmail-a")
    assert key.startswith("gmail:")
    assert "thr-99" in key
    token = client.cookies.get("seg_session")
    deps_module.get_auth_store().unlock_content(token, key)
    r1 = client.get("/api/quarantine/gmail-a/download")
    r2 = client.get("/api/quarantine/gmail-b/download")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert b"root body" in r1.content
    assert b"reply body" in r2.content


def test_release_missing_entry_404():
    root = _tmp_spool()
    client = _client_as("admin", root)
    r = client.post("/api/quarantine/nonexistent/release")
    assert r.status_code == 404

def test_reevaluate_enqueues_static_and_returns_202(monkeypatch):
    from backend.stores import assessments as store

    root = _tmp_spool()
    raw = (_FIXTURES / "phish-lookalike.eml").read_bytes()
    _seed_entry(root, "quarantine", "q1",
               {"verdict": "CLEAN", "score": 0, "subject": "old", "from": "a@b.com"},
               eml_bytes=raw)
    dest = str(root / "quarantine" / "q1")
    store.upsert_copy("q1", dest=dest, status=store.COMPLETE, ai_done=1, verdict="CLEAN")
    queued = []
    monkeypatch.setattr("workers.copy_jobs.enqueue_static", queued.append)
    client = _client_as("analyst", root)
    r = client.post("/api/quarantine/q1/reevaluate")
    assert r.status_code == 202
    body = r.json()
    assert body["queued"] is True
    assert body["queue_id"] == "q1"
    assert queued

def test_feed_refresh_rebuilds_cache():
    root = _tmp_spool()
    feed_builder._DEMO_EML_DIR = _FIXTURES
    client = _client_as("viewer", root)
    r1 = client.get("/api/feed").json()
    r2 = client.post("/api/feed/refresh").json()
    assert len(r1["entries"]) == len(r2["entries"])
    feed_builder._DEMO_EML_DIR = None

def test_audit_merges_gateway_shadow_and_activity():
    root = _tmp_spool()
    (root / "shadow_logs").mkdir(parents=True)
    (root / "shadow_logs" / "shadow_enforcement.jsonl").write_text(
        '{"ts": "2026-08-13T00:00:00Z", "verdict": "MALICIOUS",'
        ' "from": "a@b.com", "subject": "phish"}\n',
        encoding="utf-8",
    )
    feed_builder._SPOOL_ROOT = root

    from backend.api import activity_log
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


def test_audit_me_only_current_user():
    root = _tmp_spool()
    from backend.api import activity_log
    path = Path(tempfile.mkdtemp()) / "activity_audit.jsonl"
    orig = activity_log._DEFAULT_PATH
    activity_log._DEFAULT_PATH = path
    try:
        activity_log.record("login", actor="testuser", actor_role="viewer", detail="own")
        activity_log.record("login", actor="other", actor_role="admin", detail="not yours")
        client = _client_as("viewer", root)
        entries = client.get("/api/audit/me").json()["entries"]
        assert entries
        assert all(e.get("actor") == "testuser" for e in entries)
        assert not any("other" == e.get("actor") for e in entries)
        titles = {e.get("title") for e in entries}
        assert "Signed in" in titles
    finally:
        activity_log._DEFAULT_PATH = orig


def test_retry_ai_requires_analyst(monkeypatch):
    root = _tmp_spool()
    monkeypatch.setattr(feed_builder, "llm_configured", lambda: True)
    client = _client_as("viewer", root)
    assert client.post("/api/feed/retry-ai", json={}).status_code == 403


def test_retry_ai_queues_missing_assessments(monkeypatch):
    root = _tmp_spool()
    _seed_entry(root, "gmail", "gmail-stale", {
        "verdict": "LOW", "score": 8.0, "subject": "Stuck", "from": "a@b.com",
        "ai_provider": "heuristic", "ai_summary": "none yet",
    })
    monkeypatch.setattr(feed_builder, "llm_configured", lambda: True)
    called = {}

    def _fake_retry(queue_ids=None, spool_root=None, all_missing=False, limit=100):
        called["all_missing"] = all_missing
        called["queue_ids"] = queue_ids
        called["root"] = spool_root
        return ["gmail-stale"]

    from backend.api.routers import feed as feed_module
    monkeypatch.setattr(feed_module, "retry_gmail_llm", _fake_retry)
    client = _client_as("analyst", root)
    r = client.post("/api/feed/retry-ai", json={})
    assert r.status_code == 200
    assert r.json()["queued"] == 1
    assert r.json()["queue_ids"] == ["gmail-stale"]
    assert called["all_missing"] is True

    r2 = client.post("/api/feed/retry-ai", json={"queue_ids": ["gmail-stale"]})
    assert r2.status_code == 200
    assert called["queue_ids"] == ["gmail-stale"]
    assert called["all_missing"] is False


def test_email_view_records_open_and_dwell():
    root = _tmp_spool()
    from backend.api import activity_log
    from backend.api.routers import feed as feed_module
    path = Path(tempfile.mkdtemp()) / "activity_audit.jsonl"
    orig = activity_log._DEFAULT_PATH
    activity_log._DEFAULT_PATH = path
    feed_module._view_dedupe.clear()
    try:
        client = _client_as("analyst", root)
        opened = client.post("/api/activity/email-view", json={
            "queue_id": "gmail-abc",
            "event": "open",
            "subject": "Q3 invoice",
            "from_addr": "alice@example.com",
        })
        assert opened.status_code == 200
        left = client.post("/api/activity/email-view", json={
            "queue_id": "gmail-abc",
            "event": "leave",
            "dwell_ms": 125000,
            "subject": "Q3 invoice",
            "from_addr": "alice@example.com",
        })
        assert left.status_code == 200
        rows = activity_log.list_entries(path=path)
        by_action = {e["action"]: e for e in rows}
        assert "email_open" in by_action
        assert "email_view" in by_action
        ui = activity_log.to_audit_ui(by_action["email_view"])
        assert ui["title"] == "Looked at “Q3 invoice” from alice@example.com"
        assert "viewed for 2 minutes 5 seconds" in ui["detail"]
    finally:
        activity_log._DEFAULT_PATH = orig


def test_download_intent_view_does_not_log_file_download():
    root = _tmp_spool()
    _seed_entry(root, "quarantine", "q1", {"verdict": "SUSPICIOUS", "score": 50, "subject": "Q3 invoice", "from": "alice@example.com"},
               eml_bytes=b"From: alice@example.com\nSubject: Q3 invoice\n\nbody")
    from backend.api import activity_log
    path = Path(tempfile.mkdtemp()) / "activity_audit.jsonl"
    orig = activity_log._DEFAULT_PATH
    activity_log._DEFAULT_PATH = path
    try:
        client = _client_as("analyst", root, unlock_content=True)
        viewed = client.get("/api/quarantine/q1/download?intent=view")
        assert viewed.status_code == 200
        actions = [e["action"] for e in activity_log.list_entries(path=path)]
        assert "quarantine_download" not in actions
        saved = client.get("/api/quarantine/q1/download")
        assert saved.status_code == 200
        rows = activity_log.list_entries(path=path)
        dl = next(e for e in rows if e["action"] == "quarantine_download")
        assert "Q3 invoice" in activity_log.to_audit_ui(dl)["title"] or "q1" in (dl.get("detail") or "")
    finally:
        activity_log._DEFAULT_PATH = orig

