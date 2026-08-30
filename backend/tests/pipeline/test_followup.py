"""After LLM assessment, campaign / profile / sender-risk drain a shared queue."""
from __future__ import annotations

import json
from pathlib import Path

import workers
from backend.stores.campaign import CampaignStore
from workers.pipeline.correlation import BehavioralCorrelationStore
from workers.followup import after_assessment, pending_counts, take_campaign


def _dest(root: Path, qid: str, meta: dict) -> Path:
    d = root / "gmail" / qid
    d.mkdir(parents=True)
    (d / "message.eml").write_bytes(b"From: a@b.com\n\nHi\n")
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return d


def test_after_assessment_queues_campaign_profile_and_sender(tmp_path):
    dest = _dest(tmp_path, "gmail-a", {
        "from": "vendor@acme.example",
        "mailbox": "jan@pdax.ph",
        "verdict": "CLEAN",
        "message_id": "<a@x>",
        "subject": "hello",
        "stages": {"origin_ip": {"asn": "AS1", "country": "US", "ip": "1.1.1.1"}},
    })
    after_assessment(dest)
    counts = pending_counts()
    assert counts["campaign"] == 1
    assert counts["profile"] == 1
    assert counts["sender_risk"] == 1
    after_assessment(dest)
    assert pending_counts()["campaign"] == 1


def test_profile_cycle_drains_followup_queue(tmp_path):
    store = BehavioralCorrelationStore(db_path=tmp_path / "beh.sqlite3")
    dest = _dest(tmp_path, "gmail-a", {
        "from": "alice@yahoo.com",
        "mailbox": "jan@pdax.ph",
        "verdict": "CLEAN",
        "message_id": "<c@x>",
        "subject": "hello",
        "stages": {"origin_ip": {
            "asn": "AS1", "country": "US", "network_role": "esp", "ip": "1.1.1.1",
        }},
    })
    after_assessment(dest)
    stats = workers.profile_cycle(store, tmp_path, limit=20)
    assert stats["from_queue"] >= 1
    assert stats["inserted"] == 1
    assert pending_counts()["profile"] == 0


def test_ingest_copy_accepts_sqs_payload(tmp_path):
    from backend.stores import spool
    from backend.stores.sender_profile_ingest import ingest_copy

    store = BehavioralCorrelationStore(db_path=tmp_path / "beh.sqlite3")
    spool.set_root(tmp_path)
    try:
        dest = _dest(tmp_path, "gmail-sqs", {
            "from": "alice@yahoo.com",
            "mailbox": "jan@pdax.ph",
            "verdict": "CLEAN",
            "message_id": "<sqs@x>",
            "ts": "2026-08-30T01:00:00+00:00",
            "stages": {"origin_ip": {
                "asn": "AS1", "country": "US", "network_role": "esp", "ip": "1.1.1.1",
            }},
        })
        stats = ingest_copy(store, spool.as_payload(dest))
        assert stats["inserted"] == 1
        assert any(r["sender"] == "alice@yahoo.com" for r in store.list_profiles())
    finally:
        spool.set_root(None)


def test_profile_cycle_backfills_assessed_copies(tmp_path, monkeypatch):
    from backend.stores import spool

    store = BehavioralCorrelationStore(db_path=tmp_path / "beh.sqlite3")
    spool.set_root(tmp_path)
    try:
        dest = _dest(tmp_path, "gmail-backfill", {
            "from": "alice@yahoo.com",
            "mailbox": "jan@pdax.ph",
            "verdict": "CLEAN",
            "message_id": "<backfill@x>",
            "ts": "2026-08-30T01:00:00+00:00",
            "stages": {"origin_ip": {
                "asn": "AS1", "country": "US", "network_role": "esp", "ip": "1.1.1.1",
            }},
        })
        monkeypatch.setattr("workers.followup.take_profiles", lambda limit=80: [])
        monkeypatch.setattr(
            "backend.stores.assessments.list_ai_done_payloads",
            lambda limit=80: [spool.as_payload(dest)],
        )
        stats = workers.profile_cycle(store, tmp_path, limit=20)
        assert stats["inserted"] >= 1
        assert any(r["sender"] == "alice@yahoo.com" for r in store.list_profiles())
    finally:
        spool.set_root(None)


def test_sender_risk_cycle_drains_followup_queue(tmp_path, monkeypatch):
    monkeypatch.setenv("SEG_SENDER_RISK_WORKER", "1")
    store = BehavioralCorrelationStore(db_path=tmp_path / "beh.sqlite3")
    dest = _dest(tmp_path, "gmail-a", {
        "from": "vendor@acme.example",
        "mailbox": "jan@pdax.ph",
        "verdict": "CLEAN",
        "message_id": "<v@x>",
    })
    after_assessment(dest)
    stats = workers.sender_risk_cycle(store, limit=8, use_llm=False)
    assert stats["from_queue"] >= 1
    assert stats["assessed"] >= 1
    assert pending_counts()["sender_risk"] == 0
    stored = store.get_sender_risk("vendor@acme.example")
    assert stored and stored.get("summary")


def test_ingest_copy_point_lookup_skips_existing_message_id(tmp_path):
    from backend.stores.sender_profile_ingest import ingest_copy

    store = BehavioralCorrelationStore(db_path=tmp_path / "beh.sqlite3")
    dest = _dest(tmp_path, "gmail-dup", {
        "from": "alice@yahoo.com",
        "mailbox": "jan@pdax.ph",
        "verdict": "CLEAN",
        "message_id": "<dup@x>",
        "stages": {"origin_ip": {
            "asn": "AS1", "country": "US", "network_role": "esp", "ip": "1.1.1.1",
        }},
    })
    first = ingest_copy(store, dest)
    again = ingest_copy(store, dest)
    assert first["inserted"] == 1
    assert again["inserted"] == 0
    assert again["skipped"] == 1
    assert store.profile_for("alice@yahoo.com")["n"] == 1


def test_profile_sqs_loop_ingests_and_acks(tmp_path, monkeypatch):
    from backend.stores import spool
    import workers.profile as profile
    import workers.runtime as runtime

    store = BehavioralCorrelationStore(db_path=tmp_path / "beh.sqlite3")
    spool.set_root(tmp_path)
    dest = _dest(tmp_path, "gmail-sqs-loop", {
        "from": "alice@yahoo.com",
        "mailbox": "jan@pdax.ph",
        "verdict": "CLEAN",
        "message_id": "<loop@x>",
        "stages": {"origin_ip": {
            "asn": "AS1", "country": "US", "network_role": "esp", "ip": "1.1.1.1",
        }},
    })
    payload = spool.as_payload(dest)
    hits = {"n": 0}
    acked = []

    def fake_wait(kind):
        assert kind == "profile"
        hits["n"] += 1
        if hits["n"] == 1:
            return payload
        runtime.stop.set()
        return None

    monkeypatch.setattr(profile, "_store", lambda existing=None: store)
    monkeypatch.setattr("workers.copy_jobs.wait_for", fake_wait)
    monkeypatch.setattr("workers.copy_jobs.ack", lambda kind, dest: acked.append((kind, dest)))
    runtime.stop.clear()
    try:
        profile._sqs_loop()
    finally:
        runtime.stop.clear()
        spool.set_root(None)
    assert acked == [("profile", payload)]
    assert store.profile_for("alice@yahoo.com")["n"] == 1


def test_wait_for_followup_returns_immediately_when_queued(tmp_path):
    dest = _dest(tmp_path, "gmail-a", {"from": "a@b.com", "verdict": "CLEAN"})
    after_assessment(dest)
    started = __import__("time").monotonic()
    assert workers.runtime.wait_for_followup("campaign", 30) is False
    assert (__import__("time").monotonic() - started) < 1.0
    take_campaign(limit=10)


def _heuristic_result():
    from types import SimpleNamespace
    from backend.models import Verdict
    return SimpleNamespace(
        verdict=Verdict.CLEAN,
        disposition=SimpleNamespace(value="LOG"),
        composite_score=3.0,
        hard_override=None,
        reasons=[],
        subject="Hello",
        from_header="vendor@acme.example",
        to_header="",
        message_id="<mid@example.com>",
        threat_class="none",
        threat_confidence=0.0,
        stages=[],
    )


def test_enrich_queues_followup_after_llm_summary(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from workers import receiver as gr
    from backend.models import StageResult, StageStatus

    heuristic = _heuristic_result()
    qid = gr.persist_gmail_scan(
        "jan.almazora@pdax.ph", "mid-followup",
        b"From: vendor@acme.example\nSubject: Hello\n\nbody",
        heuristic, ["INBOX"], spool_root=tmp_path,
    )
    dest = tmp_path / "gmail" / qid
    llm_result = SimpleNamespace(
        **{k: getattr(heuristic, k) for k in (
            "verdict", "disposition", "composite_score", "hard_override",
            "reasons", "subject", "from_header", "to_header", "message_id",
            "threat_class", "threat_confidence",
        )},
        stages=[
            StageResult(
                stage="content_ai",
                status=StageStatus.OK,
                sub_score=8.0,
                facts={
                    "provider": "glm",
                    "summary": "Benign operational mail.",
                    "model_id": "glm-test",
                },
            ),
        ],
    )
    monkeypatch.setattr("workers.content_ai._run_llm_pipeline", lambda raw, extra_context=None: llm_result)
    gr._enrich_gmail_dest(dest)
    counts = pending_counts()
    assert counts["campaign"] == 1
    assert counts["profile"] == 1
    assert counts["sender_risk"] == 1


def test_enrich_timeout_does_not_queue_followup(tmp_path, monkeypatch):
    from workers import receiver as gr

    heuristic = _heuristic_result()
    qid = gr.persist_gmail_scan(
        "jan.almazora@pdax.ph", "mid-timeout-fu",
        b"From: vendor@acme.example\nSubject: Hello\n\nbody",
        heuristic, ["INBOX"], spool_root=tmp_path,
    )
    dest = tmp_path / "gmail" / qid
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY", "0")
    monkeypatch.setattr(
        "workers.content_ai._assess_from_joined",
        lambda *_a, **_k: heuristic,
    )
    gr._enrich_gmail_dest(dest)
    assert pending_counts() == {"campaign": 0, "profile": 0, "sender_risk": 0}
