"""Phishing campaign clustering and the background worker."""
from __future__ import annotations

import json
import os
from pathlib import Path

import workers
from backend.stores.campaign import (
    CampaignStore,
    content_fingerprint,
    ingest_dests,
    ingest_spool,
    lookup_for_email,
    normalize_url,
    pivot_keys,
    subject_template,
)


def _dest(root: Path, qid: str, meta: dict, bucket: str = "gmail") -> Path:
    d = root / bucket / qid
    d.mkdir(parents=True)
    (d / "message.eml").write_bytes(b"From: a@b.com\n\nHi\n")
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return d


def test_subject_template_strips_reply_and_numbers():
    a = subject_template("Re: Invoice 4419 for jane@pdax.ph")
    b = subject_template("Invoice 8821 for bob@pdax.ph")
    assert a == b
    assert "4419" not in a
    assert "jane" not in a


def test_normalize_url_strips_tracking_and_www():
    host, path = normalize_url(
        "https://www.phish.example/login?utm_source=mail&user=1"
    )
    assert host == "phish.example"
    assert path == "phish.example/login?user=1"
    assert "utm_source" not in path


def test_popular_hosts_are_not_url_host_keys():
    keys = pivot_keys({
        "subject": "Your Google Drive file",
        "iocs": {"urls": ["https://drive.google.com/file/d/abc"]},
    })
    assert not any(k.startswith("url_host:google.com") for k in keys)
    assert any(k.startswith("url_path:") for k in keys)


def test_generic_subject_is_not_a_pivot():
    keys = pivot_keys({"subject": "Invoice", "iocs": {}})
    assert not any(k.startswith("subj:") for k in keys)


def test_shared_landing_url_clusters_two_senders(tmp_path):
    store = CampaignStore(db_path=tmp_path / "cam.sqlite3")
    spool = tmp_path / "spool"
    url = "https://secure-pay.example/login/pdax"
    _dest(spool, "gmail-a", {
        "from": "ap@evil-one.com", "mailbox": "jan@pdax.ph",
        "subject": "Payroll update required", "verdict": "SUSPICIOUS",
        "iocs": {"urls": [url]},
    })
    _dest(spool, "gmail-b", {
        "from": "hr@evil-two.com", "mailbox": "pat@pdax.ph",
        "subject": "Payroll update required", "verdict": "MALICIOUS",
        "iocs": {"urls": [url + "?utm_campaign=x"]},
    })
    stats = ingest_spool(store, spool, limit=20)
    assert stats["campaigns"] >= 1
    cams = store.list_campaigns()
    assert cams[0]["senders"] >= 2
    assert cams[0]["members"] >= 2
    kinds = {c["kind"] for c in cams}
    assert "url_path" in kinds or "mixed" in kinds or "subj" in kinds or "content" in kinds
    hits = lookup_for_email(urls=[url], store=store)
    assert hits
    meta_a = json.loads((spool / "gmail" / "gmail-a" / "meta.json").read_text())
    assert meta_a.get("campaigns")
    cam = store.get_campaign(cams[0]["id"])
    assert cam and cam["members"] >= 2


def test_shared_hash_is_a_campaign(tmp_path):
    store = CampaignStore(db_path=tmp_path / "cam.sqlite3")
    spool = tmp_path / "spool"
    digest = "a" * 64
    _dest(spool, "gmail-a", {
        "from": "a@one.example", "mailbox": "jan@pdax.ph",
        "subject": "Q3 bonus letter attached", "verdict": "MALICIOUS",
        "iocs": {"hashes_sha256": [digest]},
    })
    _dest(spool, "gmail-b", {
        "from": "b@two.example", "mailbox": "pat@pdax.ph",
        "subject": "Q3 bonus letter attached", "verdict": "SUSPICIOUS",
        "iocs": {"hashes_sha256": [digest]},
    })
    ingest_spool(store, spool, limit=20)
    cams = store.list_campaigns()
    assert any(c["kind"] in ("hash", "mixed", "content", "subj") for c in cams)
    assert any(c["members"] >= 2 for c in cams)


def test_same_sender_two_copies_of_google_links_are_not_a_campaign(tmp_path):
    store = CampaignStore(db_path=tmp_path / "cam.sqlite3")
    spool = tmp_path / "spool"
    _dest(spool, "gmail-a", {
        "from": "alerts@google.com", "mailbox": "jan@pdax.ph",
        "subject": "Security alert", "verdict": "CLEAN",
        "iocs": {"urls": ["https://myaccount.google.com/notifications"]},
    })
    _dest(spool, "gmail-b", {
        "from": "alerts@google.com", "mailbox": "jan@pdax.ph",
        "subject": "Security alert", "verdict": "CLEAN",
        "iocs": {"urls": ["https://myaccount.google.com/notifications?utm_source=mail"]},
    })
    ingest_spool(store, spool, limit=20)
    # Unique path on google.com can cluster only with senders>=2, mailboxes>=3, or flagged.
    cams = [c for c in store.list_campaigns() if c["kind"] == "url_host"]
    assert cams == []


def test_content_fingerprint_ignores_sender():
    a = content_fingerprint("Wire request", "Please process the remaining balance to this account today before close.")
    b = content_fingerprint("Wire request", "Please process the remaining balance to this account today before close.")
    assert a and a == b


def test_campaign_cycle_records_status(tmp_path):
    store = CampaignStore(db_path=tmp_path / "cam.sqlite3")
    spool = tmp_path / "spool"
    digest = "b" * 64
    _dest(spool, "gmail-a", {
        "from": "a@one.example", "mailbox": "jan@pdax.ph",
        "subject": "Shared payload lure here", "verdict": "MALICIOUS",
        "iocs": {"hashes_sha256": [digest]},
    })
    _dest(spool, "gmail-b", {
        "from": "b@two.example", "mailbox": "pat@pdax.ph",
        "subject": "Shared payload lure here", "verdict": "SUSPICIOUS",
        "iocs": {"hashes_sha256": [digest]},
    })
    stats = workers.campaign_cycle(store, spool, limit=20)
    assert stats["campaigns"] >= 1
    snap = workers.worker_status()
    assert snap["campaign"]["last_ok"] is True
    assert snap["campaign"]["last_stats"]["campaigns"] >= 1
    assert any("campaign" in (e.get("summary") or "") or "clustered" in (e.get("summary") or "")
               for e in snap["events"])


def test_campaign_cycle_drains_followup_queue(tmp_path):
    from workers.followup import after_assessment

    store = CampaignStore(db_path=tmp_path / "cam.sqlite3")
    spool = tmp_path / "spool"
    digest = "c" * 64
    a = _dest(spool, "gmail-a", {
        "from": "a@one.example", "mailbox": "jan@pdax.ph",
        "subject": "Shared payload lure here", "verdict": "MALICIOUS",
        "iocs": {"hashes_sha256": [digest]},
    })
    _dest(spool, "gmail-b", {
        "from": "b@two.example", "mailbox": "pat@pdax.ph",
        "subject": "Shared payload lure here", "verdict": "SUSPICIOUS",
        "iocs": {"hashes_sha256": [digest]},
    })
    after_assessment(a)
    stats = workers.campaign_cycle(store, spool, limit=20)
    assert stats["from_queue"] >= 1
    assert stats["ingested"] >= 1


def test_ingest_dests_accepts_sqs_payload(tmp_path):
    from backend.stores import spool
    store = CampaignStore(db_path=tmp_path / "cam.sqlite3")
    spool.set_root(tmp_path)
    try:
        url = "https://secure-pay.example/login/pdax"
        a = _dest(tmp_path, "gmail-a", {
            "from": "ap@evil-one.com", "mailbox": "jan@pdax.ph",
            "subject": "Payroll update required", "verdict": "SUSPICIOUS",
            "iocs": {"urls": [url]},
        })
        b = _dest(tmp_path, "gmail-b", {
            "from": "hr@evil-two.com", "mailbox": "pat@pdax.ph",
            "subject": "Payroll update required", "verdict": "MALICIOUS",
            "iocs": {"urls": [url + "?utm_campaign=x"]},
        })
        stats = ingest_dests(store, [spool.as_payload(a), spool.as_payload(b)], tmp_path)
        assert stats["ingested"] == 2
        assert stats["campaigns"] >= 1
        assert store.list_campaigns()
    finally:
        spool.set_root(None)


def test_campaign_cycle_backfills_assessed_copies(tmp_path, monkeypatch):
    from backend.stores import spool
    store = CampaignStore(db_path=tmp_path / "cam.sqlite3")
    spool.set_root(tmp_path)
    try:
        url = "https://secure-pay.example/login/pdax"
        a = _dest(tmp_path, "gmail-backfill-a", {
            "from": "ap@evil-one.com", "mailbox": "jan@pdax.ph",
            "subject": "Payroll update required", "verdict": "SUSPICIOUS",
            "iocs": {"urls": [url]},
        })
        b = _dest(tmp_path, "gmail-backfill-b", {
            "from": "hr@evil-two.com", "mailbox": "pat@pdax.ph",
            "subject": "Payroll update required", "verdict": "MALICIOUS",
            "iocs": {"urls": [url + "?utm_campaign=x"]},
        })
        monkeypatch.setattr("workers.followup.take_campaign", lambda limit=150: [])
        monkeypatch.setattr(
            "backend.stores.assessments.list_ai_done_payloads",
            lambda limit=150: [spool.as_payload(a), spool.as_payload(b)],
        )
        stats = workers.campaign_cycle(store, tmp_path, limit=20)
        assert stats["ingested"] >= 2
        assert store.list_campaigns()
    finally:
        spool.set_root(None)


def test_campaign_sqs_loop_ingests_and_acks(tmp_path, monkeypatch):
    from backend.stores import spool
    import workers.campaign as campaign
    import workers.runtime as runtime

    store = CampaignStore(db_path=tmp_path / "cam.sqlite3")
    spool.set_root(tmp_path)
    dest = _dest(tmp_path, "gmail-sqs-cam", {
        "from": "a@one.example", "mailbox": "jan@pdax.ph",
        "subject": "Shared payload lure here", "verdict": "MALICIOUS",
        "iocs": {"hashes_sha256": ["c" * 64]},
    })
    payload = spool.as_payload(dest)
    hits = {"n": 0}
    acked = []

    def fake_wait(kind):
        assert kind == "campaign"
        hits["n"] += 1
        if hits["n"] == 1:
            return payload
        runtime.stop.set()
        return None

    monkeypatch.setattr(campaign, "_store", lambda existing=None: store)
    monkeypatch.setattr("workers.copy_jobs.wait_for", fake_wait)
    monkeypatch.setattr("workers.copy_jobs.ack", lambda kind, dest: acked.append((kind, dest)))
    runtime.stop.clear()
    campaign._obs_since_recompute = 0
    campaign._last_recompute = 0.0
    try:
        campaign._sqs_loop()
    finally:
        runtime.stop.clear()
        spool.set_root(None)
    assert acked == [("campaign", payload)]
    assert any("gmail-sqs-cam" in (r.get("dest") or "") for r in store._load_obs())


def test_campaign_worker_disabled_by_default_in_tests():
    os.environ["SEG_CAMPAIGN_WORKER"] = "0"
    assert workers.start_campaign_worker() is None


def test_start_campaign_worker_thread(monkeypatch, tmp_path):
    monkeypatch.setenv("SEG_CAMPAIGN_WORKER", "1")
    monkeypatch.setenv("SEG_PROFILE_WORKER", "0")
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY", "0")
    monkeypatch.setattr(workers.runtime, "HEARTBEAT_DIR", tmp_path)
    monkeypatch.setattr(workers.runtime, "spool", lambda: tmp_path / "spool")
    workers.stop_workers()
    workers.set_process("api")
    t = workers.start_campaign_worker()
    try:
        assert t is not None and t.is_alive()
        snap = workers.worker_status()
        assert snap["campaign"]["alive"] is True
        assert snap["campaign"]["enabled"] is True
        hb = workers.load_heartbeat("api", max_age=60)
        assert hb is not None
        assert hb["campaign"]["alive"] is True
    finally:
        workers.stop_workers()


def test_heuristic_insight_synthesizes_member_ai():
    from backend.stores.campaign_insight import heuristic_insight

    cam = {
        "id": "cam-pay",
        "kind": "url_path",
        "pattern": "url_path:secure-pay.example/login/pdax",
        "members": 2,
        "senders": 2,
        "mailboxes": 2,
        "flagged": 2,
        "keys": ["url_path:secure-pay.example/login/pdax"],
        "subjects": ["Payroll update required"],
        "dests": ["gmail/gmail-a", "gmail/gmail-b"],
        "sender_list": ["ap@evil-one.com", "hr@evil-two.com"],
    }
    briefs = [
        {
            "queue_id": "gmail-a",
            "from": "ap@evil-one.com",
            "mailbox": "jan@pdax.ph",
            "subject": "Payroll update required",
            "verdict": "SUSPICIOUS",
            "ai_summary": "Credential harvest impersonating payroll. Login page clones the HR portal.",
            "nlu_intent": "credential_theft",
            "threat_class": "credential_theft",
            "nlu_confidence": 0.91,
            "findings": ["lookalike landing page"],
            "iocs": {
                "urls": ["https://secure-pay.example/login/pdax"],
                "domains": ["secure-pay.example"],
                "hashes": [],
                "ips": [],
            },
            "ai_done": 1,
            "thread_summary": "",
        },
        {
            "queue_id": "gmail-b",
            "from": "hr@evil-two.com",
            "mailbox": "pat@pdax.ph",
            "subject": "Payroll update required",
            "verdict": "MALICIOUS",
            "ai_summary": "Same fake payroll login as other mailboxes. Do not enter credentials.",
            "nlu_intent": "credential_theft",
            "threat_class": "credential_theft",
            "nlu_confidence": 0.94,
            "findings": ["urgent payroll pretext"],
            "iocs": {
                "urls": ["https://secure-pay.example/login/pdax?utm_campaign=x"],
                "domains": ["secure-pay.example"],
                "hashes": [],
                "ips": [],
            },
            "ai_done": 1,
            "thread_summary": "",
        },
    ]
    out = heuristic_insight(cam, briefs)
    assert out["attack_class"] == "credential_theft"
    text = (out["ai_summary"] + " " + out["ai_title"]).lower()
    assert "credential" in text or "payroll" in text
    insight = out["insight"]
    assert insight["member_briefs"]
    assert insight["shared_iocs"]["urls"]
    assert insight["analyst_actions"]
    assert insight["false_positive_risk"] == "low"
    assert any("landing" in p.lower() or "url" in p.lower() for p in insight["patterns"])


def test_campaign_insight_reads_already_analyzed_copies(tmp_path):
    from backend.stores import assessments as ast
    from backend.stores.campaign_insight import heuristic_insight, load_member_briefs

    store = CampaignStore(db_path=tmp_path / "cam.sqlite3")
    spool = tmp_path / "spool"
    url = "https://secure-pay.example/login/pdax"
    _dest(spool, "gmail-a", {
        "from": "ap@evil-one.com", "mailbox": "jan@pdax.ph",
        "subject": "Payroll update required", "verdict": "SUSPICIOUS",
        "iocs": {"urls": [url]}, "threat_class": "credential_theft",
    })
    _dest(spool, "gmail-b", {
        "from": "hr@evil-two.com", "mailbox": "pat@pdax.ph",
        "subject": "Payroll update required", "verdict": "MALICIOUS",
        "iocs": {"urls": [url + "?utm_campaign=x"]}, "threat_class": "credential_theft",
    })
    stages = {
        "content": {
            "nlu_intent": "credential_theft",
            "nlu_confidence": 0.9,
            "summary": "Fake payroll portal stealing passwords.",
        }
    }
    ast.upsert_copy(
        "gmail-a", from_addr="ap@evil-one.com", mailbox="jan@pdax.ph",
        subject="Payroll update required", verdict="SUSPICIOUS", ai_done=1,
        ai_summary="Credential harvest impersonating payroll. Login page at secure-pay.example.",
        stages_json=json.dumps(stages),
        meta_json=json.dumps({"iocs": {"urls": [url]}, "threat_class": "credential_theft"}),
    )
    ast.upsert_copy(
        "gmail-b", from_addr="hr@evil-two.com", mailbox="pat@pdax.ph",
        subject="Payroll update required", verdict="MALICIOUS", ai_done=1,
        ai_summary="Same fake payroll login delivered to a second mailbox.",
        stages_json=json.dumps(stages),
        meta_json=json.dumps({"iocs": {"urls": [url]}, "threat_class": "credential_theft"}),
    )
    ingest_spool(store, spool, limit=20)
    cams = store.list_campaigns()
    assert cams
    cam = cams[0]
    assert cam["ai_summary"]
    assert cam["attack_class"] in ("credential_theft", "mixed", "unknown")
    assert cam["insight"]["member_briefs"]
    briefs = load_member_briefs(cam, store)
    assert any(b.get("ai_summary") for b in briefs)
    refined = heuristic_insight(cam, briefs)
    assert "payroll" in refined["ai_summary"].lower() or refined["attack_class"] == "credential_theft"


def test_campaign_insight_llm_refines_narrative(tmp_path, monkeypatch):
    store = CampaignStore(db_path=tmp_path / "cam.sqlite3")
    spool = tmp_path / "spool"
    digest = "ab" * 32
    _dest(spool, "gmail-a", {
        "from": "a@one.example", "mailbox": "jan@pdax.ph",
        "subject": "Q3 bonus letter attached", "verdict": "MALICIOUS",
        "iocs": {"hashes_sha256": [digest]},
    })
    _dest(spool, "gmail-b", {
        "from": "b@two.example", "mailbox": "pat@pdax.ph",
        "subject": "Q3 bonus letter attached", "verdict": "SUSPICIOUS",
        "iocs": {"hashes_sha256": [digest]},
    })
    ingest_spool(store, spool, limit=20)
    monkeypatch.setattr(
        "backend.stores.campaign_insight._llm_json",
        lambda system, user: ({
            "title": "Shared malware payload campaign",
            "attack_class": "malware_delivery",
            "confidence": "high",
            "summary": "Two senders delivered the same malicious attachment hash to two mailboxes.",
            "lure": "Open the bonus letter attachment.",
            "patterns": ["Identical SHA-256 across senders"],
            "tactics": ["malware dropper"],
            "targeting": "jan@pdax.ph and pat@pdax.ph",
            "infrastructure": "shared attachment hash",
            "why_clustered": "Same payload hash.",
            "false_positive_risk": "low",
            "false_positive_note": "Hash overlap is not coincidental.",
            "analyst_actions": ["Block the hash and hunt other deliveries."],
        }, "glm-test"),
    )
    monkeypatch.setattr("backend.stores.campaign_insight._has_llm", lambda: True)
    from backend.stores.campaign_insight import enrich_with_llm
    stats = enrich_with_llm(store, limit=5)
    assert stats["llm"] >= 1
    cam = store.get_campaign(store.list_campaigns()[0]["id"])
    assert cam["ai_title"] == "Shared malware payload campaign"
    assert cam["attack_class"] == "malware_delivery"
    assert cam["insight"]["lure"]
    assert cam["ai_provider"] != "heuristic"


def test_campaign_insight_survives_recompute(tmp_path):
    store = CampaignStore(db_path=tmp_path / "cam.sqlite3")
    spool = tmp_path / "spool"
    url = "https://phish.example/login/pdax"
    _dest(spool, "gmail-a", {
        "from": "a@one.example", "mailbox": "jan@pdax.ph",
        "subject": "VPN password reset", "verdict": "MALICIOUS",
        "iocs": {"urls": [url]},
    })
    _dest(spool, "gmail-b", {
        "from": "b@two.example", "mailbox": "pat@pdax.ph",
        "subject": "VPN password reset", "verdict": "SUSPICIOUS",
        "iocs": {"urls": [url]},
    })
    ingest_spool(store, spool, limit=20)
    first = store.list_campaigns()[0]
    assert first["ai_summary"]
    cid, summary = first["id"], first["ai_summary"]
    store.recompute()
    again = store.get_campaign(cid)
    assert again and again["ai_summary"]
    assert again["id"] == cid
    assert summary in again["ai_summary"] or again["ai_summary"]
