"""Filesystem spool + in-memory SQS fallback (no AWS)."""
from __future__ import annotations

from pathlib import Path

from backend.stores import spool
from workers import sqs as sqsmod
from workers.copy_jobs import enqueue_static, take, ack


def test_spool_filesystem_roundtrip(tmp_path, monkeypatch):
    monkeypatch.delenv("SEG_S3_BUCKET", raising=False)
    spool.set_root(tmp_path)
    raw = b"From: a@b.com\n\nHi\n"
    pl = spool.put_eml("gmail-x", raw, "gmail")
    spool.put_meta("gmail-x", {"queue_id": "gmail-x", "from": "a@b.com"}, "gmail")
    assert pl["s3_eml"] == "spool/gmail/gmail-x/message.eml"
    assert spool.get_eml("gmail-x") == raw
    assert spool.get_meta("gmail-x")["from"] == "a@b.com"
    assert spool.exists("gmail-x")
    copies = spool.list_copies("gmail")
    assert copies[0]["queue_id"] == "gmail-x"
    assert spool.read_message("gmail-x") == raw
    spool.set_root(None)


def test_read_meta_payload_does_not_fetch_eml(tmp_path, monkeypatch):
    monkeypatch.delenv("SEG_S3_BUCKET", raising=False)
    spool.set_root(tmp_path)
    spool.put_eml("gmail-x", b"From: a@b.com\n\nHi\n")
    spool.put_meta("gmail-x", {"gmail_thread_id": "thr-1"})

    def boom(*_a, **_k):
        raise AssertionError("read_meta must not download message.eml")

    monkeypatch.setattr(spool, "get_eml", boom)
    meta = spool.read_meta(spool.payload("gmail-x"))
    assert meta["gmail_thread_id"] == "thr-1"
    spool.set_root(None)


def test_sqs_fake_send_receive_ack():
    sqsmod.reset()
    pl = {"queue_id": "gmail-x", "bucket": "gmail", "s3_eml": "spool/gmail/gmail-x/message.eml"}
    sqsmod.send("static", pl)
    assert sqsmod.pending_counts()["static"] == 1
    got, receipt = sqsmod.receive("static", wait_seconds=0)
    assert got["queue_id"] == "gmail-x"
    assert receipt
    sqsmod.ack("static", receipt)
    assert sqsmod.pending_counts()["static"] == 0
    sqsmod.reset()


def test_sqs_fake_queue_stats_counts_in_flight():
    sqsmod.reset()
    sqsmod.send("content_ai", {"queue_id": "gmail-a"})
    sqsmod.send("content_ai", {"queue_id": "gmail-b"})
    stats = sqsmod.queue_stats()["content_ai"]
    assert stats["waiting"] == 2
    assert stats["claimed"] == 0
    _got, receipt = sqsmod.receive("content_ai", wait_seconds=0)
    stats = sqsmod.queue_stats()["content_ai"]
    assert stats["waiting"] == 1
    assert stats["claimed"] == 1
    sqsmod.ack("content_ai", receipt)
    stats = sqsmod.queue_stats()["content_ai"]
    assert stats["waiting"] == 1
    assert stats["claimed"] == 0
    sqsmod.reset()


def test_copy_jobs_sqs_payload_without_eml_body(tmp_path, monkeypatch):
    monkeypatch.delenv("SEG_S3_BUCKET", raising=False)
    monkeypatch.delenv("SEG_SQS_STATIC_URL", raising=False)
    spool.set_root(tmp_path)
    spool.put_eml("gmail-q", b"From: a@b.com\n\nHi\n")
    spool.put_meta("gmail-q", {"queue_id": "gmail-q"})
    enqueue_static(spool.payload("gmail-q"))
    dest = take("static")
    assert dest is not None
    name = dest.name if isinstance(dest, Path) else dest.get("queue_id")
    assert name == "gmail-q"
    ack("static", dest)
    spool.set_root(None)
