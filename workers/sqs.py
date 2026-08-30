"""SQS send/receive for the mail pipeline. In-memory fake when URLs are unset."""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from typing import Any, Optional

from backend.config import get_settings

_log = logging.getLogger("workers.sqs")

KINDS = ("static", "content_ai", "thread_ai", "campaign", "profile")

_fake_lock = threading.Lock()
_fake: dict[str, deque] = {k: deque() for k in KINDS}
_fake_inflight: dict[str, dict] = {}
_receipt_n = 0


def queue_url(kind: str) -> str:
    s = get_settings()
    return {
        "static": s.sqs_static_url,
        "content_ai": s.sqs_content_ai_url,
        "thread_ai": s.sqs_thread_ai_url,
        "campaign": s.sqs_campaign_url,
        "profile": s.sqs_profile_url,
    }.get(kind, "") or ""


def use_sqs() -> bool:
    return bool(queue_url("static"))


def _client():
    import boto3
    return boto3.client("sqs", region_name=get_settings().aws_region or "ap-southeast-1")


def send(kind: str, payload: dict) -> None:
    kind = (kind or "").strip()
    if kind not in KINDS or not payload:
        return
    body = json.dumps(payload, separators=(",", ":"))
    url = queue_url(kind)
    if url:
        _client().send_message(QueueUrl=url, MessageBody=body)
        return
    with _fake_lock:
        _fake[kind].append(payload)


def receive(kind: str, wait_seconds: int = 20) -> tuple[Optional[dict], str]:
    """Return (payload, receipt). Empty payload means idle."""
    kind = (kind or "").strip()
    if kind not in KINDS:
        return None, ""
    url = queue_url(kind)
    if url:
        wait = max(0, min(int(wait_seconds), 20))
        resp = _client().receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=wait,
            VisibilityTimeout=_visibility(kind),
            AttributeNames=["ApproximateReceiveCount"],
        )
        msgs = resp.get("Messages") or []
        if not msgs:
            return None, ""
        msg = msgs[0]
        try:
            payload = json.loads(msg.get("Body") or "{}")
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        try:
            payload["_receive_count"] = int(
                (msg.get("Attributes") or {}).get("ApproximateReceiveCount") or 1
            )
        except (TypeError, ValueError):
            payload["_receive_count"] = 1
        return payload, str(msg.get("ReceiptHandle") or "")
    deadline = time.time() + max(0.05, min(float(wait_seconds), 1.0))
    while True:
        with _fake_lock:
            if _fake[kind]:
                global _receipt_n
                _receipt_n += 1
                receipt = f"fake-{kind}-{_receipt_n}"
                payload = _fake[kind].popleft()
                _fake_inflight[receipt] = {"kind": kind, "payload": payload}
                return payload, receipt
        if time.time() >= deadline:
            return None, ""
        time.sleep(0.05)


def ack(kind: str, receipt: str) -> None:
    if not receipt:
        return
    url = queue_url(kind)
    if url:
        try:
            _client().delete_message(QueueUrl=url, ReceiptHandle=receipt)
        except Exception:
            _log.warning("sqs ack failed kind=%s", kind)
        return
    with _fake_lock:
        _fake_inflight.pop(receipt, None)


def nack(kind: str, receipt: str) -> None:
    if not receipt:
        return
    url = queue_url(kind)
    if url:
        try:
            _client().change_message_visibility(
                QueueUrl=url, ReceiptHandle=receipt, VisibilityTimeout=0,
            )
        except Exception:
            _log.warning("sqs nack failed kind=%s", kind)
        return
    with _fake_lock:
        item = _fake_inflight.pop(receipt, None)
        if item:
            _fake[item["kind"]].appendleft(item["payload"])


def _visibility(kind: str) -> int:
    return {
        "static": 420,
        "content_ai": 420,
        "thread_ai": 90,
        "campaign": 180,
        "profile": 120,
    }.get(kind, 120)


def wait_for(kind: str) -> tuple[Optional[dict], str]:
    import workers.runtime as runtime
    while not runtime.stop.is_set():
        payload, receipt = receive(kind, wait_seconds=20 if use_sqs() else 1)
        if payload:
            return payload, receipt
        runtime.persist_heartbeat()
        if runtime.stop.wait(0.05):
            return None, ""
    return None, ""


def reset() -> None:
    """Tests only."""
    with _fake_lock:
        for k in KINDS:
            _fake[k].clear()
        _fake_inflight.clear()


def _queue_depths() -> dict:
    """Visible (waiting) and not-visible (in-flight) counts per kind."""
    empty = {"waiting": 0, "claimed": 0}
    if use_sqs():
        client = _client()
        out = {}
        for kind in KINDS:
            url = queue_url(kind)
            if not url:
                out[kind] = dict(empty)
                continue
            try:
                attrs = client.get_queue_attributes(
                    QueueUrl=url,
                    AttributeNames=[
                        "ApproximateNumberOfMessages",
                        "ApproximateNumberOfMessagesNotVisible",
                    ],
                )
                a = attrs.get("Attributes") or {}
                out[kind] = {
                    "waiting": int(a.get("ApproximateNumberOfMessages") or 0),
                    "claimed": int(a.get("ApproximateNumberOfMessagesNotVisible") or 0),
                }
            except Exception:
                out[kind] = dict(empty)
        return out
    with _fake_lock:
        claimed = {k: 0 for k in KINDS}
        for item in _fake_inflight.values():
            k = item.get("kind")
            if k in claimed:
                claimed[k] += 1
        return {
            k: {"waiting": len(_fake[k]), "claimed": claimed[k]}
            for k in KINDS
        }


def pending_counts() -> dict:
    return {k: int(v.get("waiting") or 0) for k, v in _queue_depths().items()}


def queue_stats() -> dict:
    return {
        k: {
            "waiting": int(v.get("waiting") or 0),
            "claimed": int(v.get("claimed") or 0),
            "stale": 0,
            "oldest_claim_age": 0.0,
        }
        for k, v in _queue_depths().items()
    }
