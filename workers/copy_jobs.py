"""Queue coordinator: static checks, then AI, then thread AI.

Poll writes a ``static`` job. The static worker runs deterministic stages
(including intel) and then enqueues content AI. SQS in production; SQLite
when queue URLs are unset (pytest).
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from backend.stores import assessments as store
from backend.stores import spool
import workers.jobs as jobs
import workers.runtime as runtime
import workers.sqs as sqs

_log = logging.getLogger("workers.copy_jobs")

_receipts: dict[tuple[str, str], str] = {}


def _receipt_key(kind: str, dest) -> str:
    if kind == "thread_ai":
        if isinstance(dest, dict):
            return str(dest.get("thread_id") or "")
        return str(dest or "")
    return spool.dest_name(dest)


def enqueue_static(dest) -> None:
    put("static", dest)


def put(kind: str, dest) -> None:
    kind = (kind or "").strip()
    if sqs.use_sqs() and kind in sqs.KINDS:
        if kind == "thread_ai":
            tid = dest.get("thread_id") if isinstance(dest, dict) else str(dest or "")
            sqs.send(kind, {"thread_id": tid})
            return
        sqs.send(kind, spool.as_payload(dest))
        return
    if isinstance(dest, dict):
        dest = spool.as_path(dest)
    jobs.put(kind, dest)


def take(kind: str):
    """Claim one dest for kind, or None if idle."""
    if sqs.use_sqs() and kind in sqs.KINDS:
        payload, receipt = sqs.receive(kind, wait_seconds=0)
        if not payload:
            return None
        key = _receipt_key(kind, payload)
        if receipt and key:
            _receipts[(kind, key)] = receipt
        if kind == "thread_ai":
            return str(payload.get("thread_id") or "")
        return payload
    raw = jobs.take(kind)
    if not raw:
        return None
    text = str(raw)
    if text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    if kind == "thread_ai":
        return text
    return Path(text)


def wait_for(kind: str):
    """Block until a dest is queued or the process should exit."""
    if sqs.use_sqs() and kind in sqs.KINDS:
        while not runtime.stop.is_set():
            payload, receipt = sqs.wait_for(kind)
            if payload:
                key = _receipt_key(kind, payload)
                if receipt and key:
                    _receipts[(kind, key)] = receipt
                if kind == "thread_ai":
                    return str(payload.get("thread_id") or "")
                return payload
            if runtime.stop.is_set():
                return None
        return None
    while not runtime.stop.is_set():
        dest = take(kind)
        if dest is not None:
            return dest
        runtime.persist_heartbeat()
        if runtime.stop.wait(1.0):
            return None
    return None


def ack(kind: str, dest) -> None:
    key = _receipt_key(kind, dest)
    receipt = _receipts.pop((kind, key), "")
    if sqs.use_sqs() and kind in sqs.KINDS:
        sqs.ack(kind, receipt)
        return
    jobs.ack(kind, dest)


def defer(kind: str, dest) -> None:
    """Return the message to the queue without recording a failure."""
    key = _receipt_key(kind, dest)
    receipt = _receipts.pop((kind, key), "")
    if sqs.use_sqs() and kind in sqs.KINDS:
        sqs.nack(kind, receipt)
        return
    jobs.nack(kind, dest)


def finished(dest, kind: str = "static") -> None:
    qid = spool.dest_name(dest)
    from workers.content_ai import enqueue, llm_configured
    nxt = store.AI if llm_configured() else store.COMPLETE
    store.upsert_copy(
        qid,
        identity_done=1,
        reputation_done=1,
        static_done=1,
        sandbox_done=1,
        status=nxt,
        last_error="",
    )
    ack(kind, dest)
    if kind == "static":
        enqueue(dest)
        _log.debug("static complete %s → %s", qid, nxt)


def fail(dest, kind: str, error: str, *, terminal: bool = False) -> None:
    """Record a failed attempt. Terminal failures leave the queue (dead letter)."""
    qid = spool.dest_name(dest)
    msg = (error or "error")[:400]
    dest_s = dest if isinstance(dest, str) else (
        json.dumps(dest) if isinstance(dest, dict) else str(dest)
    )
    if terminal:
        store.upsert_copy(qid, dest=dest_s, status=store.DEAD_LETTER, last_error=msg)
        ack(kind, dest)
        return
    store.upsert_copy(qid, dest=dest_s, status=store.ERROR, last_error=msg)
    receive_count = 0
    if isinstance(dest, dict):
        receive_count = int(dest.get("_receive_count") or 0)
    try:
        from backend.config import get_settings
        cap = max(1, int(get_settings().job_max_attempts))
    except Exception:
        cap = 8
    attempts = receive_count or jobs.attempts_of(kind, dest)
    if attempts >= cap:
        store.upsert_copy(qid, status=store.DEAD_LETTER, last_error=msg)
        ack(kind, dest)
        return
    if sqs.use_sqs() and kind in sqs.KINDS:
        key = _receipt_key(kind, dest)
        receipt = _receipts.pop((kind, key), "")
        sqs.nack(kind, receipt)
        return
    jobs.nack(kind, dest)


def enqueue_incomplete(limit: int = 80) -> int:
    """Re-queue copies that never landed on the static queue (process restart).

    Does not HeadObject the spool and does not wait for in-flight static work.
    Skip when SQS already has static jobs so we do not duplicate the backlog.
    """
    from workers import sqs as sqsmod
    if sqsmod.use_sqs() and jobs.pending_count("static") > 0:
        return 0
    n = 0
    for row in store.list_incomplete_static(limit):
        qid = str(row.get("queue_id") or "")
        if not qid:
            continue
        if spool.use_s3():
            put("static", spool.payload(qid))
            n += 1
            continue
        dest = Path(row.get("dest") or "")
        if dest.is_dir():
            put("static", dest)
            n += 1
    return n


def recover_deadlocks(limit: int = 40) -> int:
    """Re-queue copies whose last_error was an Aurora deadlock."""
    holder = f"deadlock_recover:{os.getpid()}"
    if not store.try_lock("deadlock_recover", holder, ttl_seconds=60):
        return 0
    try:
        n = 0
        for row in store.recover_deadlock_copies(limit):
            qid = str(row.get("queue_id") or "")
            if not qid:
                continue
            status = str(row.get("status") or "")
            if status == store.QUEUED:
                if spool.use_s3():
                    put("static", spool.payload(qid))
                else:
                    dest = Path(row.get("dest") or "")
                    put("static", dest if dest.is_dir() else spool.payload(qid))
                n += 1
            elif status == store.AI:
                from workers.content_ai import enqueue
                dest = spool.payload(qid) if spool.use_s3() else Path(row.get("dest") or "")
                enqueue(dest)
                n += 1
        return n
    finally:
        store.release_lock("deadlock_recover", holder)


def ensure_all() -> None:
    """Start in-process pools — used by the optional all-in-one receiver."""
    from workers import static, thread_ai, content_ai
    static.ensure_workers()
    thread_ai.ensure_workers()
    content_ai.ensure_workers()
