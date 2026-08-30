"""Thread AI worker — runs once every email in a Gmail thread has a per-message assessment."""
from __future__ import annotations

import json
import logging
import os
import socket
import sys
import threading
from pathlib import Path

from backend.stores.mail_thread import (
    normalize_thread_verdict,
    propagate_thread_assessment,
    thread_prompt_context,
)
from backend.stores import assessments as store
from backend.stores import spool

import workers.copy_jobs as copy_jobs
import workers.jobs as jobs
import workers.runtime as runtime

_log = logging.getLogger("workers.thread_ai")

_threads: list[threading.Thread] = []
_lock = threading.Lock()


def _pool_size() -> int:
    try:
        from backend.config import get_settings
        return max(1, min(int(get_settings().thread_ai_workers), 32))
    except Exception:
        return 1


def _claim_holder() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{threading.current_thread().name}"


def _already_done(rows: list) -> bool:
    return bool(rows) and all(int(r.get("thread_ai_done") or 0) for r in rows)


def _tid_for(dest) -> str:
    meta = {}
    try:
        loaded = spool.read_meta(dest)
        if isinstance(loaded, dict):
            meta = loaded
    except Exception:
        meta = {}
    tid = str(meta.get("gmail_thread_id") or "").strip()
    if tid:
        return tid
    row = store.get_copy(spool.dest_name(dest)) or {}
    return str(row.get("gmail_thread_id") or "").strip()


def maybe_enqueue(dest) -> None:
    tid = _tid_for(dest)
    qid = spool.dest_name(dest)
    if tid and qid:
        store.upsert_copy(qid, gmail_thread_id=tid)
    if not tid or not store.thread_ai_ready(tid):
        return
    rows = store.copies_in_thread(tid)
    if rows and all(int(r.get("thread_ai_done") or 0) for r in rows):
        return
    copy_jobs.put("thread_ai", tid)


def _hydrate_thread_ids(limit: int = 80) -> int:
    """Copy ``gmail_thread_id`` from S3/local meta onto emails rows that lack it."""
    print(f"[thread_ai] hydrating gmail_thread_id (up to {limit} emails)",
          file=sys.stderr, flush=True)
    n = 0
    for row in store.list_missing_thread_id(limit):
        dest = _dest_from_row(row)
        if dest is None:
            continue
        try:
            meta = spool.read_meta(dest)
        except Exception:
            meta = {}
        tid = str((meta or {}).get("gmail_thread_id") or "").strip()
        if not tid:
            continue
        store.upsert_copy(str(row["queue_id"]), gmail_thread_id=tid)
        n += 1
    return n


def enqueue_pending(limit: int = 200) -> int:
    """Queue Gmail threads whose emails are all assessed but lack thread AI."""
    from workers import sqs as sqsmod
    if sqsmod.use_sqs() and jobs.pending_count("thread_ai") > 0:
        return 0
    holder = _claim_holder()
    if not store.try_lock("thread_ai_backfill", holder, ttl_seconds=90):
        return 0
    try:
        hydrated = _hydrate_thread_ids(min(80, max(1, int(limit))))
        n = 0
        for tid in store.list_awaiting_thread_ai(limit):
            copy_jobs.put("thread_ai", tid)
            n += 1
        if hydrated:
            print(f"[thread_ai] hydrated gmail_thread_id on {hydrated} emails",
                  file=sys.stderr, flush=True)
        return n
    finally:
        store.release_lock("thread_ai_backfill", holder)


def _dest_from_row(row: dict):
    qid = str(row.get("queue_id") or "").strip()
    dest_s = str(row.get("dest") or "").strip()
    if spool.use_s3() and qid:
        if dest_s.startswith("{"):
            try:
                parsed = json.loads(dest_s)
            except Exception:
                parsed = None
            if isinstance(parsed, dict) and parsed.get("queue_id"):
                return spool.from_payload(parsed)
        return spool.payload(qid)
    dest = Path(dest_s)
    if dest.is_dir() and (dest / "message.eml").is_file():
        return dest
    if qid:
        return spool.payload(qid) if spool.use_s3() else dest
    return None


def process(thread_id: str) -> None:
    runtime.mark_running("thread_ai")
    tid = str(thread_id or "").strip()
    rows = store.copies_in_thread(tid)
    if _already_done(rows):
        copy_jobs.ack("thread_ai", tid)
        runtime.finish_cycle("thread_ai", stats={"thread_id": tid, "skipped": True})
        return
    holder = _claim_holder()
    lock_name = f"thread_ai:{tid}"
    if not store.try_lock(lock_name, holder, ttl_seconds=180):
        again = store.copies_in_thread(tid)
        if _already_done(again):
            copy_jobs.ack("thread_ai", tid)
        else:
            copy_jobs.defer("thread_ai", tid)
        runtime.finish_cycle("thread_ai", stats={"thread_id": tid, "skipped": True})
        return
    try:
        _process_locked(tid, rows)
    finally:
        store.release_lock(lock_name, holder)
        copy_jobs.ack("thread_ai", tid)


def _process_locked(thread_id: str, rows: list) -> None:
    if not rows or not all(int(r.get("ai_done") or 0) for r in rows):
        print(f"[thread_ai] skip {thread_id}: not all emails assessed ({len(rows)} rows)",
              file=sys.stderr, flush=True)
        return
    dests = [d for d in (_dest_from_row(r) for r in rows) if d is not None]
    if len(dests) < 2:
        print(f"[thread_ai] skip {thread_id}: resolved {len(dests)} dests from {len(rows)} rows",
              file=sys.stderr, flush=True)
        return
    latest = dests[-1]
    meta = spool.read_meta(latest)
    if not isinstance(meta, dict):
        meta = {}
    ctx = thread_prompt_context(latest, meta)
    verdicts = [str(r.get("verdict") or "") for r in rows]
    rank = {"MALICIOUS": 4, "SUSPICIOUS": 3, "LOW": 2, "CLEAN": 1, "": 0}
    verdict = max(verdicts, key=lambda v: rank.get(v, 0)) if verdicts else ""
    verdict = normalize_thread_verdict(verdict)
    n = int((ctx or {}).get("count") or len(rows))
    summary = f"Thread of {n} emails. Highest stored verdict is {verdict or 'CLEAN'}."
    transcript = str((ctx or {}).get("transcript") or "")
    if transcript:
        summary = (summary + " " + transcript.splitlines()[0])[:800]
    propagate_thread_assessment(
        latest, summary, verdict, meta,
    )
    store.upsert_copy(spool.dest_name(latest), thread_ai_done=1)
    for row in rows:
        store.mark_stage(row["queue_id"], "thread_ai")
        try:
            from workers.followup import after_assessment
            after_assessment(_dest_from_row(row) or latest)
        except Exception:
            pass
    print(f"[thread_ai] assessed {thread_id} copies={len(rows)} verdict={verdict or 'CLEAN'}",
          file=sys.stderr, flush=True)
    runtime.finish_cycle("thread_ai", stats={
        "thread_id": thread_id,
        "copies": len(rows),
        "verdict": verdict,
    })


def _loop() -> None:
    while not runtime.stop.is_set():
        tid = copy_jobs.wait_for("thread_ai")
        if not tid:
            return
        try:
            process(str(tid))
        except Exception:
            _log.exception("thread AI failed for %s", tid)
            copy_jobs.ack("thread_ai", tid)


def ensure_workers() -> None:
    global _threads
    with _lock:
        _threads = [t for t in _threads if t.is_alive()]
        while len(_threads) < _pool_size():
            t = threading.Thread(target=_loop, name=f"thread-ai-{len(_threads)}", daemon=True)
            t.start()
            _threads.append(t)


def main() -> None:
    def _supervisor() -> None:
        print("[thread_ai] loop start", file=sys.stderr, flush=True)
        ensure_workers()
        try:
            n = enqueue_pending()
            print(f"[thread_ai] queued {n} threads for assessment",
                  file=sys.stderr, flush=True)
        except Exception:
            _log.exception("thread AI initial backfill failed")
        runtime.persist_heartbeat()
        while not runtime.stop.is_set():
            try:
                queued = enqueue_pending()
                if queued:
                    print(f"[thread_ai] backfilled {queued} threads", file=sys.stderr, flush=True)
            except Exception:
                _log.exception("thread AI backfill failed")
            ensure_workers()
            runtime.persist_heartbeat()
            if runtime.stop.wait(15.0):
                break
    runtime.run_loop("thread_ai", _supervisor)


if __name__ == "__main__":
    main()
