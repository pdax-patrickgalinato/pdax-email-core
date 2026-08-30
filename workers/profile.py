"""Sender-profile ingest loop — CLEAN/LOW hops from the spool.

Production drains the profile SQS queue with several in-process consumers
(like static / content_ai). Local pytest still uses the batch ``profile_cycle``.
"""
from __future__ import annotations

import logging
import threading
import time

from backend.config import get_settings
from backend.paths import DATA_DIR
from workers.pipeline.correlation import BehavioralCorrelationStore
from backend.stores.sender_profile_ingest import ingest_spool_profiles

import workers.copy_jobs as copy_jobs
import workers.runtime as runtime

_log = logging.getLogger("workers.profile")

_threads: list[threading.Thread] = []
_lock = threading.Lock()


def _worker_count() -> int:
    try:
        return max(1, min(int(get_settings().profile_workers), 32))
    except Exception:
        return 4


def _store(existing=None):
    return existing or BehavioralCorrelationStore(
        db_path=DATA_DIR / "behavior_history.sqlite3",
    )


def _merge_copy_stats(into: dict, one: dict) -> None:
    for key in (
        "inserted", "skipped", "request_recorded", "request_skipped",
        "volume_recorded", "volume_skipped", "identity_updated", "from_queue",
    ):
        into[key] = int(into.get(key) or 0) + int(one.get(key) or 0)


def _summary_of(stats: dict) -> str:
    inserted = int(stats.get("inserted") or 0)
    ident = int(stats.get("identity_updated") or 0)
    from_q = int(stats.get("from_queue") or 0)
    bits = []
    if from_q:
        bits.append("ingested %s assessed email%s" % (from_q, "" if from_q == 1 else "s"))
    if inserted:
        bits.append(
            "learned %s CLEAN/LOW hop%s" % (inserted, "" if inserted == 1 else "s")
        )
    if ident:
        bits.append(
            "marked %s %s identity-ineligible"
            % (ident, "email" if ident == 1 else "emails")
        )
    return "; ".join(bits)


def _is_deadlock(exc: BaseException) -> bool:
    text = f"{type(exc).__name__} {exc}".lower()
    return "deadlock" in text


def _offer_risk(sender: str) -> None:
    addr = (sender or "").strip().lower()
    if not addr:
        return
    try:
        from workers import jobs as jobsmod
        if int(jobsmod.pending_count("profile") or 0) > 80:
            return
    except Exception:
        pass
    try:
        from workers.sender_risk import offer_sender
        offer_sender(addr)
    except Exception:
        pass


def ingest_one(store, dest) -> dict:
    from backend.stores.sender_profile_ingest import ingest_copy
    stats = ingest_copy(store, dest)
    _offer_risk(str(stats.get("sender") or ""))
    return stats


def profile_cycle(store=None, spool_root=None, limit: int = 80) -> dict:
    from workers.followup import take_profiles
    cs = _store(store)
    runtime.mark_running("profile")
    try:
        queued = take_profiles(limit=max(1, int(limit)))
        if queued:
            stats = {
                "inserted": 0, "skipped": 0,
                "request_recorded": 0, "request_skipped": 0,
                "volume_recorded": 0, "volume_skipped": 0,
                "identity_updated": 0, "from_queue": 0,
            }
            for dest in queued:
                _merge_copy_stats(stats, ingest_one(cs, dest))
        else:
            from backend.stores.assessments import list_ai_done_payloads
            assessed = list_ai_done_payloads(limit=limit)
            if assessed:
                stats = {
                    "inserted": 0, "skipped": 0,
                    "request_recorded": 0, "request_skipped": 0,
                    "volume_recorded": 0, "volume_skipped": 0,
                    "identity_updated": 0, "from_queue": 0,
                }
                for dest in assessed:
                    _merge_copy_stats(stats, ingest_one(cs, dest))
            else:
                stats = ingest_spool_profiles(cs, spool_root or runtime.spool(), limit=limit)
        runtime.finish_cycle("profile", stats=stats, summary=_summary_of(stats))
        return stats
    except Exception as exc:
        runtime.fail_cycle("profile", str(exc))
        raise


def _sqs_loop() -> None:
    cs = _store()
    while not runtime.stop.is_set():
        dest = copy_jobs.wait_for("profile")
        if dest is None:
            return
        for attempt in range(4):
            try:
                runtime.mark_running("profile")
                stats = ingest_one(cs, dest)
                copy_jobs.ack("profile", dest)
                runtime.finish_cycle("profile", stats=stats, summary=_summary_of(stats))
                if stats.get("inserted"):
                    _log.info(
                        "profile worker inserted %s CLEAN/LOW rows",
                        stats["inserted"],
                    )
                break
            except Exception as exc:
                if _is_deadlock(exc) and attempt < 3:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                _log.exception("profile ingest failed for %s", dest)
                try:
                    copy_jobs.defer("profile", dest)
                except Exception:
                    _log.exception("profile nack failed")
                runtime.fail_cycle("profile", str(exc))
                break


def ensure_workers() -> None:
    from workers import sqs as sqsmod
    if not get_settings().profile_worker:
        return
    if not sqsmod.use_sqs():
        return
    n = _worker_count()
    with _lock:
        alive = [t for t in _threads if t.is_alive()]
        _threads[:] = alive
        while len(_threads) < n:
            t = threading.Thread(
                target=_sqs_loop, name=f"profile-{len(_threads)}", daemon=True,
            )
            t.start()
            _threads.append(t)


def _loop() -> None:
    from workers import sqs as sqsmod
    from workers import jobs as jobsmod
    if sqsmod.use_sqs():
        ensure_workers()
        while not runtime.stop.is_set():
            try:
                waiting = int(jobsmod.pending_count("profile") or 0)
                claimed = 0
                try:
                    claimed = int(
                        (jobsmod.queue_stats().get("profile") or {}).get("claimed") or 0
                    )
                except Exception:
                    claimed = 0
                if waiting == 0 and claimed == 0:
                    stats = profile_cycle(limit=40)
                    if stats.get("inserted"):
                        _log.info(
                            "profile worker inserted %s CLEAN/LOW rows",
                            stats["inserted"],
                        )
            except Exception:
                _log.exception("profile worker cycle failed")
            ensure_workers()
            runtime.persist_heartbeat()
            if runtime.stop.wait(15.0):
                break
        return
    while not runtime.stop.is_set():
        try:
            if get_settings().profile_worker:
                stats = profile_cycle(limit=80)
                if stats.get("inserted"):
                    _log.info(
                        "profile worker inserted %s CLEAN/LOW rows",
                        stats["inserted"],
                    )
        except Exception:
            _log.exception("profile worker cycle failed")
        interval = max(15, int(get_settings().profile_worker_seconds))
        if runtime.wait_for_followup("profile", interval):
            break


def start_profile_worker() -> threading.Thread | None:
    """Idempotent. No-op when SEG_PROFILE_WORKER=0."""
    if not get_settings().profile_worker:
        return None
    if runtime.profile_thread is not None and runtime.profile_thread.is_alive():
        return runtime.profile_thread
    runtime.stop.clear()
    t = threading.Thread(target=_loop, name="segs-sender-profile", daemon=True)
    t.start()
    runtime.profile_thread = t
    _log.info("sender profile worker started")
    runtime.persist_heartbeat()
    return t


def main() -> None:
    runtime.run_loop("profile", _loop)


if __name__ == "__main__":
    main()
