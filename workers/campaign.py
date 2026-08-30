"""Campaign clustering loop over stored spool emails.

Production drains the campaign SQS queue with several in-process consumers
that upsert observations, then reclusters on a timer. Full reclustering on
every email made the follow-up queue stall on 0.25 vCPU.
"""
from __future__ import annotations

import logging
import threading
import time

from backend.config import get_settings
from backend.paths import DATA_DIR
from backend.stores.campaign import CampaignStore, ingest_copy

import workers.copy_jobs as copy_jobs
import workers.runtime as runtime

_log = logging.getLogger("workers.campaign")

_threads: list[threading.Thread] = []
_lock = threading.Lock()
_recompute_lock = threading.Lock()
_obs_since_recompute = 0
_last_recompute = 0.0


def _worker_count() -> int:
    try:
        return max(1, min(int(get_settings().campaign_workers), 16))
    except Exception:
        return 4


def _store(existing=None):
    return existing or CampaignStore(db_path=DATA_DIR / "campaigns.sqlite3")


def _is_deadlock(exc: BaseException) -> bool:
    text = f"{type(exc).__name__} {exc}".lower()
    return "deadlock" in text


def _summary_of(stats: dict) -> str:
    ingested = int(stats.get("ingested") or 0)
    n = int(stats.get("campaigns") or 0)
    flagged = int(stats.get("flagged_campaigns") or 0)
    bits = []
    if ingested:
        bits.append("ingested %s assessed email%s" % (ingested, "" if ingested == 1 else "s"))
    if n:
        bits.append("%s campaign%s" % (n, "" if n == 1 else "s"))
        if flagged:
            bits[-1] += " (%s with flagged emails)" % flagged
    return "; ".join(bits)


def maybe_recompute(store: CampaignStore, *, every_n: int = 40, every_s: float = 20.0) -> dict:
    """Rebuild campaign rows without holding an SQS message."""
    global _obs_since_recompute, _last_recompute
    with _lock:
        _obs_since_recompute += 1
        due = (
            _obs_since_recompute >= max(1, int(every_n))
            or (time.time() - _last_recompute) >= max(5.0, float(every_s))
        )
        if not due:
            return {}
        if not _recompute_lock.acquire(blocking=False):
            return {}
        _obs_since_recompute = 0
        _last_recompute = time.time()
    try:
        campaigns = store.recompute()
        extra = {
            "campaigns": len(campaigns),
            "flagged_campaigns": sum(1 for c in campaigns if c.get("flagged")),
            "members": sum(int(c.get("members") or 0) for c in campaigns),
        }
        try:
            from backend.stores.campaign_insight import enrich_with_llm
            extra.update(enrich_with_llm(store, limit=3))
        except Exception:
            _log.debug("campaign LLM enrich failed", exc_info=True)
        return extra
    finally:
        _recompute_lock.release()


def campaign_cycle(store=None, spool_root=None, limit: int = 150) -> dict:
    from backend.stores.campaign import ingest_dests, ingest_spool
    from workers.followup import take_campaign
    cs = _store(store)
    runtime.mark_running("campaign")
    try:
        queued = take_campaign(limit=max(1, int(limit)))
        if queued:
            stats = ingest_dests(cs, queued, spool_root or runtime.spool())
        else:
            from backend.stores.assessments import list_ai_done_payloads
            assessed = list_ai_done_payloads(limit=limit)
            if assessed:
                stats = ingest_dests(cs, assessed, spool_root or runtime.spool())
            else:
                stats = ingest_spool(cs, spool_root or runtime.spool(), limit=limit)
        try:
            from backend.stores.campaign_insight import enrich_with_llm
            stats.update(enrich_with_llm(cs, limit=3))
        except Exception:
            _log.debug("campaign LLM enrich failed", exc_info=True)
        runtime.finish_cycle("campaign", stats=stats, summary=_summary_of(stats))
        return stats
    except Exception as exc:
        runtime.fail_cycle("campaign", str(exc))
        raise


def _sqs_loop() -> None:
    cs = _store()
    while not runtime.stop.is_set():
        dest = copy_jobs.wait_for("campaign")
        if dest is None:
            return
        for attempt in range(4):
            try:
                runtime.mark_running("campaign")
                stats = ingest_copy(cs, dest)
                copy_jobs.ack("campaign", dest)
                extra = maybe_recompute(cs) if stats.get("ingested") else {}
                stats.update(extra)
                runtime.finish_cycle("campaign", stats=stats, summary=_summary_of(stats))
                if extra.get("campaigns"):
                    _log.info(
                        "campaign worker clustered %s campaign(s)",
                        extra["campaigns"],
                    )
                break
            except Exception as exc:
                if _is_deadlock(exc) and attempt < 3:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                _log.exception("campaign ingest failed for %s", dest)
                try:
                    copy_jobs.defer("campaign", dest)
                except Exception:
                    _log.exception("campaign nack failed")
                runtime.fail_cycle("campaign", str(exc))
                break


def ensure_workers() -> None:
    from workers import sqs as sqsmod
    if not get_settings().campaign_worker:
        return
    if not sqsmod.use_sqs():
        return
    n = _worker_count()
    with _lock:
        alive = [t for t in _threads if t.is_alive()]
        _threads[:] = alive
        while len(_threads) < n:
            t = threading.Thread(
                target=_sqs_loop, name=f"campaign-{len(_threads)}", daemon=True,
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
                waiting = int(jobsmod.pending_count("campaign") or 0)
                claimed = 0
                try:
                    claimed = int(
                        (jobsmod.queue_stats().get("campaign") or {}).get("claimed") or 0
                    )
                except Exception:
                    claimed = 0
                if waiting == 0 and claimed == 0:
                    stats = campaign_cycle(limit=40)
                    if stats.get("campaigns"):
                        _log.info(
                            "campaign worker clustered %s campaign(s)",
                            stats["campaigns"],
                        )
            except Exception:
                _log.exception("campaign worker cycle failed")
            ensure_workers()
            runtime.persist_heartbeat()
            if runtime.stop.wait(15.0):
                break
        return
    while not runtime.stop.is_set():
        try:
            if get_settings().campaign_worker:
                stats = campaign_cycle(limit=150)
                if stats.get("campaigns"):
                    _log.info(
                        "campaign worker clustered %s campaign(s)",
                        stats["campaigns"],
                    )
        except Exception:
            _log.exception("campaign worker cycle failed")
        interval = max(30, int(get_settings().campaign_worker_seconds))
        if runtime.wait_for_followup("campaign", interval):
            break


def start_campaign_worker() -> threading.Thread | None:
    """Idempotent. No-op when SEG_CAMPAIGN_WORKER=0."""
    if not get_settings().campaign_worker:
        return None
    if runtime.campaign_thread is not None and runtime.campaign_thread.is_alive():
        return runtime.campaign_thread
    runtime.stop.clear()
    t = threading.Thread(target=_loop, name="segs-campaign", daemon=True)
    t.start()
    runtime.campaign_thread = t
    _log.info("campaign pattern worker started")
    runtime.persist_heartbeat()
    return t


def main() -> None:
    runtime.run_loop("campaign", _loop)


if __name__ == "__main__":
    main()
