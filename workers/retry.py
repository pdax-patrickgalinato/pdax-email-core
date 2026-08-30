"""Re-queue timed-out Gmail LLM assessments onto the receiver queue."""
from __future__ import annotations

import logging
import threading
from pathlib import Path

from backend.config import get_settings

import workers.runtime as runtime

_log = logging.getLogger("workers.retry")


def dests_to_auto_retry(spool_root: Path, limit: int = 5):
    from backend.stores import ai_assess
    return ai_assess.dests_inconclusive(spool_root, limit=limit)


def retry_inconclusive_cycle(enqueue, spool_root=None, limit: int | None = None,
                             already_queued=None) -> list[str]:
    from backend.stores import ai_assess
    s = get_settings()
    if not s.inconclusive_retry:
        return []
    runtime.mark_running("inconclusive_retry")
    try:
        batch = int(limit if limit is not None else s.inconclusive_retry_batch)
        dests = ai_assess.dests_inconclusive(
            runtime.spool() if spool_root is None else spool_root, limit=max(1, batch),
        )
        queued: list[str] = []
        for dest in dests:
            try:
                if already_queued is not None and already_queued(dest):
                    continue
                ai_assess.prepare_retry(dest, auto=True)
                enqueue(dest)
                queued.append(dest.name)
            except Exception:
                _log.exception("inconclusive retry failed for %s", dest)
        summary = ""
        if queued:
            n = len(queued)
            summary = f"queued {n} timed-out cop" + ("y" if n == 1 else "ies") + " for LLM retry"
        runtime.finish_cycle(
            "inconclusive_retry",
            stats={"queued": len(queued)},
            queued=queued,
            summary=summary,
        )
        return queued
    except Exception as exc:
        runtime.fail_cycle("inconclusive_retry", str(exc))
        raise


def _loop(enqueue, already_queued=None) -> None:
    from backend.stores.overview import refresh_overview_stats
    while not runtime.stop.is_set():
        try:
            if get_settings().inconclusive_retry:
                queued = retry_inconclusive_cycle(enqueue, already_queued=already_queued)
                if queued:
                    _log.info("inconclusive retry queued %s copies", len(queued))
        except Exception:
            _log.exception("inconclusive retry cycle failed")
        try:
            runtime.mark_running("overview_stats")
            stats = refresh_overview_stats()
            runtime.finish_cycle(
                "overview_stats",
                stats={
                    "total": int(stats.get("total") or 0),
                    "pending": int(stats.get("pending") or 0),
                    "computed_at": float(stats.get("computedAt") or 0),
                },
                summary="overview snapshot refreshed",
            )
        except Exception:
            _log.exception("overview stats refresh failed")
            runtime.fail_cycle("overview_stats", "refresh failed")
        interval = max(20, int(get_settings().inconclusive_retry_seconds))
        if runtime.stop.wait(interval):
            break


def start_inconclusive_retry_worker(enqueue, already_queued=None) -> threading.Thread | None:
    """Idempotent. enqueue(dest) must put work on the content-AI queue.

    The ECS retry task (``python -m workers retry``) always runs ``_loop``,
    including ``refresh_overview_stats``, even when this in-process helper
    returns None because ``SEG_INCONCLUSIVE_RETRY`` is off.
    """
    if not get_settings().inconclusive_retry:
        return None
    if runtime.retry_thread is not None and runtime.retry_thread.is_alive():
        return runtime.retry_thread
    runtime.stop.clear()
    t = threading.Thread(
        target=_loop, args=(enqueue, already_queued),
        name="segs-inconclusive-retry", daemon=True,
    )
    t.start()
    runtime.retry_thread = t
    _log.info("retry / overview-stats worker started")
    runtime.persist_heartbeat()
    return t


def main() -> None:
    from workers.content_ai import already_queued, enqueue

    def _run() -> None:
        _loop(enqueue, already_queued)

    runtime.run_loop("retry", _run)


if __name__ == "__main__":
    main()
