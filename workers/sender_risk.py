"""Sender-identity risk loop — heuristic always, LLM when configured.

Several in-process consumers share a cluster-wide lock per address so two
tasks cannot burn Vertex on the same sender. Fresh addresses from profile
ingest jump the line via ``offer_sender``.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
from collections import deque

from backend.config import get_settings
from backend.paths import DATA_DIR
from workers.pipeline.correlation import BehavioralCorrelationStore

import workers.runtime as runtime

_log = logging.getLogger("workers.sender_risk")

_threads: list[threading.Thread] = []
_pool_lock = threading.Lock()
_offered: deque[str] = deque()
_offered_set: set[str] = set()
_offered_lock = threading.Lock()
_OFFER_CAP = 4000


def _worker_count() -> int:
    try:
        return max(1, min(int(get_settings().sender_risk_workers), 16))
    except Exception:
        return 2


def _claim_holder() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{threading.current_thread().name}"


def _store(existing=None):
    return existing or BehavioralCorrelationStore(
        db_path=DATA_DIR / "behavior_history.sqlite3",
    )


def offer_sender(addr: str) -> None:
    """Wake a risk worker for this address after profile ingest."""
    key = (addr or "").strip().lower()
    if not key:
        return
    with _offered_lock:
        if key in _offered_set or len(_offered) >= _OFFER_CAP:
            return
        _offered_set.add(key)
        _offered.append(key)


def _take_offered() -> str:
    with _offered_lock:
        if not _offered:
            return ""
        key = _offered.popleft()
        _offered_set.discard(key)
        return key


def _llm_enabled() -> bool:
    try:
        from workers.pipeline import content_ai as ca
        return not isinstance(ca.get_default_provider(), ca.HeuristicProvider)
    except Exception:
        return False


def _assess_locked(store, addr: str, *, use_llm: bool) -> dict | None:
    from backend.stores import assessments as locks
    from backend.stores.sender_risk import assess_sender

    key = "sender_risk:" + (addr or "").strip().lower()
    holder = _claim_holder()
    if not locks.try_lock(key, holder, ttl_seconds=180):
        return None
    try:
        out = assess_sender(store, addr, use_llm=bool(use_llm))
        store.put_sender_risk(addr, out)
        return out
    finally:
        locks.release_lock(key, holder)


def sender_risk_cycle(store=None, limit: int | None = None, *, use_llm: bool | None = None) -> dict:
    from backend.stores.sender_risk import risk_cycle
    from workers.followup import take_senders

    s = get_settings()
    if not s.sender_risk_worker:
        return {"assessed": 0, "llm": 0, "pending": 0}
    cs = _store(store)
    batch = int(limit if limit is not None else s.sender_risk_batch)
    if use_llm is None:
        use_llm = _llm_enabled()
    runtime.mark_running("sender_risk")
    try:
        addrs = take_senders(limit=max(1, batch))
        if addrs:
            assessed = 0
            llm_n = 0
            for addr in addrs:
                out = _assess_locked(cs, addr, use_llm=bool(use_llm))
                if not out:
                    continue
                assessed += 1
                if (out.get("provider") or "") != "heuristic":
                    llm_n += 1
            stats = {
                "assessed": assessed, "llm": llm_n, "pending": 0,
                "from_queue": assessed,
            }
        else:
            stats = risk_cycle(cs, limit=max(1, batch), use_llm=bool(use_llm))
        n = int(stats.get("assessed") or 0)
        llm_n = int(stats.get("llm") or 0)
        from_q = int(stats.get("from_queue") or 0)
        summary = ""
        if n:
            summary = f"assessed {n} sender" + ("" if n == 1 else "s")
            if from_q:
                summary += " after LLM"
            if llm_n:
                summary += f" ({llm_n} with LLM narrative)"
        runtime.finish_cycle("sender_risk", stats=stats, summary=summary)
        return stats
    except Exception as exc:
        runtime.fail_cycle("sender_risk", str(exc))
        raise


def _one_job(store, *, use_llm: bool) -> bool:
    """Assess one sender. True when work ran (including a skipped lock)."""
    from backend.stores.sender_risk import build_facts, stale
    from workers.followup import take_senders

    offered = _take_offered()
    if offered:
        out = _assess_locked(store, offered, use_llm=use_llm)
        if out is None:
            return True
        runtime.finish_cycle(
            "sender_risk",
            stats={"assessed": 1, "llm": int((out.get("provider") or "") != "heuristic"),
                   "from_queue": 1},
            summary="assessed 1 sender after profile ingest",
        )
        return True
    addrs = take_senders(limit=1)
    if addrs:
        out = _assess_locked(store, addrs[0], use_llm=use_llm)
        if out is None:
            return True
        runtime.finish_cycle(
            "sender_risk",
            stats={"assessed": 1, "llm": int((out.get("provider") or "") != "heuristic"),
                   "from_queue": 1},
            summary="assessed 1 sender after LLM",
        )
        return True
    try:
        from workers import jobs as jobsmod
        if int(jobsmod.pending_count("profile") or 0) > 50:
            return False
    except Exception:
        pass
    for row in store.list_profiles(limit=400):
        addr = (row.get("sender") or "").strip().lower()
        if not addr:
            continue
        facts = build_facts(store, addr, row)
        if not stale(store.get_sender_risk(addr), facts):
            continue
        out = _assess_locked(store, addr, use_llm=use_llm)
        if out is None:
            continue
        runtime.finish_cycle(
            "sender_risk",
            stats={"assessed": 1, "llm": int((out.get("provider") or "") != "heuristic")},
            summary="assessed 1 sender",
        )
        return True
    return False


def _worker() -> None:
    cs = _store()
    while not runtime.stop.is_set():
        try:
            if not get_settings().sender_risk_worker:
                if runtime.stop.wait(5.0):
                    return
                continue
            runtime.mark_running("sender_risk")
            ran = _one_job(cs, use_llm=_llm_enabled())
            if ran:
                continue
        except Exception:
            _log.exception("sender risk worker failed")
        interval = max(15, int(get_settings().sender_risk_seconds))
        if runtime.wait_for_followup("sender_risk", interval):
            return


def ensure_workers() -> None:
    if not get_settings().sender_risk_worker:
        return
    n = _worker_count()
    with _pool_lock:
        alive = [t for t in _threads if t.is_alive()]
        _threads[:] = alive
        while len(_threads) < n:
            t = threading.Thread(
                target=_worker, name=f"sender-risk-{len(_threads)}", daemon=True,
            )
            t.start()
            _threads.append(t)


def _loop() -> None:
    ensure_workers()
    while not runtime.stop.is_set():
        ensure_workers()
        runtime.persist_heartbeat()
        if runtime.stop.wait(15.0):
            break


def start_sender_risk_worker() -> threading.Thread | None:
    """Idempotent. No-op when SEG_SENDER_RISK_WORKER=0."""
    if not get_settings().sender_risk_worker:
        return None
    if runtime.sender_risk_thread is not None and runtime.sender_risk_thread.is_alive():
        return runtime.sender_risk_thread
    runtime.stop.clear()
    t = threading.Thread(target=_loop, name="segs-sender-risk", daemon=True)
    t.start()
    runtime.sender_risk_thread = t
    _log.info("sender risk worker started")
    runtime.persist_heartbeat()
    return t


def main() -> None:
    runtime.run_loop("sender_risk", _loop)


if __name__ == "__main__":
    main()
