"""Shared worker runtime — heartbeats, cycle slots, stop event.

Each worker module can run as its own process (``python -m workers <name>``)
or as an in-process thread inside the optional all-in-one receiver / API.
Cross-process coordination is Postgres when ``SEG_DATABASE_URL`` is set
(Fargate tasks have no shared disk), otherwise local files / SQLite.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from collections import deque
from pathlib import Path

from backend.config import get_settings
from backend.db import connect as db_connect, is_postgres
from backend.paths import DATA_DIR, SPOOL_DIR

_log = logging.getLogger("workers")

profile_thread: threading.Thread | None = None
retry_thread: threading.Thread | None = None
campaign_thread: threading.Thread | None = None
sender_risk_thread: threading.Thread | None = None
gmail_poll_thread: threading.Thread | None = None

stop = threading.Event()
_lock = threading.Lock()
_process = "unknown"
_EVENTS_MAX = 24
_events: deque[dict] = deque(maxlen=_EVENTS_MAX)
_slots: dict[str, dict] = {}
HEARTBEAT_DIR = DATA_DIR / "worker_heartbeats"
HEARTBEAT_MAX_AGE = 180.0
_HEARTBEAT_SCHEMA = """
CREATE TABLE IF NOT EXISTS worker_heartbeats (
    process TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL DEFAULT '{}',
    updated_at REAL NOT NULL DEFAULT 0
);
"""

# Dedicated ``python -m workers <name>`` processes run the loop on the main
# thread, so the in-process *_thread handles stay None. Map process name →
# console slots that process owns. ``sender`` runs both profile loops.
_DEDICATED_SLOTS = {
    "gmail_poll": frozenset({"gmail_poll"}),
    "static": frozenset({"static"}),
    "content_ai": frozenset({"gmail_llm"}),
    "thread_ai": frozenset({"thread_ai"}),
    "retry": frozenset({"inconclusive_retry"}),
    "campaign": frozenset({"campaign"}),
    "profile": frozenset({"profile"}),
    "sender_risk": frozenset({"sender_risk"}),
    "sender": frozenset({"profile", "sender_risk"}),
}


def _owns_slot(process: str, slot_name: str) -> bool:
    return slot_name in _DEDICATED_SLOTS.get(process, ())


def _empty_slot() -> dict:
    return {
        "enabled": False,
        "alive": False,
        "running": False,
        "interval_seconds": 0,
        "last_started_at": 0.0,
        "last_finished_at": 0.0,
        "last_ok": True,
        "last_error": "",
        "last_stats": {},
        "last_queued": [],
        "cycles": 0,
    }


def set_process(name: str) -> None:
    global _process
    _process = (name or "unknown").strip() or "unknown"


def process_name() -> str:
    return _process


def spool() -> Path:
    root = (get_settings().quarantine_root or "").strip()
    return Path(root) if root else SPOOL_DIR


def _ensure_slot(name: str) -> dict:
    slot = _slots.get(name)
    if slot is None:
        slot = _empty_slot()
        _slots[name] = slot
    return slot


def mark_running(name: str) -> None:
    with _lock:
        slot = _ensure_slot(name)
        slot["running"] = True
        slot["last_started_at"] = time.time()
    persist_heartbeat()


def finish_cycle(
    name: str,
    *,
    stats: dict | None = None,
    queued: list | None = None,
    summary: str = "",
) -> None:
    with _lock:
        slot = _ensure_slot(name)
        slot["running"] = False
        slot["last_finished_at"] = time.time()
        slot["last_ok"] = True
        slot["last_error"] = ""
        slot["last_stats"] = dict(stats or {})
        slot["last_queued"] = list(queued or [])[:20]
        slot["cycles"] = int(slot.get("cycles") or 0) + 1
        if summary:
            _events.appendleft({
                "ts": slot["last_finished_at"],
                "process": _process,
                "worker": name,
                "ok": True,
                "summary": summary[:240],
            })
    persist_heartbeat()


def fail_cycle(name: str, error: str) -> None:
    with _lock:
        slot = _ensure_slot(name)
        slot["running"] = False
        slot["last_finished_at"] = time.time()
        slot["last_ok"] = False
        slot["last_error"] = (error or "error")[:400]
        slot["cycles"] = int(slot.get("cycles") or 0) + 1
        _events.appendleft({
            "ts": slot["last_finished_at"],
            "process": _process,
            "worker": name,
            "ok": False,
            "summary": slot["last_error"][:240],
        })
    persist_heartbeat()


def _hydrate_heartbeat(data: dict, age: float) -> dict | None:
    if not isinstance(data, dict):
        return None
    out = dict(data)
    out["reachable"] = True
    out["source"] = "heartbeat"
    out["heartbeat_age_seconds"] = round(age, 1)
    return out


def _fresher_heartbeat(a: dict | None, b: dict | None) -> dict | None:
    if a is None:
        return b
    if b is None:
        return a
    try:
        age_a = float(a.get("heartbeat_age_seconds") or 0)
        age_b = float(b.get("heartbeat_age_seconds") or 0)
    except (TypeError, ValueError):
        return a
    return a if age_a <= age_b else b


def _persist_file(snap: dict) -> None:
    HEARTBEAT_DIR.mkdir(parents=True, exist_ok=True)
    path = HEARTBEAT_DIR / f"{_process}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(snap, default=str), encoding="utf-8")
    os.replace(tmp, path)


def _upsert_heartbeat_row(conn, process: str, snap: dict, now: float) -> None:
    conn.execute(
        "INSERT INTO worker_heartbeats (process, payload_json, updated_at) "
        "VALUES (?, ?, ?) ON CONFLICT(process) DO UPDATE SET "
        "payload_json = excluded.payload_json, updated_at = excluded.updated_at",
        (process, json.dumps(snap, default=str), now),
    )
    conn.commit()


def _row_to_heartbeat(payload_json, updated_at, *, now: float, max_age: float) -> dict | None:
    try:
        age = now - float(updated_at or 0)
        if age > max(30.0, float(max_age)):
            return None
        data = json.loads(payload_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return _hydrate_heartbeat(data, age)


def _persist_db(snap: dict) -> None:
    """Aurora is the shared store across Fargate tasks (no EFS)."""
    if not is_postgres():
        return
    conn = db_connect()
    _upsert_heartbeat_row(conn, _process, snap, time.time())
    conn.close()


def persist_heartbeat() -> None:
    """Write this process's snapshot to local disk and, in prod, Postgres."""
    if _process in ("", "unknown"):
        return
    snap = worker_status()
    try:
        _persist_file(snap)
    except OSError:
        pass
    try:
        _persist_db(snap)
    except Exception:
        _log.exception("heartbeat persist to database failed")


def _load_file_heartbeat(process: str, max_age: float) -> dict | None:
    path = HEARTBEAT_DIR / f"{process}.json"
    try:
        age = time.time() - path.stat().st_mtime
        if age > max(30.0, float(max_age)):
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return _hydrate_heartbeat(data, age)


def _load_db_heartbeat(process: str, max_age: float) -> dict | None:
    if not is_postgres():
        return None
    conn = db_connect()
    try:
        row = conn.execute(
            "SELECT payload_json, updated_at FROM worker_heartbeats WHERE process = ?",
            (process,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return _row_to_heartbeat(row[0], row[1], now=time.time(), max_age=max_age)


def _list_db_processes() -> list[str]:
    if not is_postgres():
        return []
    conn = db_connect()
    try:
        rows = conn.execute("SELECT process FROM worker_heartbeats").fetchall()
    finally:
        conn.close()
    return [str(r[0]) for r in rows if r and r[0]]


def load_all_heartbeats(max_age: float = HEARTBEAT_MAX_AGE) -> dict:
    """Heartbeats from every worker — local files and, in prod, Postgres."""
    names: set[str] = set()
    try:
        names.update(p.stem for p in HEARTBEAT_DIR.glob("*.json"))
    except OSError:
        pass
    try:
        names.update(_list_db_processes())
    except Exception:
        _log.exception("heartbeat list from database failed")
    out: dict = {}
    for name in names:
        data = load_heartbeat(name, max_age=max_age)
        if data:
            out[name] = data
    return out


def run_loop(name: str, loop_fn) -> None:
    """Foreground process for an interval worker (poll, campaign, …)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    stop.clear()
    set_process(name)
    from workers.health import start_health_server
    start_health_server()
    try:
        loop_fn()
    finally:
        persist_heartbeat()


def run_pool(name: str, ensure_fn) -> None:
    """Foreground process that supervises in-container worker threads."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    stop.clear()
    set_process(name)
    from workers.health import start_health_server
    start_health_server()
    ensure_fn()
    persist_heartbeat()
    while not stop.is_set():
        persist_heartbeat()
        if stop.wait(5.0):
            break


def load_heartbeat(process: str, max_age: float = HEARTBEAT_MAX_AGE) -> dict | None:
    name = (process or "").strip()
    if not name:
        return None
    file_hb = _load_file_heartbeat(name, max_age)
    try:
        db_hb = _load_db_heartbeat(name, max_age)
    except Exception:
        _log.exception("heartbeat load from database failed")
        db_hb = None
    return _fresher_heartbeat(file_hb, db_hb)


def wait_for_followup(kind: str, idle_seconds: int) -> bool:
    """Sleep until stop, idle interval, or a follow-up row appears.

    The LLM worker writes to a sqlite queue on the shared data volume.
    Campaign / profile / sender-risk loops poll that queue every 2s so they
    re-run shortly after an assessment lands, without waiting the full idle
    interval. Returns True when the process should exit.
    """
    deadline = time.time() + max(1, int(idle_seconds))
    while not stop.is_set():
        try:
            from workers.followup import pending_counts
            if int(pending_counts().get(kind) or 0) > 0:
                return False
        except Exception:
            pass
        left = deadline - time.time()
        if left <= 0:
            return False
        if stop.wait(min(2.0, left)):
            return True
    return True


def stop_workers() -> None:
    """Test helper — stop daemon loops started in this process."""
    global profile_thread, retry_thread, campaign_thread, sender_risk_thread
    global gmail_poll_thread
    stop.set()
    for t in (
        profile_thread, retry_thread, campaign_thread, sender_risk_thread,
        gmail_poll_thread,
    ):
        if t is not None and t.is_alive():
            t.join(timeout=2)
    profile_thread = None
    retry_thread = None
    campaign_thread = None
    sender_risk_thread = None
    gmail_poll_thread = None
    try:
        from workers.health import stop_health_server
        stop_health_server()
    except Exception:
        pass


def _slot_alive(thread: threading.Thread | None, slot_name: str, slot: dict) -> bool:
    if thread is not None and thread.is_alive():
        return True
    if _owns_slot(_process, slot_name):
        return True
    # Gmail poll can run on the main thread of the all-in-one receiver;
    # treat a recent cycle as alive even when the helper thread is unset.
    if slot_name == "gmail_poll":
        if slot.get("running"):
            return True
        finished = float(slot.get("last_finished_at") or 0)
        interval = float(slot.get("interval_seconds") or 0)
        if finished and interval and (time.time() - finished) < interval * 3:
            return True
    return False


def worker_status() -> dict:
    s = get_settings()
    with _lock:
        profile = dict(_ensure_slot("profile"))
        retry = dict(_ensure_slot("inconclusive_retry"))
        campaign = dict(_ensure_slot("campaign"))
        sender_risk = dict(_ensure_slot("sender_risk"))
        poll = dict(_ensure_slot("gmail_poll"))
        llm = dict(_ensure_slot("gmail_llm"))
        static = dict(_ensure_slot("static"))
        thread_ai = dict(_ensure_slot("thread_ai"))
        events = list(_events)
        process = _process
    profile["enabled"] = bool(s.profile_worker)
    profile["interval_seconds"] = max(15, int(s.profile_worker_seconds))
    profile["alive"] = _slot_alive(profile_thread, "profile", profile)
    retry["enabled"] = bool(s.inconclusive_retry)
    retry["interval_seconds"] = max(20, int(s.inconclusive_retry_seconds))
    retry["alive"] = _slot_alive(retry_thread, "inconclusive_retry", retry)
    campaign["enabled"] = bool(s.campaign_worker)
    campaign["interval_seconds"] = max(30, int(s.campaign_worker_seconds))
    campaign["alive"] = _slot_alive(campaign_thread, "campaign", campaign)
    sender_risk["enabled"] = bool(s.sender_risk_worker)
    sender_risk["interval_seconds"] = max(30, int(s.sender_risk_seconds))
    sender_risk["alive"] = _slot_alive(sender_risk_thread, "sender_risk", sender_risk)
    poll["enabled"] = True
    poll["interval_seconds"] = max(5, int(s.gmail_poll_seconds))
    poll["alive"] = _slot_alive(gmail_poll_thread, "gmail_poll", poll)
    static["enabled"] = True
    static["interval_seconds"] = 0
    static["alive"] = _slot_alive(None, "static", static)
    thread_ai["enabled"] = True
    thread_ai["interval_seconds"] = 0
    thread_ai["alive"] = _slot_alive(None, "thread_ai", thread_ai)
    llm["enabled"] = True
    llm["interval_seconds"] = 0
    try:
        llm_mod = sys.modules.get("workers.content_ai")
        if llm_mod is None:
            # Do not import content_ai here: /health can run while that
            # module is still loading and would deadlock on the import lock.
            dedicated = _owns_slot(process, "gmail_llm")
            llm["alive"] = dedicated or _slot_alive(None, "gmail_llm", llm)
        else:
            from workers.followup import pending_counts
            dedicated = _owns_slot(process, "gmail_llm")
            llm["alive"] = bool(llm_mod.workers_alive()) or (
                dedicated and llm_mod.llm_configured()
            )
            if dedicated and not llm_mod.llm_configured():
                llm["last_error"] = "LLM provider not configured"
            pending = pending_counts()
            llm["last_stats"] = {
                "queued": llm_mod.queue_depth(),
                "campaign_pending": pending.get("campaign") or 0,
                "profile_pending": pending.get("profile") or 0,
                "sender_risk_pending": pending.get("sender_risk") or 0,
            }
    except Exception:
        llm["alive"] = False
    return {
        "process": process,
        "profile": profile,
        "inconclusive_retry": retry,
        "campaign": campaign,
        "sender_risk": sender_risk,
        "gmail_poll": poll,
        "gmail_llm": llm,
        "static": static,
        "thread_ai": thread_ai,
        "events": events,
    }
