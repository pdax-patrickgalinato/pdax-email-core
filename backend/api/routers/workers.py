"""Authenticated snapshot of background workers for the console."""
from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from fastapi import APIRouter, Depends

import workers as workers_mod
from backend.api.auth_store import User
from backend.api.deps import require_role
from backend.config import get_settings
from backend.stores.gmail_coverage import snapshot as coverage_snapshot
from backend.paths import SPOOL_DIR
from backend.stores.assessments import status_counts as assessment_status_counts
from workers import jobs as jobs_mod
from workers import sqs as sqs_mod
from workers.followup import pending_counts as followup_pending_counts

router = APIRouter(prefix="/api")

_DEFAULT_RECEIVER_HEALTH = "http://127.0.0.1:8766/health"
_PROBE_TIMEOUT = 0.8
_SPLIT_PROBE_TIMEOUT = 0.6
_SPOOL_BUCKETS = ("gmail", "quarantine", "released", "rejected")

# Dedicated ``python -m workers <name>`` heartbeats → console slot names.
# ``sender`` is one Fargate task that owns both profile ingest and risk AI.
_PROCESS_SLOTS = (
    ("gmail_poll", "gmail_poll"),
    ("content_ai", "gmail_llm"),
    ("retry", "inconclusive_retry"),
    ("static", "static"),
    ("thread_ai", "thread_ai"),
    ("sender", "profile"),
    ("sender", "sender_risk"),
    ("profile", "profile"),
    ("campaign", "campaign"),
    ("sender_risk", "sender_risk"),
)
_RECEIVER_SLOT_NAMES = frozenset({
    "gmail_poll", "gmail_llm", "inconclusive_retry", "static", "thread_ai",
})
_FOLLOWUP_SLOT_NAMES = frozenset({"profile", "campaign", "sender_risk"})
_SLOT_QUEUE = (
    ("gmail_poll", "poll"),
    ("static", "static"),
    ("gmail_llm", "content_ai"),
    ("thread_ai", "thread_ai"),
    ("campaign", "campaign"),
    ("profile", "profile"),
    ("sender_risk", "sender_risk"),
    ("inconclusive_retry", "retry"),
)


def _in_flight(stats: dict, kind: str, fallback: int = 0) -> int:
    """SQS not-visible / claimed jobs. Local sqlite may fall back to pipeline status."""
    claimed = int((stats.get(kind) or {}).get("claimed") or 0)
    if claimed > 0:
        return claimed
    return max(0, int(fallback or 0))


def queue_snapshot() -> dict:
    """Live job + pipeline counts so the console can tell waiting vs processing."""
    try:
        job = jobs_mod.pending_counts()
    except Exception:
        job = {"static": 0, "content_ai": 0, "thread_ai": 0, "intel": 0}
    try:
        stats = jobs_mod.queue_stats()
    except Exception:
        stats = {}
    try:
        follow = followup_pending_counts()
    except Exception:
        follow = {"campaign": 0, "profile": 0, "sender_risk": 0}
    try:
        pipe = assessment_status_counts()
    except Exception:
        pipe = {}
    static_jobs = int(job.get("static") or 0)
    ai_jobs = int(job.get("content_ai") or 0)
    ai_stage = int(pipe.get("ai") or 0)
    intel_jobs = int(job.get("intel") or 0)
    sqs_live = sqs_mod.use_sqs()
    alerts = []
    stale_n = sum(int((stats.get(k) or {}).get("stale") or 0) for k in ("static", "content_ai", "intel", "thread_ai"))
    if stale_n:
        alerts.append({
            "code": "stale_job_claims",
            "level": "warning",
            "summary": f"{stale_n} claimed job" + ("" if stale_n == 1 else "s") + " past lease — will be reclaimed",
        })
    timed = int(pipe.get("timed_out") or 0)
    if timed >= 25:
        alerts.append({
            "code": "timed_out_backlog",
            "level": "warning",
            "summary": f"{timed} emails timed out waiting on content AI",
        })
    dead = int(pipe.get("dead_letter") or 0)
    if dead:
        alerts.append({
            "code": "dead_letter",
            "level": "warning",
            "summary": f"{dead} email" + ("" if dead == 1 else "s") + " in dead letter (max retries)",
        })
    err = int(pipe.get("error") or 0)
    if err:
        alerts.append({
            "code": "pipeline_error",
            "level": "warning",
            "summary": f"{err} email" + ("" if err == 1 else "s") + " in error status",
        })
    oldest_ai = float((stats.get("content_ai") or {}).get("oldest_claim_age") or 0)
    if oldest_ai >= 180:
        alerts.append({
            "code": "slow_llm_claim",
            "level": "info",
            "summary": f"content AI claim age {oldest_ai:.0f}s",
        })
    return {
        "poll": {
            "waiting": int(pipe.get("queued") or 0),
            "running": 0,
        },
        "static": {
            "waiting": static_jobs,
            "running": _in_flight(stats, "static", 0 if sqs_live else int(pipe.get("static") or 0)),
            "claimed_age": (stats.get("static") or {}).get("oldest_claim_age") or 0,
        },
        "intel": {
            "waiting": intel_jobs,
            "running": int((stats.get("intel") or {}).get("claimed") or 0),
            "claimed_age": (stats.get("intel") or {}).get("oldest_claim_age") or 0,
        },
        "content_ai": {
            "waiting": ai_jobs,
            "running": _in_flight(stats, "content_ai", 0 if sqs_live else (ai_stage - ai_jobs)),
            "claimed_age": (stats.get("content_ai") or {}).get("oldest_claim_age") or 0,
        },
        "thread_ai": {
            "waiting": int(job.get("thread_ai") or 0),
            "running": int((stats.get("thread_ai") or {}).get("claimed") or 0),
        },
        "campaign": {
            "waiting": int(follow.get("campaign") or 0),
            "running": int((stats.get("campaign") or {}).get("claimed") or 0),
        },
        "profile": {"waiting": int(follow.get("profile") or 0), "running": 0},
        "sender_risk": {"waiting": int(follow.get("sender_risk") or 0), "running": 0},
        "retry": {"waiting": timed, "running": 0},
        "pipeline": {
            "queued": int(pipe.get("queued") or 0),
            "static": int(pipe.get("static") or 0),
            "ai": ai_stage,
            "timed_out": timed,
            "error": err,
            "dead_letter": dead,
            "complete": int(pipe.get("complete") or 0),
        },
        "alerts": alerts,
        "job_stats": stats,
    }


def _with_queue(slot, counts: dict) -> dict:
    out = dict(slot) if isinstance(slot, dict) else {}
    waiting = int(counts.get("waiting") or 0)
    running = int(counts.get("running") or 0)
    if running == 0 and out.get("running"):
        running = 1
    out["queue_waiting"] = waiting
    out["queue_running"] = running
    return out


def attach_queues(receiver: dict, local: dict, queues: dict) -> tuple[dict, dict]:
    rec = dict(receiver or {})
    api = dict(local or {})
    for slot_name, queue_key in _SLOT_QUEUE:
        q = queues.get(queue_key) if isinstance(queues.get(queue_key), dict) else {}
        rec[slot_name] = _with_queue(rec.get(slot_name), q)
        api[slot_name] = _with_queue(api.get(slot_name), q)
    return rec, api


def attach_queues_to_processes(processes: dict, queues: dict) -> dict:
    """Stamp the same waiting/running counts onto split-worker probes.

    The console prefers ``processes[name][slot]`` over receiver/api. Without
    this, tiles showed 0 while the Job queues card showed SQS depth.
    """
    slot_to_queue = dict(_SLOT_QUEUE)
    procs: dict = {}
    for name, snap in (processes or {}).items():
        if not isinstance(snap, dict):
            procs[name] = snap
            continue
        out = dict(snap)
        for proc_name, slot_name in _PROCESS_SLOTS:
            if proc_name != name:
                continue
            qkey = slot_to_queue.get(slot_name)
            if not qkey:
                continue
            q = queues.get(qkey) if isinstance(queues.get(qkey), dict) else {}
            slot = out.get(slot_name) if isinstance(out.get(slot_name), dict) else {}
            out[slot_name] = _with_queue(slot, q)
        procs[name] = out
    return procs


def _spool_counts() -> dict:
    root = Path((get_settings().quarantine_root or "").strip() or str(SPOOL_DIR))
    out = {}
    for name in _SPOOL_BUCKETS:
        base = root / name
        n = 0
        try:
            if base.is_dir():
                n = sum(1 for p in base.iterdir() if p.is_dir())
        except OSError:
            n = 0
        out[name] = n
    return out


def ops_snapshot(receiver: dict) -> dict:
    s = get_settings()
    rec = receiver if isinstance(receiver, dict) else {}
    cov = coverage_snapshot()
    rec_users = int(rec.get("users") or 0)
    try:
        from backend.stores.ingest_control import gmail_fetch_snapshot
        ingest = gmail_fetch_snapshot()
    except Exception:
        ingest = {"gmail_fetch": True}
    return {
        "spool": _spool_counts(),
        "gmail_users": rec_users or int(cov.get("polling") or 0),
        "coverage": cov,
        "gmail_fetch": bool(ingest.get("gmail_fetch", True)),
        "gmail_fetch_updated_by": ingest.get("updated_by") or "",
        "gmail_fetch_updated_at": ingest.get("updated_at") or "",
        "receiver_source": rec.get("source") or "",
        "heartbeat_age_seconds": rec.get("heartbeat_age_seconds"),
        "config": {
            "profile_seconds": max(15, int(s.profile_worker_seconds)),
            "retry_seconds": max(20, int(s.inconclusive_retry_seconds)),
            "retry_batch": int(s.inconclusive_retry_batch),
            "retry_max": int(s.inconclusive_retry_max),
            "poll_seconds": max(5, int(s.gmail_poll_seconds)),
            "llm_timeout_seconds": int(s.llm_assess_timeout_seconds),
            "static_workers": int(s.static_workers),
            "content_ai_workers": int(s.content_ai_workers),
            "intel_workers": int(s.intel_workers),
            "job_lease_seconds": int(s.job_lease_seconds),
            "correlation_store": bool(s.correlation_store),
            "profile_worker": bool(s.profile_worker),
            "inconclusive_retry": bool(s.inconclusive_retry),
            "campaign_worker": bool(s.campaign_worker),
            "campaign_seconds": max(30, int(s.campaign_worker_seconds)),
            "sender_risk_worker": bool(s.sender_risk_worker),
            "sender_risk_seconds": max(30, int(s.sender_risk_seconds)),
            "sender_risk_batch": int(s.sender_risk_batch),
        },
    }


def _receiver_health_url() -> str:
    return (get_settings().receiver_health_url or "").strip() or _DEFAULT_RECEIVER_HEALTH


def _ssl_context_for(url: str) -> ssl.SSLContext | None:
    if not str(url).lower().startswith("https:"):
        return None
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ca_path = (os.environ.get("SEG_TLS_CA_PATH") or "").strip() or "/opt/segs/tls/ca.crt"
    pem = (os.environ.get("SEG_TLS_CA") or "").strip()
    if os.path.isfile(ca_path):
        ctx.load_verify_locations(cafile=ca_path)
    elif pem:
        ctx.load_verify_locations(cadata=pem)
    return ctx


def _urlopen(req: urllib.request.Request, timeout: float):
    ctx = _ssl_context_for(req.full_url)
    if ctx is not None:
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)
    return urllib.request.urlopen(req, timeout=timeout)


def _http_probe(url: str, timeout: float) -> dict:
    try:
        req = urllib.request.Request(url, method="GET")
        with _urlopen(req, timeout) as resp:
            body = json.loads(resp.read().decode("utf-8") or "{}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError) as exc:
        return {
            "process": "gmail_receiver",
            "reachable": False,
            "source": "probe",
            "error": str(exc)[:200],
        }
    detail = body.get("workers_detail")
    if not isinstance(detail, dict):
        workers = body.get("workers") or {}
        detail = {
            "process": "gmail_receiver",
            "profile": workers.get("profile") if isinstance(workers.get("profile"), dict)
            else {"alive": bool(workers.get("profile"))},
            "inconclusive_retry": (
                workers.get("inconclusive_retry")
                if isinstance(workers.get("inconclusive_retry"), dict)
                else {"alive": bool(workers.get("inconclusive_retry"))}
            ),
            "campaign": (
                workers.get("campaign")
                if isinstance(workers.get("campaign"), dict)
                else {"alive": bool(workers.get("campaign"))}
            ),
            "gmail_poll": body.get("gmail_poll") or {},
            "gmail_llm": body.get("gmail_llm") or {},
            "events": [],
        }
    detail["reachable"] = True
    detail["source"] = "probe"
    detail["process"] = "gmail_receiver"
    if "users" in body:
        detail["users"] = body.get("users")
    if isinstance(body.get("gmail_poll"), dict):
        detail["gmail_poll"] = body["gmail_poll"]
    if isinstance(body.get("gmail_llm"), dict):
        detail["gmail_llm"] = body["gmail_llm"]
    return detail


def probe_receiver(url: str | None = None, timeout: float = _PROBE_TIMEOUT) -> dict:
    """Live receiver health, or a shared-DB heartbeat if HTTP cannot reach it."""
    if url is None and _worker_health_base():
        return {
            "process": "gmail_receiver",
            "reachable": False,
            "source": "skipped",
            "events": [],
        }
    probed = _http_probe(url or _receiver_health_url(), timeout)
    if probed.get("reachable"):
        return probed
    hb = workers_mod.load_heartbeat("gmail_receiver")
    if hb:
        if "users" not in hb:
            poll = hb.get("gmail_poll") or {}
            users = poll.get("last_stats") or {}
            if "mailboxes" in users:
                hb["users"] = users.get("mailboxes")
        hb["probe_error"] = probed.get("error") or ""
        return hb
    return probed


def _worker_health_base(base: str | None = None) -> str:
    if base is not None:
        return base.strip().rstrip("/")
    return (get_settings().worker_health_base_url or "").strip().rstrip("/")


def _probe_one_worker(url: str, name: str, timeout: float) -> dict | None:
    try:
        req = urllib.request.Request(url, method="GET")
        with _urlopen(req, timeout) as resp:
            body = json.loads(resp.read().decode("utf-8") or "{}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
        return None
    if not isinstance(body, dict):
        return None
    body["reachable"] = True
    body["source"] = "probe"
    if not body.get("process"):
        body["process"] = name
    return body


def probe_split_workers(base: str | None = None, timeout: float = _SPLIT_PROBE_TIMEOUT) -> dict:
    """GET /{name}/health on the internal workers ALB. Empty when unset."""
    root = _worker_health_base(base)
    if not root:
        return {}
    names = list(dict.fromkeys(name for name, _ in _PROCESS_SLOTS))
    out: dict = {}

    def one(name: str):
        return name, _probe_one_worker(f"{root}/{name}/health", name, timeout)

    with ThreadPoolExecutor(max_workers=max(1, len(names))) as pool:
        futs = [pool.submit(one, n) for n in names]
        for fut in as_completed(futs):
            name, snap = fut.result()
            if snap:
                out[name] = snap
    return out


def _slot_from_process(snap: dict, slot_name: str) -> dict | None:
    slot = snap.get(slot_name)
    return slot if isinstance(slot, dict) else None


def merge_standalone_workers(receiver: dict, api: dict, processes: dict) -> tuple[dict, dict]:
    """Fold per-worker heartbeats and ILB probes into the console shapes.

    Split ``python -m workers <name>`` processes do not share a disk with the
    API. Production probes ``SEG_WORKER_HEALTH_BASE_URL/{name}/health``;
    Compose still uses file/Postgres heartbeats.
    """
    rec = dict(receiver or {})
    local = dict(api or {})
    procs = processes if isinstance(processes, dict) else {}
    http_up = bool(rec.get("reachable") and rec.get("source") == "probe")
    merged_any = False
    ages = []

    for proc_name, slot_name in _PROCESS_SLOTS:
        snap = procs.get(proc_name)
        if not isinstance(snap, dict):
            continue
        slot = _slot_from_process(snap, slot_name)
        if slot is None:
            continue
        live = bool(slot.get("alive") or slot.get("running") or slot.get("last_finished_at"))
        if not live:
            continue
        merged_any = True
        age = snap.get("heartbeat_age_seconds")
        if age is not None:
            try:
                ages.append(float(age))
            except (TypeError, ValueError):
                pass
        if slot_name in _RECEIVER_SLOT_NAMES and not http_up:
            rec[slot_name] = slot
        if slot_name in _FOLLOWUP_SLOT_NAMES:
            current = local.get(slot_name) if isinstance(local.get(slot_name), dict) else {}
            if not current.get("alive"):
                local[slot_name] = slot
            if not http_up:
                rec[slot_name] = slot

    if merged_any and not http_up:
        rec["reachable"] = True
        sources = [
            (p.get("source") or "")
            for p in procs.values()
            if isinstance(p, dict)
        ]
        rec["source"] = "probe" if "probe" in sources else "heartbeat"
        rec["process"] = rec.get("process") or "workers"
        rec.pop("error", None)
        if ages:
            rec["heartbeat_age_seconds"] = round(min(ages), 1)
        poll = rec.get("gmail_poll") if isinstance(rec.get("gmail_poll"), dict) else {}
        stats = poll.get("last_stats") if isinstance(poll.get("last_stats"), dict) else {}
        if rec.get("users") is None and "mailboxes" in stats:
            rec["users"] = stats.get("mailboxes")
    return rec, local


def _slot_is_running(receiver: dict, processes: dict, proc_name: str, slot_name: str) -> bool:
    """True when a live heartbeat or HTTP probe says this processor is up."""
    snaps = []
    if isinstance(processes, dict):
        snaps.append(processes.get(proc_name))
        snaps.append(processes.get("gmail_receiver"))
    snaps.append(receiver)
    for snap in snaps:
        if not isinstance(snap, dict):
            continue
        slot = snap.get(slot_name)
        if isinstance(slot, dict) and (slot.get("alive") or slot.get("running")):
            return True
    return False


def _processor_down_alerts(queues: dict, receiver: dict, processes: dict) -> list[dict]:
    """Queue depths come from SQLite even when nobody is draining them."""
    checks = (
        ("static", "static", "static", "static worker", "python -m workers static"),
        ("content_ai", "content_ai", "gmail_llm", "content AI worker", "python -m workers content_ai"),
        ("thread_ai", "thread_ai", "thread_ai", "thread AI worker", "python -m workers thread_ai"),
        ("campaign", "campaign", "campaign", "campaign worker", "python -m workers campaign"),
        ("intel", "static", "static", "static/intel worker", "python -m workers static"),
    )
    out = []
    seen = set()
    for queue_key, proc_name, slot_name, label, start_cmd in checks:
        q = queues.get(queue_key) if isinstance(queues.get(queue_key), dict) else {}
        waiting = int(q.get("waiting") or 0)
        if waiting <= 0:
            continue
        if _slot_is_running(receiver, processes, proc_name, slot_name):
            continue
        code = f"{queue_key}_worker_down"
        if code in seen:
            continue
        seen.add(code)
        out.append({
            "code": code,
            "level": "warning",
            "summary": (
                f"{waiting} {label} job" + ("" if waiting == 1 else "s")
                + " waiting, but that process is not running. Start with "
                + start_cmd
            ),
        })
    return out


@router.get("/workers")
def get_workers(_: User = Depends(require_role("admin", "analyst", "viewer"))):
    local = workers_mod.worker_status()
    local["reachable"] = True
    local["source"] = "local"
    receiver = probe_receiver()
    processes = workers_mod.load_all_heartbeats()
    for name, snap in probe_split_workers().items():
        processes[name] = snap
    receiver, local = merge_standalone_workers(receiver, local, processes)
    queues = queue_snapshot()
    poll_slot = receiver.get("gmail_poll") if isinstance(receiver.get("gmail_poll"), dict) else {}
    poll_stats = poll_slot.get("last_stats") if isinstance(poll_slot.get("last_stats"), dict) else {}
    alerts = list(queues.get("alerts") or [])
    resets = int(poll_stats.get("cursor_resets") or 0)
    if resets:
        alerts.append({
            "code": "gmail_cursor_reset",
            "level": "warning",
            "summary": f"{resets} mailbox cursor" + ("" if resets == 1 else "s")
            + " reseeded after expired historyId",
        })
    elapsed = float(poll_stats.get("elapsed_seconds") or 0)
    interval = max(5, int(get_settings().gmail_poll_seconds))
    if elapsed > interval:
        alerts.append({
            "code": "poll_overrun",
            "level": "warning",
            "summary": f"Gmail poll cycle took {elapsed:.0f}s (interval {interval}s)",
        })
    alerts.extend(_processor_down_alerts(queues, receiver, processes))
    queues["alerts"] = alerts
    receiver, local = attach_queues(receiver, local, queues)
    processes = attach_queues_to_processes(processes, queues)
    events = list(local.get("events") or []) + list(receiver.get("events") or [])
    for snap in processes.values():
        events.extend(list(snap.get("events") or []))
    events.sort(key=lambda e: float(e.get("ts") or 0), reverse=True)
    return {
        "now": time.time(),
        "api": local,
        "receiver": receiver,
        "processes": processes,
        "events": events[:24],
        "ops": ops_snapshot(receiver),
        "queues": queues,
    }
