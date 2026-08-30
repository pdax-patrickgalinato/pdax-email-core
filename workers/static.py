"""Static checks worker — deterministic stages, then enqueue AI.

Identity, reputation, deception/rules, attachments, and sandbox/landing run
in this process. VirusTotal / AbuseIPDB run as a deferred ``intel`` job so
the 15s free-tier throttle does not block content AI. Content AI is a
separate worker that reads the stored stages.
"""
from __future__ import annotations

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from backend.models import StageResult, StageStatus
from workers.pipeline import attachments, deception, detection_rules as detection_rules_mod
from workers.pipeline import headers, intel, sender, urls, sandbox as sandbox_mod
from workers.pipeline.origin_ip import enrich as origin_ip_enrich, stage_result as origin_stage

import workers.copy_jobs as copy_jobs
import workers.runtime as runtime
from backend.stores import assessments as store
from workers.stage_run import config, extra, load_pe, record_stages, safe

_log = logging.getLogger("workers.static")
_threads: list[threading.Thread] = []
_intel_threads: list[threading.Thread] = []
_lock = threading.Lock()


def _pool_size(attr: str, default: int) -> int:
    try:
        from backend.config import get_settings
        n = int(getattr(get_settings(), attr))
        return max(1, min(n, 32))
    except Exception:
        return default


def _origin_facts(pe) -> dict:
    try:
        return origin_ip_enrich(
            pe.originating_hop(),
            sender_domain=(pe.from_addr or "").split("@")[-1],
        ) or {}
    except Exception:
        return {}


def process(dest) -> None:
    from backend.stores import spool
    import os
    import socket

    qid = spool.dest_name(dest)
    dest_s = json.dumps(dest) if isinstance(dest, dict) else str(dest)
    runtime.mark_running("static")
    row = store.get_copy(qid) or {}
    if store.static_complete(row):
        copy_jobs.ack("static", dest)
        runtime.finish_cycle("static", stats={"queue_id": qid, "ok": True, "skipped": True})
        return
    holder = f"{socket.gethostname()}:{os.getpid()}:{threading.current_thread().name}"
    lock_name = f"static:{qid}"
    if not store.try_lock(lock_name, holder, ttl_seconds=300):
        again = store.get_copy(qid) or {}
        if store.static_complete(again):
            copy_jobs.ack("static", dest)
        else:
            copy_jobs.defer("static", dest)
        runtime.finish_cycle("static", stats={"queue_id": qid, "ok": True, "skipped": True})
        return
    try:
        _process_locked(dest, qid, dest_s)
    finally:
        store.release_lock(lock_name, holder)


def _process_locked(dest, qid: str, dest_s: str) -> None:
    store.upsert_copy(qid, dest=dest_s, status=store.STATIC)
    pe, meta = load_pe(dest)
    if pe is None:
        copy_jobs.fail(dest, "static", "unreadable_eml", terminal=True)
        runtime.finish_cycle("static", stats={"queue_id": qid, "ok": False})
        return
    store.upsert_copy(
        qid,
        dest=dest_s,
        status=store.STATIC,
        mailbox=str((meta or {}).get("mailbox") or ""),
        gmail_thread_id=str((meta or {}).get("gmail_thread_id") or ""),
        gmail_message_id=str((meta or {}).get("gmail_message_id") or ""),
    )
    weights_cfg, protected, vips, policy_cfg, banned_ext = config()
    ctx = extra(meta)
    with ThreadPoolExecutor(max_workers=5) as pool:
        fut_h = pool.submit(safe, "headers", headers.run, pe, protected)
        fut_s = pool.submit(safe, "sender", sender.run, pe, protected, vips)
        fut_u = pool.submit(safe, "urls", urls.run, pe, protected)
        fut_a = pool.submit(
            safe, "attachments", attachments.run, pe,
            weights_cfg.get("forensics_severity_points"), banned_ext, policy_cfg,
        )
        fut_o = pool.submit(_origin_facts, pe)
        h = fut_h.result()
        s = fut_s.result()
        u = fut_u.result()
        a = fut_a.result()
        origin_facts = fut_o.result() or {}
    d = safe("deception", deception.run, pe, h.facts, u.facts)
    stages = [h, s, u, d, a]
    ost = origin_stage(origin_facts)
    if ost:
        stages.append(ost)
    flags = []
    for st in (h, u, d):
        flags.extend(st.red_flags or [])
    try:
        matched = detection_rules_mod.match_rules(flags)
    except Exception:
        matched = []
    if matched:
        stages.append(StageResult(
            stage="detection_rules",
            status=StageStatus.OK,
            facts={"matched": matched},
            red_flags=[m.get("id") or "" for m in matched if m.get("id")],
        ))
    provider = sandbox_mod.get_default_sandbox_provider()
    sandbox_facts = []
    for att in pe.attachments() or []:
        try:
            score, findings, facts = provider.detonate(
                getattr(att, "filename", "") or "",
                getattr(att, "content_type", "") or "",
                getattr(att, "payload", b"") or b"",
            )
            sandbox_facts.append({
                "filename": getattr(att, "filename", ""),
                "score": score,
                "findings": findings,
                "facts": facts,
            })
        except Exception as exc:
            sandbox_facts.append({"error": str(exc)[:200]})
    landing = []
    try:
        from workers.pipeline.landing_fetch import analyze_urls, landing_fetch_enabled
        if landing_fetch_enabled():
            url_rows = (u.facts or {}).get("urls") or []
            candidates = [r.get("url") for r in url_rows if r.get("url")]
            if candidates:
                landing = analyze_urls(candidates)
    except Exception as exc:
        landing = [{"error": str(exc)[:200]}]
    stages.append(StageResult(
        stage="sandbox",
        status=StageStatus.OK,
        sub_score=max((float(x.get("score") or 0) for x in sandbox_facts), default=0.0),
        facts={
            "attachments": sandbox_facts,
            "landing": landing,
            "provider": "sandbox_worker",
        },
    ))
    record_stages(dest, stages)
    try:
        process_intel(dest)
    except Exception:
        _log.exception("intel failed for %s", qid)
    copy_jobs.finished(dest, "static")
    runtime.finish_cycle("static", stats={"queue_id": qid, "ok": True})
    _ = (vips, policy_cfg, ctx)


def process_intel(dest) -> None:
    from backend.stores import spool
    pe, meta = load_pe(dest)
    if pe is None:
        return
    stored = store.stages_for(spool.dest_name(dest))
    def _facts(name: str) -> dict:
        payload = stored.get(name) or {}
        facts = payload.get("facts")
        return facts if isinstance(facts, dict) else dict(payload)

    ctx = extra(meta)
    correlation = None
    try:
        from backend.config import get_settings
        if get_settings().correlation_store:
            from workers.pipeline import correlation as correlation_mod
            correlation = correlation_mod.get_default_store()
    except Exception:
        correlation = None
    i = safe(
        "intel", intel.run, pe, intel.get_default_intel_client(),
        _facts("urls"), _facts("attachments"), correlation,
        origin_facts=_facts("origin_ip"), header_facts=_facts("headers"),
        mailbox=ctx.get("mailbox") or "",
    )
    record_stages(dest, [i])


def _loop() -> None:
    while not runtime.stop.is_set():
        dest = copy_jobs.wait_for("static")
        if dest is None:
            return
        try:
            process(dest)
        except Exception as exc:
            _log.exception("static failed for %s", dest)
            copy_jobs.fail(dest, "static", str(exc))


def ensure_workers() -> None:
    global _threads
    n_static = _pool_size("static_workers", 2)
    with _lock:
        _threads = [t for t in _threads if t.is_alive()]
        while len(_threads) < n_static:
            t = threading.Thread(target=_loop, name=f"static-{len(_threads)}", daemon=True)
            t.start()
            _threads.append(t)


def main() -> None:
    def _supervise() -> None:
        ensure_workers()
        while not runtime.stop.is_set():
            try:
                n = copy_jobs.enqueue_incomplete(limit=80)
                n += copy_jobs.recover_deadlocks(limit=40)
                if n:
                    _log.info("re-queued %s copies for static", n)
            except Exception:
                _log.exception("static backfill failed")
            ensure_workers()
            runtime.persist_heartbeat()
            if runtime.stop.wait(15.0):
                break
    runtime.run_loop("static", _supervise)


if __name__ == "__main__":
    main()
