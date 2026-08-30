"""AI assessment engine — content AI after the static worker.

Does not set result.verdict; ``workers.pipeline.verdict`` still owns CLEAN/LOW/
SUSPICIOUS/MALICIOUS. This worker writes the assessment row and then
enqueues per-message follow-up plus thread AI when the thread is complete.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import sys
import threading
from pathlib import Path
from typing import Optional

from backend.config import get_settings
from backend.models import PipelineResult, StageResult, StageStatus
from backend.parsed_email import ParsedEmail
from backend.paths import SPOOL_DIR
from backend.stores import ai_assess
from backend.stores import assessments as store
from backend.stores import spool

import workers.copy_jobs as copy_jobs
import workers.jobs as jobs
import workers.runtime as runtime

_log = logging.getLogger("workers.content_ai")

_inflight: set[str] = set()
_queued: set[str] = set()
_inflight_lock = threading.Lock()
_llm_threads: list[threading.Thread] = []
_llm_thread_lock = threading.Lock()


def _worker_count() -> int:
    try:
        n = int(get_settings().content_ai_workers)
        return max(1, min(n, 32))
    except Exception:
        return 4


def llm_configured() -> bool:
    try:
        from workers.pipeline import content_ai as cai
        provider = cai.get_default_provider()
    except Exception:
        return False
    return not isinstance(provider, cai.HeuristicProvider)


def _claim_holder() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{threading.current_thread().name}"


def already_queued(dest) -> bool:
    from backend.stores import spool
    key = spool.dest_name(dest) or str(dest)
    with _inflight_lock:
        if key in _inflight or key in _queued:
            return True
    return jobs.already_queued("content_ai", dest)


def enqueue(dest) -> None:
    if not llm_configured():
        return
    if already_queued(dest):
        return
    copy_jobs.put("content_ai", dest)
    key = spool.dest_name(dest) or str(dest)
    if key:
        with _inflight_lock:
            _queued.add(key)


def _spool_root() -> Path:
    return Path(get_settings().quarantine_root or str(SPOOL_DIR))


def _backfill_limit(limit: int | None) -> int:
    if limit is not None:
        return max(1, int(limit))
    try:
        return max(1, min(int(get_settings().llm_backfill_limit), 2000))
    except Exception:
        return 200


def _should_enqueue(dest: Path, meta: dict, row: dict) -> bool:
    if ai_assess.has_llm_assessment(meta.get("ai_provider") or "", meta.get("ai_summary") or ""):
        return False
    if already_queued(dest):
        return False
    if row and not store.static_complete(row):
        return False
    if str(row.get("status") or "") == store.DEAD_LETTER:
        return False
    if store.is_ai_claimed(row):
        return False
    return bool(
        ai_assess.needs_llm_assessment(meta, dest)
        or ai_assess.eligible_for_llm_retry(meta, dest)
    )


def _dest_from_row(row: dict):
    """SQS/S3 payload or local Path for an assessments row."""
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
        return spool.as_payload(dest_s) if dest_s else spool.payload(qid)
    dest = Path(dest_s)
    if dest.is_dir() and (dest / "message.eml").is_file():
        return dest
    return None


def enqueue_pending(spool_root: Optional[Path] = None, limit: int = 200) -> int:
    """Queue stored copies that still lack an LLM assessment.

    Live (still inside the wait window) copies first, newest mtime first, then
    timed-out copies oldest-first so catch-up does not starve new mail.
    """
    if not llm_configured():
        return 0
    from workers import sqs as sqsmod
    if sqsmod.use_sqs() and jobs.pending_count("content_ai") > 0:
        return 0
    holder = _claim_holder()
    if not store.try_lock("content_ai_backfill", holder, ttl_seconds=90):
        return 0
    try:
        return _enqueue_pending_locked(spool_root, limit)
    finally:
        store.release_lock("content_ai_backfill", holder)


def _enqueue_pending_locked(spool_root: Optional[Path], limit: int) -> int:
    cap = _backfill_limit(limit)
    live: list = []
    stale: list[tuple[float, object]] = []
    seen: set[str] = set()

    def _consider(dest, meta: dict, row: dict) -> None:
        key = spool.dest_key(dest) or spool.dest_name(dest) or str(dest)
        if key in seen or not _should_enqueue(dest, meta, row):
            return
        seen.add(key)
        if ai_assess.needs_llm_assessment(meta, dest):
            live.append(dest)
        else:
            stale.append((ai_assess.wait_started_at(meta, dest), dest))

    for row in store.list_awaiting_ai(cap * 2):
        dest = _dest_from_row(row)
        if dest is None:
            continue
        try:
            meta = spool.read_meta(dest)
        except Exception:
            meta = {}
        if not isinstance(meta, dict):
            meta = {}
        _consider(dest, meta, row)
    if not spool.use_s3():
        root = Path(spool_root) if spool_root else _spool_root()
        gmail_dir = root / "gmail"
        if gmail_dir.is_dir():
            for dest in gmail_dir.iterdir():
                if not dest.is_dir():
                    continue
                meta_path = dest / "meta.json"
                if not meta_path.is_file() or not (dest / "message.eml").is_file():
                    continue
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                except Exception:
                    continue
                _consider(dest, meta, store.get_copy(spool.dest_name(dest)) or {})

    def _mtime(dest) -> float:
        if isinstance(dest, Path):
            try:
                return dest.stat().st_mtime
            except OSError:
                return 0.0
        return 0.0

    live.sort(key=_mtime, reverse=True)
    stale.sort(key=lambda item: item[0])
    queued = 0
    for dest in live + [p for _, p in stale]:
        enqueue(dest)
        queued += 1
        if queued >= cap:
            break
    return queued


def retry_gmail_llm(queue_ids: Optional[list[str]] = None, spool_root: Optional[Path] = None,
                    all_missing: bool = False, limit: int = 100) -> list[str]:
    """Reset the wait window and enqueue copies that still lack an LLM assessment."""
    root = Path(spool_root) if spool_root else _spool_root()
    dests: list[Path] = []
    if all_missing or not queue_ids:
        dests = ai_assess.dests_missing_llm(root, limit=limit)
    else:
        for qid in queue_ids:
            dest = ai_assess.find_spool_dest(root, qid)
            if dest is None:
                continue
            try:
                meta = json.loads((dest / "meta.json").read_text(encoding="utf-8"))
            except Exception:
                continue
            if ai_assess.has_llm_assessment(meta.get("ai_provider") or "", meta.get("ai_summary") or ""):
                continue
            dests.append(dest)
            if len(dests) >= limit:
                break
    queued: list[str] = []
    for dest in dests:
        ai_assess.prepare_retry(dest)
        enqueue(dest)
        queued.append(spool.dest_name(dest))
    return queued


def _correlation_store():
    from workers.pipeline import correlation as correlation_mod
    return correlation_mod.get_default_store()


def _run_llm_pipeline(raw: bytes, extra_context=None):
    from workers.pipeline import content_ai as cai
    from workers.pipeline.intel import LocalIOCClient
    from workers.pipeline.runner import run_pipeline
    return run_pipeline(
        raw, source="gmail_api",
        content_provider=cai.get_default_provider(),
        intel_client=LocalIOCClient(),
        llm_triage=False,
        extra_context=extra_context,
        correlation_store=_correlation_store(),
    )


def _stage_from_payload(name: str, payload: dict) -> StageResult:
    status_s = str((payload or {}).get("status") or "ok").lower()
    try:
        status = StageStatus(status_s)
    except ValueError:
        status = StageStatus.OK
    facts = payload.get("facts")
    if not isinstance(facts, dict):
        facts = {k: v for k, v in (payload or {}).items()
                 if k not in ("status", "score", "flags", "red_flags", "latency_ms")}
    return StageResult(
        stage=name,
        status=status,
        sub_score=float(payload.get("score") or 0),
        red_flags=list(payload.get("flags") or payload.get("red_flags") or []),
        facts=facts if isinstance(facts, dict) else {},
    )


def _assess_from_joined(raw: bytes, dest: Path, extra: dict):
    """Content AI over facts the static workers already wrote. Advisory only."""
    stored = store.stages_for(spool.dest_name(dest))
    useful = any(stored.get(k) for k in ("headers", "sender", "intel", "deception", "urls"))
    if not useful:
        return _run_llm_pipeline(raw, extra)
    pe = ParsedEmail(raw)
    ctx = {}
    for name in ("headers", "sender", "urls", "attachments", "intel", "deception"):
        payload = stored.get(name) or {}
        facts = payload.get("facts")
        ctx[name] = facts if isinstance(facts, dict) else dict(payload)
    origin = stored.get("origin_ip") or {}
    origin_facts = origin.get("facts") if isinstance(origin.get("facts"), dict) else origin
    if origin_facts:
        ctx["origin_ip"] = origin_facts
    if extra:
        ctx.update(extra)
    try:
        from backend.stores import feedback as feedback_mod
        ctx["feedback"] = feedback_mod.match_pe(pe)
    except Exception:
        ctx["feedback"] = {}
    from workers.pipeline import content_ai as cai
    from workers.pipeline import runner as runner_mod
    from workers.pipeline import verdict as verdict_mod
    c = cai.run(pe, cai.get_default_provider(), ctx)
    weights_cfg, _protected, _vips, policy_cfg, _banned = runner_mod.load_config()
    result = PipelineResult(
        message_id=pe.header("Message-ID"),
        source="gmail_api",
        subject=pe.header("Subject"),
        from_header=pe.header("From"),
        to_header=pe.header("To"),
    )
    result.stages = [
        _stage_from_payload(name, payload)
        for name, payload in stored.items()
        if name != "content_ai"
    ]
    result.stages.append(c)
    result.iocs = verdict_mod.extract_iocs(pe, result.stages)
    ai_floor = (weights_cfg.get("ai_influence") or {}).get("verdict_floor_confidence")
    verdict_mod.score_and_verdict(
        result, weights_cfg["weights"], weights_cfg["thresholds"],
        policy_cfg, ai_floor,
    )
    return result


def _rfc_message_id(meta: dict) -> str:
    from backend.stores.mail_thread import extract_message_ids
    ids = extract_message_ids(str(meta.get("message_id") or ""))
    return ids[0] if ids else ""


def _after_llm_success(dest: Path) -> None:
    try:
        from workers.followup import after_assessment
        after_assessment(dest)
    except Exception as exc:
        print(f"[gmail_receiver] followup enqueue failed for {spool.dest_name(dest)}: {exc}",
              file=sys.stderr)
    try:
        from workers.thread_ai import maybe_enqueue
        maybe_enqueue(dest)
    except Exception as exc:
        print(f"[gmail_receiver] thread AI enqueue failed for {spool.dest_name(dest)}: {exc}",
              file=sys.stderr)


def _reuse_fanout(dest: Path, meta: dict) -> bool:
    """Copy an already-finished LLM assessment from another copy of this send."""
    sibling = store.find_assessed_sibling(_rfc_message_id(meta), spool.dest_name(dest))
    if not sibling:
        return False
    summary = sibling.get("ai_summary") or ""
    provider = sibling.get("ai_provider") or ""
    if not ai_assess.has_llm_assessment(provider, summary):
        return False
    try:
        src_stages = json.loads(sibling.get("stages_json") or "{}")
    except json.JSONDecodeError:
        src_stages = {}
    cai = src_stages.get("content_ai")
    if isinstance(cai, dict):
        store.merge_stage(spool.dest_name(dest), "content_ai", cai)
    store.upsert_copy(
        spool.dest_name(dest),
        dest=str(dest),
        ai_provider=provider,
        ai_summary=summary,
        ai_model=str(sibling.get("ai_model") or ""),
        verdict=str(sibling.get("verdict") or ""),
        score=sibling.get("score"),
        ai_done=1,
        status=store.COMPLETE,
    )
    ai_assess.patch_meta(dest, {
        "ai_summary": summary,
        "ai_provider": provider,
        "ai_model": sibling.get("ai_model") or "",
        "verdict": sibling.get("verdict") or "",
        "score": sibling.get("score"),
        "ai_llm_attempted": True,
        "ai_fanout_reuse": sibling.get("queue_id") or "",
    })
    store.mark_stage(spool.dest_name(dest), "ai")
    _after_llm_success(dest)
    print(f"[gmail_receiver] reused LLM assessment from {sibling.get('queue_id')} "
          f"for {spool.dest_name(dest)}", file=sys.stderr)
    return True


def _retry_or_dead(dest, reason: str) -> str:
    """Return 'retry' or 'dead' after a failed/empty LLM attempt."""
    meta = spool.read_meta(dest)
    cap = max(1, int(get_settings().inconclusive_retry_max))
    count = int(meta.get("ai_auto_retry_count") or 0)
    if count >= cap:
        store.upsert_copy(spool.dest_name(dest), status=store.DEAD_LETTER, last_error=reason[:400])
        print(f"[gmail_receiver] dead-letter {spool.dest_name(dest)}: {reason}", file=sys.stderr)
        return "dead"
    if get_settings().inconclusive_retry and ai_assess.eligible_for_llm_retry(meta, dest):
        ai_assess.prepare_retry(dest, auto=True)
        return "retry"
    if get_settings().inconclusive_retry:
        ai_assess.prepare_retry(dest, auto=True)
        return "retry"
    store.upsert_copy(spool.dest_name(dest), status=store.ERROR, last_error=reason[:400])
    return "dead"


def enrich(dest) -> str:
    """Run content AI. Returns ok / skip / retry / dead (caller acks the job)."""
    from workers.gmail import persist_gmail_scan, _content_ai_meta, _maybe_slack_alert
    from backend.stores import spool

    qid = spool.dest_name(dest)
    raw, meta = spool.read_copy(dest)
    if not raw or not meta:
        return "skip"
    if ai_assess.has_llm_assessment(meta.get("ai_provider") or "", meta.get("ai_summary") or ""):
        return "skip"
    if _reuse_fanout(dest, meta):
        return "ok"
    ai_assess.begin_attempt(dest)
    from backend.stores.mail_thread import thread_prompt_context
    from backend.stores.mail_fanout import fanout_prompt_context
    extra = {}
    thread_ctx = thread_prompt_context(dest, meta)
    if thread_ctx:
        extra["thread"] = thread_ctx
    fanout_ctx = fanout_prompt_context(dest, meta)
    if fanout_ctx:
        extra["fanout"] = fanout_ctx
    extra["mailbox"] = meta.get("mailbox") or ""
    extra["gmail_labels"] = list(meta.get("gmail_labels") or [])
    try:
        result = _assess_from_joined(raw, dest, extra)
    except Exception as exc:
        print(f"[gmail_receiver] LLM assessment failed for {dest}: {exc}",
              file=sys.stderr)
        return _retry_or_dead(dest, str(exc))
    persist_gmail_scan(
        meta.get("mailbox") or "",
        meta.get("gmail_message_id") or qid.replace("gmail-", "", 1),
        raw,
        result,
        list(meta.get("gmail_labels") or []),
        spool_root=dest.parent.parent if isinstance(dest, Path) else None,
        llm_attempted=True,
        ts=meta.get("ts"),
        gmail_thread_id=meta.get("gmail_thread_id") or "",
    )
    _maybe_slack_alert(result)
    ai = _content_ai_meta(result)
    store.mark_stage(spool.dest_name(dest), "ai")
    if ai_assess.has_llm_assessment(ai.get("ai_provider") or "", ai.get("ai_summary") or ""):
        _after_llm_success(dest)
        print(f"[gmail_receiver] LLM assessment stored for {spool.dest_name(dest)} "
              f"provider={ai.get('ai_provider') or '?'} "
              f"model={ai.get('ai_model') or '?'}",
              file=sys.stderr)
        return "ok"
    print(f"[gmail_receiver] LLM assessment stored for {spool.dest_name(dest)} "
          f"provider={ai.get('ai_provider') or '?'} "
          f"model={ai.get('ai_model') or '?'} (empty summary)",
          file=sys.stderr)
    ai_assess.mark_timed_out(dest)
    return _retry_or_dead(dest, "empty_llm_summary")


def _worker() -> None:
    while not runtime.stop.is_set():
        dest = copy_jobs.wait_for("content_ai")
        if dest is None:
            return
        key = spool.dest_name(dest) or str(dest)
        with _inflight_lock:
            _inflight.add(key)
        claimed = False
        outcome = "skip"
        try:
            claimed = store.try_claim_ai(key, _claim_holder())
            if not claimed:
                print(f"[content_ai] skip duplicate claim {key}", file=sys.stderr)
            else:
                outcome = enrich(dest)
        except Exception as exc:
            print(f"[gmail_receiver] LLM assessment failed for {dest}: {exc}",
                  file=sys.stderr)
            try:
                outcome = _retry_or_dead(dest, str(exc))
            except Exception as retry_exc:
                print(f"[gmail_receiver] LLM retry bookkeeping failed for {dest}: {retry_exc}",
                      file=sys.stderr)
                outcome = "skip"
        finally:
            with _inflight_lock:
                _inflight.discard(key)
            copy_jobs.ack("content_ai", dest)
            if claimed and outcome != "ok":
                store.release_ai_claim(key)
        if outcome == "retry":
            enqueue(dest)


def ensure_workers() -> None:
    global _llm_threads
    if not llm_configured():
        print(
            "[content_ai] SEG_CONTENT_PROVIDER is offline/heuristic — "
            "not draining the AI queue. Set glm (or another LLM) in .env.",
            file=sys.stderr,
        )
        return
    with _llm_thread_lock:
        _llm_threads = [t for t in _llm_threads if t.is_alive()]
        while len(_llm_threads) < _worker_count():
            t = threading.Thread(
                target=_worker, name=f"content-ai-{len(_llm_threads)}", daemon=True,
            )
            t.start()
            _llm_threads.append(t)


def queue_depth() -> int:
    return jobs.pending_count("content_ai")


def workers_alive() -> bool:
    with _llm_thread_lock:
        return any(t.is_alive() for t in _llm_threads)


def start_gmail_llm_worker() -> None:
    """Start AI threads and drain stored copies that still lack an assessment."""
    ensure_workers()
    pending = enqueue_pending()
    if pending:
        print(f"[gmail_receiver] queued {pending} existing Gmail copies for LLM assessment",
              file=sys.stderr)
    runtime.persist_heartbeat()


def main() -> None:
    def _loop() -> None:
        print("[content_ai] loop start", file=sys.stderr, flush=True)
        ensure_workers()
        print("[content_ai] workers ensured", file=sys.stderr, flush=True)
        enqueue_pending()
        runtime.persist_heartbeat()
        while not runtime.stop.is_set():
            try:
                n = enqueue_pending()
                n += copy_jobs.recover_deadlocks(limit=40)
                if n:
                    print(f"[gmail_receiver] backfilled {n} copies for LLM assessment",
                          file=sys.stderr)
            except Exception:
                _log.exception("LLM backfill failed")
            ensure_workers()
            runtime.persist_heartbeat()
            if runtime.stop.wait(5.0):
                break
    runtime.run_loop("content_ai", _loop)


if __name__ == "__main__":
    main()
