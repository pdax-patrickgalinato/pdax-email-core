"""LLM assessment wait window, timeout, and retry helpers.

Live Gmail copies are stored as raw mail, then a background worker runs
the full pipeline with the configured model. The feed shows INCONCLUSIVE after
SEG_LLM_ASSESS_TIMEOUT_SECONDS (default 120) without a real model summary so
the queue can move. When a worker actually starts an attempt it gets that full
budget from now — leftover 1s slices from the original enqueue clock are not
used. Each Vertex slot is capped at SEG_LLM_MODEL_TIMEOUT_SECONDS so the
fallback chain can still run. Timed-out copies are re-queued automatically
(oldest-first, with backoff and a cap); the console does not ask analysts to
retry.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.config import get_settings


def _set_copy_status(dest, status: str) -> None:
    try:
        from backend.stores import assessments
        from backend.stores import spool
        assessments.set_status(spool.dest_name(dest), status)
    except Exception:
        pass


_LLM_PROVIDERS = frozenset({"glm", "gemini", "bedrock", "ollama"})
_DEFAULT_TIMEOUT = 120
_DEFAULT_MODEL_TIMEOUT = 25
_MAX_RETRY = 100


def timeout_seconds() -> int:
    try:
        n = int(get_settings().llm_assess_timeout_seconds)
    except Exception:
        n = _DEFAULT_TIMEOUT
    return max(15, min(n, 600))


def model_timeout_seconds() -> float:
    """Per-Vertex-slot HTTP timeout, always shorter than the attempt budget."""
    assess = float(timeout_seconds())
    try:
        n = float(get_settings().llm_model_timeout_seconds)
    except Exception:
        n = float(_DEFAULT_MODEL_TIMEOUT)
    cap = max(10.0, assess - 20.0)
    return max(10.0, min(n, cap))


def has_llm_assessment(provider: str, summary: str) -> bool:
    return (provider or "").strip().lower() in _LLM_PROVIDERS and bool((summary or "").strip())


def _parse_iso(ts: str) -> Optional[float]:
    raw = (ts or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def wait_started_at(meta: dict, dest: Optional[Path] = None) -> float:
    """Epoch seconds when this copy started waiting on the LLM."""
    queued = _parse_iso(str(meta.get("ai_queued_at") or ""))
    if queued is not None:
        return queued
    if isinstance(dest, Path):
        meta_path = dest / "meta.json" if dest.is_dir() else dest
        try:
            return meta_path.stat().st_mtime
        except OSError:
            pass
    return time.time()


def is_wait_exceeded(meta: dict, dest: Optional[Path] = None, now: Optional[float] = None) -> bool:
    started = wait_started_at(meta, dest)
    return ((now if now is not None else time.time()) - started) >= timeout_seconds()


def remaining_seconds(meta: dict, dest: Optional[Path] = None, now: Optional[float] = None) -> float:
    """Time left on the *display* wait window. Workers use timeout_seconds()."""
    started = wait_started_at(meta, dest)
    left = timeout_seconds() - ((now if now is not None else time.time()) - started)
    return max(0.0, min(left, float(timeout_seconds())))


def begin_attempt(dest: Path) -> dict:
    """Stamp a full attempt window starting now; clear timeout/retry flags."""
    now = datetime.now(timezone.utc).isoformat()
    meta = patch_meta(dest, {
        "ai_timed_out": False,
        "ai_timed_out_at": "",
        "ai_retry_requested": False,
        "ai_queued_at": now,
        "ai_llm_attempted": True,
    })
    _set_copy_status(dest, "ai")
    return meta


def needs_llm_assessment(meta: dict, dest: Optional[Path] = None) -> bool:
    if has_llm_assessment(meta.get("ai_provider") or "", meta.get("ai_summary") or ""):
        return False
    if meta.get("ai_retry_requested"):
        return True
    if meta.get("ai_timed_out"):
        return False
    if is_wait_exceeded(meta, dest):
        return False
    return True


def patch_meta(dest, updates: dict) -> dict:
    from backend.stores import spool
    meta = spool.read_meta(dest)
    meta.update(updates)
    spool.write_meta(dest if isinstance(dest, Path) or isinstance(dest, dict) else Path(dest), meta)
    return meta


def mark_timed_out(dest: Path) -> dict:
    meta = patch_meta(dest, {
        "ai_timed_out": True,
        "ai_timed_out_at": datetime.now(timezone.utc).isoformat(),
        "ai_retry_requested": False,
    })
    _set_copy_status(dest, "timed_out")
    return meta


def prepare_retry(dest: Path, *, auto: bool = False) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    from backend.stores import spool
    meta = spool.read_meta(dest)
    count = int(meta.get("ai_auto_retry_count") or 0)
    if auto:
        count += 1
    else:
        count = 0
    meta = patch_meta(dest, {
        "ai_timed_out": False,
        "ai_timed_out_at": "",
        "ai_retry_requested": True,
        "ai_queued_at": now,
        "ai_llm_attempted": False,
        "ai_auto_retry_count": count,
        "ai_auto_retry_at": now if auto else (meta.get("ai_auto_retry_at") or ""),
    })
    _set_copy_status(dest, "ai")
    return meta


def _spool_copies(spool_root: Path):
    root = Path(spool_root)
    for bucket in ("gmail", "quarantine", "rejected", "released"):
        base = root / bucket
        if not base.is_dir():
            continue
        for dest in base.iterdir():
            if not dest.is_dir() or not (dest / "message.eml").is_file():
                continue
            meta_path = dest / "meta.json"
            if not meta_path.is_file():
                continue
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            yield dest, meta


def dests_missing_llm(spool_root: Path, limit: int = _MAX_RETRY) -> list[Path]:
    found: list[tuple[float, Path]] = []
    for dest, meta in _spool_copies(spool_root):
        if has_llm_assessment(meta.get("ai_provider") or "", meta.get("ai_summary") or ""):
            continue
        found.append((wait_started_at(meta, dest), dest))
    found.sort(key=lambda item: item[0])
    return [p for _, p in found[: max(1, int(limit))]]


def _auto_retry_cooldown_seconds(count: int) -> float:
    """Backoff after each auto-retry: 30s, 1m, 2m, … capped at 10 minutes."""
    if count <= 0:
        return 0.0
    return float(min(10 * 60, 30 * (2 ** min(count - 1, 5))))


def eligible_for_llm_retry(meta: dict, dest: Optional[Path] = None, *,
                           now: float | None = None,
                           max_retries: int | None = None) -> bool:
    """True when a missing-LLM copy may be put back on the worker queue."""
    if has_llm_assessment(meta.get("ai_provider") or "", meta.get("ai_summary") or ""):
        return False
    clock = time.time() if now is None else now
    timed = bool(meta.get("ai_timed_out")) or is_wait_exceeded(meta, dest, now=clock)
    if not timed:
        return False
    cap = int(max_retries if max_retries is not None else get_settings().inconclusive_retry_max)
    cap = max(1, min(cap, 50))
    count = int(meta.get("ai_auto_retry_count") or 0)
    if count >= cap:
        return False
    last = _parse_iso(str(meta.get("ai_auto_retry_at") or ""))
    if last is not None and (clock - last) < _auto_retry_cooldown_seconds(count):
        return False
    return True


def dests_inconclusive(
    spool_root: Path,
    limit: int = 5,
    *,
    now: float | None = None,
    max_retries: int | None = None,
) -> list[Path]:
    """Timed-out copies that the auto-retry worker may re-queue (oldest first)."""
    clock = time.time() if now is None else now
    found: list[tuple[float, Path]] = []
    for dest, meta in _spool_copies(spool_root):
        if not eligible_for_llm_retry(meta, dest, now=clock, max_retries=max_retries):
            continue
        found.append((wait_started_at(meta, dest), dest))
    found.sort(key=lambda item: item[0])
    return [p for _, p in found[: max(1, int(limit))]]


def find_spool_dest(spool_root: Path, queue_id: str) -> Optional[Path]:
    root = Path(spool_root)
    for bucket in ("gmail", "quarantine", "rejected", "released"):
        dest = root / bucket / queue_id
        if dest.is_dir() and (dest / "message.eml").is_file():
            return dest
    return None


def feed_ai_flags(meta: dict, dest: Optional[Path], configured: bool, source_kind: str) -> dict:
    """aiPending / aiTimedOut / aiQueuedAt for a feed row."""
    queued_ms = int(wait_started_at(meta, dest) * 1000)
    has_llm = has_llm_assessment(meta.get("ai_provider") or "", meta.get("ai_summary") or "")
    live = configured and source_kind in ("gmail", "spool") and not has_llm
    timed_out = bool(live and (
        is_wait_exceeded(meta, dest)
        or (meta.get("ai_timed_out") and not meta.get("ai_retry_requested"))
    ))
    pending = bool(live and not timed_out)
    return {
        "aiPending": pending,
        "aiTimedOut": timed_out,
        "aiQueuedAt": queued_ms,
    }
