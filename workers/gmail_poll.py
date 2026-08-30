"""Gmail history poll loop — reports through workers.runtime as gmail_poll."""
from __future__ import annotations

import logging
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from backend.config import get_settings

import workers.runtime as runtime

_log = logging.getLogger("workers.gmail_poll")


def poll_cycle(db_path: Optional[Path] = None) -> list[dict]:
    from workers.gmail import (
        CURSOR_DB, acquire_poll, poll_unlocked, release_poll,
    )

    if not acquire_poll():
        print("[gmail_receiver] skipping poll — previous cycle still running",
              file=sys.stderr)
        return []
    started = time.monotonic()
    runtime.mark_running("gmail_poll")
    try:
        from backend.stores.ingest_control import gmail_fetch_enabled
        if not gmail_fetch_enabled():
            elapsed = round(time.monotonic() - started, 1)
            stats = {
                "paused": True,
                "mailboxes": 0,
                "processed": 0,
                "errors": 0,
                "static_queued": 0,
                "llm_queued": 0,
                "elapsed_seconds": elapsed,
            }
            summary = "Gmail fetch paused"
            print(f"[gmail_receiver] fetch paused — {summary}", file=sys.stderr)
            runtime.finish_cycle("gmail_poll", stats=stats, summary=summary)
            return []
        try:
            from backend.stores.gmail_coverage import seed_from_copies
            seeded = seed_from_copies()
            if seeded:
                shown = ", ".join(seeded[:8])
                extra = f" (+{len(seeded) - 8} more)" if len(seeded) > 8 else ""
                print(f"[gmail_receiver] coverage seed +{len(seeded)}: {shown}{extra}",
                      file=sys.stderr)
        except Exception as exc:
            print(f"[gmail_receiver] coverage seed failed: {exc}", file=sys.stderr)
        out = poll_unlocked(db_path or CURSOR_DB)
        processed = sum(int(r.get("processed") or 0) for r in out)
        errors = sum(1 for r in out if r.get("error"))
        reseeded = sum(1 for r in out if r.get("reseeded") or (r.get("reset") and r.get("processed")))
        cursor_kept = sum(1 for r in out if r.get("error") and not r.get("reset"))
        elapsed = round(time.monotonic() - started, 1)
        stats = {
            "mailboxes": len(out),
            "processed": processed,
            "errors": errors,
            "static_queued": processed,
            "llm_queued": 0,
            "elapsed_seconds": elapsed,
            "cursor_resets": int(reseeded),
            "cursor_kept_on_error": int(cursor_kept),
        }
        bits = []
        if processed or errors:
            bits.append(f"scanned {processed} message" + ("" if processed == 1 else "s"))
            if errors:
                bits.append(f"{errors} mailbox error" + ("" if errors == 1 else "s"))
            if reseeded:
                bits.append(f"reseeded {reseeded} mailbox cursor" + ("" if reseeded == 1 else "s"))
        bits.append(f"{elapsed:.0f}s across {len(out)} mailbox" + ("" if len(out) == 1 else "es"))
        summary = "; ".join(bits)
        print(f"[gmail_receiver] poll cycle finished in {elapsed:.0f}s "
              f"({len(out)} mailboxes, {processed} new)", file=sys.stderr)
        runtime.finish_cycle("gmail_poll", stats=stats, summary=summary)
        return out
    except Exception as exc:
        runtime.fail_cycle("gmail_poll", str(exc))
        raise
    finally:
        release_poll()


def _loop() -> None:
    while not runtime.stop.is_set():
        try:
            poll_cycle()
        except Exception:
            _log.exception("gmail poll cycle failed")
        interval = max(5, int(get_settings().gmail_poll_seconds))
        if runtime.stop.wait(interval):
            break


def start_gmail_poll_worker() -> threading.Thread | None:
    """Idempotent. Used by the all-in-one receiver process."""
    if runtime.gmail_poll_thread is not None and runtime.gmail_poll_thread.is_alive():
        return runtime.gmail_poll_thread
    runtime.stop.clear()
    t = threading.Thread(target=_loop, name="segs-gmail-poll", daemon=True)
    t.start()
    runtime.gmail_poll_thread = t
    _log.info("gmail poll worker started")
    runtime.persist_heartbeat()
    return t


def main() -> None:
    runtime.run_loop("gmail_poll", _loop)


if __name__ == "__main__":
    main()
