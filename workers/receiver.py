#!/usr/bin/env python3
"""Gmail receiver process — FastAPI health + worker lifespan.

    uvicorn workers.receiver:app --port 8766 --reload

Starts poll, static checks, AI, thread, and retry **in this process**.
Prefer ``python -m workers <name>`` (one container each).
This module remains the ECS all-in-one receiver.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from backend.stores import ai_assess
from backend.config import get_settings
from workers.gmail import (  # noqa: F401
    _label_names,
    _monitored_users,
    get_cursor,
    persist_gmail_pending,
    persist_gmail_scan,
    poll_all_mailboxes,
    poll_mailbox,
    poll_unlocked,
    set_cursor,
)
from workers.pipeline import content_ai as _content_ai
import workers as workers_mod
from workers.content_ai import (
    already_queued as _llm_already_queued,
    enqueue as _enqueue_gmail_llm,
    enqueue_pending as enqueue_pending_gmail_llm,
    enrich as _enrich_gmail_dest,
    llm_configured as _llm_configured,
    retry_gmail_llm,
    _run_llm_pipeline,
)

_needs_llm_assessment = ai_assess.needs_llm_assessment


@asynccontextmanager
async def _lifespan(app: FastAPI):
    workers_mod.set_process("gmail_receiver")
    try:
        from backend.stores.gmail_coverage import seed_from_spool
        seeded = seed_from_spool()
        if seeded:
            shown = ", ".join(seeded[:8])
            extra = f" (+{len(seeded) - 8} more)" if len(seeded) - 8 > 0 else ""
            print(f"[gmail_receiver] fanout coverage seed +{len(seeded)}: {shown}{extra}")
    except Exception as exc:
        print(f"[gmail_receiver] coverage seed failed: {exc}")
    from workers.copy_jobs import ensure_all
    from backend.config import get_settings
    if get_settings().inline_workers:
        ensure_all()
        workers_mod.start_gmail_llm_worker()
        workers_mod.start_gmail_poll_worker()
        workers_mod.start_inconclusive_retry_worker(
            _enqueue_gmail_llm, already_queued=_llm_already_queued,
        )
        print(
            "[gmail_receiver] poll + static + AI workers started "
            f"(interval={get_settings().gmail_poll_seconds}s)"
        )
    else:
        print("[gmail_receiver] inline workers disabled (SEG_INLINE_WORKERS=0)")
    try:
        yield
    finally:
        workers_mod.stop_workers()


app = FastAPI(
    title="SEGS Gmail API Receiver",
    lifespan=_lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.get("/health")
def health():
    from workers.runtime import worker_status
    return {
        "ok": True,
        "service": "gmail_receiver",
        "workers": worker_status(),
    }


def main() -> None:
    uvicorn.run("workers.receiver:app", host="0.0.0.0", port=8766, reload=True)


if __name__ == "__main__":
    main()
