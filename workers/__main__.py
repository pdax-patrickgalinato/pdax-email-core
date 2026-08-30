"""``python -m workers <name>`` — one worker per container.

Names:
  gmail_poll, static, content_ai, thread_ai, retry,
  campaign, sender, profile, sender_risk

  receiver  — optional all-in-one FastAPI process (current ECS task)

``sender`` runs profile ingest and sender-risk AI in one process.
``profile`` / ``sender_risk`` remain as single-loop names for tests.

The name can also come from SEG_WORKER.
"""
from __future__ import annotations

import os
import sys

WORKERS = (
    "gmail_poll",
    "static",
    "content_ai",
    "thread_ai",
    "retry",
    "campaign",
    "sender",
    "profile",
    "sender_risk",
    "receiver",
)


def _main_for(name: str):
    if name == "gmail_poll":
        from workers.gmail_poll import main
        return main
    if name == "static":
        from workers.static import main
        return main
    if name == "content_ai":
        from workers.content_ai import main
        return main
    if name == "thread_ai":
        from workers.thread_ai import main
        return main
    if name == "retry":
        from workers.retry import main
        return main
    if name == "campaign":
        from workers.campaign import main
        return main
    if name == "sender":
        from workers.sender import main
        return main
    if name == "profile":
        from workers.profile import main
        return main
    if name == "sender_risk":
        from workers.sender_risk import main
        return main
    if name == "receiver":
        from workers.receiver import main
        return main
    return None


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    name = (args[0] if args else os.environ.get("SEG_WORKER", "")).strip()
    if name not in WORKERS:
        print(
            "usage: python -m workers <name>\n"
            "  or:  SEG_WORKER=<name> python -m workers\n"
            f"names: {', '.join(WORKERS)}",
            file=sys.stderr,
        )
        return 2
    # Bind :8766 before Postgres/Vertex so the ALB health check succeeds
    # while those imports are still in flight.
    print(f"[workers] boot {name}", file=sys.stderr, flush=True)
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    os.environ["SEG_WORKER"] = name
    from workers.health import start_health_server
    start_health_server()
    print("[workers] importing runtime", file=sys.stderr, flush=True)
    import workers.runtime as runtime
    print("[workers] runtime imported", file=sys.stderr, flush=True)
    runtime.set_process(name)
    print("[workers] process set", file=sys.stderr, flush=True)
    fn = _main_for(name)
    if fn is None:
        return 2
    print(f"[workers] starting {name}", file=sys.stderr, flush=True)
    fn()
    return 0


if __name__ == "__main__":
    sys.exit(main())
