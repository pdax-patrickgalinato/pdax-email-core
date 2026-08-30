"""Combined sender-profile ingest + sender-risk AI in one process.

These used to be two Fargate tasks (256/512 each). They share the same
correlation store and fire after the same LLM follow-up, so one container
runs both loops as daemon threads.
"""
from __future__ import annotations

import sys

import workers.runtime as runtime


def main() -> None:
    def _supervisor() -> None:
        print("[sender] loop start", file=sys.stderr, flush=True)
        from workers.profile import start_profile_worker
        from workers.sender_risk import start_sender_risk_worker
        start_profile_worker()
        start_sender_risk_worker()
        runtime.persist_heartbeat()
        while not runtime.stop.is_set():
            runtime.persist_heartbeat()
            if runtime.stop.wait(15.0):
                break
    runtime.run_loop("sender", _supervisor)


if __name__ == "__main__":
    main()
