"""Background workers — each module is a container entrypoint.

  python -m workers <name>

Do not import worker modules at package load time. ``python -m workers``
runs ``__init__`` before ``__main__``; pulling Vertex/Gmail here delays
:8766 and fails the ALB health check.
"""
from __future__ import annotations

__all__ = [
    "campaign_cycle",
    "dests_to_auto_retry",
    "enqueue_gmail_llm",
    "enqueue_pending_gmail_llm",
    "fail_cycle",
    "finish_cycle",
    "load_all_heartbeats",
    "load_heartbeat",
    "mark_running",
    "persist_heartbeat",
    "poll_cycle",
    "profile_cycle",
    "retry_gmail_llm",
    "retry_inconclusive_cycle",
    "sender_risk_cycle",
    "set_process",
    "start_campaign_worker",
    "start_gmail_llm_worker",
    "start_gmail_poll_worker",
    "start_inconclusive_retry_worker",
    "start_profile_worker",
    "start_sender_risk_worker",
    "stop_workers",
    "worker_status",
]

_LAZY = {
    "campaign_cycle": ("workers.campaign", "campaign_cycle"),
    "start_campaign_worker": ("workers.campaign", "start_campaign_worker"),
    "enqueue_gmail_llm": ("workers.content_ai", "enqueue"),
    "enqueue_pending_gmail_llm": ("workers.content_ai", "enqueue_pending"),
    "retry_gmail_llm": ("workers.content_ai", "retry_gmail_llm"),
    "start_gmail_llm_worker": ("workers.content_ai", "start_gmail_llm_worker"),
    "poll_cycle": ("workers.gmail_poll", "poll_cycle"),
    "start_gmail_poll_worker": ("workers.gmail_poll", "start_gmail_poll_worker"),
    "profile_cycle": ("workers.profile", "profile_cycle"),
    "start_profile_worker": ("workers.profile", "start_profile_worker"),
    "dests_to_auto_retry": ("workers.retry", "dests_to_auto_retry"),
    "retry_inconclusive_cycle": ("workers.retry", "retry_inconclusive_cycle"),
    "start_inconclusive_retry_worker": ("workers.retry", "start_inconclusive_retry_worker"),
    "fail_cycle": ("workers.runtime", "fail_cycle"),
    "finish_cycle": ("workers.runtime", "finish_cycle"),
    "load_all_heartbeats": ("workers.runtime", "load_all_heartbeats"),
    "load_heartbeat": ("workers.runtime", "load_heartbeat"),
    "mark_running": ("workers.runtime", "mark_running"),
    "persist_heartbeat": ("workers.runtime", "persist_heartbeat"),
    "set_process": ("workers.runtime", "set_process"),
    "stop_workers": ("workers.runtime", "stop_workers"),
    "worker_status": ("workers.runtime", "worker_status"),
    "sender_risk_cycle": ("workers.sender_risk", "sender_risk_cycle"),
    "start_sender_risk_worker": ("workers.sender_risk", "start_sender_risk_worker"),
}


def __getattr__(name: str):
    spec = _LAZY.get(name)
    if spec is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    mod_name, attr = spec
    import importlib
    val = getattr(importlib.import_module(mod_name), attr)
    globals()[name] = val
    return val
