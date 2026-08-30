"""Shared: load a spool copy and run pipeline stage groups."""
from __future__ import annotations

from backend.models import StageResult, StageStatus
from backend.parsed_email import ParsedEmail
from workers.pipeline import runner as runner_mod
from workers.pipeline.stage_summary import compact_stages
from backend.stores import spool


def load_pe(dest) -> tuple[ParsedEmail | None, dict]:
    raw, meta = spool.read_copy(dest)
    if not raw:
        return None, meta
    try:
        return ParsedEmail(raw), meta
    except Exception:
        return None, meta


def extra(meta: dict) -> dict:
    return {
        "mailbox": meta.get("mailbox") or "",
        "gmail_labels": list(meta.get("gmail_labels") or []),
    }


def safe(stage_name, fn, *a, **kw) -> StageResult:
    try:
        return fn(*a, **kw)
    except Exception as e:
        return StageResult(
            stage=stage_name, status=StageStatus.ERROR,
            red_flags=[f"stage_error:{type(e).__name__}"],
            facts={"error": str(e)},
        )


def config():
    return runner_mod.load_config()


def record_stages(dest, stages: list[StageResult]) -> None:
    from backend.stores.assessments import merge_stage
    from backend.stores import spool
    compact = compact_stages(type("R", (), {"stages": stages})())
    qid = spool.dest_name(dest)
    for st in stages:
        payload = dict(compact.get(st.stage) or {})
        payload["facts"] = dict(st.facts or {})
        payload["red_flags"] = list(st.red_flags or [])
        merge_stage(qid, st.stage, payload)
