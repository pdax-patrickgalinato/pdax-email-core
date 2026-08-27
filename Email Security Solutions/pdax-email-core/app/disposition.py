"""Post-verdict disposition + enforcement.

Architecture (CLAUDE.md / HANDOFF.md):
  * verdict.py is the sole owner of CLEAN/LOW/SUSPICIOUS/MALICIOUS.
  * This module only *maps* that verdict onto a gateway action using
    rules/disposition.yaml — it never re-scores or lets AI write disposition.
  * Real SMTP reject/quarantine is behind EnforceMode. Default is SHADOW:
    log the intended action and always release. Quarantine before reject;
    a 550 loses mail permanently.

Used by:
  * run_pipeline() — fills result.disposition after scoring
  * gateway/hold_consumer.py — applies EnforcementClient to held mail
"""
from __future__ import annotations

import json
import os
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol

_SAFE_QUEUE_ID_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,128}$')

import yaml

from .models import (
    Disposition, EnforceMode, PipelineResult, StageStatus, Verdict,
)

_RULES = Path(__file__).resolve().parents[1] / "rules" / "disposition.yaml"
_ENFORCE_MODE_FILE = Path(__file__).resolve().parents[1] / "rules" / "enforcement_mode.yaml"

_DEFAULT_POLICY = {
    "verdict_actions": {
        "CLEAN": "DELIVER",
        "LOW": "LOG",
        "SUSPICIOUS": "QUARANTINE",
        "MALICIOUS": "QUARANTINE",
    },
    "allow_reject_on_malicious": False,
    "on_pipeline_error": "DELIVER",
}


def load_disposition_policy(path: Optional[Path] = None) -> dict:
    p = path or _RULES
    if p.is_file():
        data = yaml.safe_load(p.read_text()) or {}
        merged = dict(_DEFAULT_POLICY)
        merged.update({k: v for k, v in data.items() if v is not None})
        if "verdict_actions" in data and data["verdict_actions"]:
            merged["verdict_actions"] = {
                **_DEFAULT_POLICY["verdict_actions"],
                **data["verdict_actions"],
            }
        return merged
    return dict(_DEFAULT_POLICY)


def _read_runtime_enforce_mode() -> Optional[str]:
    """Read the admin-written runtime override from rules/enforcement_mode.yaml.

    Returns the raw mode string, or None if the file is absent/unreadable.
    Re-read on every call so a dashboard PUT /api/enforcement takes effect on
    the next email without requiring a process restart.
    """
    try:
        if _ENFORCE_MODE_FILE.is_file():
            data = yaml.safe_load(_ENFORCE_MODE_FILE.read_text()) or {}
            mode = data.get("mode", "").strip().lower()
            if mode:
                return mode
    except Exception:
        pass
    return None


def resolve_enforce_mode(explicit: Optional[str] = None) -> EnforceMode:
    # Precedence: explicit arg > runtime file > SEG_ENFORCE env var > default shadow.
    raw = explicit
    if raw is None:
        raw = _read_runtime_enforce_mode()
    if raw is None:
        raw = os.environ.get("SEG_ENFORCE", "shadow")
    raw = (raw or "shadow").strip().lower()
    if raw in ("1", "true", "yes", "quarantine", "enforce"):
        return EnforceMode.QUARANTINE
    if raw in ("reject", "reject_malicious"):
        return EnforceMode.REJECT
    if raw in ("0", "false", "no", "off", "null", "noop"):
        return EnforceMode.SHADOW
    try:
        return EnforceMode(raw)
    except ValueError:
        return EnforceMode.SHADOW


def _pipeline_errored(result: PipelineResult) -> bool:
    return any(s.status == StageStatus.ERROR for s in result.stages)


def decide_disposition(result: PipelineResult,
                       policy: Optional[dict] = None,
                       enforce_mode: Optional[EnforceMode] = None) -> None:
    """Fill result.disposition / disposition_reason / enforce_mode in place.

    Called after verdict.score_and_verdict(). Does not change the verdict.
    """
    policy = policy or load_disposition_policy()
    mode = enforce_mode or resolve_enforce_mode()
    result.enforce_mode = mode

    actions = policy.get("verdict_actions") or _DEFAULT_POLICY["verdict_actions"]
    allow_reject = bool(policy.get("allow_reject_on_malicious", False))

    if _pipeline_errored(result):
        fallback = str(policy.get("on_pipeline_error", "DELIVER")).upper()
        try:
            result.disposition = Disposition(fallback)
        except ValueError:
            result.disposition = Disposition.DELIVER
        result.disposition_reason = (
            f"pipeline stage error — fail-{'closed' if result.disposition == Disposition.QUARANTINE else 'open'} "
            f"per on_pipeline_error={fallback}"
        )
        return

    mapped = str(actions.get(result.verdict.value, "DELIVER")).upper()
    try:
        disposition = Disposition(mapped)
    except ValueError:
        disposition = Disposition.DELIVER

    reason_bits = [f"verdict={result.verdict.value} → {disposition.value}"]
    if result.hard_override:
        reason_bits.append(f"hard_override={result.hard_override}")

    # REJECT is irreversible — only escalate MALICIOUS→REJECT when both the
    # enforce mode and the policy flag allow it.
    if (disposition == Disposition.QUARANTINE
            and result.verdict == Verdict.MALICIOUS
            and mode == EnforceMode.REJECT
            and allow_reject):
        disposition = Disposition.REJECT
        reason_bits.append("escalated to REJECT (SEG_ENFORCE=reject + allow_reject_on_malicious)")

    result.disposition = disposition
    result.disposition_reason = "; ".join(reason_bits)


# ---------------------------------------------------------------------------
# EnforcementClient — transport side-effect. Offline default is shadow/log.
# ---------------------------------------------------------------------------

class EnforcementClient(Protocol):
    def apply(self, queue_id: str, raw: bytes,
              result: PipelineResult) -> str:
        """Apply (or shadow-log) the disposition. Returns a short applied tag
        stored on result.enforcement_applied."""
        ...


class NullEnforcementClient:
    """Analysis-only — no filesystem/SMTP side effects."""

    def apply(self, queue_id: str, raw: bytes, result: PipelineResult) -> str:
        result.enforcement_applied = "noop"
        return result.enforcement_applied


class ShadowEnforcementClient:
    """Default. Logs the *intended* disposition and always treats mail as
    released. Safe for first gateway deploy and for CLI/eval."""

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = Path(log_dir) if log_dir else None

    def apply(self, queue_id: str, raw: bytes, result: PipelineResult) -> str:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "queue_id": queue_id,
            "mode": "shadow",
            "verdict": result.verdict.value,
            "disposition_intended": result.disposition.value,
            "disposition_reason": result.disposition_reason,
            "message_id": result.message_id,
            "subject": result.subject,
            "from": result.from_header,
            "score": result.composite_score,
            "hard_override": result.hard_override,
            "threat_class": result.threat_class,
            "threat_confidence": result.threat_confidence,
            "deep_analysis": result.deep_analysis,
            "iocs": result.iocs.model_dump() if hasattr(result.iocs, "model_dump") else {},
            "action_taken": "shadow_release",
        }
        line = json.dumps(record, ensure_ascii=False)
        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            path = self.log_dir / "shadow_enforcement.jsonl"
            with path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        result.enforcement_applied = "shadow_release"
        return result.enforcement_applied


class LocalQuarantineClient:
    """Filesystem quarantine for lab/gateway-dev (not production Postfix).

    Layout under root/:
      quarantine/<queue_id>/message.eml + meta.json
      released/<queue_id>/message.eml + meta.json   (DELIVER/LOG)
      rejected/<queue_id>/message.eml + meta.json   (REJECT, rare)

    In EnforceMode.SHADOW this client still only shadow-logs (delegates).
    """

    def __init__(self, root: Path, mode: Optional[EnforceMode] = None,
                 shadow_log_dir: Optional[Path] = None):
        self.root = Path(root)
        self.mode = mode or resolve_enforce_mode()
        self._shadow = ShadowEnforcementClient(log_dir=shadow_log_dir or (self.root / "shadow_logs"))

    def apply(self, queue_id: str, raw: bytes, result: PipelineResult) -> str:
        if self.mode == EnforceMode.SHADOW:
            return self._shadow.apply(queue_id, raw, result)

        # In quarantine mode, never hard-reject even if disposition says REJECT.
        effective = result.disposition
        if self.mode == EnforceMode.QUARANTINE and effective == Disposition.REJECT:
            effective = Disposition.QUARANTINE

        if effective in (Disposition.DELIVER, Disposition.LOG):
            bucket = "released"
            tag = "delivered"
        elif effective == Disposition.REJECT and self.mode == EnforceMode.REJECT:
            bucket = "rejected"
            tag = "rejected"
        else:
            bucket = "quarantine"
            tag = "quarantined"

        dest_dir = self.root / bucket / _safe_id(queue_id)
        dest_dir.mkdir(parents=True, exist_ok=True)
        (dest_dir / "message.eml").write_bytes(raw)
        meta = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "queue_id": queue_id,
            "mode": self.mode.value,
            "verdict": result.verdict.value,
            "disposition": result.disposition.value,
            "effective_disposition": effective.value,
            "disposition_reason": result.disposition_reason,
            "message_id": result.message_id,
            "subject": result.subject,
            "from": result.from_header,
            "score": result.composite_score,
            "hard_override": result.hard_override,
            "threat_class": result.threat_class,
            "threat_confidence": result.threat_confidence,
            "deep_analysis": result.deep_analysis,
            "reasons": result.reasons,
            "iocs": result.iocs.model_dump() if hasattr(result.iocs, "model_dump") else {},
        }
        (dest_dir / "meta.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        result.enforcement_applied = tag
        return tag


def _safe_id(queue_id: str) -> str:
    # Avoid path traversal from attacker-controlled Message-IDs.
    cleaned = "".join(c if c.isalnum() or c in "-_." else "_" for c in (queue_id or "unknown"))
    return (cleaned[:120] or "unknown") + f"_{int(time.time() * 1000)}"


def get_default_enforcement_client(
        enforce_mode: Optional[EnforceMode] = None,
        quarantine_root: Optional[Path] = None) -> EnforcementClient:
    """Factory used by the hold consumer. Offline CLI keeps Null/Shadow."""
    mode = enforce_mode or resolve_enforce_mode()
    root = quarantine_root or Path(os.environ.get(
        "SEG_QUARANTINE_ROOT", "gateway/spool"))
    if mode == EnforceMode.SHADOW:
        log_dir = root / "shadow_logs"
        return ShadowEnforcementClient(log_dir=log_dir)
    return LocalQuarantineClient(root=root, mode=mode)


def apply_disposition(result: PipelineResult,
                      policy: Optional[dict] = None,
                      enforce_mode: Optional[EnforceMode] = None) -> PipelineResult:
    """Convenience: decide disposition on a scored PipelineResult."""
    decide_disposition(result, policy=policy, enforce_mode=enforce_mode)
    return result


def _find_spool_entry(root: Path, queue_id: str,
                      buckets=("quarantine", "rejected", "released")) -> Path:
    """Locate a spool entry by exact id or prefix across buckets."""
    if not _SAFE_QUEUE_ID_RE.match(queue_id or ""):
        raise ValueError(f"Invalid queue_id — must match [a-zA-Z0-9_-]{{1,128}}: {queue_id!r}")
    root = Path(root)
    for bucket in buckets:
        base = root / bucket
        if not base.is_dir():
            continue
        exact = base / queue_id
        if exact.is_dir() and (exact / "message.eml").is_file():
            return exact
        matches = sorted(p for p in base.glob(queue_id + "*") if p.is_dir())
        if matches:
            return matches[0]
    raise FileNotFoundError(
        f"no spool entry matching {queue_id!r} under {root} ({', '.join(buckets)})")


def list_spool_entries(quarantine_root: Path,
                       buckets=("quarantine", "rejected", "released")) -> list:
    """Return metadata summaries for every stored message (for analyst triage)."""
    root = Path(quarantine_root)
    out = []
    for bucket in buckets:
        base = root / bucket
        if not base.is_dir():
            continue
        for entry in sorted(base.iterdir()):
            if not entry.is_dir():
                continue
            eml = entry / "message.eml"
            meta_path = entry / "meta.json"
            meta = {}
            if meta_path.is_file():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                except Exception:
                    meta = {"meta_error": "unreadable"}
            out.append({
                "bucket": bucket,
                "queue_id": entry.name,
                "path": str(entry),
                "has_eml": eml.is_file(),
                "subject": meta.get("subject", ""),
                "from": meta.get("from", ""),
                "verdict": meta.get("verdict", ""),
                "disposition": meta.get("disposition", ""),
                "score": meta.get("score"),
                "hard_override": meta.get("hard_override"),
                "ts": meta.get("ts", ""),
                "reeval_count": len(meta.get("reeval_history") or []),
            })
    return out


def _move_spool_entry(src: Path, dest_dir: Path, meta_updates: dict) -> Path:
    dest_dir = Path(dest_dir)
    dest_dir.parent.mkdir(parents=True, exist_ok=True)
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    shutil.move(str(src), str(dest_dir))
    meta_path = dest_dir / "meta.json"
    meta = {}
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            meta = {}
    meta.update(meta_updates)
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n",
                         encoding="utf-8")
    return dest_dir


def release_from_quarantine(quarantine_root: Path, queue_id: str,
                            dest: Optional[Path] = None) -> Path:
    """Analyst release — move quarantine/rejected → released/ (benign FP)."""
    root = Path(quarantine_root)
    src = _find_spool_entry(root, queue_id, buckets=("quarantine", "rejected"))
    dest_dir = Path(dest) if dest else (root / "released" / src.name)
    return _move_spool_entry(src, dest_dir, {
        "released_at": datetime.now(timezone.utc).isoformat(),
        "release_action": "analyst_release",
        "bucket": "released",
    })


def keep_blocked(quarantine_root: Path, queue_id: str,
                 dest: Optional[Path] = None) -> Path:
    """Confirm block — move quarantine → rejected/ (remain blocked)."""
    root = Path(quarantine_root)
    src = _find_spool_entry(root, queue_id, buckets=("quarantine",))
    dest_dir = Path(dest) if dest else (root / "rejected" / src.name)
    return _move_spool_entry(src, dest_dir, {
        "blocked_at": datetime.now(timezone.utc).isoformat(),
        "release_action": "keep_blocked",
        "bucket": "rejected",
        "disposition": "REJECT",
        "effective_disposition": "REJECT",
    })


def reevaluate_spool_entry(quarantine_root: Path, queue_id: str,
                           auto_release: bool = False,
                           auto_block: bool = False,
                           content_provider=None) -> dict:
    """Re-run run_pipeline on a stored message.eml and record the outcome.

    Does not move the message unless:
      * auto_release and new disposition is DELIVER/LOG → move to released/
      * auto_block and new disposition is QUARANTINE/REJECT → move to rejected/

    Always appends an entry to meta.json's reeval_history for audit.

    content_provider=None (default) uses whatever SEG_CONTENT_PROVIDER/
    SEG_CONTENT_PROVIDER configures — the CLI/gateway behavior, unchanged.
    The dashboard server passes an explicit HeuristicProvider() here to
    avoid a click in the UI triggering a paid Bedrock/Gemini/GLM call.
    """
    # Import here to avoid a circular import at module load (runner → disposition).
    from .pipeline.runner import run_pipeline

    root = Path(quarantine_root)
    src = _find_spool_entry(root, queue_id, buckets=("quarantine", "rejected", "released"))
    bucket = src.parent.name
    eml_path = src / "message.eml"
    if not eml_path.is_file():
        raise FileNotFoundError(f"missing message.eml in {src}")

    meta_path = src / "meta.json"
    meta = {}
    if meta_path.is_file():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))

    raw = eml_path.read_bytes()
    result = run_pipeline(raw, source="smtp_hold", content_provider=content_provider)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "previous_bucket": bucket,
        "previous_verdict": meta.get("verdict"),
        "previous_disposition": meta.get("disposition"),
        "new_verdict": result.verdict.value,
        "new_score": result.composite_score,
        "new_disposition": result.disposition.value,
        "new_disposition_reason": result.disposition_reason,
        "hard_override": result.hard_override,
        "reasons": result.reasons,
    }

    history = list(meta.get("reeval_history") or [])
    history.append(entry)
    meta["reeval_history"] = history
    meta["last_reeval"] = entry
    meta["verdict"] = result.verdict.value
    meta["score"] = result.composite_score
    meta["disposition"] = result.disposition.value
    meta["disposition_reason"] = result.disposition_reason
    meta["hard_override"] = result.hard_override
    meta["reasons"] = result.reasons
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n",
                         encoding="utf-8")

    action = "kept"
    final_path = src
    new_disp = result.disposition
    if auto_release and new_disp in (Disposition.DELIVER, Disposition.LOG) and bucket != "released":
        final_path = release_from_quarantine(root, src.name)
        action = "auto_released"
        # annotate release reason
        mp = final_path / "meta.json"
        m = json.loads(mp.read_text(encoding="utf-8"))
        m["release_action"] = "auto_release_after_reeval"
        m["reeval_history"] = history
        mp.write_text(json.dumps(m, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    elif auto_block and new_disp in (Disposition.QUARANTINE, Disposition.REJECT) and bucket == "quarantine":
        final_path = keep_blocked(root, src.name)
        action = "auto_blocked"
        mp = final_path / "meta.json"
        m = json.loads(mp.read_text(encoding="utf-8"))
        m["release_action"] = "auto_block_after_reeval"
        m["reeval_history"] = history
        mp.write_text(json.dumps(m, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return {
        "queue_id": final_path.name,
        "previous_bucket": bucket,
        "current_bucket": final_path.parent.name,
        "action": action,
        "path": str(final_path),
        "reeval": entry,
    }
