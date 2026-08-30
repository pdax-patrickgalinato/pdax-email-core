"""Wazuh S3 log shipper — background thread that ships SEGS audit logs to S3.

Reads two JSONL log files and uploads new records to an S3 bucket so Wazuh
can ingest them via its S3 input module. Offset state is checkpointed to
data/wazuh_shipper_offsets.json so restarts never re-ship records.

Activation:
  Set SEG_S3_BUCKET to a non-empty bucket name.  When the variable is unset
  (the default), this module is a no-op — it logs one INFO message and exits,
  imposing zero overhead on the rest of the application.

Environment variables:
  SEG_S3_BUCKET         S3 bucket name (required — shipper disabled when empty)
  SEG_S3_PREFIX         S3 key prefix (default: segs/logs)
  SEG_S3_REGION         S3 region (default: AWS_REGION env, then ap-southeast-1)
  SEG_S3_SHIP_INTERVAL  Flush interval in seconds (default: 60)

Security notes:
  - Credentials come from the ECS task role ambient IAM — no stored keys.
  - JSONL reads require no lock: appends to the log files are atomic single
    writes; reading from a byte offset is safe concurrently with the writers
    (activity_log.py and disposition.py).
  - Checkpoint file is written atomically (write to .tmp, then os.replace).
  - Each uploaded record is tagged "wazuh": true so the dashboard's
    "Wazuh alerts only" filter (feed_builder._shadow_to_ui) activates.
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from backend.config import get_settings
from backend.paths import DATA_DIR, REPO_ROOT, SPOOL_DIR

_log = logging.getLogger(__name__)

_ROOT = REPO_ROOT

_SOURCES = {
    "activity_audit": DATA_DIR / "activity_audit.jsonl",
    "shadow_enforcement": (
        Path(get_settings().quarantine_root or str(SPOOL_DIR))
        / "shadow_logs" / "shadow_enforcement.jsonl"
    ),
}

_CHECKPOINT_PATH = DATA_DIR / "wazuh_shipper_offsets.json"


def _load_checkpoints() -> dict[str, int]:
    try:
        return json.loads(_CHECKPOINT_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_checkpoints(offsets: dict[str, int]) -> None:
    tmp = _CHECKPOINT_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(offsets), encoding="utf-8")
    os.replace(tmp, _CHECKPOINT_PATH)


def _read_new_lines(path: Path, offset: int) -> tuple[list[dict], int]:
    """Return (records, new_offset). Reads from byte offset; skips malformed lines."""
    records: list[dict] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if isinstance(rec, dict):
                        records.append(rec)
                except json.JSONDecodeError:
                    pass
            new_offset = f.tell()
    except (FileNotFoundError, OSError):
        new_offset = offset
    return records, new_offset


def _upload_batch(s3_client, bucket: str, prefix: str, source_name: str,
                  records: list[dict]) -> None:
    """Tag records wazuh=true, gzip them, and put_object to S3."""
    now = datetime.now(timezone.utc)
    key = (
        f"{prefix.rstrip('/')}/{source_name}/"
        f"{now.strftime('%Y/%m/%d')}/"
        f"{now.strftime('%H%M%S')}-{uuid.uuid4().hex[:8]}.jsonl.gz"
    )
    tagged = [{**r, "wazuh": True} for r in records]
    payload = "\n".join(json.dumps(r, ensure_ascii=False) for r in tagged).encode("utf-8")
    compressed = gzip.compress(payload)
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=compressed,
        ContentEncoding="gzip",
        ContentType="application/x-ndjson",
    )
    _log.info("wazuh_shipper: uploaded %d records from %s → s3://%s/%s",
              len(records), source_name, bucket, key)


def _ship_loop(bucket: str, prefix: str, region: str, interval: int) -> None:
    import boto3
    s3 = boto3.client("s3", region_name=region)
    offsets = _load_checkpoints()
    _log.info("wazuh_shipper: started — bucket=%s prefix=%s interval=%ds", bucket, prefix, interval)

    while True:
        time.sleep(interval)
        changed = False
        for source_name, path in _SOURCES.items():
            current_offset = offsets.get(source_name, 0)
            records, new_offset = _read_new_lines(path, current_offset)
            if not records:
                offsets[source_name] = new_offset
                if new_offset != current_offset:
                    changed = True
                continue
            try:
                _upload_batch(s3, bucket, prefix, source_name, records)
                offsets[source_name] = new_offset
                changed = True
            except Exception as exc:
                _log.warning("wazuh_shipper: upload failed for %s: %s — will retry next cycle",
                             source_name, exc)
        if changed:
            try:
                _save_checkpoints(offsets)
            except Exception as exc:
                _log.warning("wazuh_shipper: failed to save checkpoints: %s", exc)


def start_shipper() -> None:
    """Start the background S3 shipper thread. No-op if SEG_S3_BUCKET is unset."""
    s = get_settings()
    bucket = s.s3_bucket.strip()
    if not bucket:
        _log.info("wazuh_shipper: disabled (SEG_S3_BUCKET not set)")
        return
    prefix = s.s3_prefix.strip()
    region = (
        s.s3_region.strip()
        or s.aws_region.strip()
        or "ap-southeast-1"
    )
    interval = max(10, int(s.s3_ship_interval))
    t = threading.Thread(
        target=_ship_loop, args=(bucket, prefix, region, interval),
        daemon=True, name="wazuh-s3-shipper",
    )
    t.start()
