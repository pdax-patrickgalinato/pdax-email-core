"""Mail spool: filesystem (tests) or CMK-encrypted S3 (ECS / compose).

Dest keys are logical ``{bucket}/{queue_id}``. SQS payloads carry S3 object keys,
never the .eml bytes.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from backend.config import get_settings
from backend.paths import SPOOL_DIR

_log = logging.getLogger("backend.stores.spool")

BUCKETS = ("gmail", "quarantine", "released", "rejected")

_root_override: Path | None = None


def set_root(path: Path | None) -> None:
    global _root_override
    _root_override = Path(path) if path is not None else None


def use_s3() -> bool:
    return bool((get_settings().s3_bucket or "").strip())


def payload(queue_id: str, bucket: str = "gmail") -> dict:
    qid = (queue_id or "").strip()
    bkt = (bucket or "gmail").strip() or "gmail"
    return {
        "queue_id": qid,
        "bucket": bkt,
        "s3_eml": f"spool/{bkt}/{qid}/message.eml",
        "s3_meta": f"spool/{bkt}/{qid}/meta.json",
    }


def from_payload(msg: dict | None) -> dict:
    if not isinstance(msg, dict):
        return payload("", "gmail")
    qid = str(msg.get("queue_id") or "").strip()
    bkt = str(msg.get("bucket") or "gmail").strip() or "gmail"
    out = payload(qid, bkt)
    if msg.get("s3_eml"):
        out["s3_eml"] = str(msg["s3_eml"])
    if msg.get("s3_meta"):
        out["s3_meta"] = str(msg["s3_meta"])
    if msg.get("thread_id"):
        out["thread_id"] = str(msg["thread_id"])
    return out


def dest_name(dest) -> str:
    return queue_id_of(dest)


def as_path(dest) -> Path:
    if isinstance(dest, Path):
        return dest
    pl = as_payload(dest)
    return local_dir(pl["queue_id"], pl["bucket"])


def as_payload(dest) -> dict:
    if isinstance(dest, dict):
        return from_payload(dest)
    if isinstance(dest, Path):
        bkt = dest.parent.name if dest.parent.name in BUCKETS else "gmail"
        return payload(dest.name, bkt)
    text = str(dest or "").strip()
    if "/" in text and not text.startswith("{") and not text.startswith("/"):
        bkt, _, qid = text.partition("/")
        return payload(qid, bkt if bkt in BUCKETS else "gmail")
    return payload(Path(text).name if text else "", "gmail")


def queue_id_of(dest) -> str:
    if isinstance(dest, dict):
        return str(dest.get("queue_id") or "").strip()
    if isinstance(dest, Path):
        return dest.name
    text = str(dest or "").strip()
    if not text:
        return ""
    return Path(text).name


def dest_key(dest) -> str:
    if isinstance(dest, dict):
        bkt = str(dest.get("bucket") or "gmail").strip() or "gmail"
        return f"{bkt}/{queue_id_of(dest)}"
    if isinstance(dest, Path):
        try:
            return f"{dest.parent.name}/{dest.name}"
        except Exception:
            return dest.name
    return str(dest or "").strip()


def _local_root() -> Path:
    if _root_override is not None:
        return _root_override
    root = (get_settings().quarantine_root or "").strip()
    return Path(root) if root else SPOOL_DIR


def local_dir(queue_id: str, bucket: str = "gmail") -> Path:
    return _local_root() / bucket / queue_id


def _s3():
    import boto3
    s = get_settings()
    region = (s.s3_region or s.aws_region or "ap-southeast-1").strip()
    return boto3.client("s3", region_name=region)


def _put_s3(key: str, body: bytes, content_type: str) -> None:
    s = get_settings()
    extra: dict[str, Any] = {
        "Bucket": s.s3_bucket,
        "Key": key,
        "Body": body,
        "ContentType": content_type,
        "ServerSideEncryption": "aws:kms",
    }
    kms = (s.kms_key_arn or "").strip()
    if kms:
        extra["SSEKMSKeyId"] = kms
    _s3().put_object(**extra)


def _get_s3(key: str) -> bytes:
    s = get_settings()
    resp = _s3().get_object(Bucket=s.s3_bucket, Key=key)
    return resp["Body"].read()


def put_eml(queue_id: str, raw: bytes, bucket: str = "gmail") -> dict:
    qid = (queue_id or "").strip()
    if not qid:
        raise ValueError("queue_id required")
    pl = payload(qid, bucket)
    if use_s3():
        _put_s3(pl["s3_eml"], raw, "message/rfc822")
    else:
        dest = local_dir(qid, bucket)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "message.eml").write_bytes(raw)
    return pl


def put_meta(queue_id: str, meta: dict, bucket: str = "gmail") -> dict:
    qid = (queue_id or "").strip()
    pl = payload(qid, bucket)
    blob = (json.dumps(meta, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if use_s3():
        _put_s3(pl["s3_meta"], blob, "application/json")
    else:
        dest = local_dir(qid, bucket)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "meta.json").write_bytes(blob)
    return pl


def get_eml(queue_id: str, bucket: str = "gmail") -> bytes:
    pl = payload(queue_id, bucket)
    if use_s3():
        return _get_s3(pl["s3_eml"])
    path = local_dir(queue_id, bucket) / "message.eml"
    return path.read_bytes()


def get_meta(queue_id: str, bucket: str = "gmail") -> dict:
    pl = payload(queue_id, bucket)
    try:
        if use_s3():
            raw = _get_s3(pl["s3_meta"])
        else:
            path = local_dir(queue_id, bucket) / "meta.json"
            if not path.is_file():
                return {}
            raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def read_message(queue_id: str, bucket: str | None = None) -> bytes:
    """Return raw RFC822 bytes for a copy (S3 or local disk).

    Looks at ``dest`` on the assessments row when *bucket* is omitted, then
    walks the usual spool buckets. Raises FileNotFoundError when nothing
    has a message.eml.
    """
    qid = (queue_id or "").strip()
    if not qid:
        raise FileNotFoundError("queue_id required")
    buckets: list[str] = []
    if bucket:
        buckets.append(str(bucket).strip() or "gmail")
    else:
        try:
            from backend.stores import assessments as store
            row = store.get_copy(qid) or {}
            dest = str(row.get("dest") or "")
            if dest:
                buckets.append(as_payload(dest)["bucket"])
        except Exception:
            pass
        buckets.extend(BUCKETS)
    seen: set[str] = set()
    last_exc: Exception | None = None
    for bkt in buckets:
        bkt = (bkt or "gmail").strip() or "gmail"
        if bkt in seen:
            continue
        seen.add(bkt)
        try:
            raw = get_eml(qid, bkt)
            if raw:
                return raw
        except Exception as exc:
            last_exc = exc
            continue
    raise FileNotFoundError(qid) from last_exc


def exists(queue_id: str, bucket: str = "gmail") -> bool:
    qid = (queue_id or "").strip()
    if not qid:
        return False
    pl = payload(qid, bucket)
    if use_s3():
        try:
            _s3().head_object(Bucket=get_settings().s3_bucket, Key=pl["s3_eml"])
            return True
        except Exception:
            return False
    return (local_dir(qid, bucket) / "message.eml").is_file()


def list_copies(bucket: str = "gmail") -> list[dict]:
    bkt = (bucket or "gmail").strip() or "gmail"
    out: list[dict] = []
    if use_s3():
        s = get_settings()
        token = None
        prefix = f"spool/{bkt}/"
        client = _s3()
        seen: set[str] = set()
        while True:
            kw: dict[str, Any] = {"Bucket": s.s3_bucket, "Prefix": prefix}
            if token:
                kw["ContinuationToken"] = token
            resp = client.list_objects_v2(**kw)
            for obj in resp.get("Contents") or []:
                key = str(obj.get("Key") or "")
                parts = key.split("/")
                if len(parts) >= 4 and parts[-1] == "meta.json":
                    qid = parts[2]
                    if qid and qid not in seen:
                        seen.add(qid)
                        out.append(payload(qid, bkt))
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
        return out
    base = _local_root() / bkt
    if not base.is_dir():
        return []
    for p in sorted(base.iterdir()):
        if p.is_dir() and (p / "meta.json").is_file():
            out.append(payload(p.name, bkt))
    return out


def iter_copies(buckets: tuple[str, ...] = BUCKETS):
    """Yield (dest, meta) for every stored copy. dest is Path or payload dict."""
    if use_s3():
        for bkt in buckets:
            for pl in list_copies(bkt):
                yield pl, get_meta(pl["queue_id"], bkt)
        return
    root = _local_root()
    for bkt in buckets:
        base = root / bkt
        if not base.is_dir():
            continue
        for p in sorted(base.iterdir()):
            if not p.is_dir() or not (p / "meta.json").is_file():
                continue
            yield p, read_meta(p)


def move(queue_id: str, src_bucket: str, dst_bucket: str) -> dict:
    qid = (queue_id or "").strip()
    src = (src_bucket or "gmail").strip()
    dst = (dst_bucket or "gmail").strip()
    eml = get_eml(qid, src)
    meta = get_meta(qid, src)
    meta["bucket"] = dst
    put_eml(qid, eml, dst)
    put_meta(qid, meta, dst)
    if use_s3():
        s = get_settings()
        client = _s3()
        for key in (payload(qid, src)["s3_eml"], payload(qid, src)["s3_meta"]):
            try:
                client.delete_object(Bucket=s.s3_bucket, Key=key)
            except Exception:
                _log.warning("spool delete failed %s", key)
    else:
        import shutil
        src_dir = local_dir(qid, src)
        if src_dir.exists() and src != dst:
            shutil.rmtree(src_dir, ignore_errors=True)
    return payload(qid, dst)


def read_meta(dest) -> dict:
    """Load meta.json only — never the .eml (thread-AI hydrate walks many copies)."""
    if isinstance(dest, Path):
        path = dest / "meta.json"
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}
        if not use_s3():
            return {}
    pl = as_payload(dest)
    qid = str(pl.get("queue_id") or "").strip()
    if not qid:
        return {}
    return get_meta(qid, pl.get("bucket") or "gmail")


def write_meta(dest, meta: dict) -> None:
    blob = json.dumps(meta, indent=2, ensure_ascii=False) + "\n"
    if isinstance(dest, Path):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "meta.json").write_text(blob, encoding="utf-8")
        if use_s3():
            bkt = dest.parent.name if dest.parent.name in BUCKETS else "gmail"
            put_meta(dest.name, meta, bkt)
        return
    pl = as_payload(dest)
    put_meta(pl["queue_id"], meta, pl["bucket"])


def read_copy(dest) -> tuple[bytes, dict]:
    """Load eml + meta from a payload, Path, or dest key."""
    if isinstance(dest, dict):
        pl = from_payload(dest)
        return get_eml(pl["queue_id"], pl["bucket"]), get_meta(pl["queue_id"], pl["bucket"])
    if isinstance(dest, Path):
        eml = dest / "message.eml"
        meta_path = dest / "meta.json"
        meta = {}
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                meta = {}
        raw = eml.read_bytes() if eml.is_file() else b""
        return raw, meta
    text = str(dest or "")
    if "/" in text:
        bkt, _, qid = text.partition("/")
        return get_eml(qid, bkt), get_meta(qid, bkt)
    return get_eml(text), get_meta(text)
