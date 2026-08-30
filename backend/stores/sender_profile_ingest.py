"""Ingest CLEAN/LOW sender-profile rows from stored spool copies.

No LLM and no ip-api. Used by the one-shot backfill and the background worker.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

from workers.pipeline.correlation import BehavioralCorrelationStore
from workers.pipeline.request_class import classify_request
from backend.stores.sender_identity import flags_from_meta, identity_skip_reason

_LEARN = frozenset({"CLEAN", "LOW"})
_BUCKETS = ("gmail", "quarantine", "released")


def from_addr(meta: dict) -> str:
    raw = str(meta.get("from") or "")
    addrs = [a.lower() for _, a in getaddresses([raw]) if a]
    return addrs[0] if addrs else raw.strip().lower()


def _has_message_id(store: BehavioralCorrelationStore, mid: str) -> bool:
    """True when this message_id is already in the profile baseline."""
    key = (mid or "").strip()
    if not key:
        return False
    try:
        conn = store._connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM sender_profile_obs WHERE message_id = ? LIMIT 1",
                (key,),
            ).fetchone()
            try:
                conn.commit()
            except Exception:
                pass
            return row is not None
        finally:
            conn.close()
    except Exception:
        return False


def ingest_spool_profiles(
    store: BehavioralCorrelationStore,
    spool_root: Path,
    *,
    limit: int = 80,
    skip_if_ready: bool = False,
    min_n: int = 5,
) -> dict:
    """Insert missing CLEAN/LOW profile rows. Returns inserted/skipped counts."""
    seen: set[str] = set()
    inserted = 0
    skipped = 0
    root = Path(spool_root)
    dests: list[Path] = []
    for bucket in _BUCKETS:
        base = root / bucket
        if not base.is_dir():
            continue
        dests.extend(p for p in base.iterdir() if p.is_dir())
    dests.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    for dest in dests:
        if inserted >= max(1, int(limit)):
            break
        meta_path = dest / "meta.json"
        if not meta_path.is_file():
            skipped += 1
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            skipped += 1
            continue
        verdict = str(meta.get("verdict") or "").upper()
        if verdict not in _LEARN:
            skipped += 1
            continue
        sender = from_addr(meta)
        origin = ((meta.get("stages") or {}).get("origin_ip") or {})
        headers = ((meta.get("stages") or {}).get("headers") or {})
        asn = origin.get("asn") or ""
        country = origin.get("country") or ""
        role = origin.get("network_role") or origin.get("networkRole") or ""
        mid = str(meta.get("message_id") or meta.get("queue_id") or dest.name)
        if not sender or mid in seen or _has_message_id(store, mid):
            skipped += 1
            continue
        if not (asn or country or role or origin.get("ip")):
            skipped += 1
            continue
        if skip_if_ready and int(store.profile_for(sender).get("n") or 0) >= min_n:
            skipped += 1
            continue
        store.record_profile_observation(
            sender,
            asn=asn,
            country=country,
            network_role=role,
            vpn=bool(origin.get("vpn")),
            spf=headers.get("spf") or "",
            dkim=headers.get("dkim") or "",
            mailbox=str(meta.get("mailbox") or ""),
            hour_utc=_hour_utc(dest, meta),
            verdict=verdict,
            message_id=mid,
        )
        seen.add(mid)
        inserted += 1
    req = ingest_recipient_requests(store, root, limit=max(200, int(limit) * 8))
    ident = apply_identity_from_spool(store, root)
    vol = ingest_mail_volume(store, root, limit=max(400, int(limit) * 10))
    return {"inserted": inserted, "skipped": skipped, **req, **ident, **vol}


def ingest_copy(store: BehavioralCorrelationStore, dest) -> dict:
    """Learn profile / volume / identity from one stored copy (post-LLM)."""
    from backend.stores import spool
    meta = spool.read_meta(dest)
    empty = {
        "inserted": 0, "skipped": 1,
        "request_recorded": 0, "request_skipped": 0,
        "volume_recorded": 0, "volume_skipped": 0,
        "identity_updated": 0,
        "from_queue": 1,
        "sender": "",
    }
    if not meta:
        return empty
    sender = from_addr(meta)
    mailbox = str(meta.get("mailbox") or "").strip()
    mid = str(meta.get("message_id") or meta.get("queue_id") or spool.dest_name(dest)).strip()
    inserted = 0
    skipped = 0
    verdict = str(meta.get("verdict") or "").upper()
    if verdict in _LEARN and sender and mid:
        origin = ((meta.get("stages") or {}).get("origin_ip") or {})
        headers = ((meta.get("stages") or {}).get("headers") or {})
        asn = origin.get("asn") or ""
        country = origin.get("country") or ""
        role = origin.get("network_role") or origin.get("networkRole") or ""
        if asn or country or role or origin.get("ip"):
            if not _has_message_id(store, mid):
                store.record_profile_observation(
                    sender,
                    asn=asn,
                    country=country,
                    network_role=role,
                    vpn=bool(origin.get("vpn")),
                    spf=headers.get("spf") or "",
                    dkim=headers.get("dkim") or "",
                    mailbox=mailbox,
                    hour_utc=_hour_utc(dest, meta),
                    verdict=verdict,
                    message_id=mid,
                )
                inserted = 1
            else:
                skipped = 1
        else:
            skipped = 1
    else:
        skipped = 1
    request_recorded = 0
    request_skipped = 0
    volume_recorded = 0
    volume_skipped = 0
    if mailbox and sender and mid:
        cls = str(
            ((meta.get("stages") or {}).get("intel") or {}).get("request_class") or ""
        ) or classify_request(str(meta.get("subject") or ""), "")
        store.record_recipient_request(mailbox, sender, cls, message_id=mid)
        request_recorded = 1
        store.record_copy_behavior(
            sender=sender,
            mailbox=mailbox,
            message_id=mid,
            peers=_peers_from_meta(meta),
            labels=list(meta.get("gmail_labels") or []),
            hour_utc=_hour_utc(dest, meta),
            request_class=cls,
            has_attachment=_has_attachment(meta),
            is_reply=_is_reply(meta),
        )
        volume_recorded = 1
    else:
        request_skipped = 1
        volume_skipped = 1
    identity_updated = 0
    if sender:
        skip = identity_skip_reason(
            sender,
            mailbox,
            list(meta.get("gmail_labels") or []),
            flags_from_meta(meta),
        )
        if skip:
            mids = []
            for cand in (meta.get("message_id"), meta.get("queue_id"), spool.dest_name(dest)):
                s = str(cand or "").strip()
                if s and s not in mids:
                    mids.append(s)
            for item in mids:
                identity_updated += store.mark_identity(item, eligible=False, reason=skip)
    return {
        "inserted": inserted,
        "skipped": skipped,
        "request_recorded": request_recorded,
        "request_skipped": request_skipped,
        "volume_recorded": volume_recorded,
        "volume_skipped": volume_skipped,
        "identity_updated": identity_updated,
        "from_queue": 1,
        "sender": sender,
    }


def ingest_recipient_requests(
    store: BehavioralCorrelationStore,
    spool_root: Path,
    *,
    limit: int = 400,
) -> dict:
    """Seed mailbox × request-class history from stored copies (any verdict)."""
    recorded = 0
    skipped = 0
    root = Path(spool_root)
    dests: list[Path] = []
    for bucket in _BUCKETS:
        base = root / bucket
        if not base.is_dir():
            continue
        dests.extend(p for p in base.iterdir() if p.is_dir())
    dests.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    for dest in dests:
        if recorded >= max(1, int(limit)):
            break
        meta_path = dest / "meta.json"
        if not meta_path.is_file():
            skipped += 1
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            skipped += 1
            continue
        mailbox = str(meta.get("mailbox") or "").strip()
        sender = from_addr(meta)
        if not mailbox or not sender:
            skipped += 1
            continue
        cls = str(
            ((meta.get("stages") or {}).get("intel") or {}).get("request_class") or ""
        ) or classify_request(str(meta.get("subject") or ""), "")
        mid = str(meta.get("message_id") or meta.get("queue_id") or dest.name)
        store.record_recipient_request(mailbox, sender, cls, message_id=mid)
        recorded += 1
    return {"request_recorded": recorded, "request_skipped": skipped}


def ingest_mail_volume(
    store: BehavioralCorrelationStore,
    spool_root: Path,
    *,
    limit: int = 400,
) -> dict:
    """Seed sent/received counts, hours, and counterparties (any verdict)."""
    recorded = 0
    skipped = 0
    root = Path(spool_root)
    dests: list[Path] = []
    for bucket in _BUCKETS:
        base = root / bucket
        if not base.is_dir():
            continue
        dests.extend(p for p in base.iterdir() if p.is_dir())
    dests.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    for dest in dests:
        if recorded >= max(1, int(limit)):
            break
        meta_path = dest / "meta.json"
        if not meta_path.is_file():
            skipped += 1
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            skipped += 1
            continue
        mailbox = str(meta.get("mailbox") or "").strip()
        sender = from_addr(meta)
        mid = str(meta.get("message_id") or meta.get("queue_id") or dest.name).strip()
        if not mailbox or not sender or not mid:
            skipped += 1
            continue
        cls = str(
            ((meta.get("stages") or {}).get("intel") or {}).get("request_class") or ""
        ) or classify_request(str(meta.get("subject") or ""), "")
        store.record_copy_behavior(
            sender=sender,
            mailbox=mailbox,
            message_id=mid,
            peers=_peers_from_meta(meta),
            labels=list(meta.get("gmail_labels") or []),
            hour_utc=_hour_utc(dest, meta),
            request_class=cls,
            has_attachment=_has_attachment(meta),
            is_reply=_is_reply(meta),
        )
        recorded += 1
    return {"volume_recorded": recorded, "volume_skipped": skipped}


def _hour_utc(dest, meta: dict):
    raw_date = ""
    eml = dest / "message.eml" if isinstance(dest, Path) else None
    if eml is not None and eml.is_file():
        try:
            blob = eml.read_bytes()[:8192]
            for line in blob.split(b"\n"):
                if line.lower().startswith(b"date:"):
                    raw_date = line.split(b":", 1)[1].decode("utf-8", "replace").strip()
                    break
                if not line.strip():
                    break
        except Exception:
            raw_date = ""
    if raw_date:
        try:
            dt = parsedate_to_datetime(raw_date)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).hour
        except Exception:
            pass
    ts = str(meta.get("ts") or "")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).hour
    except ValueError:
        return None


def _peers_from_meta(meta: dict) -> list[str]:
    found: list[str] = []
    for key in ("to", "cc"):
        raw = meta.get(key)
        if isinstance(raw, list):
            raw = ", ".join(str(x) for x in raw)
        found.extend(a.lower() for _, a in getaddresses([str(raw or "")]) if a)
    for extra in meta.get("fanout_recipients") or []:
        a = str(extra or "").strip().lower()
        if a:
            found.append(a)
    return list(dict.fromkeys(found))


def _has_attachment(meta: dict) -> bool:
    hashes = ((meta.get("iocs") or {}).get("hashes_sha256") or [])
    if hashes:
        return True
    att = ((meta.get("stages") or {}).get("attachments") or {})
    return bool(att.get("flags"))


def _is_reply(meta: dict) -> bool:
    if meta.get("is_reply"):
        return True
    return bool(str(meta.get("in_reply_to") or "").strip() or str(meta.get("references") or "").strip())


def apply_identity_from_spool(
    store: BehavioralCorrelationStore,
    spool_root: Path,
    *,
    limit: int = 0,
) -> dict:
    """Mark SENT / quoted-lure / role-ticket copies as identity-ineligible.

    limit=0 walks every spool dest. Each cycle is a cheap meta.json read plus
    a no-op UPDATE when identity is already 0.
    """
    updated = 0
    scanned = 0
    root = Path(spool_root)
    dests: list[Path] = []
    for bucket in _BUCKETS:
        base = root / bucket
        if not base.is_dir():
            continue
        dests.extend(p for p in base.iterdir() if p.is_dir())
    dests.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    cap = int(limit or 0)
    for dest in dests:
        if cap and scanned >= cap:
            break
        meta_path = dest / "meta.json"
        if not meta_path.is_file():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        scanned += 1
        sender = from_addr(meta)
        skip = identity_skip_reason(
            sender,
            str(meta.get("mailbox") or ""),
            list(meta.get("gmail_labels") or []),
            flags_from_meta(meta),
        )
        if not skip:
            continue
        mids = []
        for cand in (meta.get("message_id"), meta.get("queue_id"), dest.name):
            s = str(cand or "").strip()
            if s and s not in mids:
                mids.append(s)
        n = 0
        for mid in mids:
            n += store.mark_identity(mid, eligible=False, reason=skip)
        if n:
            updated += 1
    return {"identity_updated": updated, "identity_scanned": scanned}
