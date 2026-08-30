"""Detect when the same message was delivered to other addresses.

Used as an advisory fact for the LLM and the assessment-flow graph — it does
not change the composite score. Two match styles:

1. Same RFC Message-ID in another scanned mailbox (strongest: one send,
   many inboxes).
2. Same sender + near-identical subject/body in another mailbox (bulk tools
   that mint a unique Message-ID per recipient).

Envelope To/Cc on this copy is a weaker signal (newsletters routinely list
many recipients) and is still surfaced so the model can weigh it.
"""
from __future__ import annotations

import email
import hashlib
import json
import re
from email.utils import getaddresses
from pathlib import Path
from typing import Optional

from backend.stores.mail_thread import extract_message_ids, headers_from_raw
from backend.models import StageResult, StageStatus

_SPOOL_BUCKETS = ("gmail", "quarantine", "rejected", "released")
_FP_BODY = 240
_MAX_LIST = 12


def _read_meta(dest: Path) -> dict:
    path = dest / "meta.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _norm_addr(value: str) -> str:
    return (value or "").strip().lower()


def strip_subject(subject: str) -> str:
    return re.sub(r"^\s*((re|fw|fwd)\s*:\s*)+", "", str(subject or ""), flags=re.I).strip().lower()


def _message_id(meta: dict, dest: Path) -> str:
    ids = extract_message_ids(str(meta.get("message_id") or ""))
    if ids:
        return ids[0]
    eml = dest / "message.eml"
    if eml.is_file():
        try:
            rfc = headers_from_raw(eml.read_bytes())
        except Exception:
            rfc = {}
        ids = extract_message_ids(str(rfc.get("message_id") or ""))
        if ids:
            return ids[0]
    return ""


def _sender(meta: dict) -> str:
    raw = str(meta.get("from") or "")
    addrs = [a.lower() for _, a in getaddresses([raw]) if a]
    return addrs[0] if addrs else _norm_addr(raw)


def _envelope_addrs(dest, meta: dict) -> list[str]:
    found: list[str] = []
    for key in ("to", "cc"):
        found.extend(a.lower() for _, a in getaddresses([str(meta.get(key) or "")]) if a)
    eml = dest / "message.eml" if isinstance(dest, Path) else None
    if eml is not None and eml.is_file():
        try:
            raw = eml.read_bytes()
            crlf = raw.find(b"\r\n\r\n")
            lf = raw.find(b"\n\n")
            if crlf != -1 and (lf == -1 or crlf < lf):
                block = raw[:crlf]
            elif lf != -1:
                block = raw[:lf]
            else:
                block = raw[:8192]
            msg = email.message_from_bytes(block + b"\n")
            for h in ("To", "Cc", "Bcc"):
                found.extend(a.lower() for _, a in getaddresses([msg.get(h) or ""]) if a)
        except Exception:
            pass
    return list(dict.fromkeys(a for a in found if a))


def _content_fingerprint(dest: Path, meta: dict) -> str:
    sender = _sender(meta)
    subj = strip_subject(meta.get("subject") or "")
    excerpt = ""
    stored = (meta.get("primary_content") or "").strip()
    if stored:
        excerpt = " ".join(stored.split())[:_FP_BODY]
    else:
        eml = dest / "message.eml"
        if eml.is_file():
            try:
                from backend.parsed_email import ParsedEmail
                pe = ParsedEmail(eml.read_bytes())
                text = re.sub(r"<[^>]+>", " ", pe.text_body() or pe.html_body() or "")
                excerpt = " ".join(text.split())[:_FP_BODY]
            except Exception:
                excerpt = ""
    if not sender or not (subj or excerpt):
        return ""
    blob = f"{sender}|{subj}|{excerpt.lower()}".encode("utf-8", "ignore")
    return "fp:" + hashlib.sha1(blob).hexdigest()[:16]


def envelope_context(pe, mailbox: str = "") -> dict:
    """Fan-out from this message's own To/Cc, without scanning spool."""
    addrs = list(dict.fromkeys(
        [a for a in (getattr(pe, "to_addrs", None) or []) if a]
        + [a.lower() for _, a in getaddresses([pe.header("Cc")]) if a]
    ))
    mb = _norm_addr(mailbox)
    others = [a for a in addrs if a and a != mb]
    if not others:
        return {}
    shown = others[:_MAX_LIST]
    return {
        "envelope_recipients": shown,
        "envelope_count": len(others),
        "inbox_count": 0,
        "mailboxes": [],
        "recipients": shown,
        "match": "envelope",
        "summary": (
            f"Envelope To/Cc lists {len(others)} other address"
            f"{'' if len(others) == 1 else 'es'}: " + ", ".join(shown)
        ),
    }


def _same_blast(a: dict, dest_a: Path, b: dict, dest_b: Path) -> str:
    """Return match kind, or ''."""
    mid_a, mid_b = _message_id(a, dest_a), _message_id(b, dest_b)
    if mid_a and mid_b and mid_a == mid_b:
        return "message_id"
    if _sender(a) and _sender(a) == _sender(b):
        fp_a, fp_b = _content_fingerprint(dest_a, a), _content_fingerprint(dest_b, b)
        if fp_a and fp_a == fp_b:
            return "content"
    return ""


def fanout_prompt_context(dest: Path, meta: Optional[dict] = None) -> dict:
    """Other scanned copies of this send, plus envelope To/Cc."""
    if not isinstance(dest, Path):
        return {}
    dest = dest.resolve()
    meta = meta or _read_meta(dest)
    mailbox = _norm_addr(meta.get("mailbox") or "")
    envelope = _envelope_addrs(dest, meta)
    envelope_others = [a for a in envelope if a != mailbox]

    others: list[dict] = []
    match = ""
    root = dest.parent.parent
    for bucket in _SPOOL_BUCKETS:
        base = root / bucket
        if not base.is_dir():
            continue
        for p in base.iterdir():
            if not p.is_dir() or not (p / "meta.json").is_file():
                continue
            if p.resolve() == dest:
                continue
            other = _read_meta(p)
            if not other:
                continue
            kind = _same_blast(meta, dest, other, p)
            if not kind:
                continue
            other_mb = _norm_addr(other.get("mailbox") or "")
            other_to = _envelope_addrs(p, other)
            if mailbox and other_mb == mailbox and not (set(other_to) - {mailbox}):
                continue
            if kind == "message_id" or kind == "content":
                match = match or kind
                others.append({
                    "mailbox": other_mb,
                    "to": other_to[:4],
                    "match": kind,
                })

    mailboxes = list(dict.fromkeys(
        o["mailbox"] for o in others if o.get("mailbox") and o["mailbox"] != mailbox
    ))
    recipients = list(dict.fromkeys(
        [a for o in others for a in o.get("to") or [] if a and a != mailbox]
        + envelope_others
    ))[:_MAX_LIST]

    if not mailboxes and not envelope_others:
        return {}

    bits = []
    if mailboxes:
        bits.append(
            f"same message also delivered to {len(mailboxes)} other scanned inbox"
            f"{'' if len(mailboxes) == 1 else 'es'}: " + ", ".join(mailboxes[:_MAX_LIST])
            + (f" (matched by {'Message-ID' if match == 'message_id' else 'sender+content'})")
        )
    if envelope_others and not mailboxes:
        bits.append(
            f"envelope To/Cc lists {len(envelope_others)} other address"
            f"{'' if len(envelope_others) == 1 else 'es'}: " + ", ".join(envelope_others[:_MAX_LIST])
        )
    elif envelope_others:
        bits.append(
            f"envelope also names {len(envelope_others)} address"
            f"{'' if len(envelope_others) == 1 else 'es'}"
        )

    return {
        "inbox_count": len(mailboxes),
        "envelope_count": len(envelope_others),
        "envelope_recipients": envelope_others[:_MAX_LIST],
        "mailboxes": mailboxes[:_MAX_LIST],
        "recipients": recipients,
        "match": match or ("envelope" if envelope_others else ""),
        "summary": "; ".join(bits),
        "transcript": "; ".join(bits),
    }


def visual_score(ctx: dict) -> float:
    """Display-only weight for the flow graph. Not used in composite scoring."""
    n = int(ctx.get("inbox_count") or 0)
    if n >= 3:
        return 48.0
    if n >= 1:
        return 28.0
    if int(ctx.get("envelope_count") or 0) >= 2:
        return 22.0
    return 0.0


def stage_flags(ctx: dict) -> list[str]:
    flags: list[str] = []
    n = int(ctx.get("inbox_count") or 0)
    match = ctx.get("match") or ""
    if n:
        key = "fanout_same_message" if match == "message_id" else "fanout_same_content"
        flags.append(f"{key}:{n}")
    env = int(ctx.get("envelope_count") or 0)
    if env:
        flags.append(f"fanout_envelope:{env}")
    return flags


def stage_result(ctx: dict) -> Optional[StageResult]:
    if not ctx:
        return None
    flags = stage_flags(ctx)
    if not flags:
        return None
    return StageResult(
        stage="fanout",
        status=StageStatus.OK,
        sub_score=visual_score(ctx),
        red_flags=flags,
        facts={
            "summary": ctx.get("summary") or "",
            "mailboxes": list(ctx.get("mailboxes") or []),
            "recipients": list(ctx.get("recipients") or []),
            "inbox_count": int(ctx.get("inbox_count") or 0),
            "envelope_count": int(ctx.get("envelope_count") or 0),
            "match": ctx.get("match") or "",
        },
    )


def merge_fanout_stage(stages: dict, ctx: dict) -> dict:
    """Patch a compact stages map with the fan-out snapshot."""
    out = dict(stages or {})
    st = stage_result(ctx)
    if not st:
        out.pop("fanout", None)
        return out
    row = {
        "status": "ok",
        "score": st.sub_score,
        "flags": list(st.red_flags),
        "summary": st.facts.get("summary") or "",
        "mailboxes": st.facts.get("mailboxes") or [],
        "recipients": st.facts.get("recipients") or [],
    }
    out["fanout"] = row
    return out


def propagate_fanout(dest: Path, meta: Optional[dict] = None) -> int:
    """Refresh fan-out snapshots on sibling copies. Returns how many written."""
    dest = dest.resolve()
    meta = meta or _read_meta(dest)
    n = 0
    root = dest.parent.parent
    for bucket in _SPOOL_BUCKETS:
        base = root / bucket
        if not base.is_dir():
            continue
        for p in base.iterdir():
            if not p.is_dir() or not (p / "meta.json").is_file():
                continue
            if p.resolve() == dest:
                continue
            other = _read_meta(p)
            if not other or not _same_blast(meta, dest, other, p):
                continue
            sibling_ctx = fanout_prompt_context(p, other)
            if not sibling_ctx:
                continue
            other["fanout_count"] = int(sibling_ctx.get("inbox_count") or 0)
            other["fanout_mailboxes"] = list(sibling_ctx.get("mailboxes") or [])
            other["fanout_recipients"] = list(sibling_ctx.get("recipients") or [])
            other["fanout_match"] = sibling_ctx.get("match") or ""
            other["stages"] = merge_fanout_stage(other.get("stages") or {}, sibling_ctx)
            try:
                (p / "meta.json").write_text(
                    json.dumps(other, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )
                n += 1
            except Exception:
                continue
    return n

