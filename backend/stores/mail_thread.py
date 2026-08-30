"""Conversation threading for the SOC console.

Groups messages that belong to one email thread using, in order:

1. Gmail ``threadId`` when the receiver stored it (authoritative for Workspace).
2. RFC 5322 ``Message-ID`` / ``In-Reply-To`` / ``References``, unioned across
   the current feed so a reply that only cites its parent still joins the root.

Thread keys are advisory display grouping — they never change deterministic
scoring. The LLM content stage can still read sibling messages so it can
assess the conversation as a whole.
"""
from __future__ import annotations

import email
import json
import re
from email.header import decode_header, make_header
from pathlib import Path
from typing import Iterable, Optional

_MSGID_RE = re.compile(r"<[^<>\s]+>")


def extract_message_ids(value: str) -> list[str]:
    """Return unique Message-ID tokens in header order, lowercased."""
    if not value or not isinstance(value, str):
        return []
    found = [m.group(0).strip().lower() for m in _MSGID_RE.finditer(value)]
    if found:
        # dict.fromkeys preserves order on 3.7+
        return list(dict.fromkeys(found))
    token = value.strip().lower()
    if not token or any(c.isspace() for c in token):
        return []
    if not token.startswith("<"):
        token = f"<{token.rstrip('>')}>"
    return [token]


def headers_from_raw(raw: bytes) -> dict:
    """Pull Message-ID / In-Reply-To / References from raw RFC822 bytes.

    Parses the header block only so large attachments are not MIME-walked
    on every feed refresh.
    """
    empty = {
        "message_id": "", "in_reply_to": "", "references": "",
        "from": "", "to": "", "cc": "", "subject": "",
    }
    if not raw:
        return empty
    crlf = raw.find(b"\r\n\r\n")
    lf = raw.find(b"\n\n")
    if crlf != -1 and (lf == -1 or crlf < lf):
        head = raw[:crlf]
    elif lf != -1:
        head = raw[:lf]
    else:
        head = raw[:16384]
    try:
        msg = email.message_from_bytes(head)
    except Exception:
        return empty

    def _h(name: str) -> str:
        raw_h = msg.get(name)
        if not raw_h:
            return ""
        try:
            return str(make_header(decode_header(raw_h)))
        except Exception:
            return str(raw_h)

    return {
        "message_id": _h("Message-ID"),
        "in_reply_to": _h("In-Reply-To"),
        "references": _h("References"),
        "from": _h("From"),
        "to": _h("To"),
        "cc": _h("Cc"),
        "subject": _h("Subject"),
    }


class _UnionFind:
    def __init__(self) -> None:
        self._p: dict[str, str] = {}

    def find(self, x: str) -> str:
        self._p.setdefault(x, x)
        if self._p[x] != x:
            self._p[x] = self.find(self._p[x])
        return self._p[x]

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._p[rb] = ra


def _gmail_node(mailbox: str, thread_id: str) -> str:
    mb = (mailbox or "").strip().lower()
    tid = (thread_id or "").strip()
    if mb:
        return f"g:{mb}:{tid}"
    return f"g:{tid}"


def assign_thread_keys(entries: Iterable[dict]) -> None:
    """Mutate entries in place with ``threadKey`` and ``threadCount``.

    Singleton messages (no Gmail thread, no RFC ids, no shared parents) get
    ``threadKey = "msg:<entry id>"`` so the UI can treat every row uniformly.
    """
    rows = list(entries)
    if not rows:
        return
    uf = _UnionFind()
    for i, e in enumerate(rows):
        node = f"e:{i}"
        gid = str(e.get("gmailThreadId") or "").strip()
        if gid:
            uf.union(node, _gmail_node(str(e.get("mailbox") or ""), gid))
        mid = extract_message_ids(str(e.get("messageId") or ""))
        if mid:
            uf.union(node, f"r:{mid[0]}")
        for pid in extract_message_ids(str(e.get("inReplyTo") or "")):
            uf.union(node, f"r:{pid}")
        for pid in extract_message_ids(str(e.get("references") or "")):
            uf.union(node, f"r:{pid}")

    groups: dict[str, list[int]] = {}
    for i in range(len(rows)):
        groups.setdefault(uf.find(f"e:{i}"), []).append(i)

    for idxs in groups.values():
        gmail_keys: list[str] = []
        rfc_ids: list[str] = []
        for i in idxs:
            e = rows[i]
            gid = str(e.get("gmailThreadId") or "").strip()
            if gid:
                mb = str(e.get("mailbox") or "").strip().lower()
                gmail_keys.append(f"gmail:{mb}:{gid}" if mb else f"gmail:{gid}")
            rfc_ids.extend(extract_message_ids(str(e.get("messageId") or "")))
        if gmail_keys:
            key = sorted(set(gmail_keys))[0]
        elif rfc_ids:
            key = "rfc:" + sorted(set(rfc_ids))[0]
        else:
            key = None
        count = len(idxs)
        for i in idxs:
            e = rows[i]
            e["threadKey"] = key or f"msg:{e.get('id') or i}"
            e["threadCount"] = count


_THREAD_VERDICTS = frozenset({"CLEAN", "LOW", "SUSPICIOUS", "MALICIOUS"})
_SPOOL_BUCKETS = ("gmail", "quarantine", "rejected", "released")
_BODY_EXCERPT = 800
_MAX_THREAD_MSGS = 10


def rfc_ids_of(meta: dict) -> set[str]:
    ids: set[str] = set()
    for key in ("message_id", "in_reply_to", "references"):
        ids.update(extract_message_ids(str(meta.get(key) or "")))
    return ids


def same_spool_thread(a: dict, b: dict) -> bool:
    ga = (a.get("gmail_thread_id") or "").strip()
    gb = (b.get("gmail_thread_id") or "").strip()
    if ga and gb and ga == gb:
        ma = (a.get("mailbox") or "").strip().lower()
        mb = (b.get("mailbox") or "").strip().lower()
        return (not ma) or (not mb) or ma == mb
    return bool(rfc_ids_of(a) & rfc_ids_of(b))


def _read_meta(dest: Path) -> dict:
    path = dest / "meta.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _body_excerpt(dest: Path, meta: dict, limit: int = _BODY_EXCERPT) -> str:
    stored = (meta.get("primary_content") or "").strip()
    if stored:
        return " ".join(stored.split())[:limit]
    eml = dest / "message.eml"
    if not eml.is_file():
        return ""
    try:
        from backend.parsed_email import ParsedEmail
        pe = ParsedEmail(eml.read_bytes())
        text = re.sub(r"<[^>]+>", " ", pe.text_body() or pe.html_body() or "")
        return " ".join(text.split())[:limit]
    except Exception:
        return ""


def iter_spool_thread_dests(dest: Path, meta: Optional[dict] = None) -> list[Path]:
    """All spool copies in the same Gmail/RFC thread as *dest*, including dest."""
    dest = dest.resolve()
    meta = meta or _read_meta(dest)
    root = dest.parent.parent
    found: list[Path] = []
    for bucket in _SPOOL_BUCKETS:
        base = root / bucket
        if not base.is_dir():
            continue
        for p in base.iterdir():
            if not p.is_dir() or not (p / "meta.json").is_file():
                continue
            if p.resolve() == dest:
                found.append(p)
                continue
            other = _read_meta(p)
            if other and same_spool_thread(meta, other):
                found.append(p)
    return found


def _thread_members(dest, meta: Optional[dict] = None) -> list[tuple[str, dict, bool]]:
    """(queue_id, meta, is_current) for every copy in this Gmail/RFC thread."""
    from backend.stores import spool
    meta = dict(meta or {})
    if not meta:
        try:
            loaded = spool.read_meta(dest) if not isinstance(dest, Path) else _read_meta(dest)
            if isinstance(loaded, dict):
                meta = loaded
        except Exception:
            meta = {}
    current_qid = spool.dest_name(dest)
    members: list[tuple[str, dict, bool]] = []
    if isinstance(dest, Path):
        try:
            dest_r = dest.resolve()
        except OSError:
            dest_r = dest
        if dest_r.is_dir():
            for p in iter_spool_thread_dests(dest_r, meta):
                m = meta if p.resolve() == dest_r else _read_meta(p)
                members.append((p.name, m if isinstance(m, dict) else {}, p.resolve() == dest_r))
    if len(members) >= 2:
        return members
    tid = str(meta.get("gmail_thread_id") or "").strip()
    from backend.stores import assessments as store
    if not tid:
        tid = str((store.get_copy(current_qid) or {}).get("gmail_thread_id") or "").strip()
    if not tid:
        return members
    rows = store.copies_in_thread(
        tid, mailbox=str(meta.get("mailbox") or "").strip() or None,
    )
    if len(rows) < 2:
        return members
    out: list[tuple[str, dict, bool]] = []
    for r in rows:
        qid = str(r.get("queue_id") or "").strip()
        if not qid:
            continue
        if qid == current_qid and meta:
            m = meta
        else:
            try:
                m = spool.read_meta(spool.payload(qid))
            except Exception:
                m = {}
        if not isinstance(m, dict) or not m:
            m = {
                "from": r.get("from_addr") or "",
                "subject": r.get("subject") or "",
                "verdict": r.get("verdict") or "",
                "ts": "",
                "primary_content": "",
            }
        out.append((qid, m, qid == current_qid))
    return out


def thread_prompt_context(dest, meta: Optional[dict] = None) -> dict:
    """Compact conversation transcript for the content-AI prompt.

    Returns {} when this copy is a singleton. Neighbors are oldest-first;
    the current message is marked so the model scores that turn in context.
    Production siblings come from the copies table (S3 has no local tree).
    """
    members = _thread_members(dest, meta)
    if len(members) < 2:
        return {}
    rows = []
    for qid, m, current in members:
        rows.append({
            "qid": qid,
            "ts": str(m.get("ts") or ""),
            "from": str(m.get("from") or m.get("from_addr") or ""),
            "subject": str(m.get("subject") or ""),
            "verdict": str(m.get("verdict") or ""),
            "current": current,
            "excerpt": "" if current else " ".join(str(m.get("primary_content") or "").split())[:_BODY_EXCERPT],
        })
    rows.sort(key=lambda r: r["ts"])
    rows = rows[-_MAX_THREAD_MSGS:]
    lines = []
    for i, r in enumerate(rows, 1):
        mark = " CURRENT MESSAGE — score this turn" if r["current"] else ""
        lines.append(
            f"[{i}] {r['ts'] or '?'}  From: {r['from'] or '?'}  "
            f"Subject: {r['subject'] or '(no subject)'}  "
            f"stored_verdict={r['verdict'] or '?'}{mark}"
        )
        if r["current"]:
            lines.append("    (body is in Subject/Body above)")
        elif r["excerpt"]:
            lines.append("    " + r["excerpt"])
    return {
        "count": len(rows),
        "transcript": "\n".join(lines),
    }


def normalize_thread_verdict(value: str) -> str:
    v = (value or "").strip().upper()
    return v if v in _THREAD_VERDICTS else ""


def propagate_thread_assessment(dest, summary: str, verdict: str,
                                meta: Optional[dict] = None) -> int:
    """Copy thread-level LLM fields onto sibling spool copies. Returns how many."""
    summary = (summary or "").strip()
    verdict = normalize_thread_verdict(verdict)
    if not summary and not verdict:
        return 0
    from backend.stores import spool
    updates = {
        "thread_summary": summary,
        "thread_verdict": verdict,
        "thread_assessed_from": spool.dest_name(dest),
    }
    n = 0
    if isinstance(dest, Path):
        try:
            dest_r = dest.resolve()
        except OSError:
            dest_r = dest
        meta = meta or _read_meta(dest_r)
        for p in iter_spool_thread_dests(dest_r, meta):
            if p.resolve() == dest_r:
                continue
            other = _read_meta(p)
            other.update(updates)
            try:
                (p / "meta.json").write_text(
                    json.dumps(other, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )
                n += 1
            except Exception:
                continue
        if n:
            return n
    meta = meta if isinstance(meta, dict) else {}
    if not meta:
        try:
            meta = spool.read_meta(dest) or {}
        except Exception:
            meta = {}
    current_qid = spool.dest_name(dest)
    from backend.stores import assessments as store
    tid = str(meta.get("gmail_thread_id") or "").strip()
    if not tid:
        tid = str((store.get_copy(current_qid) or {}).get("gmail_thread_id") or "").strip()
    if not tid:
        return n
    for r in store.copies_in_thread(
        tid, mailbox=str(meta.get("mailbox") or "").strip() or None,
    ):
        qid = str(r.get("queue_id") or "").strip()
        if not qid or qid == current_qid:
            continue
        other_dest = spool.payload(qid)
        try:
            other = spool.read_meta(other_dest) or {}
        except Exception:
            other = {}
        if not isinstance(other, dict):
            other = {}
        other.update(updates)
        try:
            spool.write_meta(other_dest, other)
            n += 1
        except Exception:
            continue
    return n

