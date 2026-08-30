"""Analyst feedback store and portable good-mail indicator pack.

Analysts mark messages as not-malicious. Each label extracts sender / domain /
URL-host indicators into SQLite (`data/feedback.sqlite3`) and a JSON pack
(`backend/policy/runtime/good_indicators.json`) that can be copied into another
environment and imported there.

The pack is the redeployable artifact — it has no message bodies. The SQLite
file is local training history (who labelled what).
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from backend.paths import DATA_DIR, RULES_RUNTIME
from backend.models import Disposition

_DB_PATH = DATA_DIR / "feedback.sqlite3"
_PACK_PATH = RULES_RUNTIME / "good_indicators.json"
_lock = threading.Lock()

PACK_VERSION = 1
ADDRESS_MIN_CONFIRMATIONS = 1
DOMAIN_MIN_CONFIRMATIONS = 2

_HARD_INTEL_PREFIXES = (
    "threat_intel_hit",
    "intel_hash",
    "intel_url",
    "banned_attachment",
    "oletools_",
    "sandbox_clam",
    "html_attachment_credential_form",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS labels (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    queue_id TEXT NOT NULL UNIQUE,
    mailbox TEXT,
    gmail_message_id TEXT,
    from_addr TEXT,
    from_domain TEXT,
    subject TEXT,
    verdict TEXT,
    score REAL,
    label TEXT NOT NULL,
    actor TEXT,
    note TEXT
);
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY,
    label_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(label_id) REFERENCES labels(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ind_kind_value ON indicators(kind, value);
"""


def _db(path: Optional[Path] = None):
    from backend.db import connect as db_connect
    dest = Path(path) if path else _DB_PATH
    return db_connect(dest, schema=_SCHEMA)


def pack_path() -> Path:
    return _PACK_PATH


def empty_pack() -> dict:
    return {"version": PACK_VERSION, "updated_at": None, "indicators": []}


def load_pack(path: Optional[Path] = None) -> dict:
    dest = Path(path) if path else _PACK_PATH
    if not dest.is_file():
        return empty_pack()
    try:
        data = json.loads(dest.read_text(encoding="utf-8"))
    except Exception:
        return empty_pack()
    if not isinstance(data, dict):
        return empty_pack()
    data.setdefault("version", PACK_VERSION)
    data.setdefault("indicators", [])
    return data


def write_pack(pack: dict, path: Optional[Path] = None) -> Path:
    dest = Path(path) if path else _PACK_PATH
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": int(pack.get("version") or PACK_VERSION),
        "updated_at": pack.get("updated_at") or datetime.now(timezone.utc).isoformat(),
        "indicators": list(pack.get("indicators") or []),
    }
    dest.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return dest


def _host_from_url(url: str) -> str:
    try:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:
        return ""
    if host.startswith("www."):
        host = host[4:]
    return host


def extract_indicators(meta: dict, raw: Optional[bytes] = None) -> list[tuple[str, str]]:
    """Return (kind, value) pairs from a labelled message. No body text."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []

    def add(kind: str, value: str) -> None:
        v = (value or "").strip().lower()
        if not v or (kind, v) in seen:
            return
        seen.add((kind, v))
        out.append((kind, v))

    from_header = (meta.get("from") or "") if isinstance(meta, dict) else ""
    from_addr = ""
    if raw:
        try:
            from backend.parsed_email import ParsedEmail
            pe = ParsedEmail(raw)
            from_addr = (pe.from_addr or "").lower().strip()
            for url in pe.urls() or []:
                add("url_host", _host_from_url(url))
        except Exception:
            from_addr = ""
    if not from_addr and "@" in from_header:
        from_addr = from_header.rsplit("<", 1)[-1].rstrip(">").strip().lower()
        if "@" not in from_addr:
            from_addr = ""
    if from_addr and "@" in from_addr:
        add("sender_address", from_addr)
        add("sender_domain", from_addr.split("@", 1)[-1])

    iocs = meta.get("iocs") if isinstance(meta.get("iocs"), dict) else {}
    for url in iocs.get("urls") or []:
        add("url_host", _host_from_url(str(url)))
    for domain in iocs.get("domains") or []:
        add("url_host", str(domain))
    return out


def record_benign(
    *,
    queue_id: str,
    meta: dict,
    raw: Optional[bytes] = None,
    actor: str = "",
    note: str = "",
    db_path: Optional[Path] = None,
    pack_file: Optional[Path] = None,
) -> dict:
    """Store a benign label, extract indicators, rebuild the portable pack."""
    indicators = extract_indicators(meta, raw)
    from_addr = next((v for k, v in indicators if k == "sender_address"), "")
    from_domain = next((v for k, v in indicators if k == "sender_domain"), "")
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _db(db_path)
        try:
            conn.execute("DELETE FROM labels WHERE queue_id = ?", (queue_id,))
            cur = conn.execute(
                """INSERT INTO labels
                   (ts, queue_id, mailbox, gmail_message_id, from_addr, from_domain,
                    subject, verdict, score, label, actor, note)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'benign', ?, ?)""",
                (
                    ts, queue_id,
                    meta.get("mailbox") or "",
                    meta.get("gmail_message_id") or "",
                    from_addr, from_domain,
                    (meta.get("subject") or "")[:500],
                    meta.get("verdict") or "",
                    float(meta.get("score") or 0.0),
                    actor or "",
                    (note or "")[:500],
                ),
            )
            label_id = int(cur.lastrowid)
            conn.executemany(
                "INSERT INTO indicators (label_id, kind, value, weight) VALUES (?, ?, ?, 1)",
                [(label_id, k, v) for k, v in indicators],
            )
            conn.commit()
        finally:
            conn.close()
        pack = rebuild_pack(db_path=db_path, pack_file=pack_file)
    return {
        "queue_id": queue_id,
        "label": "benign",
        "ts": ts,
        "actor": actor,
        "indicators": [{"kind": k, "value": v} for k, v in indicators],
        "pack": pack,
    }


def remove_label(
    queue_id: str,
    *,
    db_path: Optional[Path] = None,
    pack_file: Optional[Path] = None,
) -> bool:
    with _lock:
        conn = _db(db_path)
        try:
            cur = conn.execute("DELETE FROM labels WHERE queue_id = ?", (queue_id,))
            conn.commit()
            deleted = cur.rowcount > 0
        finally:
            conn.close()
        rebuild_pack(db_path=db_path, pack_file=pack_file)
    return deleted


def rebuild_pack(
    *,
    db_path: Optional[Path] = None,
    pack_file: Optional[Path] = None,
) -> dict:
    conn = _db(db_path)
    try:
        rows = conn.execute(
            """SELECT i.kind, i.value, SUM(i.weight) AS confirmations,
                      MAX(l.ts) AS last_seen
               FROM indicators i
               JOIN labels l ON l.id = i.label_id
               WHERE l.label = 'benign'
               GROUP BY i.kind, i.value
               ORDER BY confirmations DESC, i.kind, i.value"""
        ).fetchall()
    finally:
        conn.close()
    pack = {
        "version": PACK_VERSION,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "indicators": [
            {
                "kind": r["kind"],
                "value": r["value"],
                "confirmations": int(r["confirmations"]),
                "last_seen": r["last_seen"],
            }
            for r in rows
        ],
    }
    write_pack(pack, pack_file)
    return pack


def import_pack(
    pack: dict,
    *,
    actor: str = "import",
    db_path: Optional[Path] = None,
    pack_file: Optional[Path] = None,
) -> dict:
    """Merge a portable pack into this environment's training store."""
    incoming = pack.get("indicators") if isinstance(pack, dict) else None
    if not isinstance(incoming, list):
        raise ValueError("pack.indicators must be a list")
    ts = datetime.now(timezone.utc).isoformat()
    queue_id = "import-" + ts.replace(":", "").replace(".", "")[:24]
    with _lock:
        conn = _db(db_path)
        try:
            cur = conn.execute(
                """INSERT INTO labels
                   (ts, queue_id, mailbox, gmail_message_id, from_addr, from_domain,
                    subject, verdict, score, label, actor, note)
                   VALUES (?, ?, '', '', '', '', 'imported pack', '', 0, 'benign', ?, ?)""",
                (ts, queue_id, actor, "imported good-mail indicator pack"),
            )
            label_id = int(cur.lastrowid)
            rows = []
            for item in incoming:
                if not isinstance(item, dict):
                    continue
                kind = str(item.get("kind") or "").strip()
                value = str(item.get("value") or "").strip().lower()
                if kind not in ("sender_address", "sender_domain", "url_host") or not value:
                    continue
                n = max(1, min(int(item.get("confirmations") or 1), 50))
                rows.append((label_id, kind, value, n))
            conn.executemany(
                "INSERT INTO indicators (label_id, kind, value, weight) VALUES (?, ?, ?, ?)",
                rows,
            )
            conn.commit()
        finally:
            conn.close()
        return rebuild_pack(db_path=db_path, pack_file=pack_file)


def _is_freemail(domain: str) -> bool:
    try:
        from backend.stores.lists import freemail_domains
        d = (domain or "").lower().rstrip(".")
        return d in freemail_domains()
    except Exception:
        return False


def match_pe(pe, pack: Optional[dict] = None) -> dict:
    addr = (getattr(pe, "from_addr", "") or "").lower().strip()
    domain = addr.split("@", 1)[-1] if "@" in addr else ""
    hosts = []
    try:
        for url in pe.urls() or []:
            h = _host_from_url(url)
            if h:
                hosts.append(h)
    except Exception:
        pass
    return match_sender(addr, domain, url_hosts=hosts, pack=pack)


def match_sender(
    addr: str,
    domain: str,
    url_hosts: Optional[list] = None,
    pack: Optional[dict] = None,
) -> dict:
    data = pack if pack is not None else load_pack()
    by: dict[str, dict[str, int]] = {"sender_address": {}, "sender_domain": {}, "url_host": {}}
    for item in data.get("indicators") or []:
        kind = item.get("kind")
        value = (item.get("value") or "").lower()
        if kind in by and value:
            by[kind][value] = int(item.get("confirmations") or 0)
    addr = (addr or "").lower().strip()
    domain = (domain or "").lower().strip()
    benign_sender = by["sender_address"].get(addr, 0) >= ADDRESS_MIN_CONFIRMATIONS
    benign_domain = (
        (not _is_freemail(domain))
        and by["sender_domain"].get(domain, 0) >= DOMAIN_MIN_CONFIRMATIONS
    )
    known_hosts = []
    for h in url_hosts or []:
        if by["url_host"].get(h, 0) >= 1:
            known_hosts.append(h)
    return {
        "benign_sender": benign_sender,
        "benign_domain": benign_domain,
        "benign_url_hosts": known_hosts[:8],
        "sender_confirmations": by["sender_address"].get(addr, 0),
        "domain_confirmations": by["sender_domain"].get(domain, 0),
    }


def _has_hard_intel(result) -> bool:
    for flag in getattr(result, "reasons", None) or []:
        f = str(flag)
        if any(f == p or f.startswith(p) for p in _HARD_INTEL_PREFIXES):
            return True
    return False


def apply_learned_override(result, pe, match: Optional[dict] = None) -> None:
    """After scoring: known-good sender/domain delivers, score stays on the record.

    Blocklist and malware/intel hits still win. AI does not write the verdict.
    """
    if getattr(result, "hard_override", None) in ("blocklist", "allowlist"):
        return
    if _has_hard_intel(result):
        return
    info = match if match is not None else match_pe(pe)
    if info.get("benign_sender"):
        result.hard_override = "learned_benign"
        result.disposition = Disposition.DELIVER
        n = info.get("sender_confirmations") or 1
        result.disposition_reason = (
            f"Sender address confirmed benign by analyst training ({n} label(s))"
        )
        return
    if info.get("benign_domain"):
        result.hard_override = "learned_benign"
        result.disposition = Disposition.DELIVER
        n = info.get("domain_confirmations") or 1
        result.disposition_reason = (
            f"Sender domain confirmed benign by analyst training ({n} label(s))"
        )
