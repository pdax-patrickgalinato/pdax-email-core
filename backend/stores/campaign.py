"""Phishing-campaign pattern detection.

A *campaign* here is a **scam-based + source-based** group in the sense of
Saka, Vaniea & Kökciyan, *SoK: Grouping Spam and Phishing Email Threats*
(IEEE Access 2025): emails that share a landing page, payload, or template
even when From addresses differ. Microsoft Defender-style clustering uses
several morphing-resistant queries (URL, file hash, subject, content) rather
than a single hash of the whole message.

The background worker scans spool `meta.json` files, builds inverted indexes
over those pivots, and writes connected components to SQLite. After clustering,
a campaign-insight pass reads each member's existing per-email AI assessment
and writes a narrative (lure, tactics, targeting, shared IOCs). Findings are
**reference only** — they do not change the composite score.

Fail-soft: storage errors degrade to empty results.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import threading
import time
from email.utils import getaddresses
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from backend.domainutils import registrable_domain
from backend.stores.mail_fanout import strip_subject
from backend.paths import DATA_DIR

_log = logging.getLogger(__name__)

_DEFAULT_DB_PATH = DATA_DIR / "campaigns.sqlite3"
_BUCKETS = ("gmail", "quarantine", "released")
_WINDOW = 14 * 86400
_MAX_MEMBERS = 40
_MAX_LIST = 12
_FLAGGED = frozenset({"SUSPICIOUS", "MALICIOUS"})
_STRONG = frozenset({"hash", "url_path", "content"})
_TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_name", "fbclid", "gclid", "gclsrc", "dclid", "msclkid",
    "twclid", "igshid", "li_fat_id", "mc_eid", "mc_cid", "mc_tc", "_ga",
    "_gl", "ref", "ref_src", "ncid", "icid",
})
_GENERIC_SUBJECTS = frozenset({
    "invoice", "payment", "statement", "hello", "hi", "request", "document",
    "scan", "update", "reminder", "notification", "fyi", "thanks",
    "thank you", "follow up", "followup", "fw", "fwd",
})
_POPULAR_HOSTS = frozenset({
    "google.com", "googlemail.com", "googleapis.com", "gstatic.com",
    "googleusercontent.com", "youtube.com", "youtu.be",
    "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
    "live.com", "outlook.com", "linkedin.com", "apple.com", "icloud.com",
    "icloud-content.com", "amazon.com", "amazonaws.com", "facebook.com",
    "fb.com", "instagram.com", "twitter.com", "x.com", "github.com",
    "githubusercontent.com", "gravatar.com", "cloudflare.com", "akamai.net",
    "akamaiedge.net", "cloudfront.net", "zoom.us", "slack.com",
    "dropbox.com", "box.com", "docusign.com", "docusign.net",
    "salesforce.com", "force.com", "pdax.ph",
})

_SUBJ_EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
_SUBJ_NUM = re.compile(r"\d{3,}")
_SUBJ_PUNCT = re.compile(r"[^\w\s]+", re.UNICODE)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS campaign_obs (
    dest TEXT NOT NULL PRIMARY KEY,
    message_id TEXT DEFAULT '',
    sender TEXT DEFAULT '',
    mailbox TEXT DEFAULT '',
    subject TEXT DEFAULT '',
    verdict TEXT DEFAULT '',
    threat_class TEXT DEFAULT '',
    seen_at REAL NOT NULL,
    keys_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cobs_seen ON campaign_obs(seen_at);

CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT NOT NULL PRIMARY KEY,
    kind TEXT NOT NULL,
    pattern TEXT NOT NULL,
    members INTEGER NOT NULL,
    senders INTEGER NOT NULL,
    mailboxes INTEGER NOT NULL,
    flagged INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    keys_json TEXT NOT NULL,
    senders_json TEXT NOT NULL,
    mailboxes_json TEXT NOT NULL,
    dests_json TEXT NOT NULL,
    subjects_json TEXT NOT NULL,
    updated_at REAL NOT NULL,
    ai_title TEXT NOT NULL DEFAULT '',
    ai_summary TEXT NOT NULL DEFAULT '',
    attack_class TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT '',
    insight_json TEXT NOT NULL DEFAULT '{}',
    facts_hash TEXT NOT NULL DEFAULT '',
    ai_provider TEXT NOT NULL DEFAULT '',
    ai_model TEXT NOT NULL DEFAULT '',
    ai_assessed_at REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cam_last ON campaigns(last_seen);
"""

_pg_schema_lock = threading.Lock()
_pg_schema_ready = False
_ai_cols_ready = False
_AI_COLUMNS = (
    ("ai_title", "TEXT NOT NULL DEFAULT ''"),
    ("ai_summary", "TEXT NOT NULL DEFAULT ''"),
    ("attack_class", "TEXT NOT NULL DEFAULT ''"),
    ("confidence", "TEXT NOT NULL DEFAULT ''"),
    ("insight_json", "TEXT NOT NULL DEFAULT '{}'"),
    ("facts_hash", "TEXT NOT NULL DEFAULT ''"),
    ("ai_provider", "TEXT NOT NULL DEFAULT ''"),
    ("ai_model", "TEXT NOT NULL DEFAULT ''"),
    ("ai_assessed_at", "REAL NOT NULL DEFAULT 0"),
)
_CAM_SELECT = (
    "id, kind, pattern, members, senders, mailboxes, flagged, "
    "first_seen, last_seen, keys_json, senders_json, mailboxes_json, "
    "dests_json, subjects_json, ai_title, ai_summary, attack_class, "
    "confidence, insight_json, facts_hash, ai_provider, ai_model, ai_assessed_at"
)


def _popular_hosts() -> set[str]:
    hosts = set(_POPULAR_HOSTS)
    try:
        from workers.pipeline.urls import SHORTENER_DOMAINS
        hosts.update(SHORTENER_DOMAINS)
    except Exception:
        hosts.update({"bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl"})
    try:
        from backend.stores.lists import trusted_platforms
        for p in trusted_platforms() or []:
            hosts.update(d.lower().rstrip(".") for d in (p.get("from_domains") or []))
            hosts.update(
                registrable_domain(h) for h in (p.get("link_hosts") or []) if h
            )
    except Exception:
        pass
    return {h for h in hosts if h}


def _sender(meta: dict) -> str:
    raw = str(meta.get("from") or "")
    addrs = [a.lower() for _, a in getaddresses([raw]) if a]
    return addrs[0] if addrs else raw.strip().lower()


def _parse_ts(meta: dict, dest) -> float:
    raw = str(meta.get("ts") or "")
    if raw:
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
    if isinstance(dest, Path):
        try:
            return dest.stat().st_mtime
        except OSError:
            pass
    return time.time()


def subject_template(subject: str) -> str:
    """Normalize a subject into a morphing-resistant template.

    Strips Re/Fw, recipient emails, long digit runs (invoice numbers, OTPs),
    and punctuation so "Re: Invoice 4419 for Jane" and "Invoice 8821 for Bob"
    can still share a key when the rest of the lure is the same.
    """
    s = strip_subject(subject or "")
    s = s.lower()
    s = _SUBJ_EMAIL.sub("EMAIL", s)
    s = _SUBJ_NUM.sub("#", s)
    s = _SUBJ_PUNCT.sub(" ", s)
    s = " ".join(s.split())
    return s[:80]


def normalize_url(url: str) -> tuple[str, str]:
    """Return (registrable_host, host+path) with tracking query stripped."""
    raw = (url or "").strip()
    if not raw:
        return "", ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
    except ValueError:
        return "", ""
    host = (parsed.hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return "", ""
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    q = [
        (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if k.lower() not in _TRACKING_PARAMS
    ]
    query = urlencode(q)
    path_key = urlunparse(("", host, path, "", query, "")).lstrip("/")
    return registrable_domain(host) or host, path_key[:240]


def content_fingerprint(subject: str, body: str) -> str:
    excerpt = " ".join((body or "").split())[:240].lower()
    if len(excerpt) < 40:
        return ""
    tmpl = subject_template(subject)
    blob = f"{tmpl}|{excerpt}".encode("utf-8", "ignore")
    return hashlib.sha1(blob).hexdigest()[:16]


def _message_id_key(meta: dict) -> str:
    raw = str(meta.get("message_id") or "").strip().lower()
    raw = raw.strip("<>")
    return raw[:180]


def pivot_keys(meta: dict, popular: set[str] | None = None) -> list[str]:
    """Morphing-resistant pivots for one stored copy."""
    popular = popular if popular is not None else _popular_hosts()
    keys: list[str] = []
    iocs = meta.get("iocs") if isinstance(meta.get("iocs"), dict) else {}
    for url in iocs.get("urls") or []:
        host, path = normalize_url(str(url))
        if path and "/" in path:
            keys.append("url_path:" + path)
        if host and host not in popular:
            keys.append("url_host:" + host)
    for h in iocs.get("hashes_sha256") or []:
        digest = str(h or "").strip().lower()
        if len(digest) >= 16:
            keys.append("hash:" + digest)
    tmpl = subject_template(str(meta.get("subject") or ""))
    if tmpl and len(tmpl) >= 12 and tmpl not in _GENERIC_SUBJECTS:
        keys.append("subj:" + tmpl)
    fp = content_fingerprint(
        str(meta.get("subject") or ""),
        str(meta.get("primary_content") or ""),
    )
    if fp:
        keys.append("content:" + fp)
    mid = _message_id_key(meta)
    if mid:
        keys.append("msgid:" + mid)
    # Preserve order, drop dupes.
    return list(dict.fromkeys(keys))


def _kind(key: str) -> str:
    return (key.split(":", 1)[0] if key else "")


def _qualifies(kind: str, rows: list[dict]) -> bool:
    if len(rows) < 2:
        return False
    senders = {r["sender"] for r in rows if r.get("sender")}
    mailboxes = {r["mailbox"] for r in rows if r.get("mailbox")}
    flagged = sum(1 for r in rows if (r.get("verdict") or "").upper() in _FLAGGED)
    n = len(rows)
    if kind in _STRONG:
        return len(senders) >= 2 or len(mailboxes) >= 3 or flagged >= 1
    if kind == "url_host":
        return len(senders) >= 2 and (flagged >= 1 or n >= 3)
    if kind == "subj":
        return len(senders) >= 2 and flagged >= 1
    if kind == "msgid":
        return len(mailboxes) >= 2
    return False


class _UF:
    def __init__(self):
        self.p: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.p.setdefault(x, x)
        if self.p[x] != x:
            self.p[x] = self.find(self.p[x])
        return self.p[x]

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def _campaign_id(keys: Iterable[str]) -> str:
    blob = "|".join(sorted({k for k in keys if k}))
    return "cam-" + hashlib.sha1(blob.encode("utf-8")).hexdigest()[:12]


def _rule_for(kind: str) -> str:
    return {
        "hash": "campaign_hash",
        "url_path": "campaign_url_path",
        "url_host": "campaign_url_host",
        "content": "campaign_content",
        "subj": "campaign_subject",
        "msgid": "campaign_fanout",
        "mixed": "campaign_mixed",
    }.get(kind, "campaign_mixed")


class CampaignStore:
    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH

    def _connect(self):
        from backend.db import connect as db_connect, is_postgres
        if is_postgres():
            self._ensure_pg_schema()
            conn = db_connect(self.db_path)
            self._ensure_ai_columns(conn)
            return conn
        conn = db_connect(self.db_path, schema=_SCHEMA)
        self._ensure_ai_columns(conn)
        return conn

    def _ensure_ai_columns(self, conn) -> None:
        global _ai_cols_ready
        if _ai_cols_ready:
            return
        try:
            conn.execute("SELECT ai_summary FROM campaigns LIMIT 0")
            _ai_cols_ready = True
            return
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
        from backend.db import is_postgres
        for name, spec in _AI_COLUMNS:
            try:
                sql = f"ALTER TABLE campaigns ADD COLUMN {name} {spec}"
                if is_postgres():
                    sql = (
                        f"ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS {name} "
                        + spec.replace("REAL", "DOUBLE PRECISION")
                    )
                conn.execute(sql)
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
        _ai_cols_ready = True

    def _ensure_pg_schema(self) -> None:
        """Apply CREATE TABLE/INDEX once per process.

        Passing the full schema on every ingest connect deadlocks Aurora when
        several campaign consumers INSERT into campaign_obs at the same time.
        """
        global _pg_schema_ready
        if _pg_schema_ready:
            return
        from backend.db import connect as db_connect
        from backend.stores import assessments as locks
        with _pg_schema_lock:
            if _pg_schema_ready:
                return
            holder = f"{socket.gethostname()}:{os.getpid()}:campaign"
            got = False
            try:
                got = locks.try_lock("campaign_schema", holder, ttl_seconds=180)
                if got:
                    db_connect(self.db_path, schema=_SCHEMA)
            except Exception:
                _log.exception("campaign schema apply failed")
            finally:
                if got:
                    try:
                        locks.release_lock("campaign_schema", holder)
                    except Exception:
                        pass
            _pg_schema_ready = True

    def upsert_obs(self, row: dict) -> None:
        dest = (row.get("dest") or "").strip()
        if not dest:
            return
        try:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO campaign_obs "
                    "(dest, message_id, sender, mailbox, subject, verdict, "
                    "threat_class, seen_at, keys_json) "
                    "VALUES (?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(dest) DO UPDATE SET "
                    "message_id=excluded.message_id, sender=excluded.sender, "
                    "mailbox=excluded.mailbox, subject=excluded.subject, "
                    "verdict=excluded.verdict, threat_class=excluded.threat_class, "
                    "seen_at=excluded.seen_at, keys_json=excluded.keys_json",
                    (
                        dest,
                        row.get("message_id") or "",
                        row.get("sender") or "",
                        row.get("mailbox") or "",
                        (row.get("subject") or "")[:240],
                        (row.get("verdict") or "").upper(),
                        row.get("threat_class") or "",
                        float(row.get("seen_at") or time.time()),
                        json.dumps(list(row.get("keys") or [])),
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            _log.debug("campaign upsert failed", exc_info=True)

    def _load_obs(self, now: float | None = None) -> list[dict]:
        cutoff = (now if now is not None else time.time()) - _WINDOW
        try:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT dest, message_id, sender, mailbox, subject, verdict, "
                    "threat_class, seen_at, keys_json FROM campaign_obs "
                    "WHERE seen_at >= ?",
                    (cutoff,),
                ).fetchall()
            finally:
                conn.close()
        except Exception:
            return []
        out = []
        for r in rows:
            try:
                keys = json.loads(r["keys_json"] or "[]")
            except (TypeError, ValueError):
                keys = []
            if not isinstance(keys, list):
                keys = []
            out.append({
                "dest": r["dest"],
                "message_id": r["message_id"] or "",
                "sender": r["sender"] or "",
                "mailbox": r["mailbox"] or "",
                "subject": r["subject"] or "",
                "verdict": r["verdict"] or "",
                "threat_class": r["threat_class"] or "",
                "seen_at": float(r["seen_at"] or 0),
                "keys": [str(k) for k in keys if k],
            })
        return out

    def recompute(self, now: float | None = None) -> list[dict]:
        """Rebuild campaign rows from observations in the rolling window."""
        obs = self._load_obs(now)
        by_dest = {r["dest"]: r for r in obs}
        index: dict[str, list[dict]] = {}
        for row in obs:
            for key in row["keys"]:
                index.setdefault(key, []).append(row)

        qualified: dict[str, list[dict]] = {}
        for key, rows in index.items():
            kind = _kind(key)
            # Unique dests only (a dest can theoretically repeat).
            uniq: dict[str, dict] = {}
            for r in rows:
                uniq[r["dest"]] = r
            grouped = list(uniq.values())
            if _qualifies(kind, grouped):
                qualified[key] = grouped

        uf = _UF()
        for key, rows in qualified.items():
            if _kind(key) not in _STRONG:
                continue
            dests = [r["dest"] for r in rows]
            for a, b in zip(dests, dests[1:]):
                uf.union(a, b)

        components: dict[str, set[str]] = {}
        for key, rows in qualified.items():
            if _kind(key) not in _STRONG:
                continue
            for r in rows:
                components.setdefault(uf.find(r["dest"]), set()).add(r["dest"])

        campaigns: list[dict] = []
        covered: set[str] = set()

        def _build(dests: set[str], extra_keys: Iterable[str]) -> dict | None:
            members = [by_dest[d] for d in dests if d in by_dest]
            if len(members) < 2:
                return None
            keys = set(extra_keys)
            for m in members:
                keys.update(m["keys"])
            # Keep only keys that actually qualified or are strong among members.
            kept = [k for k in sorted(keys) if k in qualified or _kind(k) in _STRONG]
            if not kept:
                kept = list(extra_keys)
            kinds = {_kind(k) for k in kept if _kind(k)}
            kind = next(iter(kinds)) if len(kinds) == 1 else "mixed"
            senders = sorted({m["sender"] for m in members if m["sender"]})
            mailboxes = sorted({m["mailbox"] for m in members if m["mailbox"]})
            subjects = list(dict.fromkeys(m["subject"] for m in members if m["subject"]))
            dest_names = sorted(m["dest"] for m in members)
            flagged = sum(1 for m in members if m["verdict"] in _FLAGGED)
            pattern = next((k for k in kept if _kind(k) in _STRONG), kept[0] if kept else "")
            return {
                "id": _campaign_id(kept or dest_names),
                "kind": kind,
                "pattern": pattern,
                "members": len(members),
                "senders": len(senders),
                "mailboxes": len(mailboxes),
                "flagged": flagged,
                "first_seen": min(m["seen_at"] for m in members),
                "last_seen": max(m["seen_at"] for m in members),
                "keys": kept[:24],
                "sender_list": senders[:_MAX_LIST],
                "mailbox_list": mailboxes[:_MAX_LIST],
                "dests": dest_names[:_MAX_MEMBERS],
                "subjects": subjects[:8],
            }

        for dests in components.values():
            built = _build(dests, [])
            if built:
                campaigns.append(built)
                covered.update(dests)

        for key, rows in qualified.items():
            dests = {r["dest"] for r in rows}
            if dests <= covered:
                continue
            built = _build(dests, [key])
            if built:
                campaigns.append(built)
                covered.update(dests)

        # Stable: collapse duplicate ids (overlapping medium groups).
        by_id: dict[str, dict] = {}
        for cam in campaigns:
            prev = by_id.get(cam["id"])
            if prev is None or cam["members"] > prev["members"]:
                by_id[cam["id"]] = cam
        campaigns = sorted(
            by_id.values(),
            key=lambda c: (-int(c["flagged"]), -int(c["members"]), -float(c["last_seen"])),
        )
        previous = self._load_ai_by_id()
        for cam in campaigns:
            prev = previous.get(cam["id"]) or {}
            if prev.get("ai_summary"):
                cam.update({
                    k: prev[k] for k in (
                        "ai_title", "ai_summary", "attack_class", "confidence",
                        "insight", "facts_hash", "ai_provider", "ai_model",
                        "ai_assessed_at",
                    ) if k in prev
                })
        self._replace_campaigns(campaigns)
        try:
            from backend.stores.campaign_insight import fill_heuristic
            fill_heuristic(self, campaigns)
        except Exception:
            _log.debug("campaign heuristic fill failed", exc_info=True)
        return campaigns

    def _load_ai_by_id(self) -> dict[str, dict]:
        try:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT id, ai_title, ai_summary, attack_class, confidence, "
                    "insight_json, facts_hash, ai_provider, ai_model, ai_assessed_at "
                    "FROM campaigns"
                ).fetchall()
            finally:
                conn.close()
        except Exception:
            return {}
        out: dict[str, dict] = {}
        for r in rows:
            try:
                insight = json.loads(r["insight_json"] or "{}")
            except (TypeError, ValueError):
                insight = {}
            if not isinstance(insight, dict):
                insight = {}
            cid = str(r["id"] or "")
            if not cid:
                continue
            out[cid] = {
                "ai_title": r["ai_title"] or "",
                "ai_summary": r["ai_summary"] or "",
                "attack_class": r["attack_class"] or "",
                "confidence": r["confidence"] or "",
                "insight": insight,
                "facts_hash": r["facts_hash"] or "",
                "ai_provider": r["ai_provider"] or "",
                "ai_model": r["ai_model"] or "",
                "ai_assessed_at": float(r["ai_assessed_at"] or 0),
            }
        return out

    def _replace_campaigns(self, campaigns: list[dict]) -> None:
        now = time.time()
        try:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM campaigns")
                conn.executemany(
                    "INSERT INTO campaigns "
                    "(id, kind, pattern, members, senders, mailboxes, flagged, "
                    "first_seen, last_seen, keys_json, senders_json, mailboxes_json, "
                    "dests_json, subjects_json, updated_at, ai_title, ai_summary, "
                    "attack_class, confidence, insight_json, facts_hash, "
                    "ai_provider, ai_model, ai_assessed_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            c["id"], c["kind"], c["pattern"],
                            int(c["members"]), int(c["senders"]), int(c["mailboxes"]),
                            int(c["flagged"]), float(c["first_seen"]),
                            float(c["last_seen"]),
                            json.dumps(c.get("keys") or []),
                            json.dumps(c.get("sender_list") or []),
                            json.dumps(c.get("mailbox_list") or []),
                            json.dumps(c.get("dests") or []),
                            json.dumps(c.get("subjects") or []),
                            now,
                            c.get("ai_title") or "",
                            c.get("ai_summary") or "",
                            c.get("attack_class") or "",
                            c.get("confidence") or "",
                            json.dumps(c.get("insight") or {}),
                            c.get("facts_hash") or "",
                            c.get("ai_provider") or "",
                            c.get("ai_model") or "",
                            float(c.get("ai_assessed_at") or 0),
                        )
                        for c in campaigns
                    ],
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            _log.debug("campaign replace failed", exc_info=True)

    def put_insight(self, cam_id: str, payload: dict) -> None:
        cid = (cam_id or "").strip()
        if not cid or not payload:
            return
        insight = payload.get("insight")
        if not isinstance(insight, dict):
            insight = {}
        try:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE campaigns SET ai_title=?, ai_summary=?, attack_class=?, "
                    "confidence=?, insight_json=?, facts_hash=?, ai_provider=?, "
                    "ai_model=?, ai_assessed_at=?, updated_at=? WHERE id=?",
                    (
                        payload.get("ai_title") or "",
                        payload.get("ai_summary") or "",
                        payload.get("attack_class") or "",
                        payload.get("confidence") or "",
                        json.dumps(insight),
                        payload.get("facts_hash") or "",
                        payload.get("ai_provider") or "",
                        payload.get("ai_model") or "",
                        float(payload.get("ai_assessed_at") or time.time()),
                        time.time(),
                        cid,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            _log.debug("campaign insight write failed", exc_info=True)

    def obs_for_dests(self, dests: list[str]) -> list[dict]:
        wanted = [str(d or "").strip() for d in dests if str(d or "").strip()]
        if not wanted:
            return []
        wanted = wanted[:_MAX_MEMBERS]
        placeholders = ",".join("?" * len(wanted))
        try:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT dest, message_id, sender, mailbox, subject, verdict, "
                    "threat_class, seen_at, keys_json FROM campaign_obs "
                    f"WHERE dest IN ({placeholders})",
                    wanted,
                ).fetchall()
            finally:
                conn.close()
        except Exception:
            return []
        out = []
        for r in rows:
            try:
                keys = json.loads(r["keys_json"] or "[]")
            except (TypeError, ValueError):
                keys = []
            out.append({
                "dest": r["dest"],
                "message_id": r["message_id"] or "",
                "sender": r["sender"] or "",
                "mailbox": r["mailbox"] or "",
                "subject": r["subject"] or "",
                "verdict": r["verdict"] or "",
                "threat_class": r["threat_class"] or "",
                "seen_at": float(r["seen_at"] or 0),
                "keys": keys if isinstance(keys, list) else [],
            })
        return out

    def list_campaigns(self, limit: int = 50) -> list[dict]:
        try:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT " + _CAM_SELECT + " FROM campaigns "
                    "ORDER BY flagged DESC, members DESC, last_seen DESC "
                    "LIMIT ?",
                    (max(1, int(limit)),),
                ).fetchall()
            finally:
                conn.close()
        except Exception:
            return []
        out = []
        for r in rows:
            out.append(_row_to_campaign(r))
        return out

    def get_campaign(self, cam_id: str) -> dict | None:
        cid = (cam_id or "").strip()
        if not cid:
            return None
        try:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT " + _CAM_SELECT + " FROM campaigns WHERE id=?",
                    (cid,),
                ).fetchone()
            finally:
                conn.close()
        except Exception:
            return None
        return _row_to_campaign(row) if row else None

    def lookup(
        self,
        urls: Iterable[str] | None = None,
        hashes: Iterable[str] | None = None,
        subject: str = "",
        body: str = "",
        message_id: str = "",
    ) -> list[dict]:
        """Campaigns whose pivots match this email. Reference only."""
        keys: list[str] = []
        popular = _popular_hosts()
        for url in urls or []:
            host, path = normalize_url(str(url))
            if path and "/" in path:
                keys.append("url_path:" + path)
            if host and host not in popular:
                keys.append("url_host:" + host)
        for h in hashes or []:
            digest = str(h or "").strip().lower()
            if len(digest) >= 16:
                keys.append("hash:" + digest)
        tmpl = subject_template(subject)
        if tmpl and len(tmpl) >= 12 and tmpl not in _GENERIC_SUBJECTS:
            keys.append("subj:" + tmpl)
        fp = content_fingerprint(subject, body)
        if fp:
            keys.append("content:" + fp)
        mid = (message_id or "").strip().lower().strip("<>")
        if mid:
            keys.append("msgid:" + mid)
        if not keys:
            return []
        keyset = set(keys)
        hits = []
        for cam in self.list_campaigns(limit=80):
            cam_keys = set(cam.get("keys") or [])
            overlap = keyset & cam_keys
            if not overlap:
                continue
            kind = _kind(next(iter(sorted(overlap))))
            hits.append({
                "id": cam["id"],
                "kind": cam["kind"],
                "rule": _rule_for(kind if kind else cam["kind"]),
                "ioc_value": cam["id"],
                "pattern": cam.get("pattern") or "",
                "members": cam["members"],
                "senders": cam["senders"],
                "mailboxes": cam["mailboxes"],
                "flagged": cam["flagged"],
                "subjects": cam.get("subjects") or [],
                "overlap": sorted(overlap)[:8],
                "ai_title": cam.get("ai_title") or "",
                "ai_summary": (cam.get("ai_summary") or "")[:400],
                "attack_class": cam.get("attack_class") or "",
                "confidence": cam.get("confidence") or "",
            })
        return hits[:8]


def _row_to_campaign(r) -> dict:
    def _loads(raw):
        try:
            val = json.loads(raw or "[]")
        except (TypeError, ValueError):
            return []
        return val if isinstance(val, list) else []

    try:
        insight = json.loads(r["insight_json"] or "{}")
    except (TypeError, ValueError, KeyError, IndexError):
        insight = {}
    if not isinstance(insight, dict):
        insight = {}

    def _col(name, default=""):
        try:
            val = r[name]
        except (KeyError, IndexError):
            return default
        return default if val is None else val

    return {
        "id": r["id"],
        "kind": r["kind"],
        "pattern": r["pattern"],
        "members": int(r["members"] or 0),
        "senders": int(r["senders"] or 0),
        "mailboxes": int(r["mailboxes"] or 0),
        "flagged": int(r["flagged"] or 0),
        "first_seen": float(r["first_seen"] or 0),
        "last_seen": float(r["last_seen"] or 0),
        "keys": _loads(r["keys_json"]),
        "sender_list": _loads(r["senders_json"]),
        "mailbox_list": _loads(r["mailboxes_json"]),
        "dests": _loads(r["dests_json"]),
        "subjects": _loads(r["subjects_json"]),
        "ai_title": str(_col("ai_title") or ""),
        "ai_summary": str(_col("ai_summary") or ""),
        "attack_class": str(_col("attack_class") or ""),
        "confidence": str(_col("confidence") or ""),
        "insight": insight,
        "facts_hash": str(_col("facts_hash") or ""),
        "ai_provider": str(_col("ai_provider") or ""),
        "ai_model": str(_col("ai_model") or ""),
        "ai_assessed_at": float(_col("ai_assessed_at", 0) or 0),
    }


def obs_from_meta(dest, meta: dict, bucket: str = "", popular=None) -> dict | None:
    keys = pivot_keys(meta, popular=popular)
    if not keys:
        return None
    name = dest.name if isinstance(dest, Path) else str(
        dest.get("queue_id") if isinstance(dest, dict) else dest
    )
    dest_id = f"{bucket}/{name}" if bucket else name
    return {
        "dest": dest_id,
        "message_id": str(meta.get("message_id") or ""),
        "sender": _sender(meta),
        "mailbox": str(meta.get("mailbox") or "").strip().lower(),
        "subject": str(meta.get("subject") or ""),
        "verdict": str(meta.get("verdict") or "").upper(),
        "threat_class": str(meta.get("threat_class") or ""),
        "seen_at": _parse_ts(meta, dest),
        "keys": keys,
        "path": dest,
    }


def ingest_spool(store: CampaignStore, spool_root: Path, *, limit: int = 150) -> dict:
    """Insert/update observations from newest spool copies, then recluster."""
    popular = _popular_hosts()
    root = Path(spool_root)
    dests: list[tuple[str, Path]] = []
    for bucket in _BUCKETS:
        base = root / bucket
        if not base.is_dir():
            continue
        dests.extend((bucket, p) for p in base.iterdir() if p.is_dir())
    dests.sort(key=lambda item: item[1].stat().st_mtime, reverse=True)
    ingested = 0
    skipped = 0
    for bucket, dest in dests:
        if ingested >= max(1, int(limit)):
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
        if not isinstance(meta, dict):
            skipped += 1
            continue
        row = obs_from_meta(dest, meta, bucket=bucket, popular=popular)
        if row is None:
            skipped += 1
            continue
        store.upsert_obs(row)
        ingested += 1
    campaigns = store.recompute()
    stamped = stamp_spool(root, campaigns)
    return {
        "ingested": ingested,
        "skipped": skipped,
        "campaigns": len(campaigns),
        "flagged_campaigns": sum(1 for c in campaigns if c.get("flagged")),
        "members": sum(int(c.get("members") or 0) for c in campaigns),
        "stamped": stamped,
    }


def ingest_copy(store: CampaignStore, dest) -> dict:
    """Upsert one assessed copy. Does not recluster — the SQS worker does that
    on a timer so draining the follow-up queue is not O(all observations)."""
    from backend.stores import spool
    popular = _popular_hosts()
    meta = spool.read_meta(dest)
    if not meta:
        return {"ingested": 0, "skipped": 1, "from_queue": 1}
    bucket = "gmail"
    if isinstance(dest, Path) and dest.parent.name in _BUCKETS:
        bucket = dest.parent.name
    elif isinstance(dest, dict):
        bucket = str(dest.get("bucket") or "gmail")
    row = obs_from_meta(dest, meta, bucket=bucket, popular=popular)
    if row is None:
        return {"ingested": 0, "skipped": 1, "from_queue": 1}
    store.upsert_obs(row)
    return {"ingested": 1, "skipped": 0, "from_queue": 1}


def ingest_dests(store: CampaignStore, dests: list, spool_root: Path) -> dict:
    """Upsert the given copies, then recluster. Used when LLM assessments land."""
    ingested = 0
    skipped = 0
    for dest in dests:
        stats = ingest_copy(store, dest)
        ingested += int(stats.get("ingested") or 0)
        skipped += int(stats.get("skipped") or 0)
    if not ingested:
        return {
            "ingested": 0,
            "skipped": skipped,
            "campaigns": 0,
            "flagged_campaigns": 0,
            "members": 0,
            "stamped": 0,
            "from_queue": 0,
        }
    campaigns = store.recompute()
    stamped = stamp_spool(Path(spool_root), campaigns)
    return {
        "ingested": ingested,
        "skipped": skipped,
        "campaigns": len(campaigns),
        "flagged_campaigns": sum(1 for c in campaigns if c.get("flagged")),
        "members": sum(int(c.get("members") or 0) for c in campaigns),
        "stamped": stamped,
        "from_queue": ingested,
    }


def stamp_spool(spool_root: Path, campaigns: list[dict]) -> int:
    """Write compact campaign membership onto matching meta.json files."""
    from backend.stores import spool as spoolmod
    if spoolmod.use_s3():
        return 0
    by_dest: dict[str, list[dict]] = {}
    for cam in campaigns:
        summary = {
            "id": cam["id"],
            "kind": cam["kind"],
            "members": cam["members"],
            "senders": cam["senders"],
            "mailboxes": cam["mailboxes"],
            "flagged": cam["flagged"],
            "pattern": cam.get("pattern") or "",
            "ai_title": cam.get("ai_title") or "",
            "ai_summary": (cam.get("ai_summary") or "")[:280],
            "attack_class": cam.get("attack_class") or "",
        }
        for dest_id in cam.get("dests") or []:
            by_dest.setdefault(dest_id, []).append(summary)
    stamped = 0
    root = Path(spool_root)
    for dest_id, cams in by_dest.items():
        parts = dest_id.split("/", 1)
        path = root.joinpath(*parts) / "meta.json" if len(parts) == 2 else root / dest_id / "meta.json"
        if not path.is_file():
            continue
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(meta, dict):
            continue
        if meta.get("campaigns") == cams:
            continue
        meta["campaigns"] = cams
        try:
            path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            stamped += 1
        except OSError:
            continue
    return stamped


def lookup_for_email(
    urls=None, hashes=None, subject: str = "", body: str = "",
    message_id: str = "", store: CampaignStore | None = None,
) -> list[dict]:
    try:
        cs = store or get_default_store()
        return cs.lookup(
            urls=urls, hashes=hashes, subject=subject, body=body,
            message_id=message_id,
        )
    except Exception:
        return []


def get_default_store() -> CampaignStore:
    return CampaignStore()
