"""Behavioral correlation store — detects attacker campaign patterns across
email traffic over a 6-month rolling window.

Three detection rules:
  1. IP-Sender drift (SUSPICIOUS): the same sender address comes from multiple
     different originating IPs, OR a single originating IP is used by ≥5
     different sender addresses (shared attack platform).
  2. IP-Shortener abuse (SUSPICIOUS): an originating IP sends emails containing
     link-shortener URLs, even across different sender addresses.
  3. Cross-sender shortener sharing (MALICIOUS): different sender addresses use
     the same link shortener domain — strongest indicator of a coordinated
     campaign.

Behavioral results are REFERENCE ONLY — they do not contribute to the SEGS
composite score or verdict. They surface in the Analyze tab's Behavioral
Correlation report panel for analyst review.

Observations are recorded for ALL emails (not only flagged ones) so behavioral
baselines reflect the full mail flow. Each record stores the final verdict so
the UI can filter to "prior flagged emails" specifically.

Fail-soft by design — all storage errors degrade to silent no-ops.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import sqlite3
import threading
import time
from collections import Counter
from pathlib import Path

from backend.paths import DATA_DIR
from backend.stores.sender_identity import (
    assessment_note as _assessment_note,
    assessment_of as _assessment_mix,
    sender_lane,
)

_log = logging.getLogger(__name__)

_DEFAULT_DB_PATH = DATA_DIR / "behavior_history.sqlite3"

_pg_schema_lock = threading.Lock()
_pg_schema_ready = False

# 6-month rolling window in seconds.
_WINDOW = 180 * 86400

# Minimum distinct-senders count before an IP is considered a shared platform.
_MANY_SENDERS_THRESHOLD = 5

# Max prior-email records returned per finding.
_MAX_EMAIL_RECORDS = 10

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sender_ip_log (
    sender TEXT NOT NULL,
    ip TEXT NOT NULL,
    verdict TEXT DEFAULT '',
    message_id TEXT,
    seen_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sil_sender ON sender_ip_log(sender);
CREATE INDEX IF NOT EXISTS idx_sil_ip ON sender_ip_log(ip);

CREATE TABLE IF NOT EXISTS ip_shortener_log (
    ip TEXT NOT NULL,
    sender TEXT NOT NULL,
    shortener_domain TEXT NOT NULL,
    verdict TEXT DEFAULT '',
    message_id TEXT,
    seen_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_isl_ip ON ip_shortener_log(ip);
CREATE INDEX IF NOT EXISTS idx_isl_shortener ON ip_shortener_log(shortener_domain);

CREATE TABLE IF NOT EXISTS sender_shortener_log (
    sender TEXT NOT NULL,
    shortener_domain TEXT NOT NULL,
    verdict TEXT DEFAULT '',
    message_id TEXT,
    seen_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ssl_sender ON sender_shortener_log(sender);
CREATE INDEX IF NOT EXISTS idx_ssl_shortener ON sender_shortener_log(shortener_domain);

CREATE TABLE IF NOT EXISTS sender_history (
    sender TEXT NOT NULL,
    seen_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sh_sender ON sender_history(sender);
CREATE INDEX IF NOT EXISTS idx_sh_seen_at ON sender_history(seen_at);

CREATE TABLE IF NOT EXISTS sender_profile_obs (
    sender TEXT NOT NULL,
    asn TEXT DEFAULT '',
    country TEXT DEFAULT '',
    network_role TEXT DEFAULT '',
    vpn INTEGER DEFAULT 0,
    spf TEXT DEFAULT '',
    dkim TEXT DEFAULT '',
    mailbox TEXT DEFAULT '',
    hour_utc INTEGER,
    verdict TEXT DEFAULT '',
    message_id TEXT,
    seen_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_spo_sender ON sender_profile_obs(sender);
CREATE INDEX IF NOT EXISTS idx_spo_seen_at ON sender_profile_obs(seen_at);
CREATE INDEX IF NOT EXISTS idx_spo_message_id ON sender_profile_obs(message_id);

CREATE TABLE IF NOT EXISTS recipient_request_log (
    mailbox TEXT NOT NULL,
    sender TEXT NOT NULL,
    request_class TEXT NOT NULL,
    message_id TEXT DEFAULT '',
    seen_at REAL NOT NULL,
    UNIQUE(mailbox, sender, request_class, message_id)
);
CREATE INDEX IF NOT EXISTS idx_rrl_mailbox_class ON recipient_request_log(mailbox, request_class);
CREATE INDEX IF NOT EXISTS idx_rrl_mailbox_sender ON recipient_request_log(mailbox, sender);

CREATE TABLE IF NOT EXISTS mail_volume_log (
    sender TEXT NOT NULL,
    mailbox TEXT NOT NULL,
    direction TEXT NOT NULL,
    message_id TEXT DEFAULT '',
    hour_utc INTEGER,
    seen_at REAL NOT NULL,
    UNIQUE(mailbox, message_id)
);
CREATE INDEX IF NOT EXISTS idx_mvl_sender ON mail_volume_log(sender);
CREATE INDEX IF NOT EXISTS idx_mvl_mailbox ON mail_volume_log(mailbox);
CREATE INDEX IF NOT EXISTS idx_mvl_seen_at ON mail_volume_log(seen_at);

CREATE TABLE IF NOT EXISTS correspondence_log (
    actor TEXT NOT NULL,
    peer TEXT NOT NULL,
    direction TEXT NOT NULL,
    request_class TEXT DEFAULT '',
    message_id TEXT DEFAULT '',
    seen_at REAL NOT NULL,
    UNIQUE(actor, peer, direction, message_id)
);
CREATE INDEX IF NOT EXISTS idx_cl_actor ON correspondence_log(actor, direction);
CREATE INDEX IF NOT EXISTS idx_cl_peer ON correspondence_log(peer);

CREATE TABLE IF NOT EXISTS sender_risk_assess (
    sender TEXT PRIMARY KEY,
    risk TEXT NOT NULL,
    score REAL DEFAULT 0,
    posture TEXT DEFAULT '',
    confidence TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    factors TEXT DEFAULT '[]',
    provider TEXT DEFAULT '',
    model_id TEXT DEFAULT '',
    facts_hash TEXT DEFAULT '',
    assessed_at REAL NOT NULL
);
"""

# CLEAN/LOW observations required before a high-confidence deviation can score.
PROFILE_MIN_N = 5
_LEARN_VERDICTS = frozenset({"CLEAN", "LOW"})
_ESP_ROLES = frozenset({"esp"})
_TRUSTED_ROLES = frozenset({"esp", "isp", "mobile_isp"})
_HOSTING_ROLES = frozenset({"cloud_hosting", "vpn_proxy"})

_FLAGGED = ("SUSPICIOUS", "MALICIOUS")
_VERDICTS = ("CLEAN", "LOW", "SUSPICIOUS", "MALICIOUS")
_ASSESS_RANK = {"MALICIOUS": 0, "SUSPICIOUS": 1, "CLEAN": 2}
_RISK_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def copy_direction(sender: str, mailbox: str, labels=None) -> str:
    """inbound = mailbox received From sender; outbound = this mailbox sent it."""
    sender_n = (sender or "").strip().lower()
    mailbox_n = (mailbox or "").strip().lower()
    labels_u = {str(x).upper() for x in (labels or [])}
    if "SENT" in labels_u or (sender_n and mailbox_n and sender_n == mailbox_n):
        return "outbound"
    return "inbound"


def copy_peers(pe, mailbox: str = "") -> list[str]:
    """To/Cc plus the scanned mailbox, excluding the From address."""
    from email.utils import getaddresses
    found: list[str] = []
    try:
        found.extend(list(pe.to_addrs or []))
    except Exception:
        pass
    try:
        found.extend(a.lower() for _, a in getaddresses([pe.header("Cc") or ""]) if a)
    except Exception:
        pass
    mb = (mailbox or "").strip().lower()
    if mb:
        found.append(mb)
    sender = ""
    try:
        sender = (pe.from_addr or "").strip().lower()
    except Exception:
        pass
    return list(dict.fromkeys(a for a in found if a and a != sender))


def copy_is_reply(pe) -> bool:
    try:
        return bool((pe.header("In-Reply-To") or "").strip() or (pe.header("References") or "").strip())
    except Exception:
        return False


class BehavioralCorrelationStore:
    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH

    def _connect(self):
        from backend.db import connect as db_connect, is_postgres
        if is_postgres():
            self._ensure_pg_schema()
            return db_connect(self.db_path)
        conn = db_connect(self.db_path, schema=_SCHEMA)
        if is_postgres():
            return conn
        for table in ("sender_ip_log", "ip_shortener_log", "sender_shortener_log"):
            try:
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN verdict TEXT DEFAULT ''")
                conn.commit()
            except Exception:
                pass
        for col, spec in (
            ("identity", "INTEGER DEFAULT 1"),
            ("identity_reason", "TEXT DEFAULT ''"),
        ):
            try:
                conn.execute(f"ALTER TABLE sender_ip_log ADD COLUMN {col} {spec}")
                conn.commit()
            except Exception:
                pass
        for col, spec in (
            ("request_class", "TEXT DEFAULT ''"),
            ("has_attachment", "INTEGER DEFAULT 0"),
            ("is_reply", "INTEGER DEFAULT 0"),
        ):
            try:
                conn.execute(f"ALTER TABLE mail_volume_log ADD COLUMN {col} {spec}")
                conn.commit()
            except Exception:
                pass
        return conn

    def _ensure_pg_schema(self) -> None:
        """Apply CREATE TABLE/INDEX once per process, and only one task in the cluster.

        Passing the full schema on every ingest connect deadlocks Aurora: CREATE
        INDEX IF NOT EXISTS takes a ShareLock while sibling tasks INSERT.
        """
        global _pg_schema_ready
        if _pg_schema_ready:
            return
        from backend.db import connect as db_connect
        from backend.stores import assessments as locks
        with _pg_schema_lock:
            if _pg_schema_ready:
                return
            holder = f"{socket.gethostname()}:{os.getpid()}:correlation"
            got = False
            try:
                got = locks.try_lock("correlation_schema", holder, ttl_seconds=180)
                if got:
                    db_connect(self.db_path, schema=_SCHEMA)
            except Exception:
                _log.exception("correlation schema apply failed")
            finally:
                if got:
                    try:
                        locks.release_lock("correlation_schema", holder)
                    except Exception:
                        pass
            _pg_schema_ready = True

    def record_observation(
        self,
        sender,            # str: pe.from_addr, normalized to lowercase
        originating_ips,   # list[str]: pe.originating_ips()
        shortener_domains, # list[str]: from url stage facts["shortener_domains"]
        message_id="",
        verdict="",        # final pipeline verdict (CLEAN/LOW/SUSPICIOUS/MALICIOUS)
        identity: int = 1,
        identity_reason: str = "",
    ):
        """Record sender-IP and shortener associations for ALL emails.

        identity=0 keeps the email in the mix / campaign tables but does not
        paint the From address (SENT replies, quoted lures, role tickets).
        """
        sender = (sender or "").lower().strip()
        originating_ips = [ip for ip in (originating_ips or []) if ip]
        shortener_domains = [d for d in (shortener_domains or []) if d]
        ident = 0 if int(identity or 0) == 0 else 1
        reason = (identity_reason or "").strip()[:80]
        if not sender and not originating_ips:
            return
        now = time.time()
        try:
            conn = self._connect()
            try:
                if sender and originating_ips:
                    conn.executemany(
                        "INSERT INTO sender_ip_log "
                        "(sender, ip, verdict, message_id, seen_at, identity, identity_reason) "
                        "VALUES (?,?,?,?,?,?,?)",
                        [(sender, ip, verdict, message_id, now, ident, reason)
                         for ip in originating_ips],
                    )
                if originating_ips and shortener_domains:
                    conn.executemany(
                        "INSERT INTO ip_shortener_log "
                        "(ip, sender, shortener_domain, verdict, message_id, seen_at) "
                        "VALUES (?,?,?,?,?,?)",
                        [
                            (ip, sender, domain, verdict, message_id, now)
                            for ip in originating_ips
                            for domain in shortener_domains
                        ],
                    )
                if sender and shortener_domains:
                    conn.executemany(
                        "INSERT INTO sender_shortener_log "
                        "(sender, shortener_domain, verdict, message_id, seen_at) "
                        "VALUES (?,?,?,?,?)",
                        [(sender, domain, verdict, message_id, now)
                         for domain in shortener_domains],
                    )
                if sender:
                    conn.execute(
                        "INSERT INTO sender_history(sender, seen_at) VALUES (?,?)",
                        (sender, now),
                    )
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            _log.warning("behavioral_store record_observation failed: %s", exc)

    def record_volume(
        self,
        sender: str,
        mailbox: str,
        message_id: str = "",
        *,
        direction: str = "",
        hour_utc=None,
        seen_at: float | None = None,
        labels=None,
        request_class: str = "",
        has_attachment: bool = False,
        is_reply: bool = False,
    ) -> None:
        """One row per scanned copy: who sent it, which mailbox saw it."""
        sender = (sender or "").strip().lower()
        mailbox = (mailbox or "").strip().lower()
        mid = (message_id or "").strip()
        if not sender or not mailbox or not mid:
            return
        now = time.time() if seen_at is None else float(seen_at)
        way = (direction or copy_direction(sender, mailbox, labels)).strip().lower()
        if way not in ("inbound", "outbound"):
            way = "inbound"
        hour = None
        if hour_utc is not None:
            try:
                hour = int(hour_utc)
                if hour < 0 or hour > 23:
                    hour = None
            except (TypeError, ValueError):
                hour = None
        cls = (request_class or "").strip()[:80]
        try:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO mail_volume_log "
                    "(sender, mailbox, direction, message_id, hour_utc, seen_at, "
                    "request_class, has_attachment, is_reply) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (sender, mailbox, way, mid, hour, now, cls,
                     1 if has_attachment else 0, 1 if is_reply else 0),
                )
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            _log.warning("behavioral_store record_volume failed: %s", exc)

    def record_correspondence(
        self,
        actor: str,
        peer: str,
        direction: str,
        message_id: str = "",
        request_class: str = "",
        seen_at: float | None = None,
    ) -> None:
        """One edge in the sender↔recipient graph (Cisco/Abnormal-style)."""
        actor = (actor or "").strip().lower()
        peer = (peer or "").strip().lower()
        way = (direction or "").strip().lower()
        if not actor or not peer or actor == peer:
            return
        if way not in ("sent_to", "received_from"):
            return
        now = time.time() if seen_at is None else float(seen_at)
        try:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO correspondence_log "
                    "(actor, peer, direction, request_class, message_id, seen_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (actor, peer, way, (request_class or "").strip()[:80],
                     (message_id or "").strip(), now),
                )
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            _log.warning("behavioral_store record_correspondence failed: %s", exc)

    def record_copy_behavior(
        self,
        *,
        sender: str,
        mailbox: str,
        message_id: str = "",
        peers: list[str] | None = None,
        direction: str = "",
        request_class: str = "",
        hour_utc=None,
        has_attachment: bool = False,
        is_reply: bool = False,
        labels=None,
        seen_at: float | None = None,
    ) -> None:
        """Volume + who-talks-to-whom for one scanned copy. All verdicts."""
        sender = (sender or "").strip().lower()
        mailbox = (mailbox or "").strip().lower()
        way = (direction or copy_direction(sender, mailbox, labels)).strip().lower()
        self.record_volume(
            sender, mailbox, message_id, direction=way, hour_utc=hour_utc,
            seen_at=seen_at, labels=labels, request_class=request_class,
            has_attachment=has_attachment, is_reply=is_reply,
        )
        others = []
        for addr in list(peers or []) + ([mailbox] if mailbox else []):
            a = (addr or "").strip().lower()
            if a and a != sender and a not in others:
                others.append(a)
        for peer in others:
            self.record_correspondence(
                sender, peer, "sent_to", message_id=message_id,
                request_class=request_class, seen_at=seen_at,
            )
            self.record_correspondence(
                peer, sender, "received_from", message_id=message_id,
                request_class=request_class, seen_at=seen_at,
            )

    def volumes_for(self, senders: list[str] | None = None) -> dict[str, dict]:
        """sent/received/mailbox-target counts for one address or a batch."""
        cutoff = time.time() - _WINDOW
        wanted = [(s or "").strip().lower() for s in (senders or []) if (s or "").strip()]
        empty = {
            "sent_count": 0, "received_count": 0, "mailbox_targets": 0,
            "outbound_count": 0, "first_seen": 0.0, "last_seen": 0.0,
        }
        out: dict[str, dict] = {}

        def _slot(addr: str) -> dict:
            slot = out.get(addr)
            if slot is None:
                slot = dict(empty)
                out[addr] = slot
            return slot

        try:
            conn = self._connect()
            try:
                sent_sql = (
                    "SELECT sender, COUNT(DISTINCT message_id), "
                    "MIN(seen_at), MAX(seen_at) FROM mail_volume_log "
                    "WHERE seen_at>? AND IFNULL(sender,'')!='' "
                )
                sent_args: list = [cutoff]
                if wanted:
                    sent_sql += f"AND sender IN ({','.join('?' * len(wanted))}) "
                    sent_args.extend(wanted)
                sent_sql += "GROUP BY sender"
                for sender, n, first, last in conn.execute(sent_sql, sent_args).fetchall():
                    addr = (sender or "").lower()
                    slot = _slot(addr)
                    slot["sent_count"] = int(n or 0)
                    slot["first_seen"] = float(first or 0)
                    slot["last_seen"] = float(last or 0)

                recv_sql = (
                    "SELECT mailbox, COUNT(DISTINCT message_id) FROM mail_volume_log "
                    "WHERE seen_at>? AND IFNULL(mailbox,'')!='' AND mailbox != sender "
                )
                recv_args: list = [cutoff]
                if wanted:
                    recv_sql += f"AND mailbox IN ({','.join('?' * len(wanted))}) "
                    recv_args.extend(wanted)
                recv_sql += "GROUP BY mailbox"
                for mailbox, n in conn.execute(recv_sql, recv_args).fetchall():
                    addr = (mailbox or "").lower()
                    if wanted and addr not in wanted:
                        continue
                    slot = _slot(addr)
                    slot["received_count"] = int(n or 0)

                tgt_sql = (
                    "SELECT sender, COUNT(DISTINCT mailbox) FROM mail_volume_log "
                    "WHERE seen_at>? AND IFNULL(sender,'')!='' AND mailbox != sender "
                )
                tgt_args: list = [cutoff]
                if wanted:
                    tgt_sql += f"AND sender IN ({','.join('?' * len(wanted))}) "
                    tgt_args.extend(wanted)
                tgt_sql += "GROUP BY sender"
                for sender, n in conn.execute(tgt_sql, tgt_args).fetchall():
                    _slot((sender or "").lower())["mailbox_targets"] = int(n or 0)

                out_sql = (
                    "SELECT sender, COUNT(DISTINCT message_id) FROM mail_volume_log "
                    "WHERE seen_at>? AND direction='outbound' AND IFNULL(sender,'')!='' "
                )
                out_args: list = [cutoff]
                if wanted:
                    out_sql += f"AND sender IN ({','.join('?' * len(wanted))}) "
                    out_args.extend(wanted)
                out_sql += "GROUP BY sender"
                for sender, n in conn.execute(out_sql, out_args).fetchall():
                    _slot((sender or "").lower())["outbound_count"] = int(n or 0)
            finally:
                conn.close()
        except Exception as exc:
            _log.warning("behavioral_store volumes_for failed: %s", exc)
            return {a: dict(empty) for a in wanted} if wanted else {}
        if wanted:
            for addr in wanted:
                _slot(addr)
        return out

    def volume_for(self, sender: str) -> dict:
        addr = (sender or "").strip().lower()
        if not addr:
            return {
                "sent_count": 0, "received_count": 0, "mailbox_targets": 0,
                "outbound_count": 0, "first_seen": 0.0, "last_seen": 0.0,
            }
        return self.volumes_for([addr]).get(addr) or {
            "sent_count": 0, "received_count": 0, "mailbox_targets": 0,
            "outbound_count": 0, "first_seen": 0.0, "last_seen": 0.0,
        }

    def volume_hours(self, sender: str) -> list[dict]:
        """Hour-of-day histogram for mail this address originated."""
        addr = (sender or "").strip().lower()
        if not addr:
            return []
        cutoff = time.time() - _WINDOW
        try:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT hour_utc, COUNT(DISTINCT message_id) FROM mail_volume_log "
                    "WHERE sender=? AND seen_at>? AND hour_utc IS NOT NULL "
                    "GROUP BY hour_utc ORDER BY hour_utc",
                    (addr, cutoff),
                ).fetchall()
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return []
        return [
            {"value": int(r[0]), "hour_utc": int(r[0]), "count": int(r[1] or 0)}
            for r in rows if r[0] is not None
        ]

    def volume_burst(self, sender: str) -> dict:
        """Daily distinct-message counts for this From address."""
        addr = (sender or "").strip().lower()
        empty = {"max_day": 0, "avg_day": 0.0, "days_active": 0}
        if not addr:
            return empty
        cutoff = time.time() - _WINDOW
        try:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT CAST(seen_at/86400 AS INTEGER) AS day, "
                    "COUNT(DISTINCT message_id) FROM mail_volume_log "
                    "WHERE sender=? AND seen_at>? GROUP BY day",
                    (addr, cutoff),
                ).fetchall()
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return empty
        counts = [int(r[1] or 0) for r in rows]
        if not counts:
            return empty
        return {
            "max_day": max(counts),
            "avg_day": round(sum(counts) / len(counts), 2),
            "days_active": len(counts),
        }

    def request_mix_for(self, sender: str, limit: int = 8) -> list[dict]:
        """What kinds of asks this From typically sends (scanned emails)."""
        addr = (sender or "").strip().lower()
        if not addr:
            return []
        cutoff = time.time() - _WINDOW
        limit_n = max(1, min(int(limit), 20))
        try:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT request_class, COUNT(DISTINCT message_id) FROM mail_volume_log "
                    "WHERE sender=? AND seen_at>? AND IFNULL(request_class,'')!='' "
                    "GROUP BY request_class "
                    "ORDER BY COUNT(DISTINCT message_id) DESC LIMIT ?",
                    (addr, cutoff, limit_n),
                ).fetchall()
                if not rows:
                    rows = conn.execute(
                        "SELECT request_class, COUNT(*) FROM recipient_request_log "
                        "WHERE sender=? AND seen_at>? GROUP BY request_class "
                        "ORDER BY COUNT(*) DESC LIMIT ?",
                        (addr, cutoff, limit_n),
                    ).fetchall()
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return []
        return [{"value": r[0] or "other", "count": int(r[1] or 0)} for r in rows]

    def receive_mix_for(self, mailbox: str, limit: int = 8) -> list[dict]:
        """What kinds of asks this mailbox typically receives."""
        addr = (mailbox or "").strip().lower()
        if not addr:
            return []
        cutoff = time.time() - _WINDOW
        try:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT request_class, COUNT(*) FROM recipient_request_log "
                    "WHERE mailbox=? AND seen_at>? GROUP BY request_class "
                    "ORDER BY COUNT(*) DESC LIMIT ?",
                    (addr, cutoff, max(1, min(int(limit), 20))),
                ).fetchall()
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return []
        return [{"value": r[0] or "other", "count": int(r[1] or 0)} for r in rows]

    def peers_for(self, addr: str, *, direction: str, limit: int = 8) -> list[dict]:
        """Top counterparties for one identity (sent_to or received_from)."""
        addr = (addr or "").strip().lower()
        way = (direction or "").strip().lower()
        if not addr or way not in ("sent_to", "received_from"):
            return []
        cutoff = time.time() - _WINDOW
        try:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT peer, COUNT(*) FROM correspondence_log "
                    "WHERE actor=? AND direction=? AND seen_at>? "
                    "GROUP BY peer ORDER BY COUNT(*) DESC LIMIT ?",
                    (addr, way, cutoff, max(1, min(int(limit), 20))),
                ).fetchall()
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return []
        return [{"value": r[0], "count": int(r[1] or 0)} for r in rows if r[0]]

    def habits_for(self, sender: str) -> dict:
        """Attachment / reply rates and request mix from volume rows."""
        addr = (sender or "").strip().lower()
        empty = {
            "n": 0, "attachment_rate": 0.0, "reply_rate": 0.0,
            "request_mix": [], "hours": [],
        }
        if not addr:
            return empty
        cutoff = time.time() - _WINDOW
        try:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT COUNT(*), AVG(has_attachment), AVG(is_reply) "
                    "FROM mail_volume_log WHERE sender=? AND seen_at>?",
                    (addr, cutoff),
                ).fetchone()
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return empty
        n = int((row[0] if row else 0) or 0)
        return {
            "n": n,
            "attachment_rate": float(row[1] or 0) if row else 0.0,
            "reply_rate": float(row[2] or 0) if row else 0.0,
            "request_mix": self.request_mix_for(addr),
            "hours": self.volume_hours(addr),
        }

    def behavior_for(self, addr: str) -> dict:
        """Console bundle: send + receive + counterparties + timing."""
        addr = (addr or "").strip().lower()
        vol = self.volume_for(addr)
        habits = self.habits_for(addr)
        return {
            "volume": vol,
            "burst": self.volume_burst(addr),
            "hours": habits.get("hours") or self.volume_hours(addr),
            "request_mix": habits.get("request_mix") or self.request_mix_for(addr),
            "receive_mix": self.receive_mix_for(addr),
            "sent_to": self.peers_for(addr, direction="sent_to"),
            "received_from": self.peers_for(addr, direction="received_from"),
            "attachment_rate": float(habits.get("attachment_rate") or 0),
            "reply_rate": float(habits.get("reply_rate") or 0),
        }

    def get_sender_risk(self, sender: str) -> dict | None:
        addr = (sender or "").strip().lower()
        if not addr:
            return None
        try:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT risk, score, posture, confidence, summary, factors, "
                    "provider, model_id, facts_hash, assessed_at "
                    "FROM sender_risk_assess WHERE sender=?",
                    (addr,),
                ).fetchone()
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return None
        if not row:
            return None
        factors = []
        try:
            parsed = json.loads(row[5] or "[]")
            if isinstance(parsed, list):
                factors = parsed
        except (TypeError, ValueError):
            factors = []
        return {
            "risk": row[0] or "LOW",
            "score": float(row[1] or 0),
            "posture": row[2] or "",
            "confidence": row[3] or "",
            "summary": row[4] or "",
            "factors": factors,
            "provider": row[6] or "",
            "model_id": row[7] or "",
            "facts_hash": row[8] or "",
            "assessed_at": float(row[9] or 0),
        }

    def list_sender_risks(self, senders: list[str] | None = None) -> dict[str, dict]:
        wanted = [(s or "").strip().lower() for s in (senders or []) if (s or "").strip()]
        out: dict[str, dict] = {}
        try:
            conn = self._connect()
            try:
                sql = (
                    "SELECT sender, risk, score, posture, confidence, summary, "
                    "provider, model_id, assessed_at FROM sender_risk_assess"
                )
                args: list = []
                if wanted:
                    sql += f" WHERE sender IN ({','.join('?' * len(wanted))})"
                    args.extend(wanted)
                rows = conn.execute(sql, args).fetchall()
            finally:
                conn.close()
        except Exception as exc:
            _log.warning("behavioral_store list_sender_risks failed: %s", exc)
            return {}
        for r in rows:
            out[(r[0] or "").lower()] = {
                "risk": r[1] or "LOW",
                "score": float(r[2] or 0),
                "posture": r[3] or "",
                "confidence": r[4] or "",
                "summary": r[5] or "",
                "provider": r[6] or "",
                "model_id": r[7] or "",
                "assessed_at": float(r[8] or 0),
            }
        return out

    def put_sender_risk(self, sender: str, payload: dict) -> None:
        addr = (sender or "").strip().lower()
        if not addr:
            return
        factors = payload.get("factors") or []
        try:
            blob = json.dumps(factors, ensure_ascii=False)
        except (TypeError, ValueError):
            blob = "[]"
        try:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO sender_risk_assess "
                    "(sender, risk, score, posture, confidence, summary, factors, "
                    "provider, model_id, facts_hash, assessed_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(sender) DO UPDATE SET "
                    "risk=excluded.risk, score=excluded.score, posture=excluded.posture, "
                    "confidence=excluded.confidence, summary=excluded.summary, "
                    "factors=excluded.factors, provider=excluded.provider, "
                    "model_id=excluded.model_id, facts_hash=excluded.facts_hash, "
                    "assessed_at=excluded.assessed_at",
                    (
                        addr,
                        str(payload.get("risk") or "LOW")[:16],
                        float(payload.get("score") or 0),
                        str(payload.get("posture") or "")[:40],
                        str(payload.get("confidence") or "")[:16],
                        str(payload.get("summary") or "")[:4000],
                        blob,
                        str(payload.get("provider") or "")[:40],
                        str(payload.get("model_id") or "")[:80],
                        str(payload.get("facts_hash") or "")[:64],
                        float(payload.get("assessed_at") or time.time()),
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            _log.warning("behavioral_store put_sender_risk failed: %s", exc)

    def behavioral_details(
        self,
        sender,            # str
        originating_ips,   # list[str]
        shortener_domains, # list[str]
    ):
        """Return a list of finding dicts for triggered rules.

        Each dict: {rule, ioc_value, behavioral_count, flagged_count, emails}
        where emails is a list of {sender, message_id, seen_at, verdict} for
        prior SUSPICIOUS/MALICIOUS emails only (up to _MAX_EMAIL_RECORDS).

        Returns [] on storage error or no matches.
        """
        sender = (sender or "").lower().strip()
        originating_ips = [ip for ip in (originating_ips or []) if ip]
        shortener_domains = [d for d in (shortener_domains or []) if d]
        if not sender and not originating_ips and not shortener_domains:
            return []

        cutoff = time.time() - _WINDOW
        try:
            conn = self._connect()
            try:
                findings = []

                # Rule 1a: sender comes from multiple originating IPs
                if sender and originating_ips:
                    row = conn.execute(
                        "SELECT COUNT(DISTINCT ip) FROM sender_ip_log "
                        "WHERE sender=? AND seen_at>?",
                        (sender, cutoff),
                    ).fetchone()
                    distinct_ips = row[0] if row else 0
                    if distinct_ips >= 2:
                        rows = conn.execute(
                            "SELECT sender, message_id, seen_at, verdict "
                            "FROM sender_ip_log "
                            "WHERE sender=? AND seen_at>? AND verdict IN (?,?) "
                            "ORDER BY seen_at DESC LIMIT ?",
                            (sender, cutoff, *_FLAGGED, _MAX_EMAIL_RECORDS),
                        ).fetchall()
                        findings.append({
                            "rule": "behavioral_sender_ip_drift",
                            "ioc_value": sender,
                            "behavioral_count": distinct_ips,
                            "flagged_count": len(rows),
                            "emails": [
                                {"sender": r[0], "message_id": r[1],
                                 "seen_at": r[2], "verdict": r[3]}
                                for r in rows
                            ],
                        })

                # Rule 1b: IP used by 5+ distinct senders
                seen_ips = set()
                for ip in originating_ips:
                    if ip in seen_ips:
                        continue
                    seen_ips.add(ip)
                    row = conn.execute(
                        "SELECT COUNT(DISTINCT sender) FROM sender_ip_log "
                        "WHERE ip=? AND seen_at>?",
                        (ip, cutoff),
                    ).fetchone()
                    distinct_senders = row[0] if row else 0
                    if distinct_senders >= _MANY_SENDERS_THRESHOLD:
                        rows = conn.execute(
                            "SELECT sender, message_id, seen_at, verdict "
                            "FROM sender_ip_log "
                            "WHERE ip=? AND seen_at>? AND verdict IN (?,?) "
                            "ORDER BY seen_at DESC LIMIT ?",
                            (ip, cutoff, *_FLAGGED, _MAX_EMAIL_RECORDS),
                        ).fetchall()
                        findings.append({
                            "rule": "behavioral_ip_many_senders",
                            "ioc_value": ip,
                            "behavioral_count": distinct_senders,
                            "flagged_count": len(rows),
                            "emails": [
                                {"sender": r[0], "message_id": r[1],
                                 "seen_at": r[2], "verdict": r[3]}
                                for r in rows
                            ],
                        })

                # Rule 2: IP has previously sent link-shortener URLs
                seen_ips_short = set()
                for ip in originating_ips:
                    if ip in seen_ips_short:
                        continue
                    seen_ips_short.add(ip)
                    row = conn.execute(
                        "SELECT COUNT(*) FROM ip_shortener_log "
                        "WHERE ip=? AND seen_at>?",
                        (ip, cutoff),
                    ).fetchone()
                    count = row[0] if row else 0
                    if count >= 1:
                        rows = conn.execute(
                            "SELECT sender, message_id, seen_at, verdict "
                            "FROM ip_shortener_log "
                            "WHERE ip=? AND seen_at>? AND verdict IN (?,?) "
                            "ORDER BY seen_at DESC LIMIT ?",
                            (ip, cutoff, *_FLAGGED, _MAX_EMAIL_RECORDS),
                        ).fetchall()
                        findings.append({
                            "rule": "behavioral_ip_shortener",
                            "ioc_value": ip,
                            "behavioral_count": count,
                            "flagged_count": len(rows),
                            "emails": [
                                {"sender": r[0], "message_id": r[1],
                                 "seen_at": r[2], "verdict": r[3]}
                                for r in rows
                            ],
                        })

                # Rule 3: shortener domain used by other senders (MALICIOUS tier)
                for domain in shortener_domains:
                    row = conn.execute(
                        "SELECT COUNT(DISTINCT sender) FROM sender_shortener_log "
                        "WHERE shortener_domain=? AND sender!=? AND seen_at>?",
                        (domain, sender, cutoff),
                    ).fetchone()
                    other_senders = row[0] if row else 0
                    if other_senders >= 1:
                        rows = conn.execute(
                            "SELECT sender, message_id, seen_at, verdict "
                            "FROM sender_shortener_log "
                            "WHERE shortener_domain=? AND sender!=? AND seen_at>? "
                            "AND verdict IN (?,?) "
                            "ORDER BY seen_at DESC LIMIT ?",
                            (domain, sender, cutoff, *_FLAGGED, _MAX_EMAIL_RECORDS),
                        ).fetchall()
                        findings.append({
                            "rule": "behavioral_shared_shortener",
                            "ioc_value": domain,
                            "behavioral_count": other_senders,
                            "flagged_count": len(rows),
                            "emails": [
                                {"sender": r[0], "message_id": r[1],
                                 "seen_at": r[2], "verdict": r[3]}
                                for r in rows
                            ],
                        })

                return findings
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return []

    def sender_prior_count(self, sender: str) -> int:
        """Return how many times this sender has been seen in the past 6 months.
        Returns 0 if sender is unknown or on storage error."""
        sender = (sender or "").lower().strip()
        if not sender:
            return 0
        cutoff = time.time() - _WINDOW
        try:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT COUNT(*) FROM sender_history WHERE sender=? AND seen_at>?",
                    (sender, cutoff),
                ).fetchone()
                return int(row[0]) if row else 0
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return 0

    def behavioral_lookup(
        self,
        sender,
        originating_ips,
        shortener_domains,
    ):
        """Return flag strings derived from behavioral_details().
        Kept for test compatibility; callers preferring rich data should use
        behavioral_details() directly."""
        details = self.behavioral_details(sender, originating_ips, shortener_domains)
        return [
            f"{d['rule']}:{d['ioc_value']}:{d['behavioral_count']}"
            for d in details
        ]

    def record_profile_observation(
        self,
        sender: str,
        *,
        asn: str = "",
        country: str = "",
        network_role: str = "",
        vpn: bool = False,
        spf: str = "",
        dkim: str = "",
        mailbox: str = "",
        hour_utc=None,
        verdict: str = "",
        message_id: str = "",
        seen_at: float | None = None,
    ):
        """Learn infrastructure identity for CLEAN/LOW emails only.

        SUSPICIOUS/MALICIOUS still count in sender_history (via record_observation)
        but must not train this baseline.
        """
        sender = (sender or "").lower().strip()
        verdict_u = (verdict or "").upper().strip()
        if not sender or verdict_u not in _LEARN_VERDICTS:
            return
        now = time.time() if seen_at is None else float(seen_at)
        hour = None
        if hour_utc is not None:
            try:
                hour = int(hour_utc)
                if hour < 0 or hour > 23:
                    hour = None
            except (TypeError, ValueError):
                hour = None
        try:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO sender_profile_obs "
                    "(sender, asn, country, network_role, vpn, spf, dkim, "
                    "mailbox, hour_utc, verdict, message_id, seen_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        sender,
                        (asn or "").strip(),
                        (country or "").strip().upper(),
                        (network_role or "").strip().lower(),
                        1 if vpn else 0,
                        (spf or "").strip().lower(),
                        (dkim or "").strip().lower(),
                        (mailbox or "").strip().lower(),
                        hour,
                        verdict_u,
                        message_id or "",
                        now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            _log.warning("behavioral_store record_profile_observation failed: %s", exc)

    def lookup_recipient_request(
        self, mailbox: str, sender: str, request_class: str,
    ) -> dict:
        """Prior counts for this mailbox × sender × request class (6-month window)."""
        empty = {
            "prior_same_class_from_sender": 0,
            "prior_same_class_any_sender": 0,
            "prior_from_sender_any_class": 0,
        }
        mailbox = (mailbox or "").strip().lower()
        sender = (sender or "").strip().lower()
        request_class = (request_class or "").strip()
        if not mailbox or not request_class:
            return empty
        cutoff = time.time() - _WINDOW
        try:
            conn = self._connect()
            try:
                n_from = conn.execute(
                    "SELECT COUNT(*) FROM recipient_request_log "
                    "WHERE mailbox=? AND sender=? AND request_class=? AND seen_at>?",
                    (mailbox, sender, request_class, cutoff),
                ).fetchone()[0]
                n_any = conn.execute(
                    "SELECT COUNT(*) FROM recipient_request_log "
                    "WHERE mailbox=? AND request_class=? AND seen_at>?",
                    (mailbox, request_class, cutoff),
                ).fetchone()[0]
                n_sender = conn.execute(
                    "SELECT COUNT(*) FROM recipient_request_log "
                    "WHERE mailbox=? AND sender=? AND seen_at>?",
                    (mailbox, sender, cutoff),
                ).fetchone()[0]
                return {
                    "prior_same_class_from_sender": int(n_from or 0),
                    "prior_same_class_any_sender": int(n_any or 0),
                    "prior_from_sender_any_class": int(n_sender or 0),
                }
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            _log.warning("behavioral_store lookup_recipient_request failed: %s", exc)
            return empty

    def record_recipient_request(
        self,
        mailbox: str,
        sender: str,
        request_class: str,
        message_id: str = "",
        seen_at: float | None = None,
    ) -> None:
        """Record that this mailbox received this request class from this sender.

        All verdicts count — the question is whether the *ask* is new to the
        recipient, not whether prior emails scored CLEAN.
        """
        mailbox = (mailbox or "").strip().lower()
        sender = (sender or "").strip().lower()
        request_class = (request_class or "").strip()
        if not mailbox or not sender or not request_class:
            return
        now = time.time() if seen_at is None else float(seen_at)
        mid = (message_id or "").strip()
        try:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO recipient_request_log "
                    "(mailbox, sender, request_class, message_id, seen_at) "
                    "VALUES (?,?,?,?,?)",
                    (mailbox, sender, request_class, mid, now),
                )
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            _log.warning("behavioral_store record_recipient_request failed: %s", exc)

    @staticmethod
    def _empty_profile() -> dict:
        return {
            "n": 0, "asns": [], "countries": [], "roles": [],
            "vpn_count": 0, "vpn_rate": 0.0, "majority_role": "",
            "spf": [], "dkim": [], "mailboxes": [], "hours": [],
        }

    @staticmethod
    def _profile_from_rows(rows: list) -> dict:
        n = len(rows)
        if not n:
            return BehavioralCorrelationStore._empty_profile()

        def _freq(values):
            return [{"value": k, "count": c} for k, c in Counter(
                v for v in values if v
            ).most_common()]

        roles = _freq([r[2] for r in rows])
        vpn_count = sum(1 for r in rows if r[3])
        hours = _freq([r[7] for r in rows if r[7] is not None])
        return {
            "n": n,
            "asns": _freq([r[0] for r in rows]),
            "countries": _freq([r[1] for r in rows]),
            "roles": roles,
            "vpn_count": vpn_count,
            "vpn_rate": vpn_count / n,
            "majority_role": roles[0]["value"] if roles else "",
            "spf": _freq([r[4] for r in rows]),
            "dkim": _freq([r[5] for r in rows]),
            "mailboxes": _freq([r[6] for r in rows]),
            "hours": hours,
        }

    def profile_for(self, sender: str) -> dict:
        """Aggregate CLEAN/LOW infrastructure identity for this From address."""
        sender = (sender or "").lower().strip()
        if not sender:
            return self._empty_profile()
        return self.profiles_for([sender]).get(sender) or self._empty_profile()

    def profiles_for(self, senders: list[str]) -> dict[str, dict]:
        """Batch ``profile_for`` so the Senders page is one query, not N+1."""
        wanted = [(s or "").strip().lower() for s in (senders or []) if (s or "").strip()]
        empty = self._empty_profile()
        out = {s: dict(empty) for s in wanted}
        if not wanted:
            return out
        cutoff = time.time() - _WINDOW
        grouped: dict[str, list] = {s: [] for s in wanted}
        try:
            conn = self._connect()
            try:
                sql = (
                    "SELECT sender, asn, country, network_role, vpn, spf, dkim, mailbox, hour_utc "
                    "FROM sender_profile_obs WHERE seen_at>? AND sender IN ("
                    + ",".join("?" * len(wanted))
                    + ")"
                )
                rows = conn.execute(sql, [cutoff, *wanted]).fetchall()
            finally:
                conn.close()
        except Exception as exc:
            _log.warning("behavioral_store profiles_for failed: %s", exc)
            return out
        for r in rows:
            sender = (r[0] or "").lower()
            if sender in grouped:
                grouped[sender].append((r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8]))
        for sender, hops in grouped.items():
            out[sender] = self._profile_from_rows(hops)
        return out

    def profile_delta(self, profile: dict | None, this_copy: dict | None) -> list[dict]:
        """Compare this email to a CLEAN/LOW baseline. ``score`` is True only when n >= 5."""
        profile = profile or {}
        this = this_copy or {}
        n = int(profile.get("n") or 0)
        ready = n >= PROFILE_MIN_N
        deltas: list[dict] = []
        if n < PROFILE_MIN_N:
            deltas.append({
                "code": "profile_cold_start",
                "severity": "info",
                "summary": (
                    f"Not enough CLEAN/LOW history yet ({n}/{PROFILE_MIN_N}) "
                    "to know what is normal for this sender."
                ),
                "score": False,
            })

        role = (this.get("network_role") or "").strip().lower()
        vpn = bool(this.get("vpn"))
        if vpn and int(profile.get("vpn_count") or 0) == 0 and n > 0:
            deltas.append({
                "code": "profile_vpn_new",
                "severity": "high",
                "summary": (
                    f"This email looks like VPN/proxy; {n} prior CLEAN/LOW "
                    "emails from this sender never did."
                ),
                "score": ready,
            })

        majority = (profile.get("majority_role") or "").strip().lower()
        hosting = bool(this.get("hosting")) or role in _HOSTING_ROLES
        if (
            n > 0 and hosting and not vpn
            and majority in _TRUSTED_ROLES
            and role != majority
        ):
            deltas.append({
                "code": "profile_hosting_new",
                "severity": "high",
                "summary": (
                    f"This email is cloud/VPS hosting; this sender usually sends "
                    f"from {majority or 'ESP/ISP'} infrastructure."
                ),
                "score": ready,
            })

        country = (this.get("country") or "").strip().upper()
        known_cc = {
            str(c.get("value") or "").upper()
            for c in (profile.get("countries") or [])
            if c.get("value")
        }
        if n > 0 and country and country not in known_cc and role not in _ESP_ROLES:
            deltas.append({
                "code": "profile_country_new",
                "severity": "medium",
                "summary": (
                    f"Origin country {country} is new for this sender "
                    f"(usual: {', '.join(sorted(known_cc)) or 'unknown'})."
                ),
                "score": ready,
            })

        asn = (this.get("asn") or "").strip()
        known_asn = {
            str(a.get("value") or "")
            for a in (profile.get("asns") or [])
            if a.get("value")
        }
        if n > 0 and asn and asn not in known_asn and role not in _ESP_ROLES:
            deltas.append({
                "code": "profile_asn_new",
                "severity": "low",
                "summary": (
                    f"ASN {asn} is new for this sender "
                    f"(usual: {', '.join(sorted(known_asn)) or 'unknown'})."
                ),
                "score": False,
            })

        usual_spf = ""
        spf_rows = profile.get("spf") or []
        if spf_rows:
            usual_spf = str(spf_rows[0].get("value") or "")
        this_spf = (this.get("spf") or "").strip().lower()
        if n > 0 and usual_spf == "pass" and this_spf in ("fail", "softfail"):
            deltas.append({
                "code": "profile_auth_regression",
                "severity": "medium",
                "summary": (
                    f"SPF is {this_spf} on this email; this sender usually passes SPF."
                ),
                "score": False,
            })

        mailbox = (this.get("mailbox") or "").strip().lower()
        known_mb = {
            str(m.get("value") or "").lower()
            for m in (profile.get("mailboxes") or [])
            if m.get("value")
        }
        if n > 0 and mailbox and known_mb and mailbox not in known_mb:
            deltas.append({
                "code": "profile_mailbox_new",
                "severity": "info",
                "summary": f"This email was delivered to {mailbox}, which this sender has not used before.",
                "score": False,
            })

        hour = this.get("hour_utc")
        known_hours = {
            int(h.get("value"))
            for h in (profile.get("hours") or [])
            if h.get("value") is not None
        }
        try:
            hour_n = int(hour) if hour is not None else None
        except (TypeError, ValueError):
            hour_n = None
        if (
            n >= PROFILE_MIN_N
            and hour_n is not None
            and known_hours
            and hour_n not in known_hours
            and role not in _ESP_ROLES
        ):
            usual = ", ".join(f"{h:02d}:00Z" for h in sorted(known_hours)[:8])
            high_risk = bool(this.get("high_risk_request"))
            deltas.append({
                "code": "profile_hour_unusual",
                "severity": "medium" if high_risk else "low",
                "summary": (
                    f"This email's Date hour is {hour_n:02d}:00 UTC; this sender's "
                    f"CLEAN/LOW mail is usually {usual}."
                ),
                "score": ready and high_risk,
            })

        prior_peer = this.get("prior_from_sender")
        if (
            n >= PROFILE_MIN_N
            and mailbox
            and prior_peer is not None
            and int(prior_peer or 0) == 0
        ):
            high_risk = bool(this.get("high_risk_request"))
            deltas.append({
                "code": "profile_peer_new",
                "severity": "medium" if high_risk else "info",
                "summary": (
                    f"This sender has not written to {mailbox} in the scanned "
                    "history — a new counterpart on this relationship graph."
                ),
                "score": ready and high_risk,
            })
        return deltas

    def mark_identity(self, message_id: str, *, eligible: bool, reason: str = "") -> int:
        """Set identity eligibility for every IP row of one RFC message-id."""
        mid = (message_id or "").strip()
        if not mid:
            return 0
        ident = 1 if eligible else 0
        why = (reason or "").strip()[:80]
        try:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "UPDATE sender_ip_log SET identity=?, identity_reason=? WHERE message_id=?",
                    (ident, why, mid),
                )
                conn.commit()
                return int(cur.rowcount or 0)
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            _log.warning("behavioral_store mark_identity failed: %s", exc)
            return 0

    def _verdict_counts_by_sender(self, cutoff: float) -> dict[str, dict]:
        """One counted copy per message_id (or seen_at if id is missing)."""
        empty = {v: 0 for v in _VERDICTS}
        out: dict[str, dict] = {}

        def _slot(sender: str) -> dict:
            return out.setdefault(sender, {
                "verdicts": dict(empty),
                "identity_verdicts": dict(empty),
                "last_seen": 0.0,
            })

        try:
            conn = self._connect()
            try:
                ip_rows = conn.execute(
                    "SELECT sender, verdict, identity, COUNT(*), MAX(seen_at) FROM ("
                    "  SELECT sender,"
                    "    CASE WHEN IFNULL(message_id,'')='' THEN CAST(seen_at AS TEXT)"
                    "         ELSE message_id END AS mid,"
                    "    CASE MAX(CASE UPPER(IFNULL(verdict,''))"
                    "         WHEN 'MALICIOUS' THEN 4 WHEN 'SUSPICIOUS' THEN 3"
                    "         WHEN 'LOW' THEN 2 WHEN 'CLEAN' THEN 1 ELSE 0 END)"
                    "      WHEN 4 THEN 'MALICIOUS' WHEN 3 THEN 'SUSPICIOUS'"
                    "      WHEN 2 THEN 'LOW' WHEN 1 THEN 'CLEAN' ELSE '' END AS verdict,"
                    "    MIN(CASE WHEN IFNULL(identity,1)=0 THEN 0 ELSE 1 END) AS identity,"
                    "    MAX(seen_at) AS seen_at"
                    "  FROM sender_ip_log"
                    "  WHERE seen_at>? AND IFNULL(sender,'')!=''"
                    "  GROUP BY sender, mid"
                    ") AS hops WHERE verdict IN ('CLEAN','LOW','SUSPICIOUS','MALICIOUS')"
                    " GROUP BY sender, verdict, identity",
                    (cutoff,),
                ).fetchall()
                from_ip = set()
                for sender, verdict, ident, n, last_seen in ip_rows:
                    sender = (sender or "").lower()
                    from_ip.add(sender)
                    slot = _slot(sender)
                    slot["verdicts"][verdict] = slot["verdicts"].get(verdict, 0) + int(n or 0)
                    if int(ident or 0) != 0:
                        slot["identity_verdicts"][verdict] = (
                            slot["identity_verdicts"].get(verdict, 0) + int(n or 0)
                        )
                    slot["last_seen"] = max(slot["last_seen"], float(last_seen or 0))
                # CLEAN/LOW emails with no originating IP never hit sender_ip_log.
                prof_rows = conn.execute(
                    "SELECT sender, UPPER(verdict), COUNT(*), MAX(seen_at) "
                    "FROM sender_profile_obs WHERE seen_at>? AND IFNULL(sender,'')!='' "
                    "GROUP BY sender, UPPER(verdict)",
                    (cutoff,),
                ).fetchall()
                for sender, verdict, n, last_seen in prof_rows:
                    sender = (sender or "").lower()
                    if sender in from_ip:
                        continue
                    if verdict not in empty:
                        continue
                    slot = _slot(sender)
                    slot["verdicts"][verdict] = int(n or 0)
                    slot["identity_verdicts"][verdict] = int(n or 0)
                    slot["last_seen"] = max(slot["last_seen"], float(last_seen or 0))
            finally:
                conn.close()
        except Exception as exc:
            _log.warning("behavioral_store verdict counts failed: %s", exc)
            return {}
        return out

    @staticmethod
    def _assessment_of(verdicts: dict, *, lane: str = "external") -> str:
        return _assessment_mix(verdicts, lane=lane)

    def list_profiles(self, query: str = "", limit: int = 400) -> list[dict]:
        """Per-address baselines plus typical-behavior assessment for the console."""
        cutoff = time.time() - _WINDOW
        q = (query or "").strip().lower()
        limit_n = max(1, min(int(limit or 400), 1000))
        mixes = self._verdict_counts_by_sender(cutoff)
        senders = set(mixes)
        try:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT DISTINCT sender FROM sender_profile_obs "
                    "WHERE seen_at>? AND IFNULL(sender,'')!=''",
                    (cutoff,),
                ).fetchall()
                senders.update((r[0] or "").lower() for r in rows if r[0])
            finally:
                conn.close()
        except Exception as exc:
            _log.warning("behavioral_store list_profiles senders failed: %s", exc)
        if q:
            senders = {s for s in senders if q in s}
        empty = {v: 0 for v in _VERDICTS}
        risks = self.list_sender_risks() if senders else {}

        def _pre_rank(s: str):
            mix = mixes.get(s) or {
                "verdicts": dict(empty),
                "identity_verdicts": dict(empty),
                "last_seen": 0.0,
            }
            verdicts = mix["verdicts"]
            emails = sum(int(verdicts.get(v) or 0) for v in _VERDICTS)
            identity_verdicts = mix.get("identity_verdicts") or dict(empty)
            identity_copies = sum(int(identity_verdicts.get(v) or 0) for v in _VERDICTS)
            skipped = max(0, emails - identity_copies)
            assess_mix = identity_verdicts if (identity_copies or skipped) else verdicts
            assessment = self._assessment_of(assess_mix, lane=sender_lane(s)) if emails else "CLEAN"
            risk = str((risks.get(s) or {}).get("risk") or "").upper()
            return (
                _RISK_RANK.get(risk, 9),
                _ASSESS_RANK.get(assessment, 9),
                -emails,
                -float(mix.get("last_seen") or 0),
            )

        ranked = sorted(senders, key=_pre_rank)[:limit_n]
        vols = self.volumes_for(ranked) if ranked else {}
        profs = self.profiles_for(ranked) if ranked else {}
        out: list[dict] = []
        for sender in ranked:
            mix = mixes.get(sender) or {
                "verdicts": dict(empty),
                "identity_verdicts": dict(empty),
                "last_seen": 0.0,
            }
            verdicts = mix["verdicts"]
            identity_verdicts = mix.get("identity_verdicts") or dict(empty)
            emails = sum(int(verdicts.get(v) or 0) for v in _VERDICTS)
            hostile = int(verdicts.get("SUSPICIOUS") or 0) + int(verdicts.get("MALICIOUS") or 0)
            prof = dict(profs.get(sender) or self._empty_profile())
            prof["sender"] = sender
            prof["last_seen"] = float(mix["last_seen"] or 0)
            prof["ready"] = int(prof.get("n") or 0) >= PROFILE_MIN_N
            if emails == 0 and int(prof.get("n") or 0):
                verdicts = {
                    "CLEAN": int(prof.get("n") or 0), "LOW": 0,
                    "SUSPICIOUS": 0, "MALICIOUS": 0,
                }
                identity_verdicts = dict(verdicts)
                emails = int(prof.get("n") or 0)
                hostile = 0
            identity_copies = sum(int(identity_verdicts.get(v) or 0) for v in _VERDICTS)
            skipped = max(0, emails - identity_copies)
            assess_mix = identity_verdicts if (identity_copies or skipped) else verdicts
            lane = sender_lane(sender)
            vol = vols.get(sender) or {}
            sent = int(vol.get("sent_count") or 0)
            received = int(vol.get("received_count") or 0)
            if sent <= 0:
                sent = emails
            prof["verdicts"] = verdicts
            prof["identity_verdicts"] = identity_verdicts
            prof["copies"] = emails
            prof["sent_count"] = sent
            prof["received_count"] = received
            prof["mailbox_targets"] = int(vol.get("mailbox_targets") or 0)
            prof["outbound_count"] = int(vol.get("outbound_count") or 0)
            prof["lane"] = lane
            prof["assessment"] = self._assessment_of(assess_mix, lane=lane) if emails else "CLEAN"
            prof["hostile_rate"] = (hostile / emails) if emails else 0.0
            prof["assessment_note"] = _assessment_note(
                copies=emails, hostile=hostile, lane=lane, skipped=skipped,
            )
            risk = risks.get(sender) or {}
            if risk:
                prof["ai_risk"] = risk.get("risk") or ""
                prof["ai_score"] = float(risk.get("score") or 0)
                prof["ai_posture"] = risk.get("posture") or ""
                prof["ai_provider"] = risk.get("provider") or ""
            else:
                prof["ai_risk"] = ""
                prof["ai_score"] = 0.0
                prof["ai_posture"] = ""
                prof["ai_provider"] = ""
            out.append(prof)
        out.sort(key=lambda p: (
            _RISK_RANK.get(str(p.get("ai_risk") or "").upper(), 9),
            _ASSESS_RANK.get(p.get("assessment") or "CLEAN", 9),
            -int(p.get("copies") or 0),
            -float(p.get("last_seen") or 0),
        ))
        return out[:limit_n]

    def profile_observations(self, sender: str, limit: int = 40) -> list[dict]:
        """Recent CLEAN/LOW hops for one From address (inspect panel)."""
        sender = (sender or "").lower().strip()
        if not sender:
            return []
        cutoff = time.time() - _WINDOW
        limit_n = max(1, min(int(limit or 40), 200))
        try:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT asn, country, network_role, vpn, spf, dkim, mailbox, "
                    "hour_utc, verdict, message_id, seen_at "
                    "FROM sender_profile_obs WHERE sender=? AND seen_at>? "
                    "ORDER BY seen_at DESC LIMIT ?",
                    (sender, cutoff, limit_n),
                ).fetchall()
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            _log.warning("behavioral_store profile_observations failed: %s", exc)
            return []
        return [
            {
                "asn": r[0] or "",
                "country": r[1] or "",
                "network_role": r[2] or "",
                "vpn": bool(r[3]),
                "spf": r[4] or "",
                "dkim": r[5] or "",
                "mailbox": r[6] or "",
                "hour_utc": r[7],
                "verdict": r[8] or "",
                "message_id": r[9] or "",
                "seen_at": float(r[10] or 0),
            }
            for r in rows
        ]


def this_copy_snapshot(
    origin_facts=None, header_facts=None, mailbox="", hour_utc=None,
    *,
    prior_from_sender=None, high_risk_request: bool = False,
) -> dict:
    """Flatten origin + header facts into the shape profile_delta expects."""
    origin = origin_facts or {}
    headers = header_facts or {}
    return {
        "asn": (origin.get("asn") or "").strip(),
        "country": (origin.get("country") or "").strip().upper(),
        "network_role": (origin.get("network_role") or "").strip().lower(),
        "vpn": bool(origin.get("vpn")),
        "hosting": bool(origin.get("hosting")),
        "spf": (headers.get("spf") or "").strip().lower(),
        "dkim": (headers.get("dkim") or "").strip().lower(),
        "mailbox": (mailbox or "").strip().lower(),
        "hour_utc": hour_utc,
        "prior_from_sender": prior_from_sender,
        "high_risk_request": bool(high_risk_request),
    }


def profile_summary_line(profile: dict | None, deltas: list | None) -> str:
    """One-line fact blurb for the LLM context and inspect panel."""
    profile = profile or {}
    n = int(profile.get("n") or 0)
    if n < PROFILE_MIN_N:
        return f"Sender profile: not enough CLEAN/LOW history yet ({n}/{PROFILE_MIN_N})."
    role = profile.get("majority_role") or "unknown"
    countries = ", ".join(
        str(c.get("value")) for c in (profile.get("countries") or [])[:4] if c.get("value")
    ) or "unknown"
    asns = ", ".join(
        str(a.get("value")) for a in (profile.get("asns") or [])[:4] if a.get("value")
    ) or "unknown"
    vpn = f"{profile.get('vpn_rate') or 0:.0%} VPN"
    mix = profile.get("request_mix") or []
    mix_s = ""
    if mix:
        top = ", ".join(
            f"{r.get('value')}×{r.get('count')}" for r in mix[:3] if r.get("value")
        )
        if top:
            mix_s = f" Typical asks: {top}."
    peers = profile.get("sent_to") or []
    peer_s = ""
    if peers:
        top_p = ", ".join(str(p.get("value")) for p in peers[:4] if p.get("value"))
        if top_p:
            peer_s = f" Typical recipients: {top_p}."
    scored = [d for d in (deltas or []) if d.get("score")]
    extra = ""
    if scored:
        extra = " Unusual vs baseline: " + "; ".join(
            str(d.get("summary") or d.get("code")) for d in scored[:3]
        )
    return (
        f"Sender profile ({n} CLEAN/LOW emails): usually {role}, "
        f"countries {countries}, ASN {asns}, {vpn}.{mix_s}{peer_s}{extra}"
    )


def get_default_store():
    return BehavioralCorrelationStore()
