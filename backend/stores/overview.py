"""Worker-written Overview snapshot: one row of all-time tile + origin totals.

GET /api/feed SELECTs this row instead of COUNT/SUM on every poll. The retry
worker recomputes from ``copies`` (and gmail_coverage) so counters cannot drift
from per-write increments. API falls back to one compute if the row is missing
or older than STALE_SECONDS.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Optional

from backend.db import is_postgres

STALE_SECONDS = 90.0
SNAPSHOT_KEY = "all"
_ORIGIN_POINTS_CAP = 200
_VERDICT_RANK = {"CLEAN": 0, "LOW": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}

_write_lock = threading.Lock()


def origin_country_sql() -> str:
    """Same expression for map rollup and ``?origin=`` so counts cannot diverge."""
    if is_postgres():
        return (
            "UPPER(TRIM(COALESCE("
            "NULLIF(origin_country, ''), "
            "NULLIF(stages_json::json->'origin_ip'->>'country', '')"
            ")))"
        )
    return (
        "UPPER(TRIM(COALESCE("
        "NULLIF(origin_country, ''), "
        "NULLIF(json_extract(stages_json, '$.origin_ip.country'), '')"
        ")))"
    )


def origin_fields_from_stages(stages) -> dict:
    """Denormalized origin columns from a stored stages_json object."""
    oi = (stages or {}).get("origin_ip") if isinstance(stages, dict) else None
    if not isinstance(oi, dict):
        return {}
    country = str(oi.get("country") or "").strip().upper()[:8]
    city = str(oi.get("city") or "").strip()[:80]
    name = str(oi.get("country_name") or oi.get("countryName") or country).strip()[:80]
    try:
        lat = float(oi["lat"]) if oi.get("lat") is not None else None
    except (TypeError, ValueError):
        lat = None
    try:
        lon = float(oi["lon"]) if oi.get("lon") is not None else None
    except (TypeError, ValueError):
        lon = None
    out = {}
    if country:
        out["origin_country"] = country
    if city:
        out["origin_city"] = city
    if name:
        out["origin_name"] = name
    if lat is not None and lon is not None:
        out["origin_lat"] = lat
        out["origin_lon"] = lon
    return out


def _n(row, key: str) -> int:
    try:
        return int(row[key] or 0)
    except (TypeError, KeyError, IndexError, ValueError):
        return 0


def _f(row, key: str) -> Optional[float]:
    try:
        val = row[key]
        if val is None or val == "":
            return None
        return float(val)
    except (TypeError, KeyError, IndexError, ValueError):
        return None


def _worst(a: str, b: str) -> str:
    ra = _VERDICT_RANK.get((a or "").upper(), -1)
    rb = _VERDICT_RANK.get((b or "").upper(), -1)
    return b if rb > ra else (a or "CLEAN")


def _empty_origin() -> dict:
    return {"located": 0, "countries": [], "points": []}


def compute_overview_stats(*, since_seconds: float | None = None) -> dict:
    """All-time (or windowed) COUNT/GROUP BY over copies. Source of truth."""
    from backend.stores import assessments as store
    from backend.stores.gmail_coverage import snapshot as coverage_snapshot

    window = store.OVERVIEW_WINDOW_SECONDS if since_seconds is None else float(since_seconds)
    where_sql, where_params = store._overview_where(window)
    mailbox_where = where_sql
    mailbox_params = where_params
    extra = "TRIM(COALESCE(mailbox, '')) != ''"
    if mailbox_where:
        mailbox_where = mailbox_where + " AND " + extra
    else:
        mailbox_where = "WHERE " + extra
    bucket_secs = 3600 if 0 < window <= 172800 else 86400
    cc_sql = origin_country_sql()
    with store._lock:
        conn = store._connect()
        try:
            row = conn.execute(
                """
                SELECT
                  COUNT(*) AS total,
                  SUM(CASE WHEN COALESCE(ai_done, 0) = 0
                            AND COALESCE(status, '') NOT IN (?, ?, ?, ?)
                       THEN 1 ELSE 0 END) AS pending,
                  SUM(CASE WHEN COALESCE(status, '') = ?
                            OR UPPER(COALESCE(verdict, '')) = 'INCONCLUSIVE'
                       THEN 1 ELSE 0 END) AS inconclusive,
                  SUM(CASE WHEN COALESCE(ai_done, 0) = 1
                            AND UPPER(COALESCE(verdict, '')) = 'CLEAN'
                       THEN 1 ELSE 0 END) AS clean,
                  SUM(CASE WHEN COALESCE(ai_done, 0) = 1
                            AND UPPER(COALESCE(verdict, '')) = 'LOW'
                       THEN 1 ELSE 0 END) AS low,
                  SUM(CASE WHEN COALESCE(ai_done, 0) = 1
                            AND UPPER(COALESCE(verdict, '')) = 'SUSPICIOUS'
                       THEN 1 ELSE 0 END) AS suspicious,
                  SUM(CASE WHEN COALESCE(ai_done, 0) = 1
                            AND UPPER(COALESCE(verdict, '')) = 'MALICIOUS'
                       THEN 1 ELSE 0 END) AS malicious,
                  SUM(CASE WHEN COALESCE(ai_done, 0) = 1
                       THEN 1 ELSE 0 END) AS assessed,
                  SUM(CASE WHEN COALESCE(thread_ai_done, 0) = 1
                       THEN 1 ELSE 0 END) AS thread_assessed,
                  SUM(CASE WHEN UPPER(COALESCE(disposition, '')) = 'QUARANTINE'
                       THEN 1 ELSE 0 END) AS quarantined
                FROM copies
                """ + ((" " + where_sql) if where_sql else ""),
                (store.ERROR, store.DEAD_LETTER, store.COMPLETE, store.TIMED_OUT,
                 store.TIMED_OUT) + where_params,
            ).fetchone()
            pending_row = conn.execute(
                """
                SELECT COUNT(*) AS n FROM copies
                WHERE COALESCE(ai_done, 0) = 0
                  AND COALESCE(status, '') NOT IN (?, ?, ?, ?)
                """,
                (store.ERROR, store.DEAD_LETTER, store.COMPLETE, store.TIMED_OUT),
            ).fetchone()
            timeout_row = conn.execute(
                """
                SELECT COUNT(*) AS n FROM copies
                WHERE COALESCE(status, '') = ?
                   OR (COALESCE(ai_done, 0) = 0
                       AND UPPER(COALESCE(verdict, '')) = 'INCONCLUSIVE')
                """,
                (store.TIMED_OUT,),
            ).fetchone()
            mailbox_row = conn.execute(
                "SELECT COUNT(DISTINCT LOWER(TRIM(mailbox))) AS n FROM copies "
                + mailbox_where,
                mailbox_params,
            ).fetchone()
            hour_sql = """
                SELECT CAST(updated_at / ? AS INTEGER) * ? AS bucket,
                       COUNT(*) AS total,
                       SUM(CASE WHEN COALESCE(ai_done, 0) = 1
                                 AND UPPER(COALESCE(verdict, '')) = 'LOW'
                            THEN 1 ELSE 0 END) AS low,
                       SUM(CASE WHEN COALESCE(ai_done, 0) = 1
                                 AND UPPER(COALESCE(verdict, '')) = 'SUSPICIOUS'
                            THEN 1 ELSE 0 END) AS suspicious,
                       SUM(CASE WHEN COALESCE(ai_done, 0) = 1
                                 AND UPPER(COALESCE(verdict, '')) = 'MALICIOUS'
                            THEN 1 ELSE 0 END) AS malicious
                FROM copies
                """ + ((" " + where_sql) if where_sql else "") + """
                GROUP BY CAST(updated_at / ? AS INTEGER)
                ORDER BY 1
                """
            hour_rows = conn.execute(
                hour_sql,
                (bucket_secs, bucket_secs) + where_params + (bucket_secs,),
            ).fetchall()
            origin_where = where_sql
            origin_params = where_params
            loc_pred = cc_sql + " != ''"
            if origin_where:
                origin_where = origin_where + " AND " + loc_pred
            else:
                origin_where = "WHERE " + loc_pred
            origin_rows = conn.execute(
                """
                SELECT """ + cc_sql + """ AS cc,
                       COALESCE(NULLIF(origin_city, ''), '') AS city,
                       origin_lat AS lat,
                       origin_lon AS lon,
                       COALESCE(NULLIF(origin_name, ''), """ + cc_sql + """) AS name,
                       UPPER(COALESCE(verdict, '')) AS verdict,
                       COALESCE(ai_done, 0) AS ai_done
                FROM copies
                """ + (" " + origin_where if origin_where else ""),
                origin_params,
            ).fetchall()
        finally:
            conn.close()

    mailboxes = _n(mailbox_row, "n") if mailbox_row is not None else 0
    out = {
        "windowSeconds": int(window) if window > 0 else 0,
        "total": _n(row, "total") if row is not None else 0,
        "pending": _n(row, "pending") if row is not None else 0,
        "inconclusive": _n(row, "inconclusive") if row is not None else 0,
        "clean": _n(row, "clean") if row is not None else 0,
        "low": _n(row, "low") if row is not None else 0,
        "suspicious": _n(row, "suspicious") if row is not None else 0,
        "malicious": _n(row, "malicious") if row is not None else 0,
        "assessed": _n(row, "assessed") if row is not None else 0,
        "threadAssessed": _n(row, "thread_assessed") if row is not None else 0,
        "mailboxes": mailboxes,
        "quarantined": _n(row, "quarantined") if row is not None else 0,
        "held": _n(row, "quarantined") if row is not None else 0,
        "aiPendingTotal": _n(pending_row, "n") if pending_row is not None else 0,
        "aiTimedOutTotal": _n(timeout_row, "n") if timeout_row is not None else 0,
        "hourly": [
            {
                "start": _n(h, "bucket") * 1000,
                "count": _n(h, "total"),
                "low": _n(h, "low"),
                "suspicious": _n(h, "suspicious"),
                "malicious": _n(h, "malicious"),
            }
            for h in hour_rows
        ],
        "feedLimit": store.FEED_LIST_LIMIT,
        "inboxesMonitored": mailboxes,
        "inboxesPolling": 0,
        "inboxesConfigured": 0,
        "inboxesDiscovered": 0,
        "inboxesSkipped": 0,
        "origin": _rollup_origin(origin_rows),
        "computedAt": time.time(),
    }
    try:
        cov = coverage_snapshot()
        polling = int(cov.get("polling") or 0)
        out["inboxesPolling"] = polling
        out["inboxesMonitored"] = max(mailboxes, polling)
        out["inboxesConfigured"] = int(cov.get("configured") or 0)
        out["inboxesDiscovered"] = int(cov.get("discovered") or 0)
        out["inboxesSkipped"] = int(cov.get("skipped") or 0)
    except Exception:
        pass
    return out


def _rollup_origin(rows) -> dict:
    countries: dict[str, dict] = {}
    spots: dict[str, dict] = {}
    located = 0
    for r in rows or []:
        cc = str(r["cc"] or "").strip().upper()
        if not cc:
            continue
        located += 1
        city = str(r["city"] or "").strip()
        name = str(r["name"] or cc).strip() or cc
        verd = str(r["verdict"] or "").upper()
        if int(r["ai_done"] or 0) != 1:
            verd = "CLEAN"
        if verd not in _VERDICT_RANK:
            verd = "CLEAN"
        lat = _f(r, "lat")
        lon = _f(r, "lon")
        c = countries.get(cc)
        if c is None:
            c = {
                "country": cc, "name": name, "count": 0, "worst": "CLEAN",
                "lat": lat if lat is not None else 0.0,
                "lon": lon if lon is not None else 0.0,
                "city": city,
            }
            countries[cc] = c
        c["count"] += 1
        c["worst"] = _worst(c["worst"], verd)
        if name and name != cc:
            c["name"] = name
        if city:
            c["city"] = city
        if lat is not None and lon is not None:
            c["lat"] = lat
            c["lon"] = lon
        if lat is None or lon is None:
            continue
        key = "%.1f,%.1f:%s" % (lat, lon, cc)
        p = spots.get(key)
        if p is None:
            p = {
                "lat": round(lat, 1), "lon": round(lon, 1),
                "country": cc, "name": name, "city": city,
                "count": 0, "worst": "CLEAN",
            }
            spots[key] = p
        p["count"] += 1
        p["worst"] = _worst(p["worst"], verd)
        if city:
            p["city"] = city
    country_list = sorted(countries.values(), key=lambda x: -int(x["count"]))
    point_list = sorted(spots.values(), key=lambda x: -int(x["count"]))[:_ORIGIN_POINTS_CAP]
    return {"located": located, "countries": country_list, "points": point_list}


def write_snapshot(payload: dict) -> None:
    from backend.stores import assessments as store

    body = json.dumps(payload, default=str)
    now = float(payload.get("computedAt") or time.time())
    with store._lock:
        conn = store._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS overview_stats (
                    key TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    computed_at REAL NOT NULL DEFAULT 0
                )
                """
            )
            if is_postgres():
                conn.execute(
                    "INSERT INTO overview_stats (key, payload_json, computed_at) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT (key) DO UPDATE SET payload_json = EXCLUDED.payload_json, "
                    "computed_at = EXCLUDED.computed_at",
                    (SNAPSHOT_KEY, body, now),
                )
            else:
                conn.execute(
                    "INSERT INTO overview_stats (key, payload_json, computed_at) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET payload_json = excluded.payload_json, "
                    "computed_at = excluded.computed_at",
                    (SNAPSHOT_KEY, body, now),
                )
            conn.commit()
        finally:
            conn.close()


def read_snapshot() -> Optional[tuple]:
    """Return (payload, computed_at) or None."""
    from backend.stores import assessments as store

    with store._lock:
        conn = store._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS overview_stats (
                    key TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    computed_at REAL NOT NULL DEFAULT 0
                )
                """
            )
            row = conn.execute(
                "SELECT payload_json, computed_at FROM overview_stats WHERE key = ?",
                (SNAPSHOT_KEY,),
            ).fetchone()
        except Exception:
            return None
        finally:
            conn.close()
    if not row:
        return None
    try:
        payload = json.loads(row["payload_json"] or "{}")
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload, float(row["computed_at"] or 0)


def refresh_overview_stats(*, since_seconds: float | None = None) -> dict:
    """Recompute from copies and persist. Called by the retry worker."""
    with _write_lock:
        payload = compute_overview_stats(since_seconds=since_seconds)
        write_snapshot(payload)
        return payload


def _overlay_inbox(payload: dict) -> dict:
    """Coverage is a tiny table; overlay so inbox tiles stay live vs 90s copies snapshot."""
    out = dict(payload)
    historical = int(out.get("mailboxes") or 0)
    out.setdefault("inboxesMonitored", historical)
    try:
        from backend.stores.gmail_coverage import snapshot as coverage_snapshot
        cov = coverage_snapshot()
        polling = int(cov.get("polling") or 0)
        out["inboxesPolling"] = polling
        out["inboxesMonitored"] = max(historical, polling)
        out["inboxesConfigured"] = int(cov.get("configured") or 0)
        out["inboxesDiscovered"] = int(cov.get("discovered") or 0)
        out["inboxesSkipped"] = int(cov.get("skipped") or 0)
    except Exception:
        pass
    return out


def overview_stats(*, since_seconds: float | None = None) -> dict:
    """API read path: SELECT the snapshot, compute once if missing/stale."""
    from backend.stores import assessments as store

    window = store.OVERVIEW_WINDOW_SECONDS if since_seconds is None else float(since_seconds)
    if window != store.OVERVIEW_WINDOW_SECONDS and window > 0:
        # Windowed reads (tests) skip the all-time snapshot.
        return _overlay_inbox(compute_overview_stats(since_seconds=window))
    hit = read_snapshot()
    now = time.time()
    if hit is not None:
        payload, computed_at = hit
        age = now - computed_at
        if 0 <= age < STALE_SECONDS and int(payload.get("windowSeconds") or 0) == 0:
            return _overlay_inbox(payload)
    try:
        return _overlay_inbox(
            refresh_overview_stats(since_seconds=0.0 if window <= 0 else window)
        )
    except Exception:
        empty = store.empty_overview_stats(window=window)
        empty["origin"] = _empty_origin()
        empty["computedAt"] = 0.0
        empty["quarantined"] = 0
        empty["held"] = 0
        return _overlay_inbox(empty)
