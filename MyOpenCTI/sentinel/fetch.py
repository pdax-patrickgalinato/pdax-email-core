"""HTTP fetch, RSS/Atom parse, and CISA KEV catalog."""
from __future__ import annotations

import calendar
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional, Tuple

import feedparser
import requests
import streamlit as st
from bs4 import BeautifulSoup

from sentinel.config import (
    BROWSER_USER_AGENT, CACHE_TTL_SECONDS, DEFAULT_TIMEOUT, KEV_CACHE_TTL_SECONDS,
    KEV_URL, MAX_WORKERS, REDDIT_CACHE_TTL_SECONDS, USER_AGENT,
)
from sentinel.models import Article, FeedSource, FetchResult

def _is_reddit_url(url: str) -> bool:
    host = (url or "").lower()
    return "reddit.com/" in host or host.startswith("https://redd.it/")


def _friendly_feed_error(msg: str) -> str:
    """Turn raw HTTP/exception noise into a short analyst-facing status line."""
    text = (msg or "").strip()
    if not text:
        return "Fetch failed"
    low = text.lower()
    code: Optional[int] = None
    m = re.search(r"\b([45]\d{2})\b", text)
    if m:
        try:
            code = int(m.group(1))
        except ValueError:
            code = None
    by_code = {
        401: "Login required by publisher",
        403: "Blocked by publisher (bot filter)",
        404: "Feed retired or moved",
        408: "Timed out waiting for publisher",
        429: "Rate limited — retry later",
        500: "Publisher server error",
        502: "Publisher gateway error",
        503: "Publisher temporarily unavailable",
        504: "Publisher gateway timeout",
        520: "Publisher origin error",
        521: "Publisher web server down",
        522: "Publisher connection timed out",
        523: "Publisher origin unreachable",
        524: "Publisher timeout",
        525: "Publisher SSL handshake failed",
        526: "Publisher invalid SSL",
        530: "Publisher origin error",
    }
    if code in by_code:
        return by_code[code]
    if "timed out" in low or "timeout" in low:
        return "Timed out reaching publisher"
    if "ssl" in low or "certificate" in low:
        return "TLS/SSL connection failed"
    if any(s in low for s in ("name or service not known", "nodename", "getaddrinfo", "dns")):
        return "DNS lookup failed"
    if "connection refused" in low:
        return "Connection refused"
    if "empty response" in low or "no content" in low:
        return "Empty response from publisher"
    if "contained no entries" in low or "feed is empty" in low:
        return "Feed is empty"
    if "malformed" in low:
        return "Malformed feed XML"
    if "parse failure" in low or "parse error" in low:
        return "Could not parse feed"
    # Strip exception class + trailing URL from requests errors.
    text = re.sub(
        r"^(?:RuntimeError|HTTPError|ConnectionError|ReadTimeout|ConnectTimeout|"
        r"SSLError|ValueError|MaxRetryError|ProxyError):\s*",
        "",
        text,
    )
    text = re.sub(r"\s+for url:.*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+Client Error:.*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+Server Error:.*$", "", text, flags=re.IGNORECASE)
    return (text.strip()[:120] or "Fetch failed")


def _http_get(url: str, timeout: int) -> bytes:
    """GET with UA fallbacks; Reddit gets Atom Accept + 429 backoff (rate-limited)."""
    last_err: Optional[Exception] = None
    accept = (
        "application/atom+xml, application/rss+xml, application/xml;q=0.9, */*;q=0.8"
        if _is_reddit_url(url)
        else "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"
    )
    header_sets = (
        {"User-Agent": USER_AGENT, "Accept": accept},
        {"User-Agent": BROWSER_USER_AGENT, "Accept": accept},
    )
    attempts = 3 if _is_reddit_url(url) else 2
    for attempt in range(attempts):
        for headers in header_sets:
            try:
                resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
                if resp.status_code == 429:
                    last_err = RuntimeError("429")
                    # Anonymous Reddit RSS is tightly throttled — wait longer each try.
                    time.sleep(min(4.0 * (2 ** attempt), 20.0))
                    continue
                if resp.status_code >= 400:
                    # Keep a short status-only error (no URL dump for the UI).
                    last_err = RuntimeError(str(resp.status_code))
                    continue
                if resp.content:
                    return resp.content
                last_err = ValueError("Empty response body")
            except Exception as exc:  # noqa: BLE001 — one bad feed must never stop the run
                last_err = exc
    raise RuntimeError(_friendly_feed_error(str(last_err) if last_err else "unknown fetch failure"))


def _fetch_one(source: FeedSource, timeout: int) -> Tuple[str, dict]:
    started = time.perf_counter()
    payload = {"raw": None, "error": "", "ts": time.time(), "latency_ms": 0}
    try:
        payload["raw"] = _http_get(source.url, timeout)
    except Exception as exc:  # noqa: BLE001
        payload["error"] = _friendly_feed_error(str(exc))
    payload["latency_ms"] = int((time.perf_counter() - started) * 1000)
    return source.url, payload


def fetch_sources(sources: List[FeedSource], timeout: int, ttl: int, force: bool,
                  progress_cb=None) -> Dict[str, dict]:
    """Fetch sources concurrently; Reddit feeds are serialised to avoid 429s."""
    cache: Dict[str, dict] = st.session_state.setdefault("_feed_cache", {})
    now = time.time()
    pending: List[FeedSource] = []
    for s in sources:
        hit = cache.get(s.url)
        age = (now - hit["ts"]) if hit else None
        # Reddit: keep a longer cache window so we don't burn the rate limit every run.
        limit = REDDIT_CACHE_TTL_SECONDS if _is_reddit_url(s.url) else ttl
        if force or hit is None or age is None or age > limit:
            pending.append(s)
        else:
            hit["from_cache"] = True

    if pending:
        reddit = [s for s in pending if _is_reddit_url(s.url)]
        other = [s for s in pending if not _is_reddit_url(s.url)]
        done = 0
        total = len(pending)

        if other:
            with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(other))) as pool:
                futures = {pool.submit(_fetch_one, s, timeout): s for s in other}
                for fut in as_completed(futures):
                    url, payload = fut.result()
                    payload["from_cache"] = False
                    cache[url] = payload
                    done += 1
                    if progress_cb:
                        progress_cb(done, total, futures[fut].name)

        # Reddit anonymous RSS allows ~1 fresh pull at a time. Round-robin a couple
        # of subs per run; everyone else keeps stale cache (or waits for its turn).
        reddit_budget = len(reddit) if force else min(2, len(reddit))
        cursor = int(st.session_state.get("_reddit_cursor", 0) or 0)
        refresh_now: List[FeedSource] = []
        if reddit:
            ordered = reddit[cursor % len(reddit):] + reddit[:cursor % len(reddit)]
            refresh_now = list(ordered[:reddit_budget])
            defer = ordered[reddit_budget:]
            st.session_state["_reddit_cursor"] = (cursor + max(reddit_budget, 1)) % len(reddit)
            for s in defer:
                prior = cache.get(s.url)
                if prior and prior.get("raw"):
                    prior = dict(prior)
                    prior["from_cache"] = True
                    prior["note"] = "deferred Reddit refresh (rate-limit budget)"
                    cache[s.url] = prior
                    done += 1
                    if progress_cb:
                        progress_cb(min(done, total), total, f"{s.name} (cached)")
                else:
                    # No cache yet — still try once so first-run isn't empty.
                    refresh_now.append(s)

        for i, s in enumerate(refresh_now):
            if i:
                time.sleep(7.0)
            url, payload = _fetch_one(s, max(timeout, 25))
            if payload.get("error") and "429" in (payload.get("error") or ""):
                prior = cache.get(url)
                if prior and prior.get("raw"):
                    prior = dict(prior)
                    prior["from_cache"] = True
                    prior["error"] = ""
                    prior["note"] = "served stale cache after Reddit 429"
                    cache[url] = prior
                    done += 1
                    if progress_cb:
                        progress_cb(min(done, total), total, f"{s.name} (stale cache)")
                    continue
            payload["from_cache"] = False
            cache[url] = payload
            done += 1
            if progress_cb:
                progress_cb(min(done, total), total, s.name)
    return cache


def fetch_kev_catalog(timeout: int = 20, force: bool = False) -> dict:
    """Pull CISA's Known Exploited Vulnerabilities catalog (CVE → metadata).

    Returns {"cves": {CVE: {…}}, "error": "", "count": N, "from_cache": bool}.
    """
    cache = st.session_state.setdefault("_kev_cache", {})
    now = time.time()
    if (not force and cache.get("cves") is not None
            and (now - cache.get("ts", 0)) < KEV_CACHE_TTL_SECONDS):
        return {
            "cves": cache["cves"],
            "error": cache.get("error", ""),
            "count": len(cache["cves"]),
            "from_cache": True,
            "catalog_version": cache.get("catalog_version", ""),
            "date_released": cache.get("date_released", ""),
        }

    result = {
        "cves": {},
        "error": "",
        "count": 0,
        "from_cache": False,
        "catalog_version": "",
        "date_released": "",
    }
    try:
        raw = _http_get(KEV_URL, timeout)
        data = json.loads(raw.decode("utf-8", errors="replace"))
        vulns = data.get("vulnerabilities") or []
        cves: Dict[str, dict] = {}
        for v in vulns:
            cve_id = (v.get("cveID") or "").upper().strip()
            if not cve_id:
                continue
            cves[cve_id] = {
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "date_added": v.get("dateAdded", ""),
                "due_date": v.get("dueDate", ""),
                "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                "required_action": v.get("requiredAction", ""),
                "short_description": v.get("shortDescription", ""),
            }
        result["cves"] = cves
        result["count"] = len(cves)
        result["catalog_version"] = str(data.get("catalogVersion", ""))
        result["date_released"] = str(data.get("dateReleased", ""))
        cache.clear()
        cache.update({
            "cves": cves,
            "error": "",
            "ts": now,
            "catalog_version": result["catalog_version"],
            "date_released": result["date_released"],
        })
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"[:220]
        # Keep a stale catalog if we have one rather than failing closed.
        if cache.get("cves"):
            result["cves"] = cache["cves"]
            result["count"] = len(cache["cves"])
            result["from_cache"] = True
            result["catalog_version"] = cache.get("catalog_version", "")
            result["date_released"] = cache.get("date_released", "")
            result["error"] = f"Refresh failed ({result['error']}); using cached KEV"
        else:
            cache.update({"cves": {}, "error": result["error"], "ts": now})
    return result


def kev_hits_for(cves: List[str], kev: dict) -> List[str]:
    catalog = kev.get("cves") or {}
    return [c for c in cves if c in catalog]


def _clean_html(raw: str, limit: int = 900) -> str:
    if not raw:
        return ""
    try:
        text = BeautifulSoup(raw, "html.parser").get_text(" ", strip=True)
    except Exception:  # noqa: BLE001
        text = re.sub(r"<[^>]+>", " ", raw)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def _parse_date(entry) -> Tuple[Optional[datetime], str]:
    """Try struct_time fields, then a list of string formats, then RFC 2822."""
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        st_time = entry.get(key)
        if st_time:
            try:
                return datetime.fromtimestamp(calendar.timegm(st_time), tz=timezone.utc), key
            except Exception:  # noqa: BLE001
                pass

    for key in ("published", "updated", "created", "pubDate", "dc:date"):
        raw = entry.get(key)
        if not raw or not isinstance(raw, str):
            continue
        try:
            dt = parsedate_to_datetime(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc), key
        except Exception:  # noqa: BLE001
            pass
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d", "%d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z"):
            try:
                dt = datetime.strptime(raw.strip(), fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc), key
            except Exception:  # noqa: BLE001
                continue
    return None, "none"


def parse_feed(source: FeedSource, payload: dict, max_items: int) -> Tuple[List[Article], FetchResult]:
    result = FetchResult(source=source, ok=False, latency_ms=payload.get("latency_ms", 0),
                         from_cache=payload.get("from_cache", False))
    if payload.get("error"):
        result.error = _friendly_feed_error(payload["error"])
        return [], result
    if not payload.get("raw"):
        result.error = "Empty response from publisher"
        return [], result

    try:
        parsed = feedparser.parse(payload["raw"])
    except Exception as exc:  # noqa: BLE001
        result.error = _friendly_feed_error(f"Parse failure: {exc}")
        return [], result

    entries = parsed.get("entries", []) or []
    if not entries:
        if getattr(parsed, "bozo", 0):
            result.error = _friendly_feed_error(
                f"Malformed feed: {str(getattr(parsed, 'bozo_exception', ''))[:120]}"
            )
        else:
            result.error = "Feed is empty"
        return [], result

    result.feed_title = (parsed.feed.get("title", "") if hasattr(parsed, "feed") else "")[:80]
    articles: List[Article] = []
    ingest_time = datetime.now(timezone.utc)

    for entry in entries[:max_items]:
        title = _clean_html(entry.get("title", ""), 300) or "(untitled)"
        link = entry.get("link") or entry.get("id") or ""
        if isinstance(link, str) and not link.lower().startswith(("http://", "https://")):
            link = ""

        summary = entry.get("summary", "")
        if not summary and entry.get("content"):
            try:
                summary = entry["content"][0].get("value", "")
            except Exception:  # noqa: BLE001
                summary = ""
        summary = _clean_html(summary)

        published, origin = _parse_date(entry)
        if published is None:
            published, origin = ingest_time, "ingest-time fallback"

        articles.append(Article(
            title=title,
            link=link,
            summary=summary,
            source_name=source.name,
            category=source.category,
            published=published,
            published_raw=origin,
        ))

    result.ok = True
    result.entries = len(articles)
    return articles, result



def fetch_article_text(url: str, timeout: int = 15, max_chars: int = 20000) -> Tuple[str, str]:
    """Fetch the full article page and return (plain text, error). Used to search for IOCs /
    MITRE ATT&CK / TTPs that a truncated RSS summary would miss."""
    if not url:
        return "", "No article link available"
    try:
        raw = _http_get(url, timeout)
    except Exception as exc:  # noqa: BLE001
        return "", _friendly_feed_error(str(exc))
    try:
        soup = BeautifulSoup(raw, "html.parser")
        for tag in soup(["script", "style", "nav", "header", "footer", "aside", "form"]):
            tag.decompose()
        text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
    except Exception as exc:  # noqa: BLE001
        return "", _friendly_feed_error(f"Parse failure: {exc}")
    if not text:
        return "", "No extractable text on the page"
    return text[:max_chars], ""
