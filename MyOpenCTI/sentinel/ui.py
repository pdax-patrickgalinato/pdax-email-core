"""Streamlit UI — layout, sidebar, and results tabs only."""
from __future__ import annotations

import hashlib
import html
import io
import json
import re
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from sentinel.config import (
    APP_ICON, APP_NAME, APP_TAGLINE, BAND_COLORS, BAND_ORDER, CATEGORY_ORDER,
    DEFAULT_TIMEOUT, INDUSTRY_OPTIONS, PH_TZ, STRETCH, WAZUH_DEFAULT_LIST,
)
from sentinel.feeds_matrix import FEED_MATRIX
from sentinel.fetch import (
    _friendly_feed_error, fetch_article_text, fetch_kev_catalog, fetch_sources, parse_feed,
)
from sentinel.intel_data import INDUSTRY_PROFILES
from sentinel.ioc_utils import _llm_ioc_label
from sentinel.llm import (
    LLM_PROVIDER_ORDER, LLM_PROVIDER_PRESETS, _apply_provider_preset,
    _llm_key_source, llm_cfg_from_state, llm_enrich_article, llm_test_connection,
)
from sentinel.models import Article, article_llm, set_article_llm
from sentinel.scoring import (
    band_of, build_executive_summary, collect_all_iocs, compile_terms, correlate_articles,
    dedupe, deep_enrich_top, extract_intel, parse_terms, recommend, score_article,
    _merge_intel_into_article, _scan_intel_signals,
)
from sentinel.settings import (
    _on_llm_provider_change, _on_settings_change, init_persisted_state,
    reset_persisted_settings, save_persisted_settings,
)
from sentinel.styles import inject_styles
from sentinel.ioc_utils import normalize_iocs_for_wazuh
from sentinel.wazuh import build_wazuh_cdb, wazuh_push_iocs, wazuh_test_connection


def run() -> None:
    st.set_page_config(
        page_title=APP_NAME, page_icon=APP_ICON, layout="wide",
        initial_sidebar_state="expanded",
    )
    inject_styles()
    init_persisted_state()

    # Hero — title only (no shield icon); typography handled in styles.py
    st.markdown(
        f'<div class="sf-hero">'
        f'<div class="sf-kicker">Local CTI desk</div>'
        f'<div class="sf-title">{html.escape(APP_NAME)}</div>'
        f'<div class="sf-tag">{html.escape(APP_TAGLINE)}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.markdown('<div class="sf-section">Company profile</div>', unsafe_allow_html=True)

        industry = st.selectbox(
            "Target industry",
            INDUSTRY_OPTIONS,
            key="industry",
            on_change=_on_settings_change,
            help="Drives the priority multiplier and unlocks sector-specific source boosts.",
        )

        with st.expander("Tech stack & focus keywords", expanded=True):
            tech_blob = st.text_area(
                "Tech stack & security controls",
                key="tech_blob",
                height=150,
                on_change=_on_settings_change,
                help="One category per line ('Cloud: AWS, S3') or a plain comma-separated list. "
                     "Exact product names score best. Click outside the box (or Cmd/Ctrl+Enter) to "
                     "save — your entry is written to disk and survives page refresh.",
            )
            kw_blob = st.text_area(
                "Active threat focus areas",
                key="kw_blob",
                height=80,
                on_change=_on_settings_change,
                help="Comma-separated. These carry moderate weight on top of stack matches. "
                     "Saved to disk when the field commits (blur / Cmd+Enter).",
            )

        run = st.button("🛰️ Fetch & analyze latest intel", type="primary", **STRETCH)

        with st.expander("🛰️ Threat intel sources", expanded=True):
            sc1, sc2 = st.columns(2)
            if sc1.button("Select all", key="_src_all", **STRETCH):
                for f in FEED_MATRIX:
                    st.session_state[f"feed_{f.url}"] = True
                for cat in CATEGORY_ORDER:
                    st.session_state[f"cat_{cat}"] = True
                st.rerun()
            if sc2.button("Clear all", key="_src_none", **STRETCH):
                for f in FEED_MATRIX:
                    st.session_state[f"feed_{f.url}"] = False
                st.rerun()

            enabled_categories = []
            for cat in CATEGORY_ORDER:
                count = sum(1 for f in FEED_MATRIX if f.category == cat)
                if st.checkbox(f"{cat}  ·  {count}", key=f"cat_{cat}"):
                    enabled_categories.append(cat)

            disabled_feeds: set = set()
            with st.expander("Individual feeds"):
                for cat in CATEGORY_ORDER:
                    if cat not in enabled_categories:
                        continue
                    st.caption(cat)
                    for f in [x for x in FEED_MATRIX if x.category == cat]:
                        if not st.checkbox(f.name, key=f"feed_{f.url}"):
                            disabled_feeds.add(f.url)

        # Recompute from session so collapsed expanders still drive the run.
        enabled_categories = [
            cat for cat in CATEGORY_ORDER
            if st.session_state.get(f"cat_{cat}", True)
        ]
        disabled_feeds = {
            f.url for f in FEED_MATRIX
            if not st.session_state.get(f"feed_{f.url}", True)
        }

        with st.expander("🎛️ Scoring & collection", expanded=False):
            st.caption("Weights & fetch tuning — leave defaults unless you need to retune.")
            w_tech = st.slider("Tech stack match", 2, 25, key="w_tech",
                               help="Points per matched stack component (max 4 counted).")
            w_keyword = st.slider("Focus keyword", 1, 15, key="w_keyword")
            w_exploit = st.slider("Active exploitation", 2, 25, key="w_exploit")
            w_cve = st.slider("CVE / CVSS signal", 1, 15, key="w_cve")
            w_kev = st.slider("CISA KEV hit", 5, 30, key="w_kev",
                              help="Points per CVE that appears in CISA's Known Exploited Vulnerabilities catalog.")
            w_actor = st.slider("Threat actor named", 2, 20, key="w_actor")
            w_malware = st.slider("Malware family named", 1, 15, key="w_malware")
            w_ransomware = st.slider("Ransomware family named", 2, 20, key="w_ransomware")
            w_recency = st.slider("Recency bonus", 0, 20, key="w_recency")
            w_industry_step = st.slider("Industry multiplier step", 0.0, 0.30, step=0.01,
                                        key="w_industry_step")
            w_industry_cap = st.slider("Industry multiplier cap", 1.0, 2.5, step=0.1,
                                       key="w_industry_cap")
            w_sector_source = st.slider("Sector-aligned source bonus", 0, 25, key="w_sector_source")
            w_authority_scale = st.slider("Source authority influence", 0.0, 2.0, step=0.1,
                                          key="w_authority_scale")
            curve_midpoint = st.slider("Score curve midpoint", 20, 150, step=5, key="curve_midpoint",
                                       help="Raw points needed to reach ~63/100.")
            w_corroboration = st.slider("Cross-source corroboration", 0, 20, key="w_corroboration")
            st.divider()
            max_items = st.slider("Max items per feed", 5, 60, key="max_items")
            max_age_days = st.slider("Look-back window (days)", 1, 60, key="max_age_days")
            timeout = st.slider("Per-feed timeout (s)", 5, 45, key="timeout")
            ttl_minutes = st.slider("Cache lifetime (min)", 0, 120, key="ttl_minutes")
            deep_scan_top = st.slider(
                "Deep-scan top N items (fetch full article)", 0, 25, key="deep_scan_top",
                help="0 = off. Auto-fetch full pages for top-N scored items.")
            force_refresh = st.checkbox("Ignore cache on next run", key="force_refresh")
            refresh_kev = st.checkbox("Force-refresh CISA KEV catalog", key="refresh_kev")

        with st.expander("🤖 AI deep-research", expanded=False):
            st.caption("Prefer **Ollama** (local). Cloud: OpenRouter free models, or Groq if captcha works.")
            st.checkbox("Enable AI enrichment", key="llm_enabled",
                        help="Must be on for per-article deep-research buttons.")
            _prov_opts = list(LLM_PROVIDER_ORDER)
            _cur_prov = (st.session_state.get("llm_provider") or "ollama").strip().lower()
            if _cur_prov not in _prov_opts:
                _prov_opts = [_cur_prov] + _prov_opts
            st.selectbox(
                "Provider",
                _prov_opts,
                key="llm_provider",
                format_func=lambda p: (LLM_PROVIDER_PRESETS.get(p) or {}).get("label") or p,
                on_change=_on_llm_provider_change,
            )
            provider_now = (st.session_state.get("llm_provider") or "ollama").strip().lower()
            preset_now = LLM_PROVIDER_PRESETS.get(provider_now) or {}
            if preset_now.get("blurb"):
                st.caption(preset_now["blurb"])
            if preset_now.get("signup"):
                st.markdown(f"[Get a key]({preset_now['signup']})")

            if provider_now == "glm_vertex":
                st.text_input("GCP project id", key="llm_project_id", on_change=_on_settings_change)
                st.text_input("Location", key="llm_location", on_change=_on_settings_change)
                st.text_input("Service-account JSON path", key="llm_credentials_path",
                              on_change=_on_settings_change)
                if (st.session_state.get("llm_model") or "").startswith("gemini"):
                    st.session_state["llm_model"] = preset_now.get("model") or "zai-org/glm-4.7-maas"
                st.text_input("Model id", key="llm_model", on_change=_on_settings_change)
                st.text_input("API key (optional)", key="llm_api_key", type="password",
                              on_change=_on_settings_change)
            else:
                if provider_now in {"openai_compatible", "ollama"} or not preset_now.get("base_url"):
                    st.text_input("Base URL", key="llm_base_url", on_change=_on_settings_change)
                elif preset_now.get("base_url"):
                    if not (st.session_state.get("llm_base_url") or "").strip():
                        st.session_state["llm_base_url"] = preset_now["base_url"]
                    st.caption(f"`{st.session_state.get('llm_base_url') or preset_now['base_url']}`")

                key_src = _llm_key_source(llm_cfg_from_state())
                if key_src and key_src != "sidebar field":
                    st.success(f"Key from **{key_src}**")
                key_files = ", ".join(preset_now.get("key_files") or ("LLM_API_KEY.txt",))
                st.text_input(
                    "API key" + ("" if preset_now.get("needs_key", True) else " (optional)"),
                    key="llm_api_key", type="password", on_change=_on_settings_change,
                    help=f"Paste here, or drop {key_files} next to app.py.",
                )
                models = list(preset_now.get("models") or [])
                current_model = (st.session_state.get("llm_model") or preset_now.get("model") or "").strip()
                if models:
                    if current_model not in models:
                        st.session_state["llm_model"] = preset_now.get("model") or models[0]
                        current_model = st.session_state["llm_model"]
                    picked = st.selectbox("Model", models, index=models.index(current_model))
                    if picked != st.session_state.get("llm_model"):
                        st.session_state["llm_model"] = picked
                        _on_settings_change()
                else:
                    st.text_input("Model", key="llm_model", on_change=_on_settings_change)

            st.slider("Max tokens", 800, 16000, key="llm_max_tokens")
            st.slider("Auto deep-research top N after fetch", 0, 15, key="llm_enrich_top")
            if st.button("🔌 Test AI connection", key="_llm_test", **STRETCH):
                if not st.session_state.get("llm_enabled"):
                    st.warning("Enable enrichment first.")
                else:
                    ok, msg = llm_test_connection(llm_cfg_from_state())
                    (st.success if ok else st.error)(msg)

        with st.expander("🖥️ Wazuh SIEM", expanded=False):
            st.caption(
                f"Push IOCs to CDB list `etc/lists/"
                f"{st.session_state.get('wazuh_list_name', WAZUH_DEFAULT_LIST)}`."
            )
            st.text_input("API URL", key="wazuh_url", help="Usually https://<manager>:55000")
            st.text_input("Username", key="wazuh_user")
            st.text_input("Password", key="wazuh_password", type="password")
            st.text_input("CDB list name", key="wazuh_list_name")
            st.checkbox("Verify TLS certificate", key="wazuh_verify_ssl")
            st.checkbox("Restart manager after upload", key="wazuh_restart")
            if st.button("🔌 Test Wazuh connection", key="_wazuh_test", **STRETCH):
                ok, msg = wazuh_test_connection(
                    st.session_state["wazuh_url"],
                    st.session_state["wazuh_user"],
                    st.session_state["wazuh_password"],
                    verify_ssl=bool(st.session_state["wazuh_verify_ssl"]),
                    timeout=int(st.session_state.get("timeout") or DEFAULT_TIMEOUT),
                )
                (st.success if ok else st.error)(msg)

        with st.expander("Maintenance", expanded=False):
            if st.button("🧹 Clear cached feeds", **STRETCH):
                st.session_state.pop("_feed_cache", None)
                st.session_state.pop("_kev_cache", None)
                st.session_state.pop("results", None)
                st.toast("Cache cleared.")
            if st.button("♻️ Reset settings to defaults", **STRETCH):
                reset_persisted_settings()
                st.toast("Settings reset to defaults.")
                st.rerun()
            _saved_at = st.session_state.get("_settings_saved_at")
            if _saved_at:
                st.caption(f"💾 Saved {_saved_at.strftime('%I:%M:%S %p PHT')}")
            else:
                st.caption("💾 Settings auto-save to disk on this machine.")

        save_persisted_settings(st.session_state)

    # ----------------------------- Run -----------------------------

    active_sources = [
        f for f in FEED_MATRIX
        if f.category in enabled_categories and f.url not in disabled_feeds
    ]

    if run:
        if not active_sources:
            st.warning("No feeds selected. Enable at least one category in the sidebar.")
        else:
            tech_terms = parse_terms(tech_blob)
            kw_terms = parse_terms(kw_blob)
            industry_terms = INDUSTRY_PROFILES.get(industry, [])

            progress = st.progress(0.0, text="Loading CISA KEV catalog…")
            kev = fetch_kev_catalog(timeout=timeout, force=refresh_kev)

            cfg = {
                "industry": industry,
                "tech_compiled": compile_terms(tuple(tech_terms)),
                "kw_compiled": compile_terms(tuple(kw_terms)),
                "industry_compiled": compile_terms(tuple(industry_terms)),
                "w_tech": w_tech,
                "w_keyword": w_keyword,
                "w_exploit": w_exploit,
                "w_cve": w_cve,
                "w_kev": w_kev,
                "w_actor": w_actor,
                "w_malware": w_malware,
                "w_ransomware": w_ransomware,
                "w_recency": w_recency,
                "w_industry_step": w_industry_step,
                "w_industry_cap": w_industry_cap,
                "w_sector_source": w_sector_source,
                "w_authority_scale": w_authority_scale,
                "max_age_days": max_age_days,
                "curve_midpoint": curve_midpoint,
                "kev": kev,
            }

            def _tick(done: int, total: int, name: str) -> None:
                progress.progress(done / total, text=f"Fetched {done}/{total} — {name}")

            cache = fetch_sources(active_sources, timeout, ttl_minutes * 60, force_refresh, _tick)
            progress.progress(1.0, text="Parsing, scoring and correlating…")

            all_articles: List[Article] = []
            health: List[FetchResult] = []
            cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)

            for source in active_sources:
                payload = cache.get(source.url, {"error": "Not fetched"})
                arts, res = parse_feed(source, payload, max_items)
                health.append(res)
                for a in arts:
                    if a.published and a.published < cutoff:
                        continue
                    all_articles.append(extract_intel(score_article(a, source, cfg)))

            all_articles = dedupe(all_articles)
            all_articles = correlate_articles(all_articles, boost=float(w_corroboration))

            def _by_score(a: Article):
                return (a.score, a.published or datetime.min.replace(tzinfo=timezone.utc))

            def _by_date(a: Article):
                # Newest first; score breaks ties so same-day items still surface relevance.
                return (a.published or datetime.min.replace(tzinfo=timezone.utc), a.score)

            # Deep-scan still targets the highest-scored items (most actionable), regardless of
            # the final feed order the analyst sees.
            all_articles.sort(key=_by_score, reverse=True)
            deep_n = int(deep_scan_top or 0)
            if deep_n > 0 and all_articles:
                progress.progress(1.0, text=f"Deep-scanning top {deep_n} articles for IOCs / TTPs…")

                def _deep_tick(done: int, total: int) -> None:
                    progress.progress(min(done / max(total, 1), 1.0),
                                      text=f"Deep-scanned {done}/{total} full articles…")

                deep_enrich_top(all_articles, deep_n, timeout, kev, _deep_tick)

            # Optional LLM pass — highest-scored items first for the deepest IOC analysis.
            llm_n = int(st.session_state.get("llm_enrich_top") or 0)
            llm_ok_count = 0
            if llm_n > 0 and st.session_state.get("llm_enabled") and all_articles:
                all_articles.sort(key=_by_score, reverse=True)
                progress.progress(1.0, text=f"LLM-enriching top {llm_n} articles for deep IOCs…")
                llm_cfg = llm_cfg_from_state()
                llm_cache = st.session_state.setdefault("_llm_cache", {})
                targets = all_articles[:llm_n]
                for i, art in enumerate(targets, start=1):
                    progress.progress(min(i / max(len(targets), 1), 1.0),
                                      text=f"LLM enrich {i}/{len(targets)} — {art.title[:48]}")
                    analysis, lerr = llm_enrich_article(art, llm_cfg, timeout=timeout, kev=kev)
                    key = art.link or f"title::{art.title}"
                    if lerr:
                        llm_cache[key] = {"error": lerr}
                    else:
                        llm_cache[key] = analysis
                        llm_ok_count += 1

            # Feed display order: chronological (newest → oldest).
            all_articles.sort(key=_by_date, reverse=True)

            progress.empty()
            st.session_state["results"] = {
                "articles": all_articles,
                "health": health,
                "generated": datetime.now(timezone.utc),
                "industry": industry,
                "tech_terms": tech_terms,
                "kw_terms": kw_terms,
                "deep_scanned": deep_n,
                "llm_enriched": llm_ok_count,
                "kev": {
                    "count": kev.get("count", 0),
                    "error": kev.get("error", ""),
                    "from_cache": kev.get("from_cache", False),
                    "catalog_version": kev.get("catalog_version", ""),
                    "date_released": kev.get("date_released", ""),
                    # Keep the catalog itself so the landscape/report tabs can show KEV detail.
                    "cves": kev.get("cves") or {},
                },
            }

    # ----------------------------- Results -----------------------------

    results = st.session_state.get("results")

    if not results:
        st.info(
            f"**Get started:** set your company profile in the sidebar, then click "
            f"**🛰️ Fetch & analyze latest intel**. "
            f"{len(FEED_MATRIX)} sources · {len(CATEGORY_ORDER)} categories."
        )
        with st.expander("How scoring works", expanded=False):
            st.markdown(
                """
                | Factor | Effect |
                |---|---|
                | Tech stack match | Strongest additive signal |
                | Focus keyword | Moderate additive |
                | Active exploitation / KEV | Large additive |
                | Named actor / malware / ransomware | Identity boost |
                | Cross-source corroboration | Multi-feed boost |
                | Industry / source authority | Multipliers |
                | No stack/keyword/industry/actor/KEV | Score cut ~55% |
                """
            )
        st.stop()

    articles: List[Article] = results["articles"]
    # Older session results predate llm_analysis — attach an empty dict so attribute access is safe.
    for _a in articles:
        if not hasattr(_a, "llm_analysis"):
            setattr(_a, "llm_analysis", {})
    health: List[FetchResult] = results["health"]
    ok_feeds = [h for h in health if h.ok]
    failed_feeds = [h for h in health if not h.ok]
    high = [a for a in articles if a.score >= 60]
    kev_meta = results.get("kev") or {}
    kev_hits = [a for a in articles if a.kev_cves]
    actor_hits = [a for a in articles if a.threat_actors]

    m1, m2, m3, m4 = st.columns(4, gap="small")
    # Keep labels/deltas same length so Streamlit metric boxes render at matching height.
    _feed_delta = f"{len(failed_feeds)} down" if failed_feeds else "all healthy"
    m1.metric("Articles", f"{len(articles):,}", f"{len(high)} high (≥60)")
    m2.metric("KEV hits", f"{len(kev_hits):,}",
              f"catalog {kev_meta.get('count', 0):,}" if kev_meta.get("count") else "catalog n/a")
    m3.metric("Named actors", f"{len(actor_hits):,}", "from this run")
    m4.metric("Feeds", f"{len(ok_feeds)}/{len(health)}", _feed_delta)

    with st.expander("Run details", expanded=False):
        kev_note = "⚠️ KEV error" if kev_meta.get("error") else (
            f"KEV v{kev_meta.get('catalog_version') or '?'} · {kev_meta.get('count', 0):,} CVEs · "
            f"{'cached' if kev_meta.get('from_cache') else 'fresh'}"
            if kev_meta.get("count") else "KEV not loaded"
        )
        st.write(
            f"**{results['industry']}** · {len(results['tech_terms'])} stack terms · "
            f"{len(results['kw_terms'])} focus keywords · {kev_note}"
        )
        st.caption(
            f"Last run {results['generated'].astimezone(PH_TZ).strftime('%m/%d/%Y, %I:%M %p PHT')}"
            + (f" · deep-scanned top {results['deep_scanned']}" if results.get("deep_scanned") else "")
            + (f" · AI-enriched {results['llm_enriched']}" if results.get("llm_enriched") else "")
        )

    tab_intel, tab_landscape, tab_siem, tab_health, tab_data, tab_report = st.tabs(
        ["🎯 Intel feed", "🧬 Landscape", "🖥️ Wazuh",
         "📡 Feeds", "📊 Export", "📝 Report"]
    )

    with tab_intel:
        st.markdown('<div class="sf-section">Prioritised intel</div>', unsafe_allow_html=True)

        with st.expander("Filters & sort", expanded=False):
            f1, f2, f3, f4 = st.columns([2, 2, 1.2, 1.3])
            cats = sorted({a.category for a in articles})
            sel_cats = f1.multiselect("Source category", cats, default=cats)
            srcs = sorted({a.source_name for a in articles})
            sel_srcs = f2.multiselect("Source", srcs, default=[])
            min_score = f3.slider("Minimum score", 0, 100, 25)
            sort_mode = f4.selectbox(
                "Sort by",
                ["Date (newest first)", "Score (highest first)"],
                index=0,
            )
            band_counts: Dict[str, int] = {}
            for a in articles:
                b = band_of(a.recommendation)
                band_counts[b] = band_counts.get(b, 0) + 1
            band_options = [b for b in BAND_ORDER if b in band_counts]
            band_label = {b: f"{b} ({band_counts[b]})" for b in band_options}
            sel_band = st.pills(
                "Recommendation band",
                band_options,
                format_func=lambda b: band_label[b],
                selection_mode="single",
                default=None,
            )
            g1, g2, g3, g4, g5 = st.columns([2, 1.2, 1.1, 1.1, 1.2])
            query = g1.text_input("Search title & summary", "")
            only_stack = g2.checkbox("Only my stack", value=False)
            only_cve = g3.checkbox("Only with CVE", value=False)
            only_kev = g4.checkbox("Only KEV hits", value=False)
            only_actor = g5.checkbox("Only named actors", value=False)

        # Defaults when filters expander state is fresh (widgets still ran above).
        sel_bands = {sel_band} if sel_band else set(band_options)

        view = [
            a for a in articles
            if a.category in sel_cats
            and (not sel_srcs or a.source_name in sel_srcs)
            and a.score >= min_score
            and band_of(a.recommendation) in sel_bands
            and (not only_stack or a.matched_tech)
            and (not only_cve or a.cves)
            and (not only_kev or a.kev_cves)
            and (not only_actor or a.threat_actors)
            and (not query or query.lower() in f"{a.title} {a.summary}".lower())
        ]
        _epoch = datetime.min.replace(tzinfo=timezone.utc)
        if sort_mode.startswith("Score"):
            view.sort(key=lambda a: (a.score, a.published or _epoch), reverse=True)
        else:
            view.sort(key=lambda a: (a.published or _epoch, a.score), reverse=True)

        st.caption(
            f"{len(view)} of {len(articles)} · "
            f"{'score' if sort_mode.startswith('Score') else 'newest first'}"
        )
        if not view:
            st.warning("Nothing matches these filters. Open **Filters & sort** to widen them.")

        enrichment_cache = st.session_state.setdefault("_enrichment_cache", {})

        def _article_anchor_id(key: str) -> str:
            digest = hashlib.md5(key.encode("utf-8", errors="replace")).hexdigest()[:16]
            return f"sf-a-{digest}"

        def _scroll_to_article(anchor_id: str) -> None:
            """After a Streamlit rerun, jump back to the article the user acted on."""
            components.html(
                f"""
                <script>
                (function() {{
                  const id = {json.dumps(anchor_id)};
                  function go() {{
                    try {{
                      const doc = window.parent.document;
                      const el = doc.getElementById(id);
                      if (!el) return false;
                      el.scrollIntoView({{behavior: 'instant', block: 'start'}});
                      return true;
                    }} catch (e) {{ return false; }}
                  }}
                  if (!go()) {{
                    let n = 0;
                    const t = setInterval(function() {{
                      n += 1;
                      if (go() || n > 60) clearInterval(t);
                    }}, 50);
                  }}
                }})();
                </script>
                """,
                height=0,
            )

        for idx, a in enumerate(view[:200]):
            band = band_of(a.recommendation)
            color = BAND_COLORS.get(band, "#5f6368")
            pub = a.published.strftime("%d %b %Y") if a.published else "date unknown"
            enrich_key = a.link or f"title::{a.title}"
            anchor_id = _article_anchor_id(enrich_key)
            cached = enrichment_cache.get(enrich_key)
            llm_cache = st.session_state.setdefault("_llm_cache", {})
            llm_cached = article_llm(a) or llm_cache.get(enrich_key) or {}

            st.markdown(f'<div id="{anchor_id}"></div>', unsafe_allow_html=True)
            # Restore viewport after Deep-scan / AI research (Streamlit otherwise jumps away).
            if st.session_state.get("_scroll_anchor") == anchor_id:
                _scroll_to_article(anchor_id)
            left, right = st.columns([9, 1.15])
            with left:
                safe_title = html.escape(a.title or "")
                title_html = (
                    f'<a href="{html.escape(a.link, quote=True)}" target="_blank" '
                    f'rel="noopener noreferrer">{safe_title}</a>'
                    if a.link else safe_title
                )
                st.markdown(f'<div class="sf-item-title">{title_html}</div>', unsafe_allow_html=True)
                badges = (
                    f'<span class="sf-badge" style="background:{color}1a;color:{color};'
                    f'border-color:{color}59;">{html.escape(band)}</span>'
                    f'<span class="sf-badge">{html.escape(a.source_name)}</span>'
                    f'<span class="sf-badge">{html.escape(pub)}</span>'
                )
                if a.kev_cves:
                    badges += f'<span class="sf-badge sf-badge-kev">🔥 KEV ×{len(a.kev_cves)}</span>'
                for actor in a.threat_actors[:2]:
                    badges += (
                        f'<span class="sf-badge sf-badge-actor">🕵️ {html.escape(actor)}</span>'
                    )
                for rw in a.ransomware_families[:1]:
                    badges += f'<span class="sf-badge sf-badge-kev">💀 {html.escape(rw)}</span>'
                if a.cves:
                    badges += f'<span class="sf-badge sf-badge-cve">🧷 {len(a.cves)} CVE</span>'
                if a.correlated_sources:
                    badges += f'<span class="sf-badge">🔗 ×{len(a.correlated_sources) + 1}</span>'
                st.markdown(badges, unsafe_allow_html=True)
                clip = (a.summary or "").strip()
                if clip:
                    shown = html.escape(clip[:280]) + ("…" if len(clip) > 280 else "")
                    st.markdown(f'<div class="sf-summary-clip">{shown}</div>', unsafe_allow_html=True)
            with right:
                st.markdown(
                    f'<div class="sf-score" style="font-size:1.45rem;color:{color};text-align:right;">'
                    f'{a.score:g}</div>'
                    f'<div class="sf-meta" style="text-align:right;">score</div>',
                    unsafe_allow_html=True,
                )

            act1, act2, act3 = st.columns([1.2, 1.4, 2.4])
            with act1:
                if st.button("🔍 Deep-scan", key=f"enrich_btn_{idx}",
                             disabled=not a.link, **STRETCH,
                             help="Fetch full article and regex-scan for IOCs / ATT&CK."):
                    st.session_state["_scroll_anchor"] = anchor_id
                    with st.spinner("Deep-scanning…"):
                        text, err = fetch_article_text(a.link, timeout=timeout, max_chars=60000)
                        if err:
                            enrichment_cache[enrich_key] = {"error": err}
                        else:
                            signals = _scan_intel_signals(text, exclude=a.link, cap=120)
                            signals["error"] = ""
                            signals["chars"] = len(text)
                            enrichment_cache[enrich_key] = signals
                            _merge_intel_into_article(a, signals)
                    cached = enrichment_cache.get(enrich_key)
            with act2:
                if st.button("🔬 AI research", key=f"llm_btn_{idx}",
                             disabled=not st.session_state.get("llm_enabled"), **STRETCH,
                             help="Deep-research IOCs + CTI via your configured AI provider."):
                    st.session_state["_scroll_anchor"] = anchor_id
                    with st.spinner("Deep-researching threat intel…"):
                        analysis, lerr = llm_enrich_article(
                            a, llm_cfg_from_state(), timeout=max(timeout, 25),
                            kev=results.get("kev"), full_text="",
                        )
                        if lerr:
                            llm_cache[enrich_key] = {"error": lerr}
                            st.error(lerr)
                        else:
                            llm_cache[enrich_key] = analysis
                            set_article_llm(a, analysis)
                            st.toast(f"Research complete · {len(analysis.get('iocs') or [])} IOCs",
                                     icon="🔬")
                            if a.link and not enrichment_cache.get(enrich_key):
                                enrichment_cache[enrich_key] = {
                                    "iocs": {k: list(v) for k, v in a.iocs.items()},
                                    "techniques": list(a.mitre_techniques),
                                    "tactics": list(a.mitre_tactics),
                                    "cta_signals": list(a.cta_signals),
                                    "cves": list(a.cves),
                                    "threat_actors": list(a.threat_actors),
                                    "malware_families": list(a.malware_families),
                                    "ransomware_families": list(a.ransomware_families),
                                    "error": "",
                                    "chars": analysis.get("chars") or 0,
                                }
                    llm_cached = article_llm(a) or llm_cache.get(enrich_key) or {}
            with act3:
                status_bits = []
                if cached and cached.get("error"):
                    status_bits.append(f"⚠️ scan failed")
                elif cached:
                    status_bits.append(f"✅ scanned {cached.get('chars', 0):,} chars")
                if llm_cached.get("error"):
                    status_bits.append("🔬 research failed")
                elif llm_cached and not llm_cached.get("error"):
                    act_i = sum(1 for r in (llm_cached.get("iocs") or []) if r.get("actionable", True))
                    status_bits.append(
                        f"🔬 {act_i}/{len(llm_cached.get('iocs') or [])} IOCs · "
                        f"conf {llm_cached.get('confidence', '?')}"
                    )
                st.caption(" · ".join(status_bits) if status_bits else "RSS summary only")

            enriched = bool(cached) and not cached.get("error")
            llm_ok = bool(llm_cached) and not llm_cached.get("error")
            display_techniques = sorted(set(
                a.mitre_techniques
                + (cached.get("techniques", []) if enriched else [])
                + (llm_cached.get("techniques", []) if llm_ok else [])
            ))
            display_tactics = list(dict.fromkeys(
                a.mitre_tactics
                + (cached.get("tactics", []) if enriched else [])
                + (llm_cached.get("tactics", []) if llm_ok else [])
            ))
            display_iocs: Dict[str, List[str]] = {k: list(v) for k, v in a.iocs.items()}
            if enriched:
                for label, values in cached.get("iocs", {}).items():
                    display_iocs[label] = sorted(set(display_iocs.get(label, []) + values))[:120]
            if llm_ok:
                for row in llm_cached.get("iocs") or []:
                    if not row.get("actionable", True):
                        continue
                    label = row.get("label") or _llm_ioc_label(str(row.get("type") or "other"))
                    val = row.get("value") or ""
                    if val:
                        display_iocs[label] = sorted(set(display_iocs.get(label, []) + [val]))[:120]
            display_cta = list(dict.fromkeys(
                a.cta_signals + (cached.get("cta_signals", []) if enriched else [])
            ))
            display_actors = list(dict.fromkeys(
                a.threat_actors
                + (cached.get("threat_actors", []) if enriched else [])
                + (llm_cached.get("actors", []) if llm_ok else [])
            ))
            display_malware = list(dict.fromkeys(
                a.malware_families
                + (cached.get("malware_families", []) if enriched else [])
                + (llm_cached.get("malware", []) if llm_ok else [])
            ))
            display_ransom = list(dict.fromkeys(
                a.ransomware_families
                + (cached.get("ransomware_families", []) if enriched else [])
                + (llm_cached.get("ransomware", []) if llm_ok else [])
            ))

            with st.expander("Scoring & context", expanded=False):
                st.write(a.summary or "_No summary supplied by the feed._")
                d1, d2 = st.columns(2)
                with d1:
                    st.markdown("**Triggers**")
                    st.write(f"Stack: {', '.join(a.matched_tech) if a.matched_tech else '—'}")
                    st.write(f"Keywords: {', '.join(a.matched_keywords) if a.matched_keywords else '—'}")
                    st.write(f"Industry: {', '.join(a.matched_industry) if a.matched_industry else '—'}")
                    if a.cves:
                        st.write(f"CVEs: {', '.join(a.cves)}")
                    if a.kev_cves:
                        st.markdown("**CISA KEV**")
                        catalog = (results.get("kev") or {}).get("cves") or {}
                        for cve in a.kev_cves:
                            meta = catalog.get(cve) or {}
                            due = f" · due {meta['due_date']}" if meta.get("due_date") else ""
                            st.write(
                                f"- [{cve}](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)"
                                f"{due}"
                            )
                    if display_actors or display_malware or display_ransom:
                        if display_actors:
                            st.write(f"Actors: {', '.join(display_actors)}")
                        if display_ransom:
                            st.write(f"Ransomware: {', '.join(display_ransom)}")
                        if display_malware:
                            st.write(f"Malware: {', '.join(display_malware)}")
                    if a.correlated_sources:
                        st.write(f"Corroborated by: {', '.join(a.correlated_sources)}")
                with d2:
                    st.markdown(f"**{a.recommendation}**")
                    if a.breakdown:
                        st.dataframe(
                            pd.DataFrame([{"Factor": k, "Value": v} for k, v in a.breakdown.items()]
                                         + [{"Factor": "Final score", "Value": a.score}]),
                            hide_index=True, **STRETCH, height=220,
                        )

            with st.expander("IOCs & ATT&CK", expanded=bool(display_iocs or display_techniques)):
                d3, d4 = st.columns(2)
                with d3:
                    st.markdown("**ATT&CK**")
                    if display_techniques:
                        st.markdown(", ".join(
                            f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)"
                            for t in display_techniques
                        ))
                    else:
                        st.caption("No techniques yet — run Deep-scan or AI research.")
                    if display_tactics:
                        st.caption("Tactics: " + ", ".join(display_tactics))
                    st.markdown("**Actions**")
                    st.write(f"- {a.recommendation}")
                    for s in display_cta[:6]:
                        st.write(f"- {s.capitalize()}")
                    if llm_ok:
                        for s in (llm_cached.get("recommended_actions") or [])[:6]:
                            st.write(f"- {s}")
                with d4:
                    st.markdown("**IOCs**")
                    if display_iocs:
                        for label, values in display_iocs.items():
                            st.write(f"*{label}:* {', '.join(values[:40])}"
                                     + (f" (+{len(values)-40})" if len(values) > 40 else ""))
                    else:
                        st.caption("No IOCs yet — run Deep-scan or AI research.")

            if llm_ok or llm_cached.get("error"):
                with st.expander(
                    "🔬 AI deep-research findings",
                    expanded=llm_ok and bool(llm_cached.get("iocs")),
                ):
                    if llm_cached.get("error"):
                        st.error(llm_cached["error"])
                    else:
                        st.markdown(llm_cached.get("summary") or "_No summary._")
                        if llm_cached.get("threat_assessment"):
                            st.caption(llm_cached["threat_assessment"])
                        meta_bits = []
                        if llm_cached.get("campaign"):
                            meta_bits.append(f"**Campaign:** {llm_cached['campaign']}")
                        if llm_cached.get("victimology"):
                            meta_bits.append(f"**Victimology:** {llm_cached['victimology']}")
                        if llm_cached.get("kill_chain"):
                            meta_bits.append("**Kill chain:** " + " → ".join(llm_cached["kill_chain"]))
                        if llm_cached.get("tools"):
                            meta_bits.append("**Tools:** " + ", ".join(llm_cached["tools"]))
                        if meta_bits:
                            st.markdown(" · ".join(meta_bits))
                        ioc_rows = llm_cached.get("iocs") or []
                        if ioc_rows:
                            st.dataframe(
                                pd.DataFrame([
                                    {
                                        "IOC": r.get("value", ""),
                                        "Type": r.get("label") or r.get("type", ""),
                                        "Confidence": r.get("confidence", ""),
                                        "Actionable": "yes" if r.get("actionable", True) else "no",
                                        "Context": r.get("context", ""),
                                    }
                                    for r in ioc_rows
                                ]),
                                hide_index=True, **STRETCH,
                                height=min(420, 48 + 36 * min(len(ioc_rows), 10)),
                            )
                        if llm_cached.get("hunt_queries"):
                            st.markdown("**Hunt ideas**")
                            for q in llm_cached["hunt_queries"]:
                                st.code(q, language="text")
                        if llm_cached.get("research_gaps") or llm_cached.get("false_positives_filtered"):
                            gcol, ncol = st.columns(2)
                            with gcol:
                                if llm_cached.get("research_gaps"):
                                    st.caption("Gaps: " + "; ".join(llm_cached["research_gaps"][:5]))
                            with ncol:
                                if llm_cached.get("false_positives_filtered"):
                                    st.caption(
                                        "Filtered noise: "
                                        + ", ".join(llm_cached["false_positives_filtered"][:8])
                                    )
                        st.caption(
                            f"`{llm_cached.get('model', '?')}` · "
                            f"{llm_cached.get('chars', 0):,} chars · "
                            f"chunks {llm_cached.get('chunks_analysed', 1)}/"
                            f"{llm_cached.get('chunks_total', 1)}"
                        )

            # Second pass after the card finishes rendering (layout may have shifted).
            if st.session_state.get("_scroll_anchor") == anchor_id:
                _scroll_to_article(anchor_id)
                st.session_state.pop("_scroll_anchor", None)

            st.divider()

    with tab_landscape:
        st.markdown('<div class="sf-section">Corpus threat landscape</div>', unsafe_allow_html=True)
        st.caption("Aggregated signals from this run — for the daily intel standup.")

        actor_counter: Counter = Counter()
        malware_counter: Counter = Counter()
        ransom_counter: Counter = Counter()
        cve_counter: Counter = Counter()
        tech_counter: Counter = Counter()
        tactic_counter: Counter = Counter()
        for a in articles:
            actor_counter.update(a.threat_actors)
            malware_counter.update(a.malware_families)
            ransom_counter.update(a.ransomware_families)
            cve_counter.update(a.cves)
            tech_counter.update(a.mitre_techniques)
            tactic_counter.update(a.mitre_tactics)

        l1, l2, l3, l4 = st.columns(4)
        l1.metric("Distinct CVEs", len(cve_counter))
        l2.metric("Threat actors", len(actor_counter))
        l3.metric("Malware families", len(malware_counter))
        l4.metric("Ransomware families", len(ransom_counter))

        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("#### Top threat actors")
            if actor_counter:
                st.dataframe(
                    pd.DataFrame(
                        [{"Actor": k, "Mentions": v} for k, v in actor_counter.most_common(20)]
                    ),
                    hide_index=True, **STRETCH,
                )
            else:
                st.write("— none detected in this window —")

            st.markdown("#### Top ransomware families")
            if ransom_counter:
                st.dataframe(
                    pd.DataFrame(
                        [{"Family": k, "Mentions": v} for k, v in ransom_counter.most_common(15)]
                    ),
                    hide_index=True, **STRETCH,
                )
            else:
                st.write("— none detected in this window —")

            st.markdown("#### ATT&CK tactics referenced")
            if tactic_counter:
                st.bar_chart(
                    pd.DataFrame(
                        [{"Tactic": k, "Mentions": v} for k, v in tactic_counter.most_common()]
                    ).set_index("Tactic")
                )
            else:
                st.write("— none detected —")

        with col_b:
            st.markdown("#### Hot CVEs (by mention count)")
            if cve_counter:
                cve_rows = []
                catalog = (results.get("kev") or {}).get("cves") or {}
                for cve, count in cve_counter.most_common(25):
                    meta = catalog.get(cve) or {}
                    cve_rows.append({
                        "CVE": cve,
                        "Mentions": count,
                        "On KEV": "YES" if cve in catalog else "",
                        "KEV ransomware": meta.get("ransomware_use", ""),
                        "Vendor": meta.get("vendor", ""),
                        "Product": meta.get("product", ""),
                        "NVD": f"https://nvd.nist.gov/vuln/detail/{cve}",
                    })
                st.dataframe(
                    pd.DataFrame(cve_rows), hide_index=True, **STRETCH,
                    column_config={"NVD": st.column_config.LinkColumn("NVD")},
                )
            else:
                st.write("— no CVEs in this window —")

            st.markdown("#### Top malware families")
            if malware_counter:
                st.dataframe(
                    pd.DataFrame(
                        [{"Family": k, "Mentions": v} for k, v in malware_counter.most_common(15)]
                    ),
                    hide_index=True, **STRETCH,
                )
            else:
                st.write("— none detected in this window —")

            st.markdown("#### ATT&CK techniques")
            if tech_counter:
                tech_rows = [
                    {
                        "Technique": t,
                        "Mentions": n,
                        "MITRE": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/",
                    }
                    for t, n in tech_counter.most_common(20)
                ]
                st.dataframe(
                    pd.DataFrame(tech_rows), hide_index=True, **STRETCH,
                    column_config={"MITRE": st.column_config.LinkColumn("MITRE")},
                )
            else:
                st.write("— none detected —")

        with st.expander("KEV CVEs in this run", expanded=bool(kev_hits)):
            if kev_hits:
                catalog = (results.get("kev") or {}).get("cves") or {}
                kev_rows = []
                seen_kev: Set[str] = set()
                for a in kev_hits:
                    for cve in a.kev_cves:
                        if cve in seen_kev:
                            continue
                        seen_kev.add(cve)
                        meta = catalog.get(cve) or {}
                        kev_rows.append({
                            "CVE": cve,
                            "Name": meta.get("name", ""),
                            "Vendor": meta.get("vendor", ""),
                            "Product": meta.get("product", ""),
                            "Date added": meta.get("date_added", ""),
                            "Due date": meta.get("due_date", ""),
                            "Ransomware use": meta.get("ransomware_use", ""),
                            "Required action": (meta.get("required_action") or "")[:120],
                        })
                st.dataframe(pd.DataFrame(kev_rows), hide_index=True, **STRETCH)
            else:
                st.caption("No CISA KEV CVEs in this look-back window.")

        with st.expander("Cross-source corroborations", expanded=False):
            corr = [a for a in articles if a.correlated_sources]
            if corr:
                corr_df = pd.DataFrame([
                    {
                        "Score": a.score,
                        "Title": a.title,
                        "Primary source": a.source_name,
                        "Also seen in": ", ".join(a.correlated_sources),
                        "CVEs": ", ".join(a.cves),
                        "Link": a.link,
                    }
                    for a in sorted(corr, key=lambda x: x.score, reverse=True)[:40]
                ])
                st.dataframe(corr_df, hide_index=True, **STRETCH,
                             column_config={"Link": st.column_config.LinkColumn("Link")})
            else:
                st.caption("No multi-source corroborations in this window.")

        with st.expander("IOC export (corpus-wide)", expanded=False):
            enrichment_cache = st.session_state.setdefault("_enrichment_cache", {})
            llm_cache = st.session_state.setdefault("_llm_cache", {})
            all_iocs = collect_all_iocs(articles, enrichment_cache, llm_cache)
            if all_iocs:
                total_iocs = sum(len(v) for v in all_iocs.values())
                st.caption(f"{total_iocs} unique indicators across {len(all_iocs)} types.")
                ioc_json = json.dumps(all_iocs, indent=2)
                ioc_lines = []
                for label, values in all_iocs.items():
                    for v in values:
                        ioc_lines.append(f"{label}\t{v}")
                x1, x2, x3 = st.columns(3)
                stamp = results["generated"].strftime("%Y%m%d-%H%M")
                x1.download_button("📥 IOCs (JSON)", ioc_json,
                                   file_name=f"sentinel-iocs-{stamp}.json",
                                   mime="application/json", **STRETCH)
                x2.download_button("📥 IOCs (TSV)", "\n".join(ioc_lines),
                                   file_name=f"sentinel-iocs-{stamp}.tsv",
                                   mime="text/tab-separated-values", **STRETCH)
                exclude_links = {a.link for a in articles if a.link}
                wazuh_entries = normalize_iocs_for_wazuh(all_iocs, exclude_urls=exclude_links)
                cdb_preview = build_wazuh_cdb(wazuh_entries, stamp=results["generated"].isoformat())
                x3.download_button("🖥️ Wazuh CDB", cdb_preview,
                                   file_name=f"{st.session_state.get('wazuh_list_name', WAZUH_DEFAULT_LIST)}.cdb.txt",
                                   mime="text/plain", **STRETCH)
            else:
                st.caption("No IOCs yet — run Deep-scan or AI research on priority items.")

    with tab_siem:
        st.markdown('<div class="sf-section">Wazuh SIEM push</div>', unsafe_allow_html=True)
        st.caption("Upload harvested IOCs to a Wazuh CDB list. Configure connection in the sidebar.")

        enrichment_cache = st.session_state.setdefault("_enrichment_cache", {})
        llm_cache = st.session_state.setdefault("_llm_cache", {})
        all_iocs = collect_all_iocs(articles, enrichment_cache, llm_cache)
        exclude_links = {a.link for a in articles if a.link}
        wazuh_entries = normalize_iocs_for_wazuh(all_iocs, exclude_urls=exclude_links)
        stamp = results["generated"].isoformat()
        cdb_body = build_wazuh_cdb(wazuh_entries, stamp=stamp)

        type_counts = Counter(label for _, label in wazuh_entries)
        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Ready for Wazuh", len(wazuh_entries))
        s2.metric("Hashes", sum(type_counts[t] for t in type_counts if "SHA" in t or t == "MD5"))
        s3.metric("IPs / hosts", type_counts.get("IPv4", 0) + sum(
            v for k, v in type_counts.items() if "host" in k or k == "Defanged indicator"))
        s4.metric("URLs / other", max(0, len(wazuh_entries) - (
            sum(type_counts[t] for t in type_counts if "SHA" in t or t == "MD5")
            + type_counts.get("IPv4", 0))))

        if not wazuh_entries:
            st.warning(
                "No usable IOCs yet. Run an analysis with **Deep-scan top N** > 0, or open "
                "individual items and click **🔍 Deep-scan full article**."
            )
        else:
            st.markdown(
                f"Target list: `{st.session_state.get('wazuh_list_name', WAZUH_DEFAULT_LIST)}` · "
                f"API: `{st.session_state.get('wazuh_url', '')}`"
            )
            with st.expander("CDB preview (what will be uploaded)", expanded=False):
                st.code(cdb_body[:6000] + ("\n…\n" if len(cdb_body) > 6000 else ""), language="text")

            push_col, tip_col = st.columns([1.2, 2])
            with push_col:
                push = st.button(
                    "🚀 Push IOCs to Wazuh",
                    type="primary",
                    **STRETCH,
                    help="Authenticate to the Wazuh API, upload the CDB list, optionally restart the manager.",
                )
            with tip_col:
                st.caption(
                    "After upload, reference the list in a Wazuh rule, e.g. "
                    f"`<list field=\"url\">etc/lists/{st.session_state.get('wazuh_list_name', WAZUH_DEFAULT_LIST)}</list>` "
                    "or match `srcip` / `md5` / `sha256` fields against it."
                )

            if push:
                if not st.session_state.get("wazuh_password"):
                    st.error("Set the Wazuh API password in the sidebar first.")
                else:
                    with st.spinner("Authenticating and uploading CDB list to Wazuh…"):
                        ok, msg = wazuh_push_iocs(
                            st.session_state["wazuh_url"],
                            st.session_state["wazuh_user"],
                            st.session_state["wazuh_password"],
                            st.session_state.get("wazuh_list_name") or WAZUH_DEFAULT_LIST,
                            cdb_body,
                            verify_ssl=bool(st.session_state.get("wazuh_verify_ssl")),
                            restart_manager=bool(st.session_state.get("wazuh_restart", True)),
                            timeout=max(20, int(st.session_state.get("timeout") or DEFAULT_TIMEOUT)),
                        )
                    if ok:
                        st.success(msg)
                        st.toast("IOCs pushed to Wazuh", icon="🖥️")
                        st.session_state["_wazuh_last_push"] = {
                            "at": datetime.now(PH_TZ).isoformat(),
                            "count": len(wazuh_entries),
                            "list": st.session_state.get("wazuh_list_name"),
                            "msg": msg,
                        }
                    else:
                        st.error(msg)
                        st.info(
                            "If the API is unreachable, download the **🖥️ Wazuh CDB** file from the "
                            "Threat landscape tab and copy it to "
                            f"`/var/ossec/etc/lists/{st.session_state.get('wazuh_list_name', WAZUH_DEFAULT_LIST)}` "
                            "on the manager, then run `wazuh-control restart`."
                        )

        last = st.session_state.get("_wazuh_last_push")
        if last:
            st.caption(
                f"Last successful push: {last.get('count', 0)} indicators → "
                f"`{last.get('list')}` at {last.get('at', '')}"
            )

        st.markdown("#### How the integration works")
        st.markdown(
            """
            1. Sentinel Feed extracts IOCs from RSS summaries, deep-scans, and optional **LLM enrichment**
               (context-aware, actionable-only indicators).
            2. Indicators are **refanged**, de-duplicated and scrubbed of private/bogus noise.
            3. Clicking **Push** authenticates to the Wazuh Manager API (`/security/user/authenticate`),
               uploads a CDB list via `PUT /lists/files/<name>`, and optionally restarts the manager.
            4. Use that CDB list in decoder/rule `<list>` lookups for real-time matching in your SIEM.
            """
        )

    with tab_health:
        st.subheader("📡 Per-feed collection status")
        if failed_feeds:
            st.warning(
                f"{len(failed_feeds)} of {len(health)} feeds were unreachable this run "
                "(bot filters, retired RSS, or rate limits). Deselect noisy ones in the sidebar "
                "if they stay down."
            )
        else:
            st.success(f"All {len(health)} monitored feeds returned data.")
        health_df = pd.DataFrame([
            {
                "Status": "OK" if h.ok else "Issue",
                "Feed": h.source.name,
                "Category": h.source.category,
                "Items": h.entries,
                "Latency (ms)": h.latency_ms,
                "Cached": h.from_cache,
                "Authority": h.source.authority,
                "Detail": (_friendly_feed_error(h.error) if h.error else (h.feed_title or "—")),
                "URL": h.source.url,
            }
            for h in sorted(health, key=lambda x: (x.ok, x.source.category, x.source.name))
        ])
        st.dataframe(health_df, hide_index=True, **STRETCH,
                     column_config={"URL": st.column_config.LinkColumn("URL")})

        st.subheader("Volume by category")
        if articles:
            counts = pd.DataFrame(
                [{"Category": a.category, "Items": 1} for a in articles]
            ).groupby("Category", as_index=True).sum()
            st.bar_chart(counts)

    with tab_data:
        table = pd.DataFrame([
            {
                "Score": a.score,
                "Band": band_of(a.recommendation),
                "Published (UTC)": a.published.strftime("%Y-%m-%d %H:%M") if a.published else "",
                "Title": a.title,
                "Source": a.source_name,
                "Category": a.category,
                "Stack triggers": ", ".join(a.matched_tech),
                "Keywords": ", ".join(a.matched_keywords),
                "CVEs": ", ".join(a.cves),
                "KEV": ", ".join(a.kev_cves),
                "Actors": ", ".join(a.threat_actors),
                "Malware": ", ".join(a.malware_families),
                "Ransomware": ", ".join(a.ransomware_families),
                "Corroborated by": ", ".join(a.correlated_sources),
                "Recommendation": a.recommendation,
                "Link": a.link,
            }
            for a in articles
        ])
        st.dataframe(table, hide_index=True, **STRETCH, height=520,
                     column_config={"Link": st.column_config.LinkColumn("Link")})

        csv_buf = io.StringIO()
        table.to_csv(csv_buf, index=False)
        stamp = results["generated"].strftime("%Y%m%d-%H%M")

        lines = [
            f"# Threat Intelligence Brief — {results['generated'].strftime('%d %B %Y %H:%M UTC')}",
            "",
            f"**Profile:** {results['industry']}  ",
            f"**Sources:** {len(ok_feeds)} healthy of {len(health)} monitored  ",
            f"**Items scored:** {len(articles)} · **High relevance:** {len(high)}",
            "",
            "## Latest items",
            "",
        ]
        for a in articles[:25]:
            lines.append(f"### [{a.score:g}] {a.title}")
            lines.append(f"*{a.source_name} · "
                         f"{a.published.strftime('%d %b %Y') if a.published else 'date unknown'} · "
                         f"{a.recommendation}*")
            if a.matched_tech:
                lines.append(f"**Stack triggers:** {', '.join(a.matched_tech)}")
            if a.kev_cves:
                lines.append(f"**CISA KEV:** {', '.join(a.kev_cves)}")
            if a.cves:
                lines.append(f"**CVEs:** {', '.join(a.cves)}")
            if a.threat_actors:
                lines.append(f"**Actors:** {', '.join(a.threat_actors)}")
            if a.ransomware_families:
                lines.append(f"**Ransomware:** {', '.join(a.ransomware_families)}")
            if a.correlated_sources:
                lines.append(f"**Also reported by:** {', '.join(a.correlated_sources)}")
            lines.append("")
            lines.append(a.summary[:400] if a.summary else "_No summary._")
            lines.append("")
            if a.link:
                lines.append(f"<{a.link}>")
            lines.append("")

        e1, e2 = st.columns(2)
        e1.download_button("Download CSV", csv_buf.getvalue(),
                           file_name=f"sentinel-feed-{stamp}.csv", mime="text/csv",
                           **STRETCH)
        e2.download_button("Download Markdown brief", "\n".join(lines),
                           file_name=f"sentinel-brief-{stamp}.md", mime="text/markdown",
                           **STRETCH)

    with tab_report:
        st.subheader("Single-article report builder")
        if not articles:
            st.info("Run an analysis first.")
        else:
            labels = [f"[{a.score:g}] {a.title} — {a.source_name}" for a in articles]
            choice_idx = st.selectbox(
                "Choose an article",
                options=list(range(len(articles))),
                format_func=lambda i: labels[i],
            )
            sel = articles[choice_idx]

            enrichment_cache = st.session_state.setdefault("_enrichment_cache", {})
            llm_cache = st.session_state.setdefault("_llm_cache", {})
            enrich_key = sel.link or f"title::{sel.title}"
            cached = enrichment_cache.get(enrich_key)
            enriched = bool(cached) and not cached.get("error")
            llm_cached = article_llm(sel) or llm_cache.get(enrich_key) or {}
            llm_ok = bool(llm_cached) and not llm_cached.get("error")

            techniques = sorted(set(
                sel.mitre_techniques
                + (cached.get("techniques", []) if enriched else [])
                + (llm_cached.get("techniques", []) if llm_ok else [])
            ))
            tactics = list(dict.fromkeys(
                sel.mitre_tactics
                + (cached.get("tactics", []) if enriched else [])
                + (llm_cached.get("tactics", []) if llm_ok else [])
            ))
            iocs: Dict[str, List[str]] = {k: list(v) for k, v in sel.iocs.items()}
            if enriched:
                for label, values in cached.get("iocs", {}).items():
                    iocs[label] = sorted(set(iocs.get(label, []) + values))[:25]
            if llm_ok:
                for row in llm_cached.get("iocs") or []:
                    if not row.get("actionable", True):
                        continue
                    label = row.get("label") or _llm_ioc_label(str(row.get("type") or "other"))
                    val = row.get("value") or ""
                    if val:
                        iocs[label] = sorted(set(iocs.get(label, []) + [val]))[:40]
            cta_hits = list(dict.fromkeys(sel.cta_signals + (cached.get("cta_signals", []) if enriched else [])))
            actors = list(dict.fromkeys(
                sel.threat_actors
                + (cached.get("threat_actors", []) if enriched else [])
                + (llm_cached.get("actors", []) if llm_ok else [])
            ))
            malware = list(dict.fromkeys(
                sel.malware_families
                + (cached.get("malware_families", []) if enriched else [])
                + (llm_cached.get("malware", []) if llm_ok else [])
            ))
            ransom = list(dict.fromkeys(
                sel.ransomware_families
                + (cached.get("ransomware_families", []) if enriched else [])
                + (llm_cached.get("ransomware", []) if llm_ok else [])
            ))

            if not enriched and not llm_ok:
                st.caption("Tip: run **🔍 Deep-scan** and/or **🔬 AI deep-research IOCs** on this item "
                           "in Prioritised intel first for richer IOC / ATT&CK data.")

            exec_summary = build_executive_summary(sel)

            st.markdown("### Executive summary")
            st.markdown(exec_summary)
            if llm_ok and llm_cached.get("summary"):
                st.markdown("### 🤖 LLM analyst brief")
                st.markdown(llm_cached["summary"])
                if llm_cached.get("threat_assessment"):
                    st.caption(llm_cached["threat_assessment"])

            r1, r2 = st.columns(2)
            with r1:
                st.markdown("### MITRE ATT&CK techniques")
                if techniques:
                    st.markdown(", ".join(
                        f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)" for t in techniques
                    ))
                else:
                    st.write("— none detected —")
                st.markdown("### TTPs (tactics referenced)")
                st.write(", ".join(tactics) if tactics else "— none detected —")
                st.markdown("### Threat identity")
                st.write(f"*Actors:* {', '.join(actors) if actors else '—'}")
                st.write(f"*Ransomware:* {', '.join(ransom) if ransom else '—'}")
                st.write(f"*Malware:* {', '.join(malware) if malware else '—'}")
                if sel.kev_cves:
                    st.markdown("### CISA KEV")
                    st.write(", ".join(sel.kev_cves))
            with r2:
                st.markdown("### Indicators of Compromise (IOCs)")
                if iocs:
                    for label, values in iocs.items():
                        st.write(f"*{label}:* {', '.join(values)}")
                else:
                    st.write("— none detected —")

            st.markdown("### Call to action")
            suggested_lines = [f"- {sel.recommendation}"]
            for s in cta_hits:
                suggested_lines.append(f"- {s.capitalize()} (mentioned in source)")
            if sel.kev_cves:
                suggested_lines.append(
                    f"- Prioritise remediation for KEV CVE(s) {', '.join(sel.kev_cves)} "
                    "(CISA-confirmed exploitation)"
                )
            if sel.cves:
                suggested_lines.append(f"- Verify exposure to {', '.join(sel.cves)} and confirm patch status")
            if actors:
                suggested_lines.append(f"- Hunt for TTPs associated with {', '.join(actors)}")
            cta_text = st.text_area(
                "Suggested — edit before exporting",
                value="\n".join(suggested_lines),
                height=150,
                key=f"cta_edit_{enrich_key}",
            )

            report_lines = [
                f"# Threat Intel Report — {sel.title}",
                "",
                f"*{sel.source_name} · {sel.category} · "
                f"{sel.published.strftime('%d %b %Y') if sel.published else 'date unknown'} · "
                f"Score {sel.score:g}/100 ({band_of(sel.recommendation)})*",
                "",
            ]
            if sel.link:
                report_lines += [f"Link: {sel.link}", ""]
            report_lines += [
                "## Executive summary", "", exec_summary, "",
                "## Threat identity", "",
                f"- **Actors:** {', '.join(actors) if actors else 'None detected'}",
                f"- **Ransomware:** {', '.join(ransom) if ransom else 'None detected'}",
                f"- **Malware:** {', '.join(malware) if malware else 'None detected'}",
                f"- **CISA KEV:** {', '.join(sel.kev_cves) if sel.kev_cves else 'None'}",
                "",
                "## MITRE ATT&CK techniques", "",
                ", ".join(techniques) if techniques else "None detected", "",
                "## TTPs (tactics referenced)", "",
                ", ".join(tactics) if tactics else "None detected", "",
                "## Indicators of Compromise (IOCs)", "",
            ]
            if iocs:
                report_lines += [f"- **{label}:** {', '.join(values)}" for label, values in iocs.items()]
            else:
                report_lines.append("None detected")
            report_lines += ["", "## Call to action", "", cta_text, ""]

            stamp = results["generated"].astimezone(PH_TZ).strftime("%Y%m%d-%H%M")
            st.download_button(
                "Download report (Markdown)",
                "\n".join(report_lines),
                file_name=f"sentinel-report-{stamp}.md",
                mime="text/markdown",
                **STRETCH,
            )
