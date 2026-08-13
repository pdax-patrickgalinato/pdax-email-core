"""
Sentinel Feed — Company-Contextual Threat Intelligence Aggregator
=================================================================
Thin entrypoint. Domain logic and UI live under the `sentinel/` package:

    sentinel/config.py        constants, industries, categories
    sentinel/models.py        FeedSource / Article / FetchResult
    sentinel/feeds_matrix.py  RSS source catalogue
    sentinel/intel_data.py    actor/malware aliases, ATT&CK signals
    sentinel/fetch.py         HTTP + RSS parse + CISA KEV
    sentinel/scoring.py       company-contextual scoring & deep-scan
    sentinel/llm.py           AI deep-research enrichment
    sentinel/ioc_utils.py     IOC refang / Wazuh normalisation
    sentinel/wazuh.py         Wazuh Manager API push
    sentinel/settings.py      persisted sidebar settings
    sentinel/styles.py        CSS / theme
    sentinel/ui.py            Streamlit layout

Run:
    pip install streamlit feedparser requests beautifulsoup4 lxml openai google-genai
    python3 -m streamlit run app.py
"""

from __future__ import annotations

from sentinel.ui import run

run()
