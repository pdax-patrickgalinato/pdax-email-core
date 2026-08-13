"""App-wide constants and Streamlit layout helpers."""
from __future__ import annotations

import re
from datetime import timedelta, timezone

import streamlit as st

_SV = tuple(int(x) for x in re.findall(r"\d+", getattr(st, "__version__", "0.0"))[:2])
STRETCH = {"width": "stretch"} if _SV >= (1, 49) else {"use_container_width": True}

APP_NAME = "Sentinel Feed"
APP_TAGLINE = "Threat intel, filtered to what can actually hurt you."
APP_ICON = "🛡️"
USER_AGENT = (
    "Mozilla/5.0 (compatible; SentinelFeed/1.0; +local CTI aggregator; "
    "contact: security-team@internal)"
)
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 15
MAX_WORKERS = 12
CACHE_TTL_SECONDS = 900  # 15 minutes
REDDIT_CACHE_TTL_SECONDS = 7_200  # 2h — Reddit rate-limits anonymous RSS hard
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_TTL_SECONDS = 86_400  # refresh KEV at most once a day
WAZUH_DEFAULT_LIST = "sentinel-feed-iocs"
WAZUH_DEFAULT_PORT = 55000

# Philippines doesn't observe DST, so a fixed UTC+8 offset is always correct.
PH_TZ = timezone(timedelta(hours=8), name="PHT")

IND_FINTECH = "FinTech / Digital Payments"
IND_VASP = "Crypto / Virtual Asset Service Provider"
IND_BANKING = "Financial Services / Banking"
IND_HEALTH = "Healthcare / Life Sciences"
IND_RETAIL = "Retail / E-commerce"
IND_CI = "Critical Infrastructure / OT-ICS"
IND_SAAS = "SaaS / Technology"
IND_MFG = "Manufacturing / Logistics"
IND_GOV = "Government / Public Sector"
IND_ENERGY = "Energy / Utilities"
IND_TELCO = "Telecommunications"
IND_EDU = "Education / Research"
IND_GENERAL = "General / Cross-Sector"
IND_PH = "Philippines — E-Wallets, IDs & Fraud"

CAT_GOV = "Government & National CTI"
CAT_VULN = "Vulnerability Databases"
CAT_VENDOR = "Vendor Advisories"
CAT_SUPPLY = "Supply Chain & AppSec"
CAT_RESEARCH = "Global CTI & Research"
CAT_SECTOR = "Sector-Specific (Finance, Health, OT)"
CAT_PH = "Philippines — FinTech, Fraud & Cyber"

CATEGORY_ORDER = [CAT_GOV, CAT_VULN, CAT_VENDOR, CAT_SUPPLY, CAT_SECTOR, CAT_PH, CAT_RESEARCH]

INDUSTRY_OPTIONS = [
    IND_FINTECH, IND_VASP, IND_BANKING, IND_HEALTH, IND_RETAIL, IND_CI, IND_SAAS,
    IND_MFG, IND_GOV, IND_ENERGY, IND_TELCO, IND_EDU, IND_PH, IND_GENERAL,
]

DEFAULT_TECH_STACK = """Cloud: AWS, EC2, S3, IAM, CloudTrail, GuardDuty, Lambda
Identity & MDM: JumpCloud, Google Workspace, SSO, SAML, OAuth
Endpoint: macOS, Santa, Trend Micro, Vision One
SIEM / XDR: Wazuh, OpenSearch, Elastic
Network: Cloudflare, VPN, FortiGate
AppSec & Build: Python, PyPI, FastAPI, Docker, GitHub Actions, PostgreSQL
Collaboration: Slack, Telegram, Confluence, Jira"""

DEFAULT_KEYWORDS = (
    "zero-day, ransomware, RCE, supply chain, typosquatting, slopsquatting, "
    "credential dumping, infostealer, KEV, API security, phishing kit, "
    "business email compromise, malicious package, exchange hack, private key theft"
)

BAND_COLORS = {
    "Critical": "#b3261e",
    "High": "#c25e00",
    "Medium": "#8a6d00",
    "Low": "#2b6a8f",
    "Informational": "#5f6368",
}

BAND_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

