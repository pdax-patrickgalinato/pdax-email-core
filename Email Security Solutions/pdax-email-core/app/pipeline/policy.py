"""Policy layer — maps red_flags to the 6 TMES-parity categories (see
rules/policy.yaml) and enforces which categories are allowed to contribute to
scoring/hard-overrides. Built as a categorization of app/report.py's
_FLAG_DESCRIPTIONS/_FLAG_PREFIX_DESCRIPTIONS catalogue so the two never drift
apart — every time a new flag is added to report.py's translation layer,
check whether it also needs a home here.

Not every flag belongs to one of the 6 categories. Sender/header
authentication signals (spf_*, dkim_*, dmarc_*, return_path_mismatch,
lookalike_of, vip_name_spoof, ...), the BEC/phishing content heuristics
(urgency_language, credential_request, bec_pattern, ...), and the
bec_vip_impersonation hard override are deliberately left ungated — TMES's 6
categories don't have a slot for "sender identity" or "phishing content" as
distinct concepts, and CLAUDE.md's architecture invariant doesn't require
everything to be categorized, only that the categories that DO exist gate the
right flags.
"""
from __future__ import annotations

from typing import Optional

# {category: {"exact": {flag, ...}, "prefix": {prefix, ...}}}
# "exact" matches the full flag string; "prefix" matches flag.split(":")[0]
# (the same convention app/report.py's _FLAG_PREFIX_DESCRIPTIONS already
# uses for "flag:value"-shaped tags).
CATEGORY_FLAG_MATCH: dict = {
    "malware_scanning": {
        "exact": {"macro_capable_doc", "html_attachment_credential_form"},
        "prefix": {"macro_capable_doc", "office_macro", "static_severity", "forensics"},
    },
    "file_blocking": {
        "exact": {"banned_attachment_type", "spoofed_attachment_type",
                  "double_extension_executable"},
        "prefix": {"banned_attachment", "spoofed_attachment_type",
                   "double_extension_executable"},
    },
    "web_reputation": {
        "exact": {"anchor_href_mismatch", "url_embedded_redirect",
                  "url_ip_literal", "url_brand_keyword_offbrand",
                  "url_deep_subdomain", "url_oauth_state_email_exposure",
                  "url_redirect_unrelated_domain", "url_redirect_to_page_file",
                  "url_redirect_to_ip", "url_lookalike_domain"},
        "prefix": {"url_lookalike", "url_risky_tld", "domain_age"},
    },
    "correlated_intelligence": {
        "exact": {"threat_intel_hit"},
        "prefix": {"intel_domain", "intel_ip", "intel_url", "intel_hash",
                   "correlation_seen_before"},
    },
    "advanced_spam_protection": {
        "exact": {"bulk_sender_no_unsubscribe"},
        "prefix": {"bulk"},
    },
    "virtual_analyzer": {
        "exact": set(),
        "prefix": {"sandbox"},
    },
}

ALL_CATEGORIES = tuple(CATEGORY_FLAG_MATCH.keys())

# Defaults used when rules/policy.yaml is missing, or missing a category key.
# Mirrors the yaml file's own comment: everything on except virtual_analyzer,
# which has no real capability behind it yet.
_DEFAULT_ENABLED = {c: True for c in ALL_CATEGORIES}
_DEFAULT_ENABLED["virtual_analyzer"] = False


def _matches_prefix(flag: str, prefix: str) -> bool:
    """A registered "prefix" matches either a colon-value tag (url_lookalike
    in "url_lookalike:pdax.ph") or an underscore-joined tag with no value
    (forensics in "forensics_type_mismatch") — this codebase uses both
    shapes for different flags, so both need to match here."""
    return flag == prefix or flag.startswith(prefix + ":") or flag.startswith(prefix + "_")


def category_for_flag(flag: str) -> Optional[str]:
    """Which of the 6 TMES categories owns this flag, or None if it's
    ungated (sender/header/content-AI signals — see module docstring)."""
    for category, match in CATEGORY_FLAG_MATCH.items():
        if flag in match["exact"] or any(_matches_prefix(flag, p) for p in match["prefix"]):
            return category
    return None


def is_enabled(policy_cfg: Optional[dict], category: str) -> bool:
    """policy_cfg=None means "everything enabled" — the default for every
    existing call site that doesn't opt into policy gating."""
    if policy_cfg is None:
        return True
    categories = policy_cfg.get("categories", {})
    entry = categories.get(category)
    if entry is None:
        return _DEFAULT_ENABLED.get(category, True)
    return bool(entry.get("enabled", _DEFAULT_ENABLED.get(category, True)))


def filter_flags(flags: list, policy_cfg: Optional[dict]) -> tuple:
    """Splits flags into (active, suppressed) based on policy_cfg. A flag
    belonging to a disabled category is suppressed; an ungated flag, or one
    belonging to an enabled category, stays active. Suppressed flags are
    still returned (tagged by the caller) so they remain visible in the
    audit trail — see rules/policy.yaml's module comment."""
    if policy_cfg is None:
        return list(flags), []
    active, suppressed = [], []
    for flag in flags:
        category = category_for_flag(flag)
        if category is not None and not is_enabled(policy_cfg, category):
            suppressed.append(flag)
        else:
            active.append(flag)
    return active, suppressed
