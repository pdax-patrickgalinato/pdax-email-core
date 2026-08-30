"""Classify the *kind* of ask in a message, independent of sender trust.

Trusted / analyst-confirmed From addresses are a channel signal. They do not
mean this recipient has seen this request before. A first payment, access, or
account-control ask to a mailbox is the BEC-shaped abuse of a trusted tool.
"""
from __future__ import annotations

import re

from backend.stores.lists import is_trusted_saas_domain

HIGH_RISK_CLASSES = frozenset({
    "payment_request",
    "access_request",
    "account_control",
})

_LABELS = {
    "payment_request": "payment or invoice request",
    "access_request": "access or permission request",
    "account_control": "account restrict / funds-control request",
    "hr_request": "HR / manpower request",
    "settlement_task": "settlements / treasury task",
    "fraud_alert": "fraud-review task",
    "other": "unclassified request",
}

_PAYMENT = re.compile(
    r"request for payment|\brfp\b|payment request|invoice approval|"
    r"vendor (?:change|update)|wire transfer|bank (?:detail|account) change",
    re.I,
)
_ACCESS = re.compile(
    r"user access|access request|permission request|privilege (?:grant|request)|"
    r"role (?:change|request)|entitlement",
    re.I,
)
_ACCOUNT = re.compile(
    r"account restrict|unrestrict|block funds?|hold and block|"
    r"restricting request|account (?:block|hold|freeze)",
    re.I,
)
_HR = re.compile(r"manpower|mrf\b|employee request|headcount", re.I)
_SETTLE = re.compile(r"settlement|cash[- ]in|treasury|\bcwl\b", re.I)
_FRAUD = re.compile(r"fraud flag|fraud review|fraud[- ]management", re.I)
_NEW_TASK = re.compile(r"^(.+?)\s+-\s+New Task\b", re.I)


def classify_request(subject: str, body: str = "") -> str:
    """Stable request-class key from subject (and a short body prefix)."""
    subj = (subject or "").strip()
    blob = f"{subj}\n{(body or '')[:2000]}"
    if _PAYMENT.search(blob):
        return "payment_request"
    if _ACCESS.search(blob):
        return "access_request"
    if _ACCOUNT.search(blob):
        return "account_control"
    if _HR.search(blob):
        return "hr_request"
    if _SETTLE.search(blob):
        return "settlement_task"
    if _FRAUD.search(blob):
        return "fraud_alert"
    m = _NEW_TASK.search(subj)
    if m:
        slug = re.sub(r"[^a-z0-9]+", "_", m.group(1).lower()).strip("_")
        return (slug[:80] or "workflow_task")
    return "other"


def is_high_risk_request(request_class: str) -> bool:
    return (request_class or "") in HIGH_RISK_CLASSES


def request_label(request_class: str) -> str:
    cls = request_class or "other"
    return _LABELS.get(cls, cls.replace("_", " "))


def is_trusted_channel(addr: str, domain: str) -> bool:
    """Known-good From (SaaS list or analyst pack). Does not skip content analysis."""
    if is_trusted_saas_domain(domain):
        return True
    try:
        from backend.stores import feedback as feedback_mod
        info = feedback_mod.match_sender(addr or "", domain or "")
    except Exception:
        return False
    return bool(info.get("benign_sender") or info.get("benign_domain"))


def request_summary_line(
    mailbox: str,
    request_class: str,
    hist: dict | None,
    *,
    trusted: bool,
) -> str:
    hist = hist or {}
    label = request_label(request_class)
    mb = (mailbox or "").strip() or "this mailbox"
    bits = [f"this email is a {label}"]
    if trusted:
        bits.append("from a trusted/known-good channel")
    n_from = int(hist.get("prior_same_class_from_sender") or 0)
    n_any = int(hist.get("prior_same_class_any_sender") or 0)
    n_sender = int(hist.get("prior_from_sender_any_class") or 0)
    if n_from == 0:
        bits.append(f"first time this sender has dropped a {label} to {mb}")
    else:
        bits.append(f"this sender has sent a {label} to {mb} {n_from} time(s) before")
    if n_any == 0:
        bits.append(f"{mb} has never received a {label} from any scanned sender")
    if n_sender == 0:
        bits.append(f"this sender has not written to {mb} before")
    return ". ".join(bits) + "."
