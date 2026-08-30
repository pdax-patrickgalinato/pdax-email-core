"""Sender-identity assessment — typical behavior, not worst email.

Copy verdicts still stand. This module decides whether a copy should paint
the From address, and how to turn a 6-month mix into CLEAN/SUSPICIOUS/MALICIOUS.
"""
from __future__ import annotations

from pathlib import Path

from backend.domainutils import registrable_domain
from backend.paths import RULES_IDENTITY

_PROTECTED_PATH = RULES_IDENTITY / "protected_domains.txt"
_ROLE_PATH = RULES_IDENTITY / "role_mailboxes.txt"

_DEFAULT_ROLES = frozenset({
    "support", "security", "noreply", "no-reply", "helpdesk",
    "abuse", "postmaster", "alerts", "notifications", "csirt", "soc",
})

_QUOTED_LURE_FLAGS = frozenset({
    "forwarded_lure", "forwarded_thread",
    "nlu_intent:bec", "nlu_intent:extortion", "nlu_intent:ransomware",
    "nlu_intent:malware_delivery",
})

_TICKET_CONTENT_FLAGS = frozenset({
    "forensics_high_entropy_content",
    "malware_delivery",
    "brand_impersonation",
    "nlu_intent:malware_delivery",
    "nlu_intent:credential_theft",
})

_OUTBOUND_BEC_FLAGS = frozenset({
    "bec_pattern", "nlu_intent:bec", "reply_to_freemail",
})

_VERDICTS = ("CLEAN", "LOW", "SUSPICIOUS", "MALICIOUS")


def _lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def load_protected_domains() -> list[str]:
    return _lines(_PROTECTED_PATH)


def load_role_localparts() -> frozenset[str]:
    extra = {p.lower().split("@", 1)[0].split("+", 1)[0] for p in _lines(_ROLE_PATH)}
    return _DEFAULT_ROLES | extra


def localpart(addr: str) -> str:
    local = (addr or "").strip().lower().split("@", 1)[0]
    return local.split("+", 1)[0]


def sender_domain(addr: str) -> str:
    raw = (addr or "").strip().lower()
    if "@" not in raw:
        return registrable_domain(raw)
    return registrable_domain(raw.split("@", 1)[-1])


def is_protected_sender(addr: str, protected: list[str] | None = None) -> bool:
    dom = sender_domain(addr)
    if not dom:
        return False
    names = {registrable_domain(p) for p in (protected if protected is not None else load_protected_domains())}
    return dom in names


def is_role_mailbox(addr: str, roles: frozenset[str] | None = None) -> bool:
    return localpart(addr) in (roles if roles is not None else load_role_localparts())


def sender_lane(addr: str, protected: list[str] | None = None) -> str:
    if is_role_mailbox(addr):
        return "role"
    if is_protected_sender(addr, protected):
        return "internal"
    return "external"


def flags_from_meta(meta: dict | None) -> list[str]:
    """Flatten spool meta reasons + compact stage flags + NLU intent."""
    meta = meta or {}
    out: list[str] = []
    for flag in meta.get("reasons") or []:
        if flag:
            out.append(str(flag))
    stages = meta.get("stages") or {}
    if isinstance(stages, dict):
        for row in stages.values():
            if not isinstance(row, dict):
                continue
            for flag in row.get("flags") or row.get("red_flags") or []:
                if flag:
                    out.append(str(flag))
            intent = str(row.get("nlu_intent") or "").strip()
            if intent and intent != "none":
                out.append(f"nlu_intent:{intent}")
    return out


def _outbound_bec(flags: set[str]) -> bool:
    """Unquoted outbound BEC — may still paint an org/role From address."""
    if flags & {"forwarded_lure", "forwarded_thread"}:
        return False
    return bool(flags & _OUTBOUND_BEC_FLAGS)


def identity_skip_reason(
    sender: str,
    mailbox: str = "",
    labels: list[str] | None = None,
    flags: list[str] | None = None,
    *,
    protected: list[str] | None = None,
) -> str:
    """Empty string means the email may paint this From address."""
    sender_n = (sender or "").strip().lower()
    mailbox_n = (mailbox or "").strip().lower()
    labels_u = {str(x).upper() for x in (labels or [])}
    flag_set = {str(f) for f in (flags or []) if f}

    if "SENT" in labels_u or (sender_n and mailbox_n and sender_n == mailbox_n):
        if _outbound_bec(flag_set):
            return ""
        return "outbound_sent"

    lure = bool(flag_set & _QUOTED_LURE_FLAGS)
    if lure and (is_protected_sender(sender_n, protected) or is_role_mailbox(sender_n)):
        return "quoted_lure"

    if is_role_mailbox(sender_n) and (flag_set & _TICKET_CONTENT_FLAGS):
        return "role_ticket_content"
    return ""


def assessment_of(verdicts: dict, *, lane: str = "external") -> str:
    """Typical-behavior label from a verdict mix.

    MALICIOUS: majority malicious, or at least 3 malicious emails at ≥20% hostility.
    SUSPICIOUS: at least 3 hostile emails at ≥5%, or a small-n majority hostile.
    Role mailboxes stay CLEAN unless identity-eligible emails themselves
    meet the hostility bar (unquoted outbound BEC). Quoted lures and ticket
    IOCs are excluded before this function runs.
    """
    emails = sum(int(verdicts.get(v) or 0) for v in _VERDICTS)
    mal = int(verdicts.get("MALICIOUS") or 0)
    sus = int(verdicts.get("SUSPICIOUS") or 0)
    hostile = mal + sus
    if emails <= 0:
        return "CLEAN"
    rate = hostile / emails
    mal_rate = mal / emails
    if (mal >= 3 and rate >= 0.20) or (mal >= 1 and mal_rate >= 0.50):
        return "MALICIOUS"
    if (hostile >= 3 and rate >= 0.05) or (emails < 5 and hostile >= 1 and rate >= 0.50):
        return "SUSPICIOUS"
    return "CLEAN"


def assessment_note(
    *,
    copies: int,
    hostile: int,
    lane: str,
    skipped: int = 0,
) -> str:
    if lane == "role":
        head = "Role mailbox — typical behavior, not worst email."
    elif lane == "internal":
        head = "Internal address — hostility rate, not a single email."
    else:
        head = "Typical behavior from the mix, not worst email."
    bits = [head]
    if copies:
        bits.append(f"{hostile} hostile / {copies} emails.")
    if skipped:
        bits.append(f"{skipped} emails excluded from identity (outbound or quoted lure).")
    return " ".join(bits)
