"""Shared schemas. Every stage returns one of these; the runner assembles
them into a PipelineResult. Transport-agnostic: the same models are produced
whether the raw email came from the Gmail API (POC) or the SMTP hold queue
(gateway)."""
from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class Disposition(str, Enum):
    """Post-verdict gateway action. Derived deterministically from Verdict
    (see backend/disposition.py + backend/policy/detection/disposition.yaml) — never set by AI."""
    DELIVER = "DELIVER"           # release to mailbox
    LOG = "LOG"                   # deliver, but keep an audit trail
    QUARANTINE = "QUARANTINE"     # hold out of the inbox (reversible)
    REJECT = "REJECT"             # SMTP reject / drop (irreversible — shadow first)


class EnforceMode(str, Enum):
    """How aggressively EnforcementClient may act. Shadow is the default
    until reject FP≈0 on real traffic (handoff.md P3 #10)."""
    SHADOW = "shadow"             # log intended action; always release
    QUARANTINE = "quarantine"     # actually quarantine; never hard-reject
    REJECT = "reject"             # quarantine SUSPICIOUS; may REJECT MALICIOUS


class StageStatus(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"      # stage ran but an enrichment source was unavailable
    SKIPPED = "skipped"        # stage intentionally not run (e.g. no URLs present)
    ERROR = "error"


class StageResult(BaseModel):
    stage: str
    status: StageStatus = StageStatus.OK
    sub_score: float = 0.0             # 0..100 risk contributed by this stage
    red_flags: list[str] = Field(default_factory=list)
    facts: dict = Field(default_factory=dict)
    latency_ms: int = 0


class HeaderFacts(BaseModel):
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    dmarc_policy: str = "none"         # none|quarantine|reject (from p= if seen)
    dmarc_aligned: Optional[bool] = None
    from_domain: str = ""
    return_path_domain: str = ""
    reply_to_domain: str = ""
    return_path_mismatch: bool = False
    reply_to_divergent: bool = False
    reply_to_freemail: bool = False
    message_id_domain: str = ""
    # Advanced Spam Protection (TMES policy parity) — bulk-mail signals,
    # distinct from the auth/spoofing facts above.
    has_list_unsubscribe: bool = False
    list_unsubscribe_one_click: bool = False   # RFC 8058
    precedence_bulk: bool = False
    has_list_id: bool = False
    # Extended header signals
    display_name_domain_impersonation: bool = False
    missing_message_id: bool = False
    missing_mime_version: bool = False
    date_anomaly: str = ""          # "" | "future" | "stale"
    suspicious_x_mailer: bool = False
    x_mailer_value: str = ""
    max_hop_delay_hours: float = 0.0


class IOCSet(BaseModel):
    sender_emails: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)               # public IPs only — URL IP-literals + Received-chain hops
    urls: list[str] = Field(default_factory=list)
    hashes_sha256: list[str] = Field(default_factory=list)
    subjects: list[str] = Field(default_factory=list)
    authenticated_relay_senders: list[str] = Field(default_factory=list)  # "Authenticated sender:" accounts from Received headers


class PipelineResult(BaseModel):
    message_id: str = ""
    source: str = "unknown"           # gmail_api | smtp_hold | file
    subject: str = ""
    from_header: str = ""
    to_header: str = ""
    verdict: Verdict = Verdict.CLEAN
    composite_score: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    hard_override: Optional[str] = None
    thresholds: dict = Field(default_factory=dict)   # {"malicious":70,"suspicious":45,"low":20} — lets reports show margin-to-next-verdict
    stages: list[StageResult] = Field(default_factory=list)
    iocs: IOCSet = Field(default_factory=IOCSet)
    # Named detection rules that fired — mirrors Sublime Security's "Matched Feed Rules".
    # Populated by detection_rules.match_rules() after scoring. Each entry:
    # {"id": str, "name": str, "description": str, "severity": str, "tags": list}
    matched_rules: list[dict] = Field(default_factory=list)

    # Multi-threat classification from the AI content stage (nlu_intent): the
    # attack class this email belongs to — phishing/credential_theft, bec,
    # malware_delivery, ransomware, extortion, callback_scam, steal_pii,
    # reconnaissance, job_scam, or "none". Advisory label surfaced to analysts;
    # a high-confidence value can also floor the verdict up (see verdict.py).
    threat_class: str = "none"
    threat_confidence: float = 0.0

    # Tier-2 deep forensic report (eml_analysis_agent), auto-attached by the
    # gateway consumer only for flagged mail (SUSPICIOUS/MALICIOUS). None when
    # not run (clean mail) or unavailable. Shape: {status, markdown, analysis,
    # playbook} — see workers/pipeline/deep_analysis.py.
    deep_analysis: Optional[dict] = None

    # Post-verdict enforcement intent (filled by disposition.apply after scoring).
    disposition: Disposition = Disposition.DELIVER
    disposition_reason: str = ""
    enforce_mode: EnforceMode = EnforceMode.SHADOW
    # What the EnforcementClient actually did (shadow always "released").
    enforcement_applied: str = ""     # shadow_release | quarantined | rejected | delivered | noop

    def stage(self, name: str) -> Optional[StageResult]:
        return next((s for s in self.stages if s.stage == name), None)
