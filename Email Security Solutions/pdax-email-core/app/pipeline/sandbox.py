"""Stage — Virtual Analyzer (TMES policy parity).

Integration-point-only, deliberately: no real sandbox/detonation capability
exists here or anywhere else in this repo. Mirrors content_ai.py's
ContentProvider Protocol pattern exactly (a Protocol interface + an honest
no-op default + an env-var-selected factory) so a real provider can be
dropped in later without a design change, and so the rest of the pipeline
already has something to call.

Why not build a real one now: HANDOFF.md already records a deliberate
decision against ever sending PDAX documents to a third-party public
detonation service, citing RA 10173 (Philippine Data Privacy Act) — the
same data-residency posture that governs GeminiProvider/GLMProvider needing
explicit DPO sign-off before touching real mail. When this becomes real,
the two realistic paths are:
  (a) self-hosted CAPEv2/Cuckoo on PDAX-controlled infrastructure — free/
      open-source, keeps documents in-house, matches the RA 10173 stance
      already on record; real infra/ops burden to stand up and maintain.
  (b) a data-residency-compliant hosted vendor — needs the same explicit
      DPO sign-off GeminiProvider/GLMProvider already required before
      touching real mail, not assumed.
Neither is built here — this module only defines the shape a future
SandboxProvider must satisfy.

Architecture invariant unchanged: detonate() returns (score, findings,
facts) advisory data only. verdict.py still owns every decision — a
sandbox result, real or stubbed, never sets result.verdict directly.
"""
from __future__ import annotations

import os
from typing import Protocol


class SandboxProvider(Protocol):
    def detonate(self, filename: str, content_type: str,
                 payload: bytes) -> tuple:
        """Return (score, findings, facts) — same 3-tuple contract as
        ContentProvider.analyze()/IntelClient.check()."""
        ...


class NullSandboxProvider:
    """No detonation capability. Honest zero + degraded — mirrors
    content_ai.NullProvider exactly."""

    def detonate(self, filename, content_type, payload):
        return 0.0, [], {"provider": "null_sandbox",
                         "note": "no real detonation configured — see module docstring"}


def get_default_sandbox_provider() -> SandboxProvider:
    """Selects the sandbox provider from SEG_SANDBOX_PROVIDER. Defaults to
    NullSandboxProvider — as of this writing, that's the ONLY implementation
    that exists, so this defaulting has no real effect either way yet
    (see tests/test_policy.py's virtual_analyzer no-op-baseline test)."""
    choice = os.environ.get("SEG_SANDBOX_PROVIDER", "null").strip().lower()
    if choice == "null":
        return NullSandboxProvider()
    # Unrecognized choice degrades to the safe default rather than raising —
    # same posture as every other get_default_*() factory in this codebase.
    return NullSandboxProvider()
