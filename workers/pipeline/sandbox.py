"""Stage — Virtual Analyzer (TMES policy parity).

Integration-point-only, deliberately: no real sandbox/detonation capability
exists here or anywhere else in this repo. Mirrors content_ai.py's
ContentProvider Protocol pattern exactly (a Protocol interface + an honest
no-op default + an env-var-selected factory) so a real provider can be
dropped in later without a design change, and so the rest of the pipeline
already has something to call.

Why not build a real one now: handoff.md already records a deliberate
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

from typing import Protocol

from backend.config import get_settings


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


class ClamAVSandboxProvider:
    """Stream-scan each attachment's bytes via a running clamd daemon.

    Integration notes:
    - In-memory only: bytes are streamed to clamd over TCP/Unix socket via
      pyclamd; files are NEVER written to disk inside SEGS.
    - Requires `pyclamd` (pip install pyclamd) and a reachable clamd instance.
      When either is missing the scan degrades gracefully rather than raising.
    - Config: SEG_CLAMD_SOCKET (preferred) or SEG_CLAMD_HOST + SEG_CLAMD_PORT.
    - ClamAV is a signature layer complementing, not replacing, the static
      forensics in app/attachment_forensics.py. Static forensics always runs
      unconditionally first; ClamAV adds a second pass for known-malware hits.
    """
    MAX_SCAN_BYTES = 20 * 1024 * 1024   # 20 MB — same cap as forensics

    def __init__(self, host: str = "localhost", port: int = 3310,
                 socket_path: str = None):
        self._host = host
        self._port = port
        self._socket = socket_path

    def _client(self):
        import pyclamd   # optional dep — ImportError surfaced in detonate()
        if self._socket:
            return pyclamd.ClamdUnixSocket(self._socket)
        return pyclamd.ClamdNetworkSocket(self._host, self._port)

    def detonate(self, filename: str, content_type: str, payload: bytes) -> tuple:
        if not payload:
            return 0.0, [], {"provider": "clamav", "result": "skipped",
                             "reason": "empty_payload"}
        if len(payload) > self.MAX_SCAN_BYTES:
            return 0.0, [], {"provider": "clamav", "result": "skipped",
                             "reason": "exceeds_size_cap",
                             "size_bytes": len(payload)}
        try:
            cd = self._client()
            result = cd.scan_stream(payload)
        except ImportError:
            return 0.0, ["clam_unavailable"], {
                "provider": "clamav", "result": "pyclamd_not_installed",
                "note": "pip install pyclamd to enable ClamAV scanning"}
        except Exception as exc:
            return 0.0, ["clam_unavailable"], {
                "provider": "clamav", "result": "unavailable",
                "error": str(exc)[:200]}

        if result is None:
            return 0.0, [], {"provider": "clamav", "result": "clean"}

        # pyclamd returns {"stream": ("FOUND", "Signature.Name")} on a hit
        _, (status, signature) = next(iter(result.items()))
        if status == "FOUND":
            return 85.0, ["clam_found"], {
                "provider": "clamav", "result": "malicious",
                "signature": signature}
        # ERROR or other unexpected statuses — don't add score, still flag it
        return 0.0, [f"clam_{status.lower()}"], {
            "provider": "clamav", "result": status.lower(), "detail": signature}


def get_default_sandbox_provider() -> SandboxProvider:
    """Selects the sandbox provider from SEG_SANDBOX_PROVIDER.

    Supported values:
      clamav  — ClamAVSandboxProvider (requires pyclamd + running clamd)
      null    — NullSandboxProvider (default, no-op)

    Any unrecognized value degrades to NullSandboxProvider rather than raising
    — same posture as every other get_default_*() factory in this codebase.
    To activate ClamAV: set SEG_SANDBOX_PROVIDER=clamav and configure
    SEG_CLAMD_SOCKET (preferred) or SEG_CLAMD_HOST + SEG_CLAMD_PORT.
    """
    s = get_settings()
    choice = s.sandbox_provider.strip().lower()
    if choice == "clamav":
        socket_path = s.clamd_socket.strip() or None
        host = s.clamd_host.strip()
        try:
            port = int(s.clamd_port)
        except (TypeError, ValueError):
            port = 3310
        return ClamAVSandboxProvider(host=host, port=port, socket_path=socket_path)
    if choice == "null":
        return NullSandboxProvider()
    # Unrecognized choice degrades to the safe default rather than raising.
    return NullSandboxProvider()
