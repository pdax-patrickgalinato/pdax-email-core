"""Optional Tier-2 forensic agent on flagged mail. Advisory only."""
from __future__ import annotations

from backend.models import Verdict

_DEEP_ANALYSIS_VERDICTS = (Verdict.SUSPICIOUS, Verdict.MALICIOUS)


def maybe_deep_analyze(raw: bytes, filename: str, result) -> None:
    """Attach a deep forensic report on SUSPICIOUS/MALICIOUS only."""
    if result.verdict not in _DEEP_ANALYSIS_VERDICTS:
        return
    try:
        from cli.eml_analysis_agent import (
            analyze_eml_bytes, resolve_glm_credentials_path,
        )
        creds = resolve_glm_credentials_path()
        if not creds.is_file():
            result.deep_analysis = {
                "status": "unavailable",
                "reason": "GLM credentials not configured",
            }
            return
        deep = analyze_eml_bytes(raw, filename, credentials_path=str(creds))
        result.deep_analysis = {
            "status": "ok",
            "markdown": deep.get("markdown"),
            "analysis": deep.get("analysis"),
            "playbook": deep.get("playbook"),
            "model": deep.get("model"),
        }
    except Exception as e:
        result.deep_analysis = {
            "status": "unavailable",
            "reason": f"{type(e).__name__}: {e}",
        }
