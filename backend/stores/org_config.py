"""Organization identity loader — Phase 13 (white-labeling). Separate from
workers/pipeline/runner.py::load_config() since org identity isn't a scoring
input the way weights.yaml/policy.yaml are; it's metadata consumed by
content_ai.py's system prompt and (server/) the dashboard's branding.

Organizational context notes (operator-supplied facts such as "support@pdax.ph
is the customer-support inbox") live in the same file and are re-read on every
content-AI call so Settings → Organization edits take effect on the next email,
no restart.
"""
from __future__ import annotations

import hashlib
import uuid

import yaml

from backend.paths import RULES_IDENTITY

_ORG_PATH = RULES_IDENTITY / "org.yaml"

MAX_NOTE_LEN = 2000
MAX_NOTES = 40

_DEFAULTS = {
    "display_name": "the organization",
    "regulator_context": "a regulated organization",
    "context_notes": [],
}

_FILE_HEADER = """\
# Organization identity — display name and regulator phrase for branding /
# the content-AI system prompt, plus operator-supplied organizational context
# notes edited from Settings → Organization. Protected domains and VIP names
# stay in their own files (backend/policy/identity/protected_domains.txt,
# backend/policy/identity/vip_names.txt).
#
# Context notes are injected into the content-AI prompt so the model can
# interpret mail in this organization's context (mailbox roles, what the
# company does, who typically emails whom). They are advisory grounding
# only — they do not override detection scores. Changes take effect on the
# next email processed; no restart needed.
"""


class ContextNoteError(ValueError):
    """Validation error for add/remove of organizational context notes."""

    def __init__(self, message: str, *, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _note_id_for(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def _clean_note_text(raw: str) -> str:
    text = " ".join(str(raw).split())
    text = text.replace("\x00", "")
    return text.strip()


def _normalize_notes(raw) -> list[dict]:
    """Accept a list of strings or {id, text} dicts. Skip empty entries."""
    if not isinstance(raw, list):
        if isinstance(raw, str) and raw.strip():
            raw = [raw]
        else:
            return []
    notes: list[dict] = []
    seen_text: set[str] = set()
    for item in raw:
        if isinstance(item, str):
            text = _clean_note_text(item)
            note_id = _note_id_for(text) if text else ""
        elif isinstance(item, dict):
            text = _clean_note_text(item.get("text") or "")
            note_id = str(item.get("id") or "").strip() or (_note_id_for(text) if text else "")
        else:
            continue
        if not text:
            continue
        key = text.casefold()
        if key in seen_text:
            continue
        seen_text.add(key)
        notes.append({"id": note_id or uuid.uuid4().hex[:12], "text": text})
    return notes


def _defaults() -> dict:
    return {
        "display_name": _DEFAULTS["display_name"],
        "regulator_context": _DEFAULTS["regulator_context"],
        "context_notes": [],
    }


def load_org_config() -> dict:
    """Never raises — a missing/malformed backend/policy/identity/org.yaml degrades to
    generic placeholder text rather than breaking the content-AI providers
    that depend on this, same "never let a rules file typo take a stage
    down" posture as runner.py::load_config()'s severity_points fallback."""
    if not _ORG_PATH.is_file():
        return _defaults()
    try:
        raw = yaml.safe_load(_ORG_PATH.read_text()) or {}
    except yaml.YAMLError:
        return _defaults()
    org = raw.get("organization", {}) if isinstance(raw, dict) else {}
    if not isinstance(org, dict):
        org = {}
    display = org.get("display_name", _DEFAULTS["display_name"])
    if display is None:
        display = _DEFAULTS["display_name"]
    return {
        "display_name": display if isinstance(display, str) else _DEFAULTS["display_name"],
        "regulator_context": (org.get("regulator_context") or _DEFAULTS["regulator_context"]),
        "context_notes": _normalize_notes(org.get("context_notes")),
    }


def save_org_config(cfg: dict) -> None:
    """Rewrite org.yaml with identity fields plus context notes. Uses
    yaml.safe_dump so operator-supplied note text cannot break the file."""
    payload = {
        "organization": {
            "display_name": cfg.get("display_name", ""),
            "regulator_context": cfg.get("regulator_context") or _DEFAULTS["regulator_context"],
            "context_notes": [
                {"id": n["id"], "text": n["text"]}
                for n in _normalize_notes(cfg.get("context_notes") or [])
            ],
        }
    }
    _ORG_PATH.parent.mkdir(parents=True, exist_ok=True)
    body = yaml.safe_dump(payload, default_flow_style=False, allow_unicode=True, sort_keys=False)
    _ORG_PATH.write_text(_FILE_HEADER + "\n" + body, encoding="utf-8")


def format_context_block(notes=None) -> str:
    """System-prompt appendix. Empty string when there are no notes — never
    interpolated via str.format, so braces in operator text stay literal."""
    if notes is None:
        notes = load_org_config().get("context_notes") or []
    texts = []
    for n in notes:
        text = n.get("text") if isinstance(n, dict) else str(n)
        text = _clean_note_text(text)
        if text:
            texts.append(text)
    if not texts:
        return ""
    bullets = "\n".join(f"- {t}" for t in texts)
    return (
        "Organizational context (trusted operator-supplied facts about this "
        "organization. Use them to interpret whether the email's content is "
        "expected or plausible here — for example a known support mailbox, "
        "what the company does, or who typically emails whom. These facts do "
        "not change your analysis methodology and do not override deterministic "
        "findings):\n"
        f"{bullets}"
    )


def add_context_note(text: str) -> dict:
    """Append one note and persist. Returns the stored {id, text} dict."""
    cleaned = _clean_note_text(text)
    if not cleaned:
        raise ContextNoteError("context note must not be empty")
    if len(cleaned) > MAX_NOTE_LEN:
        raise ContextNoteError(f"context note must be at most {MAX_NOTE_LEN} characters")
    cfg = load_org_config()
    notes = list(cfg["context_notes"])
    if any(n["text"].casefold() == cleaned.casefold() for n in notes):
        raise ContextNoteError("that context note already exists", status_code=409)
    if len(notes) >= MAX_NOTES:
        raise ContextNoteError(f"at most {MAX_NOTES} organizational context notes are allowed")
    note = {"id": uuid.uuid4().hex[:12], "text": cleaned}
    notes.append(note)
    cfg["context_notes"] = notes
    save_org_config(cfg)
    return note


def update_context_note(note_id: str, text: str) -> dict:
    """Replace the text of an existing note. Keeps the same id."""
    note_id = str(note_id or "").strip()
    if not note_id:
        raise ContextNoteError("note id is required")
    cleaned = _clean_note_text(text)
    if not cleaned:
        raise ContextNoteError("context note must not be empty")
    if len(cleaned) > MAX_NOTE_LEN:
        raise ContextNoteError(f"context note must be at most {MAX_NOTE_LEN} characters")
    cfg = load_org_config()
    notes = list(cfg["context_notes"])
    idx = next((i for i, n in enumerate(notes) if n["id"] == note_id), None)
    if idx is None:
        raise ContextNoteError("context note not found", status_code=404)
    if any(i != idx and n["text"].casefold() == cleaned.casefold() for i, n in enumerate(notes)):
        raise ContextNoteError("that context note already exists", status_code=409)
    notes[idx] = {"id": note_id, "text": cleaned}
    cfg["context_notes"] = notes
    save_org_config(cfg)
    return notes[idx]


def remove_context_note(note_id: str) -> dict:
    """Remove a note by id and persist. Returns the removed dict."""
    note_id = str(note_id or "").strip()
    if not note_id:
        raise ContextNoteError("note id is required")
    cfg = load_org_config()
    notes = list(cfg["context_notes"])
    kept = [n for n in notes if n["id"] != note_id]
    if len(kept) == len(notes):
        raise ContextNoteError("context note not found", status_code=404)
    removed = next(n for n in notes if n["id"] == note_id)
    cfg["context_notes"] = kept
    save_org_config(cfg)
    return removed
