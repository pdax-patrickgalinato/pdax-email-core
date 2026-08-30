"""Organization identity + context notes — GET /api/org (any authenticated
user, for dashboard branding) and admin-only add/update/remove of
organizational context notes used by the content-AI system prompt.
Settings → Organization is the console UI for this.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend.stores import org_config
from backend.api import activity_log
from backend.api.auth_store import User
from backend.api.deps import get_current_user, require_role

router = APIRouter(prefix="/api")


class ContextNoteCreate(BaseModel):
    text: str = Field(min_length=1, max_length=org_config.MAX_NOTE_LEN)


@router.get("/org")
def get_org(_=Depends(get_current_user)):
    """Organization identity (backend/policy/identity/org.yaml) — requires a valid session.
    Branding info is returned only to authenticated dashboard users, not to
    unauthenticated visitors performing reconnaissance."""
    return org_config.load_org_config()


@router.post("/org/context", status_code=201)
def add_org_context(body: ContextNoteCreate, user: User = Depends(require_role("admin"))):
    try:
        note = org_config.add_context_note(body.text)
    except org_config.ContextNoteError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    activity_log.record(
        "org_context_add",
        actor=user.username,
        actor_role=user.role,
        detail=f"Added organizational context note {note['id']}: {note['text']}",
        meta={"id": note["id"]},
    )
    return {"added": note, "context_notes": org_config.load_org_config()["context_notes"]}


@router.patch("/org/context/{note_id}")
def update_org_context(note_id: str, body: ContextNoteCreate, user: User = Depends(require_role("admin"))):
    try:
        note = org_config.update_context_note(note_id, body.text)
    except org_config.ContextNoteError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    activity_log.record(
        "org_context_update",
        actor=user.username,
        actor_role=user.role,
        detail=f"Updated organizational context note {note['id']}: {note['text']}",
        meta={"id": note["id"]},
    )
    return {"updated": note, "context_notes": org_config.load_org_config()["context_notes"]}


@router.delete("/org/context/{note_id}")
def remove_org_context(note_id: str, user: User = Depends(require_role("admin"))):
    try:
        removed = org_config.remove_context_note(note_id)
    except org_config.ContextNoteError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    activity_log.record(
        "org_context_remove",
        actor=user.username,
        actor_role=user.role,
        detail=f"Removed organizational context note {removed['id']}: {removed['text']}",
        meta={"id": removed["id"]},
    )
    return {"removed": removed, "context_notes": org_config.load_org_config()["context_notes"]}
