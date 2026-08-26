"""Admin-only CRUD for allowlist and blocklist — GET/POST/DELETE /api/lists/*.

Reads and writes rules/allowlist.yaml and rules/blocklist.yaml. Changes take
effect on the next email without a restart (lists are read fresh per email).
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from .. import activity_log
from ..auth_store import User
from ..deps import require_role
from app import lists as lists_mod

router = APIRouter(prefix="/api")

_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


class ListEntry(BaseModel):
    type: Literal["address", "domain"]
    value: str
    note: Optional[str] = ""

    @field_validator("value")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("value must not be empty")
        return v


def _to_dict(entry: ListEntry) -> dict:
    d: dict = {entry.type: entry.value}
    if entry.note:
        d["note"] = entry.note
    return d


def _load(name: str) -> list[dict]:
    return lists_mod.load_allowlist() if name == "allowlist" else lists_mod.load_blocklist()


def _save(name: str, entries: list[dict]) -> None:
    path = _RULES_DIR / f"{name}.yaml"
    lists_mod._save_list_file(path, entries)


def _key(entry: dict) -> str:
    return entry.get("address") or entry.get("domain") or ""


@router.get("/lists")
def get_lists(user: User = Depends(require_role("admin"))):
    return {
        "allowlist": lists_mod.load_allowlist(),
        "blocklist": lists_mod.load_blocklist(),
    }


@router.post("/lists/{list_name}", status_code=201)
def add_entry(
    list_name: Literal["allowlist", "blocklist"],
    body: ListEntry,
    user: User = Depends(require_role("admin")),
):
    entries = _load(list_name)
    new_key = body.value
    if any(_key(e) == new_key for e in entries):
        raise HTTPException(status_code=409, detail=f"{new_key} is already in {list_name}")
    entry = _to_dict(body)
    entries.append(entry)
    _save(list_name, entries)
    activity_log.record(
        f"{list_name}_add",
        actor=user.username,
        actor_role=user.role,
        detail=f"Added {body.type} {body.value!r} to {list_name}",
        meta={"list": list_name, "type": body.type, "value": body.value},
    )
    return {"added": entry, "list": list_name}


@router.delete("/lists/{list_name}/{value}")
def remove_entry(
    list_name: Literal["allowlist", "blocklist"],
    value: str,
    user: User = Depends(require_role("admin")),
):
    value = value.strip().lower()
    entries = _load(list_name)
    before = len(entries)
    entries = [e for e in entries if _key(e) != value]
    if len(entries) == before:
        raise HTTPException(status_code=404, detail=f"{value!r} not found in {list_name}")
    _save(list_name, entries)
    activity_log.record(
        f"{list_name}_remove",
        actor=user.username,
        actor_role=user.role,
        detail=f"Removed {value!r} from {list_name}",
        meta={"list": list_name, "value": value},
    )
    return {"removed": value, "list": list_name}
