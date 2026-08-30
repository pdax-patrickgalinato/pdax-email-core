"""Unit tests for backend/org_config.py — identity load plus organizational
context notes used by the content-AI system prompt.

Run: python3 -m pytest backend/tests/pipeline/test_org_config.py
"""
import tempfile
from pathlib import Path

from backend.stores import org_config
from backend.paths import RULES_IDENTITY


def _restore_org_path():
    org_config._ORG_PATH = RULES_IDENTITY / "org.yaml"


def test_real_org_yaml_loads():
    cfg = org_config.load_org_config()
    # display_name is intentionally blank in the real backend/policy/identity/org.yaml (dropped
    # company name, white-labeled dashboard) — check the key exists and is a
    # string, not that it's truthy.
    assert "display_name" in cfg and isinstance(cfg["display_name"], str)
    assert cfg["regulator_context"]
    assert "context_notes" in cfg and isinstance(cfg["context_notes"], list)


def test_missing_file_degrades_to_defaults():
    org_config._ORG_PATH = Path(tempfile.mkdtemp()) / "does_not_exist.yaml"
    try:
        cfg = org_config.load_org_config()
        assert cfg == org_config._defaults()
    finally:
        _restore_org_path()


def test_malformed_yaml_degrades_to_defaults():
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text("not: valid: yaml: [[[")
    org_config._ORG_PATH = tmp
    try:
        cfg = org_config.load_org_config()
        assert cfg == org_config._defaults()
    finally:
        _restore_org_path()


def test_partial_org_yaml_fills_missing_defaults():
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text("organization:\n  display_name: TestCo\n")
    org_config._ORG_PATH = tmp
    try:
        cfg = org_config.load_org_config()
        assert cfg["display_name"] == "TestCo"
        assert cfg["regulator_context"] == org_config._DEFAULTS["regulator_context"]
        assert cfg["context_notes"] == []
    finally:
        _restore_org_path()


def test_explicit_empty_display_name_is_preserved_not_defaulted():
    # A deployment that wants no company name at all sets display_name: ""
    # deliberately (Part 3) — this must survive, not silently become the
    # generic "the organization" default the way a *missing* key does.
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text('organization:\n  display_name: ""\n')
    org_config._ORG_PATH = tmp
    try:
        cfg = org_config.load_org_config()
        assert cfg["display_name"] == ""
        assert cfg["regulator_context"] == org_config._DEFAULTS["regulator_context"]
    finally:
        _restore_org_path()


def test_string_context_notes_normalized_to_id_text_dicts():
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text(
        "organization:\n"
        "  display_name: PDAX\n"
        "  context_notes:\n"
        "    - support@pdax.ph is the customer-support inbox\n"
        "    - PDAX is a Philippine-based crypto exchange\n"
    )
    org_config._ORG_PATH = tmp
    try:
        cfg = org_config.load_org_config()
        assert len(cfg["context_notes"]) == 2
        assert cfg["context_notes"][0]["text"] == "support@pdax.ph is the customer-support inbox"
        assert cfg["context_notes"][1]["text"] == "PDAX is a Philippine-based crypto exchange"
        assert all(n["id"] for n in cfg["context_notes"])
    finally:
        _restore_org_path()


def test_add_and_remove_context_note_roundtrip():
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text('organization:\n  display_name: ""\n  regulator_context: "a BSP-regulated crypto exchange"\n')
    org_config._ORG_PATH = tmp
    try:
        note = org_config.add_context_note(
            "  support@pdax.ph is a customer support email where clients raise concerns.  "
        )
        assert note["text"] == "support@pdax.ph is a customer support email where clients raise concerns."
        loaded = org_config.load_org_config()
        assert loaded["display_name"] == ""  # preserved through rewrite
        assert loaded["regulator_context"] == "a BSP-regulated crypto exchange"
        assert loaded["context_notes"][0]["id"] == note["id"]

        removed = org_config.remove_context_note(note["id"])
        assert removed["id"] == note["id"]
        assert org_config.load_org_config()["context_notes"] == []
    finally:
        _restore_org_path()


def test_update_context_note_keeps_id():
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text("organization:\n  display_name: PDAX\n")
    org_config._ORG_PATH = tmp
    try:
        note = org_config.add_context_note("support@pdax.ph is a shared inbox")
        updated = org_config.update_context_note(
            note["id"], "support@pdax.ph is the customer-support inbox"
        )
        assert updated["id"] == note["id"]
        assert updated["text"] == "support@pdax.ph is the customer-support inbox"
        loaded = org_config.load_org_config()["context_notes"]
        assert len(loaded) == 1
        assert loaded[0]["text"] == updated["text"]
    finally:
        _restore_org_path()


def test_update_missing_context_note_404():
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text("organization:\n  display_name: PDAX\n")
    org_config._ORG_PATH = tmp
    try:
        try:
            org_config.update_context_note("missing", "new text")
            assert False, "expected ContextNoteError"
        except org_config.ContextNoteError as exc:
            assert exc.status_code == 404
    finally:
        _restore_org_path()


def test_duplicate_context_note_rejected():
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text("organization:\n  display_name: PDAX\n")
    org_config._ORG_PATH = tmp
    try:
        org_config.add_context_note("PDAX is a Philippine-based crypto exchange")
        try:
            org_config.add_context_note("pdax is a philippine-based crypto exchange")
            assert False, "expected ContextNoteError"
        except org_config.ContextNoteError as exc:
            assert exc.status_code == 409
    finally:
        _restore_org_path()


def test_empty_context_note_rejected():
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text("organization:\n  display_name: PDAX\n")
    org_config._ORG_PATH = tmp
    try:
        try:
            org_config.add_context_note("   ")
            assert False, "expected ContextNoteError"
        except org_config.ContextNoteError as exc:
            assert exc.status_code == 400
    finally:
        _restore_org_path()


def test_format_context_block_empty_when_no_notes():
    assert org_config.format_context_block([]) == ""


def test_format_context_block_lists_facts_and_keeps_braces_literal():
    block = org_config.format_context_block([
        {"id": "a", "text": "support@pdax.ph is the customer-support inbox"},
        {"id": "b", "text": "Use {this} as a mailbox role fact"},
    ])
    assert "Organizational context" in block
    assert "- support@pdax.ph is the customer-support inbox" in block
    assert "- Use {this} as a mailbox role fact" in block
    assert "do not override deterministic findings" in block
