"""Unit tests for app/org_config.py — Phase 13 (white-labeling) of the
dashboard-overhaul plan.

Run: python3 -m pytest tests/test_org_config.py
     (or python3 tests/test_org_config.py)
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import org_config


def test_real_org_yaml_loads():
    cfg = org_config.load_org_config()
    # display_name is intentionally blank in the real rules/org.yaml (dropped
    # company name, white-labeled dashboard) — check the key exists and is a
    # string, not that it's truthy.
    assert "display_name" in cfg and isinstance(cfg["display_name"], str)
    assert cfg["regulator_context"]


def test_missing_file_degrades_to_defaults():
    org_config._ORG_PATH = Path(tempfile.mkdtemp()) / "does_not_exist.yaml"
    cfg = org_config.load_org_config()
    assert cfg == org_config._DEFAULTS
    org_config._ORG_PATH = Path(__file__).resolve().parents[1] / "rules" / "org.yaml"   # restore


def test_malformed_yaml_degrades_to_defaults():
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text("not: valid: yaml: [[[")
    org_config._ORG_PATH = tmp
    cfg = org_config.load_org_config()
    assert cfg == org_config._DEFAULTS
    org_config._ORG_PATH = Path(__file__).resolve().parents[1] / "rules" / "org.yaml"   # restore


def test_partial_org_yaml_fills_missing_defaults():
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text("organization:\n  display_name: TestCo\n")
    org_config._ORG_PATH = tmp
    cfg = org_config.load_org_config()
    assert cfg["display_name"] == "TestCo"
    assert cfg["regulator_context"] == org_config._DEFAULTS["regulator_context"]
    org_config._ORG_PATH = Path(__file__).resolve().parents[1] / "rules" / "org.yaml"   # restore


def test_explicit_empty_display_name_is_preserved_not_defaulted():
    # A deployment that wants no company name at all sets display_name: ""
    # deliberately (Part 3) — this must survive, not silently become the
    # generic "the organization" default the way a *missing* key does.
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text('organization:\n  display_name: ""\n')
    org_config._ORG_PATH = tmp
    cfg = org_config.load_org_config()
    assert cfg["display_name"] == ""
    assert cfg["regulator_context"] == org_config._DEFAULTS["regulator_context"]
    org_config._ORG_PATH = Path(__file__).resolve().parents[1] / "rules" / "org.yaml"   # restore


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn(); passed += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
