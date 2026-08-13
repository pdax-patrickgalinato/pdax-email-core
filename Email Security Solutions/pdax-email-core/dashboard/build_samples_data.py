#!/usr/bin/env python3
"""Convert the Markdown reports in samples_output/ into a JS data file the
dashboard can load (dashboard/samples_data.js -> window.PDAX_SAMPLES).

The reports are produced by eml_analysis_agent.py with a deterministic layout
(see its render_markdown()), so this parses that layout back into structured
records rather than re-running the LLM. Run it whenever samples_output/ changes:

    python3 dashboard/build_samples_data.py

These are the standalone analyst agent's *risk ratings* (LOW/MEDIUM/HIGH/
CRITICAL), a different taxonomy from the scored pipeline's verdicts — the
dashboard surfaces them on their own page, never mixed into the gateway feed.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CELL_SPLIT = re.compile(r"(?<!\\)\|")


def _unescape(cell: str) -> str:
    return cell.strip().replace("\\|", "|")


def _split_row(line: str) -> list[str]:
    line = line.strip()
    if not line.startswith("|") or not line.endswith("|"):
        return []
    inner = line[1:-1]
    return [_unescape(c) for c in _CELL_SPLIT.split(inner)]


def _is_separator(line: str) -> bool:
    return bool(re.match(r"^\|[\s\-|]+\|$", line.strip()))


def _sections(text: str) -> dict[str, list[str]]:
    """Split the report body into {section-title: lines}, plus a '_head' block
    for everything before the first '## ' heading."""
    out: dict[str, list[str]] = {"_head": []}
    current = "_head"
    for line in text.splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            out[current] = []
        else:
            out[current].append(line)
    return out


def _field(lines: list[str], label: str) -> str:
    """Value of a '- **Label:** value' or '**Label:** value' bullet."""
    for line in lines:
        m = re.match(r"^-?\s*\*\*" + re.escape(label) + r":\*\*\s*(.*)$", line.strip())
        if m:
            return m.group(1).strip()
    return ""


def _list_field(lines: list[str], label: str) -> list[str]:
    raw = _field(lines, label)
    if not raw or raw.lower() == "none":
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


def _entity(lines: list[str], label: str) -> list[str]:
    """Value of a '- Label: a, b, c' bullet (entities block)."""
    for line in lines:
        m = re.match(r"^-\s*" + re.escape(label) + r":\s*(.*)$", line.strip())
        if m:
            raw = m.group(1).strip()
            if not raw or raw.lower() == "none":
                return []
            return [p.strip() for p in raw.split(",") if p.strip()]
    return []


def _table_rows(lines: list[str]) -> list[list[str]]:
    rows = []
    seen_header = False
    for line in lines:
        s = line.strip()
        if not s.startswith("|"):
            continue
        if _is_separator(s):
            seen_header = True
            continue
        cells = _split_row(s)
        if not seen_header:  # first row is the header
            seen_header = "pending"
            continue
        if cells:
            rows.append(cells)
    return rows


def _metadata(lines: list[str]) -> dict[str, str]:
    field_map = {
        "Subject": "subject", "From": "from", "To": "to", "Cc": "cc",
        "Reply-To": "reply_to", "Date": "date", "Message-ID": "message_id",
    }
    out = {v: "" for v in field_map.values()}
    for cells in _table_rows(lines):
        if len(cells) >= 2 and cells[0] in field_map:
            out[field_map[cells[0]]] = cells[1]
    return out


def _action_items(lines: list[str]) -> list[str]:
    items, collecting = [], False
    for line in lines:
        s = line.strip()
        if s.startswith("**Action items:**"):
            collecting = True
            continue
        if collecting:
            if s.startswith("- "):
                item = s[2:].strip()
                if item and item.lower() != "none identified.":
                    items.append(item)
            elif s.startswith("##") or s.startswith("**"):
                break
    return items


def parse_report(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    sec = _sections(text)
    threat = sec.get("Threat Assessment", [])
    auth = sec.get("Authentication Forensics", [])
    content = sec.get("Content Analysis", [])
    meta = _metadata(sec.get("Metadata", []))

    score_raw = _field(threat, "Risk score")
    m = re.match(r"(\d+)", score_raw)
    risk_score = int(m.group(1)) if m else None

    urls = []
    for cells in _table_rows(sec.get("Suspicious URLs", [])):
        if len(cells) >= 3:
            urls.append({"display_text": cells[0], "actual_url": cells[1],
                         "mismatch": cells[2].strip().lower() == "true"})
    attachments = []
    for cells in _table_rows(sec.get("Attachments", [])):
        if len(cells) >= 5:
            attachments.append({"filename": cells[0], "type": cells[1], "sha256": cells[2],
                                "flagged": cells[3].strip().lower() == "true", "reason": cells[4]})

    source_file = _field(sec.get("_head", []), "Source file").strip("`") or path.stem + ".eml"

    return {
        "source_file": source_file,
        "risk_level": (_field(threat, "Risk level") or "UNKNOWN").upper(),
        "risk_score": risk_score,
        "indicators": _list_field(threat, "Indicators"),
        "warning": _field(threat, "Warning"),
        "metadata": meta,
        "auth": {
            "originating_ip": _field(auth, "Originating IP"),
            "spf": _field(auth, "SPF"),
            "dkim": _field(auth, "DKIM"),
            "address_mismatch": _field(auth, "Address mismatch detected").strip().lower() == "true",
            "mismatch_details": _field(auth, "Mismatch details"),
        },
        "content": {
            "summary": _field(content, "Summary"),
            "category": _field(content, "Category"),
            "sentiment": _field(content, "Sentiment"),
            "entities": {
                "people": _entity(content, "People"),
                "organizations": _entity(content, "Organizations"),
                "dates_mentioned": _entity(content, "Dates mentioned"),
                "amounts_mentioned": _entity(content, "Amounts mentioned"),
            },
            "action_items": _action_items(content),
        },
        "suspicious_urls": urls,
        "attachments": attachments,
    }


_RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def main() -> int:
    in_dir = _ROOT / "samples_output"
    out_path = Path(__file__).resolve().parent / "samples_data.js"
    if not in_dir.is_dir():
        print(f"error: {in_dir} not found", file=sys.stderr)
        return 1

    reports = [parse_report(p) for p in sorted(in_dir.glob("*.md"))]
    reports.sort(key=lambda r: (_RISK_ORDER.get(r["risk_level"], 4),
                                -(r["risk_score"] or 0)))

    payload = json.dumps(reports, indent=2, ensure_ascii=False)
    out_path.write_text(
        "// AUTO-GENERATED by dashboard/build_samples_data.py — do not edit by hand.\n"
        "// Source: samples_output/*.md (eml_analysis_agent.py reports).\n"
        "window.PDAX_SAMPLES = " + payload + ";\n",
        encoding="utf-8",
    )
    print(f"wrote {out_path} — {len(reports)} report(s)")
    for r in reports:
        print(f"  {r['risk_level']:<8} {str(r['risk_score']):>4}  {r['source_file']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
