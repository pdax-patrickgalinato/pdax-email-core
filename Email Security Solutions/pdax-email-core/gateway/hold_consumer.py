#!/usr/bin/env python3
"""SMTP HOLD consumer (Annex C skeleton) — shadow-first enforcement + re-eval.

Reads held .eml files, runs `run_pipeline(..., source="smtp_hold")`, then
applies an EnforcementClient. Quarantined / blocked mail is kept under
`gateway/spool/` so analysts can re-evaluate later.

Spool layout (SEG_QUARANTINE_ROOT, default gateway/spool):
  quarantine/<id>/message.eml + meta.json   ← held for review
  rejected/<id>/...                         ← confirmed blocked
  released/<id>/...                         ← delivered / false-positive release
  shadow_logs/shadow_enforcement.jsonl      ← shadow-mode audit

Enforce modes (SEG_ENFORCE):
  shadow      (default) — log intended disposition; always "release"
  quarantine  — write SUSPICIOUS/MALICIOUS to spool/quarantine/
  reject      — as quarantine; REJECT only if disposition.yaml allows it

Usage:
  python3 gateway/hold_consumer.py path/to/held.eml
  SEG_ENFORCE=quarantine python3 gateway/hold_consumer.py samples/
  python3 gateway/hold_consumer.py --list
  python3 gateway/hold_consumer.py --reeval <queue_id>
  python3 gateway/hold_consumer.py --reeval-all --auto-release
  python3 gateway/hold_consumer.py --release <queue_id>
  python3 gateway/hold_consumer.py --keep-blocked <queue_id>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.disposition import (  # noqa: E402
    get_default_enforcement_client, keep_blocked, list_spool_entries,
    reevaluate_spool_entry, release_from_quarantine, resolve_enforce_mode,
)
from app.pipeline.runner import run_pipeline  # noqa: E402
from app.report import text_report, audit_record  # noqa: E402


def _iter_eml(path: Path):
    if path.is_file() and path.suffix.lower() == ".eml":
        yield path
        return
    if path.is_dir():
        for p in sorted(path.iterdir()):
            if p.is_file() and p.suffix.lower() == ".eml":
                yield p
        return
    raise FileNotFoundError(f"not a file or directory of .eml: {path}")


from app.models import Verdict  # noqa: E402

# Verdicts that trigger the Tier-2 deep forensic pass (eml_analysis_agent).
_DEEP_ANALYSIS_VERDICTS = (Verdict.SUSPICIOUS, Verdict.MALICIOUS)


def _maybe_deep_analyze(raw: bytes, filename: str, result) -> None:
    """Tier 2: on flagged mail only, auto-run the deep forensic agent and
    attach its report to `result.deep_analysis` so it is persisted with the
    quarantine/shadow record. Heavy + LLM-backed, so it is gated on verdict to
    bound cost and wrapped so a failure can never break enforcement — clean
    mail is untouched, and any error degrades to a status marker."""
    if result.verdict not in _DEEP_ANALYSIS_VERDICTS:
        return
    try:
        # Lazy import: keeps the optional deep-analysis deps out of the normal
        # consumer path and mirrors server/routers/analyze.py's usage.
        from eml_analysis_agent import analyze_eml_bytes, resolve_glm_credentials_path
        creds = resolve_glm_credentials_path()
        if not creds.is_file():
            result.deep_analysis = {"status": "unavailable",
                                    "reason": "GLM credentials not configured"}
            return
        deep = analyze_eml_bytes(raw, filename, credentials_path=str(creds))
        result.deep_analysis = {
            "status": "ok",
            "markdown": deep.get("markdown"),
            "analysis": deep.get("analysis"),
            "playbook": deep.get("playbook"),
            "model": deep.get("model"),
        }
    except Exception as e:  # never let the heavy agent break enforcement
        result.deep_analysis = {"status": "unavailable",
                                "reason": f"{type(e).__name__}: {e}"}


def process_one(eml_path: Path, client, print_report: bool = True) -> dict:
    raw = eml_path.read_bytes()
    result = run_pipeline(raw, source="smtp_hold")
    queue_id = eml_path.stem or result.message_id or eml_path.name
    # Tier 2 — deep forensic pass on flagged mail, before enforcement writes
    # the record, so the deep report is persisted alongside the verdict.
    _maybe_deep_analyze(raw, eml_path.name, result)
    applied = client.apply(queue_id, raw, result)
    summary = {
        "file": str(eml_path),
        "queue_id": queue_id,
        "verdict": result.verdict.value,
        "score": result.composite_score,
        "disposition": result.disposition.value,
        "disposition_reason": result.disposition_reason,
        "enforce_mode": result.enforce_mode.value,
        "enforcement_applied": applied,
        "hard_override": result.hard_override,
        "threat_class": result.threat_class,
        "threat_confidence": result.threat_confidence,
        "deep_analysis": (result.deep_analysis or {}).get("status") if result.deep_analysis else None,
        "message_id": result.message_id,
        "subject": result.subject,
    }
    if print_report:
        print(text_report(result))
        print("-" * 64)
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        print()
    return summary


def _print_list(spool: Path) -> int:
    rows = list_spool_entries(spool)
    if not rows:
        print(f"(empty spool) {spool}")
        print("  Expected folders: quarantine/  rejected/  released/")
        return 0
    print(f"{'BUCKET':<12} {'VERDICT':<12} {'DISP':<12} {'SCORE':>6}  QUEUE_ID")
    print("-" * 88)
    for r in rows:
        score = r.get("score")
        score_s = f"{score:.0f}" if isinstance(score, (int, float)) else "-"
        print(f"{r['bucket']:<12} {(r.get('verdict') or '-'):<12} "
              f"{(r.get('disposition') or '-'):<12} {score_s:>6}  {r['queue_id']}")
        subj = (r.get("subject") or "")[:70]
        frm = (r.get("from") or "")[:60]
        if subj or frm:
            print(f"{'':12} from: {frm}")
            print(f"{'':12} subj: {subj}")
    print("-" * 88)
    print(f"{len(rows)} entr(y/ies) under {spool}")
    print("Re-eval:  python3 gateway/hold_consumer.py --reeval <QUEUE_ID>")
    print("Release:  python3 gateway/hold_consumer.py --release <QUEUE_ID>")
    print("Block:    python3 gateway/hold_consumer.py --keep-blocked <QUEUE_ID>")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="SEG hold consumer — quarantine/block spool + re-evaluation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Spool root: gateway/spool/ (override with --spool or SEG_QUARANTINE_ROOT)",
    )
    ap.add_argument("path", nargs="?", default=None,
                    help=".eml file or directory of held messages")
    ap.add_argument("--spool", default=str(_ROOT / "gateway" / "spool"),
                    help="quarantine/release root (default: gateway/spool)")
    ap.add_argument("--enforce", default=None,
                    help="shadow|quarantine|reject (default: SEG_ENFORCE or shadow)")
    ap.add_argument("--jsonl", action="store_true",
                    help="print one audit JSONL record per message instead of text")
    ap.add_argument("--list", action="store_true",
                    help="list quarantined / rejected / released messages in the spool")
    ap.add_argument("--reeval", metavar="QUEUE_ID",
                    help="re-run pipeline on a stored message; keep in place unless --auto-*")
    ap.add_argument("--reeval-all", action="store_true",
                    help="re-evaluate every entry in quarantine/ (and rejected/)")
    ap.add_argument("--auto-release", action="store_true",
                    help="with --reeval*: move to released/ if new disposition is DELIVER/LOG")
    ap.add_argument("--auto-block", action="store_true",
                    help="with --reeval*: move quarantine → rejected/ if still QUARANTINE/REJECT")
    ap.add_argument("--release", metavar="QUEUE_ID",
                    help="analyst release: quarantine/rejected → released/ (benign)")
    ap.add_argument("--keep-blocked", metavar="QUEUE_ID",
                    help="confirm block: quarantine → rejected/ (remain blocked)")
    ap.add_argument("--quiet", action="store_true", help="summaries only")
    args = ap.parse_args(argv)

    spool = Path(args.spool)
    if args.enforce:
        import os
        os.environ["SEG_ENFORCE"] = args.enforce

    if args.list:
        return _print_list(spool)

    if args.release:
        dest = release_from_quarantine(spool, args.release)
        print(f"released (benign) → {dest}")
        return 0

    if args.keep_blocked:
        dest = keep_blocked(spool, args.keep_blocked)
        print(f"kept blocked → {dest}")
        return 0

    if args.reeval or args.reeval_all:
        ids = []
        if args.reeval:
            ids = [args.reeval]
        else:
            ids = [r["queue_id"] for r in list_spool_entries(
                spool, buckets=("quarantine", "rejected"))]
        if not ids:
            print("nothing to re-evaluate", file=sys.stderr)
            return 0
        failures = 0
        for qid in ids:
            try:
                out = reevaluate_spool_entry(
                    spool, qid,
                    auto_release=args.auto_release,
                    auto_block=args.auto_block,
                )
                print(json.dumps(out, indent=2, ensure_ascii=False))
            except Exception as e:
                failures += 1
                print(f"ERROR reeval {qid}: {type(e).__name__}: {e}", file=sys.stderr)
        return 1 if failures else 0

    if not args.path:
        ap.error("path to .eml required, or use --list / --reeval / --release / --keep-blocked")

    mode = resolve_enforce_mode(args.enforce)
    client = get_default_enforcement_client(enforce_mode=mode, quarantine_root=spool)
    print(f"hold_consumer: enforce_mode={mode.value} spool={spool}", file=sys.stderr)

    summaries = []
    failures = 0
    for eml in _iter_eml(Path(args.path)):
        try:
            if args.jsonl:
                raw = eml.read_bytes()
                result = run_pipeline(raw, source="smtp_hold")
                client.apply(eml.stem, raw, result)
                print(audit_record(result))
                summaries.append({"file": str(eml), "verdict": result.verdict.value,
                                  "disposition": result.disposition.value})
            else:
                summaries.append(process_one(eml, client, print_report=not args.quiet))
        except Exception as e:
            failures += 1
            print(f"ERROR {eml}: {type(e).__name__}: {e}", file=sys.stderr)

    from collections import Counter
    by_disp = Counter(s.get("disposition") for s in summaries)
    by_verdict = Counter(s.get("verdict") for s in summaries)
    print(f"Done: {len(summaries)} processed, {failures} failed. "
          f"verdicts={dict(by_verdict)} dispositions={dict(by_disp)}",
          file=sys.stderr)
    print(f"Spool: {spool}  (list with: python3 gateway/hold_consumer.py --list)",
          file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
