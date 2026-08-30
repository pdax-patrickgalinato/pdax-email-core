#!/usr/bin/env python3
"""Analyze an .eml file offline and print the verdict.

Usage:
    python -m cli.analyze backend/tests/fixtures/eml/phish-lookalike.eml
    python -m cli.analyze backend/tests/fixtures/eml/clean-normal.eml --json
    python -m cli.analyze somefile.eml --slack
"""
import argparse
import json
import os
import sys

from workers.pipeline.runner import run_pipeline
from backend.report import text_report, slack_blocks, audit_record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("eml", help="path to .eml file")
    ap.add_argument("--json", action="store_true", help="print audit JSONL record")
    ap.add_argument("--slack", action="store_true", help="print Slack Block Kit payload")
    args = ap.parse_args()

    with open(args.eml, "rb") as f:
        raw = f.read()

    result = run_pipeline(raw, source="file")

    try:
        if args.json:
            print(audit_record(result))
        elif args.slack:
            print(json.dumps(slack_blocks(result), indent=2))
        else:
            print(text_report(result))
    except BrokenPipeError:
        # piped into head/grep and the reader closed early — not an error
        try:
            sys.stdout.close()
        except Exception:
            pass
        os._exit(0)

    # exit code reflects verdict — handy for CI / eval gating
    sys.exit(0 if result.verdict.value in ("CLEAN", "LOW") else 2)


if __name__ == "__main__":
    main()
