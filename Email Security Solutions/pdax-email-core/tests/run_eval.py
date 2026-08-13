#!/usr/bin/env python3
"""Golden-set eval harness (Annex B step 11).

Replays real captured mail in samples/ through the pipeline and reports
precision/recall for the malicious class. Labels come from samples/labels.yaml
(hand-triaged ground truth) rather than filename prefixes — the original
clean_/phish_/bec_ convention assumed synthetic filenames; the corpus is now
21 real .eml files with their original subjects as filenames. The synthetic
hard-override fixtures (clean_normal.eml/phish_lookalike.eml/bec_giftcard.eml)
moved to samples/fixtures/ and are exercised by tests/test_core.py instead —
this script only evaluates the real-mail corpus.

labels.yaml's "suspicious" and "malicious" labels both count as the malicious
class (matches MAL_VERDICTS below): a suspicious-labeled email is expected to
land at SUSPICIOUS or MALICIOUS, not necessarily MALICIOUS specifically.

Pass/fail gate is FP=0 (no clean-labeled email wrongly verdicts
SUSPICIOUS/MALICIOUS) — NOT per-row recall. As of 2026-08-13 recall on this
real corpus is well under 100% (see labels.yaml's header note); that's a
known, expected gap this pipeline's detection work is actively closing across
several phases, not something this eval should hard-fail on. False positives
on real legitimate mail are the actual production risk, so that's the bar
this script enforces.

Usage:  python3 tests/run_eval.py samples/
Exit code 0 if FP=0, 1 otherwise (CI-gate friendly).
"""
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.pipeline.runner import run_pipeline   # noqa: E402

MAL_LABELS = {"suspicious", "malicious"}
MAL_VERDICTS = {"SUSPICIOUS", "MALICIOUS"}


def load_labels(corpus: Path) -> dict:
    labels_path = corpus / "labels.yaml"
    if not labels_path.is_file():
        return {}
    data = yaml.safe_load(labels_path.read_text()) or {}
    return data.get("labels", {})


def main():
    corpus = Path(sys.argv[1] if len(sys.argv) > 1 else "samples")
    labels = load_labels(corpus)
    if not labels:
        print(f"error: no labels.yaml found under {corpus} — nothing to evaluate", file=sys.stderr)
        sys.exit(1)

    tp = fp = tn = fn = 0
    rows = []
    for eml in sorted(corpus.glob("*.eml")) + sorted(corpus.glob("*.EML")):
        entry = labels.get(eml.name)
        if entry is None:
            continue
        exp = entry["label"] in MAL_LABELS
        r = run_pipeline(eml.read_bytes(), source="eval")
        got_mal = r.verdict.value in MAL_VERDICTS
        ok = got_mal == exp
        if exp and got_mal: tp += 1
        elif exp and not got_mal: fn += 1
        elif not exp and got_mal: fp += 1
        else: tn += 1
        rows.append((eml.name, entry["label"], r.verdict.value,
                     round(r.composite_score, 1), "PASS" if ok else "FAIL"))

    print(f"{'file':<70}{'label':<12}{'verdict':<12}{'score':<8}result")
    print("-" * 116)
    for name, lab, verd, sc, res in rows:
        print(f"{name:<70}{lab:<12}{verd:<12}{sc:<8}{res}")
    print("-" * 116)
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}  precision={prec:.2f} recall={rec:.2f}")
    if fn:
        print(f"note: {fn} known-bad email(s) not yet caught (recall gap) — "
              f"expected pre-Phase-1..6, not a gate failure on its own")

    sys.exit(1 if fp else 0)


if __name__ == "__main__":
    main()
