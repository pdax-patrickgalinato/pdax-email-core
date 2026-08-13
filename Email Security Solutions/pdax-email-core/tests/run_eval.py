#!/usr/bin/env python3
"""Golden-set eval harness (Annex B step 11).

Replays a directory of labelled .eml files through the pipeline and reports
precision / recall for the malicious class. Label is taken from filename prefix:
    phish_*, bec_*, malicious_*   -> expected malicious (SUSPICIOUS or MALICIOUS)
    clean_*, ham_*                -> expected benign  (CLEAN or LOW)

Usage:  python3 tests/run_eval.py samples/
Exit code 0 if all pass, 1 otherwise (CI-gate friendly).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.pipeline.runner import run_pipeline   # noqa: E402

MAL_PREFIXES = ("phish_", "bec_", "malicious_")
BENIGN_PREFIXES = ("clean_", "ham_")
MAL_VERDICTS = {"SUSPICIOUS", "MALICIOUS"}


def expected_malicious(name: str):
    if name.startswith(MAL_PREFIXES):
        return True
    if name.startswith(BENIGN_PREFIXES):
        return False
    return None


def main():
    corpus = Path(sys.argv[1] if len(sys.argv) > 1 else "samples")
    tp = fp = tn = fn = 0
    rows = []
    for eml in sorted(corpus.glob("*.eml")):
        exp = expected_malicious(eml.name)
        if exp is None:
            continue
        r = run_pipeline(eml.read_bytes(), source="eval")
        got_mal = r.verdict.value in MAL_VERDICTS
        ok = got_mal == exp
        if exp and got_mal: tp += 1
        elif exp and not got_mal: fn += 1
        elif not exp and got_mal: fp += 1
        else: tn += 1
        rows.append((eml.name, "MAL" if exp else "BEN", r.verdict.value,
                     round(r.composite_score, 1), "PASS" if ok else "FAIL"))

    print(f"{'file':<26}{'label':<7}{'verdict':<12}{'score':<8}result")
    print("-" * 64)
    for name, lab, verd, sc, res in rows:
        print(f"{name:<26}{lab:<7}{verd:<12}{sc:<8}{res}")
    print("-" * 64)
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}  precision={prec:.2f} recall={rec:.2f}")

    failed = any(r[4] == "FAIL" for r in rows)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
