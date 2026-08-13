# Gateway enforcement (Annex C skeleton)

Detection stays in `app/pipeline/` (`run_pipeline`). This package **stores and
acts on** the result: quarantine, confirm-block, release, and **re-evaluate**.

## Where mail goes

Root: `gateway/spool/` (override with `--spool` or `PDAX_QUARANTINE_ROOT`)

```
gateway/spool/
├── quarantine/<queue_id>/
│   ├── message.eml      ← original bytes (for re-eval)
│   └── meta.json        ← verdict, disposition, IOCs, reeval_history
├── rejected/<queue_id>/ ← confirmed blocked (remain blocked)
├── released/<queue_id>/ ← delivered or analyst false-positive release
└── shadow_logs/
    └── shadow_enforcement.jsonl
```

| Bucket | Meaning |
|--------|---------|
| `quarantine/` | Held for human review (SUSPICIOUS / MALICIOUS) |
| `rejected/` | Confirmed blocked — do not deliver |
| `released/` | Allowed through (or FP released after review) |

Each entry keeps **`message.eml`**, so you can re-run the pipeline later without
needing the live mail server.

## Enforce modes (`PDAX_ENFORCE`)

| Mode | Behavior |
|------|----------|
| `shadow` (default) | Log intended action; always release (safe first deploy) |
| `quarantine` | Write hold-worthy mail into `spool/quarantine/` |
| `reject` | As quarantine; hard REJECT only if `rules/disposition.yaml` allows it |

## Analyst workflow — re-evaluate quarantined / blocked mail

```bash
# 1) See what is held
python3 gateway/hold_consumer.py --list

# 2) Re-scan one message (updates meta.json reeval_history; leaves it in place)
python3 gateway/hold_consumer.py --reeval invoice_exe_1786062224782

# 3a) Looks benign now → release to inbox path
python3 gateway/hold_consumer.py --release invoice_exe_1786062224782

# 3b) Still bad → confirm block
python3 gateway/hold_consumer.py --keep-blocked invoice_exe_1786062224782

# Or batch re-eval of everything in quarantine/ + rejected/
python3 gateway/hold_consumer.py --reeval-all
python3 gateway/hold_consumer.py --reeval-all --auto-release   # DELIVER/LOG → released/
python3 gateway/hold_consumer.py --reeval-all --auto-block     # still bad → rejected/
```

`--reeval` always records `reeval_history[]` in `meta.json` (previous vs new
verdict/disposition) so you have an audit trail of FP decisions.

## Ingest held mail

```bash
PDAX_ENFORCE=quarantine python3 gateway/hold_consumer.py path/to/held.eml
PDAX_ENFORCE=quarantine python3 gateway/hold_consumer.py gateway/spool/hold/
```

## Disposition map (`rules/disposition.yaml`)

| Verdict | Disposition |
|---------|-------------|
| CLEAN | DELIVER |
| LOW | LOG |
| SUSPICIOUS | QUARANTINE |
| MALICIOUS | QUARANTINE (REJECT only when enabled) |

## Production (not wired yet)

Replace `LocalQuarantineClient` with a Postfix/Rspamd adapter that implements
the same `EnforcementClient` Protocol (RELEASE / quarantine mailbox / 550).
Keep the same spool (or a DB) for re-eval — do not put SMTP calls in `verdict.py`.
