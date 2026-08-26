# Gateway enforcement (Annex C skeleton)

Detection stays in `app/pipeline/` (`run_pipeline`). This package **stores and
acts on** the result: quarantine, confirm-block, release, and **re-evaluate**.

## Where mail goes

Root: `gateway/spool/` (override with `--spool` or `SEG_QUARANTINE_ROOT`)

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

## Enforce modes (`SEG_ENFORCE`)

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
SEG_ENFORCE=quarantine python3 gateway/hold_consumer.py path/to/held.eml
SEG_ENFORCE=quarantine python3 gateway/hold_consumer.py gateway/spool/hold/
```

## Disposition map (`rules/disposition.yaml`)

| Verdict | Disposition |
|---------|-------------|
| CLEAN | DELIVER |
| LOW | LOG |
| SUSPICIOUS | QUARANTINE |
| MALICIOUS | QUARANTINE (REJECT only when enabled) |

## Path B upgrade — pre-delivery Postfix/Rspamd gateway

The platform currently runs **Path A** (post-delivery Gmail API scanning). When
you are ready to intercept mail before delivery (Path B), only three things change:

### Step 1 — Write a `PostfixMilterClient`

The only new code is a class that implements the `EnforcementClient` Protocol
defined in `app/disposition.py:156`:

```python
class EnforcementClient(Protocol):
    def apply(self, queue_id: str, raw: bytes, result: PipelineResult) -> str: ...
```

The milter adapter calls back into Postfix via a milter socket
(use `python-milter` library):

```python
class PostfixMilterClient:
    def apply(self, queue_id: str, raw: bytes, result: PipelineResult) -> str:
        disposition = get_disposition(result.verdict)
        if disposition == Disposition.DELIVER:
            milter_continue()          # SMFIS_CONTINUE
            return "delivered"
        elif disposition == Disposition.QUARANTINE:
            milter_quarantine(queue_id)  # move to quarantine queue
            return "quarantined"
        elif disposition == Disposition.REJECT:
            milter_reject("550 5.7.1 Message rejected by SEGS")
            return "rejected"
```

Pass it to `process_one()` in `hold_consumer.py` in place of `LocalQuarantineClient`.
The spool structure, quarantine dashboard, re-evaluation, and release UI all work
unchanged — they operate on the same spool paths.

### Step 2 — Change MX DNS

Point your domain's MX record from `aspmx.l.google.com` to your Postfix server.
Google Workspace receives clean mail forwarded from Postfix (configured as a
"smart host" or relay). This is a one-line DNS change.

### Step 3 — Flip the enforcement mode

```bash
# In AWS Secrets Manager / .env
SEG_ENFORCE=quarantine
```

No code redeployment required. The switch takes effect on the next ECS task restart
(run `bash deploy/update-service.sh` to force it immediately).

### Checklist before Path B cutover

- [ ] `PostfixMilterClient` written and unit-tested
- [ ] Postfix + Rspamd server running (separate from SEGS ECS)
- [ ] SEGS pipeline accuracy validated on 2+ weeks of real traffic (Path A shadow mode)
- [ ] False-positive rate acceptable (< 0.1% of clean mail flagged)
- [ ] Runbook written for analysts: how to release a quarantined email, how to report an FP
- [ ] MX change tested in staging domain first
- [ ] Rollback plan: revert MX record (< 5 min TTL change)
