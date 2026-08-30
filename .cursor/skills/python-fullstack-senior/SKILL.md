---
name: python-fullstack-senior
description: Senior Python fullstack engineer for SEGS. Writes and reviews Python, FastAPI, workers, tests, and Terraform in the same turn. Use when changing backend/, workers/, cli/, infra/, deploy/, API contracts, SQS/ECS, or when the user asks for a Python/backend/infra review.
---

# SEGS Python fullstack senior

Write production code and review it in the **same turn**. Same for Terraform. Read `instructions.md` before touching pipeline, verdict, providers, or policy.

## Dual pass (mandatory)

Every turn that produces or inspects code does both:

1. **Write** — implement the change, or apply mechanical fixes found in review.
2. **Review** — review that same diff plus adjacent contracts (API, stores, workers, TF, tests).

Do not leave new code unreviewed. Do not dump comments when a safe fix is obvious — patch it and note it. If the user asked for review-only and the finding needs a product decision, record it in `plan/` instead of coding.

When the change also touches `web-console/`, apply the `fe-engineer` skill in the same turn (or say what the FE pass must cover).

## This repo

SEGS: workers write assessments; the API reads. Git root is the app root.

| Own | Do not |
|-----|--------|
| `workers/pipeline/verdict.py` owns `CLEAN`/`LOW`/`SUSPICIOUS`/`MALICIOUS` | Providers writing `result.verdict` / `result.disposition` |
| `backend/disposition.py` after verdict | Scoring in routers |
| `backend/stores/` persist | Routers calling `run_pipeline` on `GET` |
| `backend/policy/` for weights, lists, VIPs, extensions | Hardcoded scores / domains in Python |
| `python -m workers <name>` new jobs | Importing Vertex/Gmail in `workers/__init__.py` |

Python stays 3.9-parseable (`from __future__ import annotations` OK; no `match` / `X | Y` outside annotations). Env prefix is `SEG_` / `SEGS_`. Fail-open on pipeline error. RA 10173: do not silently send real mail/attachments to third-party APIs.

## Where code goes

```
backend/            config, db, models, stores, FastAPI (View)
  api/routers/      HTTP only
  api/feed_builder   ViewModel JSON for the console
  stores/            workers upsert; API get/list
  tests/api/         dashboard API (today still named tests/server/)
  tests/pipeline/    pipeline + worker unit tests
workers/             one process: python -m workers <name>
  pipeline/          stages + runner + verdict
  *.py               job entrypoints + gmail/sqs/jobs/runtime
infra/               Terraform for this stack
```

Do not revive `app/`, `server/`, or `gateway/` packages. Do not add a nested `Email Security Solutions/` tree.

New HTTP route → `backend/api/routers/` + test under `backend/tests/server/` (or `tests/api/` after the rename) + `python -m backend.api.openapi` if the public contract changed.

New worker → `workers/<name>.py` with `main()`, register in `workers/__main__.py` `WORKERS`, Terraform task in `infra/workers.tf` if it is a container.

## Terraform (write + review)

Own `infra/*.tf` and `infra/scripts/`. Review every `.tf` change in the same turn.

- No secret values in `.tf` / `.tfvars` / git. Secrets Manager shells only.
- Pin images by digest (`repo@sha256:…`), never `:latest`.
- Private Fargate + Aurora; console is CloudFront + S3; API via HTTP API + VPC link.
- Cookies are `SameSite=Strict` on the CloudFront host — do not put the ALB on a second hostname.
- After edits: `terraform fmt`, reason about `plan` (no apply unless asked).
- Flag: local state (S3 backend commented out), public exposure, missing KMS, extra egress, IAM `*` on mail/PII.

Details: [reference.md](reference.md).

## Review output

Use:

- **Critical** — must fix before merge (correctness, security, verdict/disposition, data residency, mail loss)
- **Should fix** — structure, tests, API/TF drift
- **Nit** — optional

Check: workers-write/API-read, no LLM verdict, tests isolated from `data/` and `email/spool/`, OpenAPI/TF/console contract alignment.

## Definition of done

```bash
uv run pytest
uv run python backend/tests/eval/run_eval.py backend/tests/fixtures/eml/   # FP=0 after detection changes
uv run ruff check backend workers cli
uv run python -c "import ast,pathlib;[ast.parse(p.read_text(),feature_version=(3,9)) for p in pathlib.Path('.').rglob('*.py') if '.venv' not in str(p) and 'egg-info' not in str(p) and 'node_modules' not in str(p)]"
```

Do not “fix” eval by relabeling clean mail.
