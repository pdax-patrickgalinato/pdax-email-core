# SEGS Python fullstack — reference

Read `instructions.md` for scoring, providers, and compliance. This file is layout + TF detail.

## Target packages

```
backend/
  config.py           pydantic-settings (no .env auto-load)
  db.py               Postgres or SQLite
  models.py           StageResult, PipelineResult, Verdict, Disposition
  parsed_email.py     MIME + originating IPs
  disposition.py      verdict → spool action
  report.py           CLI / Slack / flag descriptions
  notify.py           quarantine notify
  paths.py            repo-rooted paths
  schema.sql
  stores/             persistence; workers write, API reads
  api/                FastAPI View + ViewModels
    main.py           app factory, static SPA last
    routers/          HTTP
    feed_builder.py   console JSON
    security.py       headers, SSO, limiters
  tests/
    pipeline/         stages, workers, stores
    server/           API (rename target: tests/api/)
    gateway/          leftover name (gmail poll)
    tools/            CLI
    eval/run_eval.py
workers/
  __main__.py         name → main()
  pipeline/           detection only
  gmail.py            Gmail API I/O
  sqs.py / jobs.py     queues
  runtime.py          heartbeats / process name
infra/                one stack, ap-southeast-1
```

## Invariants (do not re-learn)

- `run_pipeline()` in `workers/pipeline/runner.py` is the only scoring entry for CLI and eval.
- Stage `run()` returns `StageResult`; runner `safe()` wraps it. Never raise out of `run()`.
- Intel before content AI. Correlation is weighted-only.
- `allow_reject_on_malicious` stays false until shadow-mode FP is essentially zero.
- Default enforce is shadow (`SEG_ENFORCE`).
- Hash-only VT; no file upload of PDAX attachments.
- `workers/__init__.py` stays lazy. Eager Vertex/Gmail imports delay `:8766` and fail the ALB health check.

## Known structural debt (do not make worse)

- `backend/tests/server/` and `backend/tests/gateway/` are leftover names.
- `workers/gmail_llm.py` is a re-export of `workers.content_ai`.
- `workers/sender.py` (job) vs `workers/pipeline/sender.py` (stage) — import the package path explicitly.
- `workers/content_ai.py` (job) vs `workers/pipeline/content_ai.py` (stage providers).
- `jobs.KINDS` is not the full SQS graph; production is SQS in `infra/sqs.tf`.
- API `GET /api/feed` must stay a SELECT. Do not add `run_pipeline` to list handlers.
- `backend/api/main.py` must not start Gmail poll or LLM workers.

## Terraform map

| File | Owns |
|------|------|
| `vpc.tf` `network.tf` | Dedicated VPC, subnets, NAT |
| `ecs.tf` `workers.tf` `workers_alb.tf` `autoscaling.tf` | API + split workers |
| `sqs.tf` | static → content_ai → thread_ai → campaign ∥ profile |
| `aurora.tf` `s3.tf` `kms.tf` | Data plane |
| `apigateway.tf` `openapi.yaml` | Public `/api` `/scim` |
| `cloudfront.tf` `waf.tf` `s3.tf` | Console |
| `iam.tf` `logs.tf` `monitoring.tf` | Least privilege + 90-day logs |

Do not commit `infra/.bin/`, `*.tfstate`, or real `terraform.tfvars`. Remote state in `versions.tf` is still commented — flag it on infra reviews; do not enable without the user asking.

Worker containers match `WORKERS` in `workers/__main__.py` (except `receiver` / test-only `profile` / `sender_risk` aliases). Changing a worker name means TF + health path + console workers page.

## Tests

- New tests under `backend/tests/{pipeline,server,tools}/` so pytest collects them.
- Monkey-patch paths to temp dirs. Never touch real `data/`, `email/spool/`, or `backend/policy/`.
- Server tests: FastAPI `TestClient`.
- Isolation fixtures live in `backend/tests/conftest.py`.
