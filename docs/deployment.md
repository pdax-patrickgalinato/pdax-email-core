# SEGS — AWS deployment

Infrastructure lives in [`infra/`](../infra/README.md). Apply that stack instead
of the older `deploy/ecs/*.json` task definitions.

After `terraform apply` you will have:

- SOC console at the CloudFront URL (`terraform output console_url`) — S3 origin,
  `/api*` and `/scim*` proxied to API Gateway (OpenAPI `infra/openapi.yaml`) →
  VPC link → internal ALB so `seg_session` cookies stay same-origin
- API on Fargate (1024 CPU / 2048 MiB, two tasks) behind a **VPC-internal** ALB
  reachable only through that VPC link
- Gmail workers on Fargate — **split tasks** (`gmail_poll`, `static`, `content_ai`,
  `thread_ai`, `retry`, `campaign`, `sender`) when `worker_image_digest` is set.
  Each serves `/health` on :8766 behind a **VPC-internal ALB**; the API probes
  `{alb}/{name}/health` via `SEG_WORKER_HEALTH_BASE_URL`. `static` / `content_ai` /
  `thread_ai` autoscale on SQS visible messages (one consumer thread per task).
  The all-in-one receiver stays as a fallback with `receiver_desired_count = 0`
  and `SEG_INLINE_WORKERS=0`.
- Aurora Serverless v2 Postgres (0.5–2 ACU, private subnets) for application data
- S3 mail spool + five SQS queues, all encrypted with one project CMK
- CloudWatch dashboard (`terraform output dashboard_url`) plus DLQ / API / Aurora alarms
- Secrets Manager `segs/{env}/app` (operator) and `segs/{env}/infra` (Terraform)
- Immutable ECR repos; CloudWatch Logs retention 90 days

**Before you start**: `credentials.json` and API keys. This stack creates its
own VPC (not the account default). Workspace DWD is
[`gmail-api-setup.md`](gmail-api-setup.md).

## Apply order

1. Copy `infra/terraform.tfvars.example` → `infra/terraform.tfvars` (region /
   environment only — VPC and subnets are created by Terraform).
2. `cd infra && terraform init && terraform apply`
3. `bash scripts/put-secrets.sh` (values from `.env.prod`, not git)
4. `bash scripts/push-images.sh` then apply again with the printed digests
5. `cd web-console && npm ci && npm run build` then
   `terraform apply -var sync_console=true`
6. Open `console_url`, complete first-admin setup

Image tags are immutable. Task definitions pin `repo@sha256:…`, never `:latest`.

Custom DNS (`segs.pdax.ph`) is optional later: ACM in us-east-1 + CloudFront
aliases. Do not put the ALB on a second hostname.

Dockerfiles live under `deploy/docker/`. ECS JSON under `deploy/ecs/` is
superseded by Terraform and should not be used for new deploys.

Local stand-in is **one container per worker** plus the API and a Postgres sidecar:

```bash
cp .env.example .env   # fill keys
docker compose up --build
```

- API: `http://localhost:8765` — HTTP only (no in-process jobs)
- Workers: `python -m workers <name>` — gmail_poll, static, content_ai, thread_ai, retry, campaign, profile, sender_risk
- Postgres: `postgresql://segs:segs@localhost:5432/segs`
- Filesystem spool unless `SEG_S3_BUCKET` is set
