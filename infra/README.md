# SEGS Terraform (ap-southeast-1)

Deploys the current Path A layout: analysts hit one CloudFront URL, the API
runs on Fargate, the Gmail receiver polls Workspace outbound (no public
callback, no Route 53).

```
Analyst browser
    │
    ▼
CloudFront + WAF          https://dxxxx.cloudfront.net   (Amazon cert)
    ├─ /*      → S3 OAC   web-console dist
    ├─ /api*   → HTTP API (infra/openapi.yaml) → VPC link → internal ALB
    └─ /scim*  → same HTTP API
                    │
              ECS Fargate api    1024 CPU / 2048 MiB × 2
                    │
              Internal ALB (private)  GET /{worker}/health
                    │
Gmail API ◄── ECS Fargate workers  (private, poll + SQS)
                    │
              Aurora (private) + S3 mail spool + SQS
              KMS CMK (one key)
              Secrets Manager segs/{env}/app + segs/{env}/infra
              ECR pdax/segs-api + pdax/segs-worker (immutable)
```

Private Fargate and Aurora subnets egress through a NAT gateway in the
dedicated SEGS VPC (not the account default VPC) so tasks can pull ECR,
write logs, read secrets, and call Gmail / VirusTotal / GLM.

## Apply

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars   # region / environment; VPC is created
terraform init
terraform apply                                # ECR, ALB, CloudFront, Aurora, SQS, S3, WAF

# Seed secrets (values come from env / .env.prod, not from git)
set -a && source ../.env.prod && set +a
bash scripts/put-secrets.sh

# Build + push digest-pinned images, then apply again
bash scripts/push-images.sh
# terraform apply -var api_image_digest=sha256:… -var receiver_image_digest=sha256:…

# Console objects
cd ../web-console && npm ci && npm run build
cd ../infra && terraform apply -var sync_console=true
```

`terraform output console_url` is the login page. Bootstrap the first admin
the same way as local (`deploy/bootstrap_admin.sh` against that URL, or the
setup wizard).

Workspace setup is unchanged: domain-wide delegation with
`gmail.readonly`. See [docs/gmail-api-setup.md](../docs/gmail-api-setup.md).

## What this stack does not create

- A Route 53 hosted zone
- A public URL for the receiver (poll mode does not need one)
- Secret *values* (only the Secrets Manager shell)

The stack **does** create a dedicated VPC (`10.80.0.0/16` by default), two
public subnets (ALB), two private subnets (Fargate + Aurora), an internet
gateway, and a NAT gateway. It does not use the account default VPC.

Custom domain later: ACM in us-east-1 + `aliases` on the CloudFront
distribution. Do not put the ALB on a second hostname; cookies are
`SameSite=Strict` on the CloudFront host.

## Image immutability

Repositories use `image_tag_mutability = IMMUTABLE`. Task definitions pin
`repo@sha256:…`, never `:latest`. `push-images.sh` tags with the git SHA
and prints the digest for `-var`.

## Fargate sizes and scaling

| Service | CPU / memory | Count | Why |
|---------|--------------|------|-----|
| API | 1024 / 2048 | 2 | Analyze still runs GLM in-process; two tasks for HA |
| gmail_poll | 512 / 1024 | 1 | Singleton (Gmail history). Do not scale out |
| static | 512 / 1024 | 1–4 | SQS target tracking on visible messages |
| content_ai | 1024 / 2048 | 1–6 | SQS target tracking; one LLM thread per task |
| thread_ai | 256 / 512 | 1–3 | SQS target tracking |
| retry / campaign / sender | 256 / 512 | 1 each | Timer loops, not queue drainers |
| Receiver | 512 / 1024 | 0 | Fallback only (`SEG_INLINE_WORKERS=0`) |

Each SQS worker runs **one in-process consumer** (`SEG_STATIC_WORKERS=1`, `SEG_CONTENT_AI_WORKERS=1`). Do not raise uvicorn `--workers` on the API. Aurora Serverless v2 defaults to 0.5–2 ACU; raise `aurora_max_capacity` before lifting `content_ai_max_count` above 4.

SQS autoscaling is off until the account has the Application Auto Scaling service-linked role (`iam:CreateServiceLinkedRole`) or `iam:PassRole` on `esdd-*-autoscaling` to `application-autoscaling.amazonaws.com`. Then set `enable_worker_autoscaling = true`.

CloudWatch dashboard: `terraform output dashboard_url`.

Override with `api_cpu` / `receiver_cpu` if needed.

## CloudFront analyze timeout

Origin read timeout is 60s (CloudFront max without a quota increase).
Long `/api/analyze` runs may need that quota raised to 180s.
