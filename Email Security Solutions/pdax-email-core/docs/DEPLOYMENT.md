# SEGS — AWS ECS Fargate Deployment Guide

This guide deploys the Secure Email Gateway Suite (SEGS) to AWS ECS Fargate in the PDAX
ap-southeast-1 environment. After following all steps you will have:

- A live dashboard at `https://segs.pdax.ph` (internet-facing, SEGS login + rate limiting)
- A Gmail Pub/Sub receiver at `https://segs-mail.pdax.ph` (Google IPs only, WAF-gated)
- Persistent storage on EFS (SQLite databases + quarantine spool)
- All secrets in AWS Secrets Manager — nothing sensitive in the Docker images
- Daily Gmail watch renewal via EventBridge Lambda

**Phases at a glance**

| Phase | Steps | What it does |
|-------|-------|-------------|
| Infrastructure | 1 – 9 | ECR, EFS, IAM, ACM, Secrets Manager, task definitions, CloudWatch, ECS cluster |
| Build & Deploy | 10 – 13 | Docker images → ECR, security groups, ALBs, ECS services |
| Activation | 14 – 19 | DNS, first admin, Pub/Sub, Gmail watches, Lambda fallback, alarms |
| Verification | — | Go-live checklist |

**Before you start**: have `credentials.json` (GCP service account key) and all API keys
ready. See [docs/GMAIL_API_SETUP.md](GMAIL_API_SETUP.md) for the GCP side.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| AWS CLI v2 | Configured with a role that can manage ECR, ECS, EFS, ALB, Secrets Manager |
| Docker | For building and pushing images |
| Python 3.12+ | Used by `deploy/setup-secrets.sh` and `deploy/bootstrap_admin.sh` |
| `curl` + `jq` | For verification and the bootstrap script |
| Existing PDAX VPC | ap-southeast-1, private and public subnets in ≥ 2 AZs |
| Route 53 hosted zone for `pdax.ph` | Or equivalent DNS admin access |
| GCP project with Pub/Sub + service account | See [docs/GMAIL_API_SETUP.md](GMAIL_API_SETUP.md) |

---

## Step 1 — Collect required values

Collect everything before starting — nothing is hardcoded. All values go into Secrets Manager
or shell variables.

**Recommended**: create a local `.env.prod` file (gitignored) and source it. The secrets
setup script in Step 6 reads these automatically and skips interactive prompts.

```bash
# Create your local secrets file — NEVER commit this
cp .env.example .env.prod
nano .env.prod   # fill in all REPLACE_ME values
```

**AWS infrastructure** (get from your AWS account / PDAX network team)
```
AWS_ACCOUNT_ID=<12-digit account ID>
AWS_REGION=ap-southeast-1
VPC_ID=vpc-xxxxxxxx
PRIVATE_SUBNET_IDS=subnet-aaaa,subnet-bbbb    # ≥2 AZs — for ECS tasks (no public IP)
PUBLIC_SUBNET_IDS=subnet-cccc,subnet-dddd     # ≥2 AZs — for both ALBs
OFFICE_CIDR=x.x.x.x/32                        # Optional: PDAX office IP for extra SG restriction
```

**Domains** (you'll create ACM certs in Step 5)
```
DASHBOARD_DOMAIN=segs.pdax.ph          # Dashboard — internet-facing, SEGS login is the gate
RECEIVER_DOMAIN=segs-mail.pdax.ph      # Gmail receiver — Google IPs only (WAF-enforced)
```

**Google / GCP** (from GCP Console and GMAIL_API_SETUP.md)
```
SEG_GMAIL_TOPIC=projects/pdax-prod/topics/segs-gmail
SEG_GMAIL_USERS=security@pdax.ph,pat@pdax.ph
SEG_PUBSUB_TOKEN=<generate: python3 -c "import secrets; print(secrets.token_urlsafe(32))">
credentials.json   # GCP service account key — downloaded from GCP Console
```

**API keys**
```
SEG_GLM_API_KEY=<from existing .env>
SEG_GLM_PROJECT_ID=<from existing .env>
SEG_GLM_MODEL_ID=<from existing .env>
SEG_GLM_FALLBACK1_MODEL_ID=<from existing .env>
SEG_GLM_FALLBACK2_MODEL_ID=<from existing .env>
SEG_GLM_FALLBACK2_LOCATION=<from existing .env>
SEG_GLM_FALLBACK3_MODEL_ID=<from existing .env>
SEG_GLM_FALLBACK3_LOCATION=<from existing .env>
SEG_VT_API_KEY=<VirusTotal API key — virustotal.com/gui/my-apikey>
SEG_ABUSEIPDB_API_KEY=<AbuseIPDB API key — abuseipdb.com/account/api>
SEGS_NOTIFY_SMTP_PASS=<Google Workspace App Password for segs-alerts@pdax.ph>
```

---

## Step 2 — Create ECR repository

```bash
aws ecr create-repository \
  --region ap-southeast-1 \
  --repository-name pdax/segs \
  --image-scanning-configuration scanOnPush=true \
  --encryption-configuration encryptionType=AES256
```

---

## Step 3 — Create EFS file system

EFS provides persistent shared storage across ECS tasks for SQLite databases and the quarantine spool.

```bash
EFS_ID=$(aws efs create-file-system \
  --region ap-southeast-1 \
  --performance-mode generalPurpose \
  --throughput-mode bursting \
  --encrypted \
  --query 'FileSystemId' --output text)

echo "EFS_FILESYSTEM_ID=$EFS_ID"   # save this — needed in Steps 7 and 13

# Create mount targets in each private subnet
for SUBNET_ID in subnet-aaaa subnet-bbbb; do
  aws efs create-mount-target \
    --region ap-southeast-1 \
    --file-system-id "$EFS_ID" \
    --subnet-id "$SUBNET_ID" \
    --security-groups sg-efs-XXXXX   # SG that allows NFS (port 2049) from ECS task SGs
done
```

---

## Step 4 — Create IAM roles

### ECS task execution role
```bash
cat > /tmp/ecs-trust.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role \
  --role-name segs-ecs-execution-role \
  --assume-role-policy-document file:///tmp/ecs-trust.json

aws iam attach-role-policy \
  --role-name segs-ecs-execution-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

# Allow reading Secrets Manager secret
aws iam put-role-policy \
  --role-name segs-ecs-execution-role \
  --policy-name segs-secrets-read \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:ap-southeast-1:'$AWS_ACCOUNT_ID':secret:segs/prod*"
    }]
  }'
```

### Lambda execution role (for Gmail watch renewal)
```bash
aws iam create-role \
  --role-name segs-lambda-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
```

Apply the managed policy document from `deploy/lambda-iam-policy.json` (replace `REPLACE_AWS_ACCOUNT_ID` first):

```bash
sed "s/REPLACE_AWS_ACCOUNT_ID/$AWS_ACCOUNT_ID/g" deploy/lambda-iam-policy.json > /tmp/lambda-policy.json

aws iam put-role-policy \
  --role-name segs-lambda-role \
  --policy-name SegsLambdaPolicy \
  --policy-document file:///tmp/lambda-policy.json
```

The policy grants:
- `secretsmanager:GetSecretValue` on `segs/prod-*` (to read `SEG_PUBSUB_TOKEN` and `SEG_GMAIL_USERS`)
- `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` on the Lambda's own CloudWatch log group

> **Security note**: The current policy grants access to the entire `segs/prod` secret. For least privilege, create a separate `segs/lambda` secret containing only `SEG_PUBSUB_TOKEN` and `SEG_GMAIL_USERS`, then restrict the ARN in `lambda-iam-policy.json` to `segs/lambda-*`. See the `_comment` field in the JSON file for the exact change.

---

## Step 5 — Request ACM certificates

```bash
# Dashboard domain
aws acm request-certificate \
  --region ap-southeast-1 \
  --domain-name segs.pdax.ph \
  --validation-method DNS

# Receiver domain
aws acm request-certificate \
  --region ap-southeast-1 \
  --domain-name segs-mail.pdax.ph \
  --validation-method DNS
```

After running both commands, go to **ACM Console → Certificates → Create CNAME record in Route 53**
for each certificate. Validation completes in about 5 minutes. Wait until both show **Issued** before
continuing — the ALBs won't accept unvalidated certificates.

---

## Step 6 — Store secrets in AWS Secrets Manager

This step uploads all API keys and the Google service account key to a single AWS Secrets Manager
secret (`segs/prod`). ECS tasks read from it at startup — nothing sensitive is ever in the Docker
image or task definition plaintext.

**Option A — recommended (pre-fill `.env.prod`, run the script)**

```bash
# Source your .env.prod from Step 1, then run:
set -a && source .env.prod && set +a
AWS_ACCOUNT_ID=123456789012 bash deploy/setup-secrets.sh
```

The script reads all values from the environment, converts `credentials.json` to an inline JSON
string (`SEGS_GMAIL_CREDENTIALS_JSON`), and creates or updates the `segs/prod` secret.

**Option B — manual prompts (if .env.prod isn't ready yet)**

```bash
AWS_ACCOUNT_ID=123456789012 bash deploy/setup-secrets.sh
# The script will prompt for each value interactively
```

**Verify the secret was created:**

```bash
aws secretsmanager get-secret-value \
  --region ap-southeast-1 \
  --secret-id segs/prod \
  --query SecretString --output text \
  | python3 -c "import json,sys; keys=json.load(sys.stdin).keys(); print('\n'.join(sorted(keys)))"
```

You should see all expected keys listed (SEG_GMAIL_TOPIC, SEG_VT_API_KEY, SEGS_GMAIL_CREDENTIALS_JSON, etc.).

**Updating a single secret later (e.g., rotating a key):**

```bash
aws secretsmanager put-secret-value \
  --region ap-southeast-1 \
  --secret-id segs/prod \
  --secret-string "$(aws secretsmanager get-secret-value \
    --region ap-southeast-1 --secret-id segs/prod \
    --query SecretString --output text \
    | python3 -c "import json,sys; d=json.load(sys.stdin); d['SEG_VT_API_KEY']='NEW_KEY'; print(json.dumps(d))")"

# Then force a re-deploy so containers pick up the new value:
bash deploy/update-service.sh
```

---

## Step 7 — Fill in task definition placeholders

```bash
# Replace placeholder values with your actual account ID and EFS ID
sed -i "s/REPLACE_AWS_ACCOUNT_ID/$AWS_ACCOUNT_ID/g" \
  ecs/task-definition-dashboard.json \
  ecs/task-definition-receiver.json

sed -i "s/REPLACE_EFS_FILESYSTEM_ID/$EFS_ID/g" \
  ecs/task-definition-dashboard.json \
  ecs/task-definition-receiver.json
```

> **Verify**: open both JSON files and confirm no `REPLACE_*` strings remain.

---

## Step 8 — Create CloudWatch log groups

```bash
aws logs create-log-group --log-group-name /segs/dashboard --region ap-southeast-1
aws logs create-log-group --log-group-name /segs/receiver  --region ap-southeast-1

aws logs put-retention-policy --log-group-name /segs/dashboard \
  --retention-in-days 90 --region ap-southeast-1
aws logs put-retention-policy --log-group-name /segs/receiver \
  --retention-in-days 90 --region ap-southeast-1
```

---

## Step 9 — Create ECS cluster

```bash
aws ecs create-cluster \
  --cluster-name segs \
  --region ap-southeast-1 \
  --capacity-providers FARGATE FARGATE_SPOT \
  --default-capacity-provider-strategy capacityProvider=FARGATE,weight=1
```

---

## Step 10 — Build and push Docker images

From the repo root:

```bash
export AWS_ACCOUNT_ID=123456789012
export AWS_REGION=ap-southeast-1
export ECR_REPO=pdax/segs

bash deploy/push-images.sh
```

This builds both images (dashboard + receiver), tags them with the current Git SHA and `latest`,
and pushes to ECR. The script logs into ECR automatically. This step takes 3–5 minutes on first run.

---

## Step 11 — Create security groups

### Dashboard ALB SG (internet-facing — SEGS login is the access control layer)

```bash
DASHBOARD_ALB_SG=$(aws ec2 create-security-group \
  --vpc-id $VPC_ID \
  --group-name segs-dashboard-alb \
  --description "SEGS dashboard ALB — internet-facing" \
  --query 'GroupId' --output text)

# Allow HTTPS from anywhere. SEGS enforces login + rate limiting on every request.
# Optional: replace 0.0.0.0/0 with $OFFICE_CIDR to restrict to the PDAX office IP.
aws ec2 authorize-security-group-ingress \
  --group-id $DASHBOARD_ALB_SG \
  --protocol tcp --port 443 --cidr 0.0.0.0/0
```

> **JumpCloud SSO (planned future step)**: When SSO is activated, the ALB's OIDC authenticator
> becomes an additional access control layer before login. No code change required — see
> [docs/JUMPCLOUD_SSO.md](JUMPCLOUD_SSO.md) for the one-time activation steps.

### Receiver ALB SG (Google Pub/Sub IPs — WAF-enforced)

```bash
RECEIVER_ALB_SG=$(aws ec2 create-security-group \
  --vpc-id $VPC_ID \
  --group-name segs-receiver-alb \
  --description "SEGS receiver ALB — Google IPs via WAF" \
  --query 'GroupId' --output text)

# Open to all — WAF Web ACL enforces the Google IP restriction
aws ec2 authorize-security-group-ingress \
  --group-id $RECEIVER_ALB_SG \
  --protocol tcp --port 443 --cidr 0.0.0.0/0
```

> **WAF IP set**: Google publishes 997+ IP ranges — more than the 60-rule SG limit. After creating
> the receiver ALB, attach a WAF Web ACL with an IP set from `deploy/google-pubsub-ips.txt` and set
> the default action to BLOCK. Refresh quarterly (see Maintenance section).

### ECS task SGs (private — only accepts traffic from the ALB above)

```bash
DASHBOARD_TASK_SG=$(aws ec2 create-security-group \
  --vpc-id $VPC_ID \
  --group-name segs-dashboard-task \
  --description "SEGS dashboard ECS task" \
  --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress \
  --group-id $DASHBOARD_TASK_SG \
  --protocol tcp --port 8765 \
  --source-group $DASHBOARD_ALB_SG

RECEIVER_TASK_SG=$(aws ec2 create-security-group \
  --vpc-id $VPC_ID \
  --group-name segs-receiver-task \
  --description "SEGS receiver ECS task" \
  --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress \
  --group-id $RECEIVER_TASK_SG \
  --protocol tcp --port 8766 \
  --source-group $RECEIVER_ALB_SG
```

---

## Step 12 — Create ALBs, target groups, and listeners

Use the AWS Console or Terraform — the CLI commands for ALBs are long. Key settings:

| ALB | Scheme | Subnets | SG | Listener | Target port |
|-----|--------|---------|-----|----------|------------|
| `segs-dashboard-alb` | internet-facing | Public subnets | `$DASHBOARD_ALB_SG` | 443 HTTPS | 8765 |
| `segs-receiver-alb` | internet-facing | Public subnets | `$RECEIVER_ALB_SG` | 443 HTTPS | 8766 |

**Target group health check paths:**
- Dashboard: `GET /api/health` — expect HTTP 200
- Receiver: `GET /health` — expect HTTP 200

**Assign the ACM certificates** from Step 5 to the respective HTTPS listeners.

**Note the ARNs** — you'll need them in Step 13:
```bash
DASHBOARD_TG_ARN=arn:aws:elasticloadbalancing:ap-southeast-1:...:targetgroup/segs-dashboard/...
RECEIVER_TG_ARN=arn:aws:elasticloadbalancing:ap-southeast-1:...:targetgroup/segs-receiver/...
```

---

## Step 13 — Create ECS services (first deploy)

```bash
export AWS_ACCOUNT_ID=123456789012
export EFS_FILESYSTEM_ID=fs-xxxxxxxxx   # from Step 3

# Register task definitions
aws ecs register-task-definition \
  --cli-input-json file://ecs/task-definition-dashboard.json

aws ecs register-task-definition \
  --cli-input-json file://ecs/task-definition-receiver.json

# Create services (first deploy only — use update-service.sh for subsequent deploys)
aws ecs create-service \
  --cluster segs \
  --service-name segs-dashboard \
  --task-definition segs-dashboard \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$PRIVATE_SUBNET_IDS],securityGroups=[$DASHBOARD_TASK_SG],assignPublicIp=DISABLED}" \
  --load-balancers "targetGroupArn=$DASHBOARD_TG_ARN,containerName=segs-dashboard,containerPort=8765"

aws ecs create-service \
  --cluster segs \
  --service-name segs-receiver \
  --task-definition segs-receiver \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$PRIVATE_SUBNET_IDS],securityGroups=[$RECEIVER_TASK_SG],assignPublicIp=DISABLED}" \
  --load-balancers "targetGroupArn=$RECEIVER_TG_ARN,containerName=segs-receiver,containerPort=8766"

# Wait until both services are stable (takes 2-3 minutes)
aws ecs wait services-stable \
  --cluster segs \
  --services segs-dashboard segs-receiver
```

> **Future deploys**: for code updates, run `bash deploy/update-service.sh` — it re-registers the
> task definitions with the new image SHA and forces a rolling restart.

---

## Step 14 — Configure DNS

Add A records (ALB alias) in Route 53:

| Name | Type | Value |
|------|------|-------|
| `segs.pdax.ph` | A (Alias) | `segs-dashboard-alb` DNS name |
| `segs-mail.pdax.ph` | A (Alias) | `segs-receiver-alb` DNS name |

DNS propagation is near-instant for Route 53 alias records. Verify with:

```bash
curl -sf https://segs.pdax.ph/api/health && echo "Dashboard reachable"
curl -sf https://segs-mail.pdax.ph/health && echo "Receiver reachable"
```

---

## Step 15 — Create the first admin account

**Do this immediately after DNS resolves — before anyone visits the dashboard.** The setup
endpoint closes permanently after the first account is created.

**Option A — CLI bootstrap (recommended for DevOps)**

```bash
SEGS_URL=https://segs.pdax.ph \
SEGS_ADMIN_USER=admin \
SEGS_ADMIN_PASS='YourStr0ng!Pass' \
bash deploy/bootstrap_admin.sh
```

Password rules enforced by the app:
- Minimum 8 characters
- At least one uppercase letter (A–Z)
- At least one lowercase letter (a–z)
- At least one number (0–9)
- At least one special character (`!@#$%^&*` etc.)

The script checks setup status first and exits safely if an account already exists.

**Option B — browser**

Visit `https://segs.pdax.ph` — if no admin account exists yet, the login page automatically
displays a first-admin creation form.

**After creating the admin account:**
1. Log in to verify the dashboard loads correctly
2. Go to **Settings → Users** to add analyst and viewer accounts for the SOC team
3. Keep the enforcement mode on **shadow** (default) for the first two weeks — review the Feed
   before enabling quarantine

> **Security note**: clear the password from your shell history after running:
> `history -c` (bash) or `history -p` (zsh)

---

## Step 16 — Configure Pub/Sub push subscription

In GCP Console → Pub/Sub → your topic → Subscriptions → Create subscription:

```
Delivery type:          Push
Endpoint URL:           https://segs-mail.pdax.ph/pubsub
Authentication:         Add authorization header
  Header name:          Authorization
  Header value:         Bearer <SEG_PUBSUB_TOKEN>   (same token stored in segs/prod)
Acknowledgement deadline: 60 seconds
Retry policy:           Retry with exponential backoff (min 10s, max 600s)
Message retention:      7 days
```

---

## Step 17 — Register Gmail watches

Log in to the dashboard, then go to **Settings → Gmail Watches → Register** for each monitored
mailbox. Or use the API directly:

```bash
# Log in first to get a session cookie
LOGIN_RESP=$(curl -s -c /tmp/segs-cookies.txt -X POST https://segs.pdax.ph/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YourStr0ng!Pass"}')
echo "$LOGIN_RESP"   # should show {"success": true}

# Register a watch for each mailbox
curl -s -b /tmp/segs-cookies.txt \
  -X POST "https://segs.pdax.ph/api/gmail/watch/security@pdax.ph" \
  -H "Content-Type: application/json"
```

The watch auto-renews on every ECS task restart (lifespan hook in `gateway/gmail_receiver.py`).
The EventBridge Lambda in Step 18 provides a daily fallback.

---

## Step 18 — Deploy Lambda watch renewal fallback

```bash
cd deploy
zip lambda_renew_watches.zip lambda_renew_watches.py

aws lambda create-function \
  --function-name segs-renew-watches \
  --runtime python3.12 \
  --handler lambda_renew_watches.handler \
  --role arn:aws:iam::$AWS_ACCOUNT_ID:role/segs-lambda-role \
  --zip-file fileb://lambda_renew_watches.zip \
  --environment "Variables={RECEIVER_URL=https://segs-mail.pdax.ph,SECRET_NAME=segs/prod}"

# EventBridge rule: daily at 00:00 PHT (16:00 UTC)
aws events put-rule \
  --name segs-renew-watches-daily \
  --schedule-expression "cron(0 16 * * ? *)" \
  --state ENABLED

aws lambda add-permission \
  --function-name segs-renew-watches \
  --statement-id segs-eventbridge \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:ap-southeast-1:$AWS_ACCOUNT_ID:rule/segs-renew-watches-daily

aws events put-targets \
  --rule segs-renew-watches-daily \
  --targets "Id=1,Arn=arn:aws:lambda:ap-southeast-1:$AWS_ACCOUNT_ID:function:segs-renew-watches"
```

---

## Step 19 — Create CloudWatch alarms

```bash
SNS_ARN=arn:aws:sns:ap-southeast-1:$AWS_ACCOUNT_ID:segs-alerts

# Dashboard unhealthy
aws cloudwatch put-metric-alarm \
  --alarm-name segs-dashboard-unhealthy \
  --metric-name HealthyHostCount \
  --namespace AWS/ApplicationELB \
  --dimensions Name=TargetGroup,Value=$DASHBOARD_TG_ID Name=LoadBalancer,Value=$DASHBOARD_ALB_ID \
  --statistic Minimum --period 60 --evaluation-periods 2 \
  --threshold 1 --comparison-operator LessThanThreshold \
  --alarm-actions $SNS_ARN

# Watch renewal failed (log-based metric)
aws logs put-metric-filter \
  --log-group-name /segs/receiver \
  --filter-name watch-renewal-failed \
  --filter-pattern "watch renewal FAILED" \
  --metric-transformations \
    metricName=WatchRenewalFailed,metricNamespace=SEGS,metricValue=1

aws cloudwatch put-metric-alarm \
  --alarm-name segs-watch-renewal-failed \
  --metric-name WatchRenewalFailed \
  --namespace SEGS \
  --statistic Sum --period 86400 --evaluation-periods 1 \
  --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions $SNS_ARN
```

---

## Go-live checklist

Run through this after completing all 19 steps:

```bash
# ── Infrastructure ──────────────────────────────────────────────────────────

# Both ECS services running
aws ecs describe-services \
  --cluster segs --services segs-dashboard segs-receiver \
  --query 'services[*].[serviceName,runningCount,desiredCount,status]' \
  --output table
# Expected: 1/1 running, ACTIVE for both

# Health endpoints
curl -sf https://segs.pdax.ph/api/health && echo "Dashboard OK"
curl -sf https://segs-mail.pdax.ph/health && echo "Receiver OK"

# Security headers present
curl -sI https://segs.pdax.ph/api/health | grep -E "x-frame-options|strict-transport|x-content"

# ── Application ─────────────────────────────────────────────────────────────

# Login page reachable
curl -sf https://segs.pdax.ph/ | grep -q "Sign in" && echo "Login page OK"

# Admin account exists (setup should be closed)
curl -sf https://segs.pdax.ph/api/auth/setup/status | python3 -c \
  "import json,sys; d=json.load(sys.stdin); print('Setup closed OK' if not d.get('needs_setup') else 'WARNING: no admin account yet')"

# Gmail watch renewal logged at last receiver startup
aws logs filter-log-events \
  --region ap-southeast-1 \
  --log-group-name /segs/receiver \
  --filter-pattern "watch renewed" \
  --start-time $(python3 -c "import time; print(int((time.time()-3600)*1000))")
```

**Manual checks (do in a browser):**
- [ ] Log in to `https://segs.pdax.ph` with the admin account
- [ ] Dashboard Feed page loads without errors
- [ ] Settings → Users shows the admin account
- [ ] Settings → Gmail Watches shows watches registered for each monitored mailbox
- [ ] Send a test email to a monitored mailbox — it should appear in the Feed within 30 seconds

**After two weeks in shadow mode:**
- [ ] Review the Feed — confirm low false-positive rate
- [ ] Enable quarantine: in the dashboard go to **Settings → Enforcement → Quarantine**
  (or update `SEG_ENFORCE=quarantine` in Secrets Manager and run `bash deploy/update-service.sh`)

---

## Ongoing maintenance

### Deploying a code update

```bash
bash deploy/push-images.sh        # rebuild + push new images to ECR
bash deploy/update-service.sh     # register new task definitions + rolling restart
```

### Rotating a secret (e.g. an API key)

```bash
# Update the value in Secrets Manager
aws secretsmanager put-secret-value \
  --region ap-southeast-1 \
  --secret-id segs/prod \
  --secret-string "$(aws secretsmanager get-secret-value \
    --region ap-southeast-1 --secret-id segs/prod \
    --query SecretString --output text \
    | python3 -c "import json,sys; d=json.load(sys.stdin); d['SEG_VT_API_KEY']='NEW_KEY'; print(json.dumps(d))")"

# Restart containers to pick up the new value
bash deploy/update-service.sh
```

### Adding a user account

Log in to the dashboard → **Settings → Users → Add User**. Roles:
- **Admin**: full access (users, settings, policy, all actions)
- **Analyst**: view feed, release/block quarantine
- **Viewer**: read-only feed

### Scaling

```bash
# Scale the dashboard service (the receiver rarely needs > 1 task)
aws ecs update-service \
  --cluster segs --service segs-dashboard --desired-count 2
```

### Connecting ClamAV (recommended — defense-in-depth for attachments AND URLs)

SEGS is pre-wired to use ClamAV for **two independent scanning paths**. Both activate with a single environment variable and require no code changes.

**What `SEG_SANDBOX_PROVIDER=clamav` enables:**

| Scan path | Input | What ClamAV checks | Outbound connection from SEGS? |
|-----------|-------|-------------------|-------------------------------|
| **Attachment scan** (`app/pipeline/sandbox.py`) | Attachment bytes streamed to `clamd` | Full ClamAV signature database — malware, ransomware, phishing kits, malicious macros (~9M+ sigs) | None — local clamd only |
| **URL string scan** (`app/pipeline/intel.py`) | URL bytes streamed to `clamd` | URL-based signatures — URLhaus blocklist, phishing URL patterns, malware-distribution domains | **None — local clamd only** |

> **Important — URL detonation policy:** SEGS never opens attacker URLs from the SEGS machine. `SEG_LANDING_FETCH` is **permanently disabled (`0`) in all task definitions** — do not change it. URL intelligence comes from two safe sources: VirusTotal's API (VT's servers fetch the URL, not SEGS) and ClamAV URL signature scanning (local, zero outbound). See `docs/CONFIGURATION.md §Defense in Depth — URL Analysis`.

**How to wire it:**

1. **Ensure clamd is running** on a host reachable from the SEGS ECS tasks. The most common setups:
   - **Sidecar container** (recommended): add a `clamav` container to both ECS task definitions (`segs-dashboard` and `segs-receiver`), sharing the same network namespace. clamd listens on `localhost:3310`.
   - **Shared ECS service**: run clamd as a separate `segs-clamav` ECS service in the same VPC. Use the service's internal DNS name as `SEG_CLAMD_HOST`.

2. **Install pyclamd**: in `requirements.txt`, uncomment the `pyclamd` line and rebuild the Docker image.

3. **Add the env vars** to Secrets Manager (`segs/prod`):
   ```bash
   # For sidecar (same task):
   SEG_SANDBOX_PROVIDER=clamav
   SEG_CLAMD_HOST=localhost
   SEG_CLAMD_PORT=3310

   # For Unix socket (if using a shared volume mount):
   SEG_CLAMD_SOCKET=/var/run/clamav/clamd.ctl
   ```

4. **Verify attachment scanning** — upload an EICAR test EML via the Analyzer:
   ```
   # Expected in the Full Markdown Report:
   # ClamAV | 🔴 MALICIOUS — Eicar-Signature
   # Hard Override: clam_malicious
   ```

5. **Verify URL scanning** — upload an EML containing a URLhaus-listed URL:
   ```
   # Expected in the Intel stage flags:
   # intel_url_clam:<url>
   # Hard Override: threat_intel_hit   (verdict = MALICIOUS, score = 100)
   ```

**Graceful degradation:** If clamd is not configured or is unreachable, both scan paths skip silently — SEGS logs `sandbox_clam_unavailable` for attachment scans and skips URL string scans without error. No other stage is affected. The pipeline always completes normally.

**Policy gates:**
- Attachment hits: gated by `virtual_analyzer` in `rules/policy.yaml` (default: `enabled: true`). A hit fires the `clam_malicious` hard override.
- URL hits: gated by `correlated_intelligence` in `rules/policy.yaml` (default: `enabled: true`). A hit fires the `threat_intel_hit` hard override — same gate as VirusTotal URL matches.

---

### Enabling Wazuh SIEM integration (S3 log shipping)

SEGS ships audit logs to S3 as gzip-compressed JSONL batches. The shipper runs as a background thread inside the dashboard ECS task and is enabled by adding three env vars to Secrets Manager.

**Step 1 — Create the S3 bucket** (if it doesn't already exist):

```bash
aws s3 create-bucket \
  --bucket segs-logs-pdax \
  --region ap-southeast-1 \
  --create-bucket-configuration LocationConstraint=ap-southeast-1

# Enable server-side encryption
aws s3api put-bucket-encryption \
  --bucket segs-logs-pdax \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Block public access
aws s3api put-public-access-block \
  --bucket segs-logs-pdax \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

**Step 2 — Grant the ECS task role `s3:PutObject`**:

```bash
aws iam put-role-policy \
  --role-name segs-task-role \
  --policy-name segs-s3-log-shipping \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::segs-logs-pdax/segs/logs/*"
    }]
  }'
```

**Step 3 — Add env vars to Secrets Manager**:

```bash
# Add SEG_S3_BUCKET, SEG_S3_PREFIX, SEG_S3_REGION to segs/prod
aws secretsmanager put-secret-value \
  --region ap-southeast-1 \
  --secret-id segs/prod \
  --secret-string "$(aws secretsmanager get-secret-value \
    --region ap-southeast-1 --secret-id segs/prod \
    --query SecretString --output text \
    | python3 -c "
import json, sys
d = json.load(sys.stdin)
d['SEG_S3_BUCKET'] = 'segs-logs-pdax'
d['SEG_S3_PREFIX'] = 'segs/logs'
d['SEG_S3_REGION'] = 'ap-southeast-1'
print(json.dumps(d))")"

bash deploy/update-service.sh
```

**Step 4 — Verify** (wait ~60 seconds for the first batch):

```bash
aws s3 ls s3://segs-logs-pdax/segs/logs/ --recursive --region ap-southeast-1 | tail -20
```

You should see `.jsonl.gz` objects under `segs/logs/activity_audit/` and optionally `segs/logs/shadow_enforcement/`.

**Wazuh S3 integration**: point Wazuh's S3 bucket module at `segs-logs-pdax` with prefix `segs/logs`. Each record carries `"wazuh": true` and standard fields (`action`, `actor`, `actor_role`, `ts`, `detail`, `meta`). See `docs/OPERATIONS.md §Wazuh SIEM log shipping` for monitoring and troubleshooting.

---

### Refreshing Google IP list for WAF (quarterly)

```bash
curl -s https://www.gstatic.com/ipranges/cloud.json \
  | python3 -c "import json,sys; [print(p['ipv4Prefix']) for p in json.load(sys.stdin)['prefixes'] if 'ipv4Prefix' in p]" \
  > deploy/google-pubsub-ips.txt
# Then update the WAF IP set: AWS Console → WAF → IP sets → segs-google-ips → Edit
```

Google publishes change notifications at `https://www.gstatic.com/ipranges/cloud-services.json`.
