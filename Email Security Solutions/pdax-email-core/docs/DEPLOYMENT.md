# SEGS — AWS ECS Fargate Deployment Guide

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| AWS CLI v2 | Configured with a role that can manage ECR, ECS, EFS, ALB, Secrets Manager |
| Docker | For building and pushing images |
| Python 3.12+ | For `deploy/setup-secrets.sh` helper |
| Existing PDAX VPC | ap-southeast-1, with private and public subnets in ≥2 AZs |
| Route 53 hosted zone for `pdax.ph` | Or equivalent DNS admin access |
| GCP project with Pub/Sub + service account | See [docs/GMAIL_API_SETUP.md](GMAIL_API_SETUP.md) |
| JumpCloud VPN CIDR | The CIDR block(s) SOC analysts connect from |

---

## Step 1 — Gather required values

Collect these before starting. Nothing is hardcoded — all values go into Secrets Manager or shell variables.

**AWS**
```
AWS_ACCOUNT_ID=<12-digit account ID>
AWS_REGION=ap-southeast-1
VPC_ID=vpc-xxxxxxxx
PRIVATE_SUBNET_IDS=subnet-aaaa,subnet-bbbb    # ≥2 AZs, for dashboard + ECS tasks
PUBLIC_SUBNET_IDS=subnet-cccc,subnet-dddd     # ≥2 AZs, for receiver ALB
VPN_CIDR=10.8.0.0/16                          # JumpCloud VPN CIDR
```

**Domains (request ACM certs via DNS validation in Route 53)**
```
DASHBOARD_DOMAIN=segs.pdax.ph          # Internal, VPN-only
RECEIVER_DOMAIN=segs-mail.pdax.ph      # Public, Google IPs only
```

**Google (from GCP setup — see GMAIL_API_SETUP.md)**
```
SEG_GMAIL_TOPIC=projects/pdax-prod/topics/segs-gmail
SEG_GMAIL_USERS=security@pdax.ph,pat@pdax.ph
SEG_PUBSUB_TOKEN=<random token — generate: python3 -c "import secrets; print(secrets.token_urlsafe(32))">
credentials.json  # GCP service account key file (downloaded from GCP Console)
```

**Content AI**
```
SEG_GLM_MODEL_ID=<from existing .env>
SEG_GLM_API_KEY=<from existing .env>
SEG_GLM_PROJECT_ID=<from existing .env>
# ... fallback model IDs (see .env.example)
```

**Threat intel**
```
SEG_VT_API_KEY=<VirusTotal API key>
SEG_ABUSEIPDB_API_KEY=<AbuseIPDB API key>
```

**SMTP notifications**
```
SEGS_NOTIFY_SMTP_PASS=<App Password for segs-alerts@pdax.ph>
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

```bash
# Create file system
EFS_ID=$(aws efs create-file-system \
  --region ap-southeast-1 \
  --performance-mode generalPurpose \
  --throughput-mode bursting \
  --encrypted \
  --query 'FileSystemId' --output text)

echo "EFS_FILESYSTEM_ID=$EFS_ID"

# Create mount targets in each private subnet
for SUBNET_ID in subnet-aaaa subnet-bbbb; do
  aws efs create-mount-target \
    --region ap-southeast-1 \
    --file-system-id "$EFS_ID" \
    --subnet-id "$SUBNET_ID" \
    --security-groups sg-efs-XXXXX   # SG that allows NFS (2049) from ECS tasks
done
```

Note the `EFS_FILESYSTEM_ID` — you'll need it in Step 7.

---

## Step 4 — Create IAM roles

### ECS task execution role
```bash
# Trust policy
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

# Attach managed policies
aws iam attach-role-policy \
  --role-name segs-ecs-execution-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

# Allow reading the Secrets Manager secret
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

### Lambda execution role (for watch renewal)
```bash
aws iam create-role \
  --role-name segs-lambda-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

aws iam attach-role-policy \
  --role-name segs-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws iam put-role-policy \
  --role-name segs-lambda-role \
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

---

## Step 5 — Request ACM certificates

```bash
# Dashboard (internal ALB — DNS validation in Route 53)
aws acm request-certificate \
  --region ap-southeast-1 \
  --domain-name segs.pdax.ph \
  --validation-method DNS

# Receiver (internet-facing ALB)
aws acm request-certificate \
  --region ap-southeast-1 \
  --domain-name segs-mail.pdax.ph \
  --validation-method DNS
```

Add the CNAME records to Route 53 as prompted by the ACM console. Validation completes in ~5 minutes.

---

## Step 6 — Store secrets in AWS Secrets Manager

From the repo root (with `credentials.json` present):

```bash
AWS_ACCOUNT_ID=123456789012 bash deploy/setup-secrets.sh
```

This prompts for each secret value interactively, reads `credentials.json`, converts it to a single-line JSON string, and creates (or updates) the `segs/prod` secret.

To update a single key later:

```bash
aws secretsmanager put-secret-value \
  --region ap-southeast-1 \
  --secret-id segs/prod \
  --secret-string "$(aws secretsmanager get-secret-value \
    --region ap-southeast-1 --secret-id segs/prod \
    --query SecretString --output text \
    | python3 -c "import json,sys; d=json.load(sys.stdin); d['SEG_VT_API_KEY']='NEW_KEY'; print(json.dumps(d))")"
```

---

## Step 7 — Fill in placeholders in task definitions

Edit `ecs/task-definition-dashboard.json` and `ecs/task-definition-receiver.json`:

```bash
# Replace all REPLACE_AWS_ACCOUNT_ID occurrences
sed -i "s/REPLACE_AWS_ACCOUNT_ID/$AWS_ACCOUNT_ID/g" \
  ecs/task-definition-dashboard.json \
  ecs/task-definition-receiver.json

# Replace REPLACE_EFS_FILESYSTEM_ID with your EFS ID
sed -i "s/REPLACE_EFS_FILESYSTEM_ID/$EFS_ID/g" \
  ecs/task-definition-dashboard.json \
  ecs/task-definition-receiver.json
```

---

## Step 8 — Create CloudWatch log groups

```bash
aws logs create-log-group --log-group-name /segs/dashboard --region ap-southeast-1
aws logs create-log-group --log-group-name /segs/receiver  --region ap-southeast-1

# Retention: 90 days (adjust to your policy)
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
  --default-capacity-provider-strategy \
    capacityProvider=FARGATE,weight=1
```

---

## Step 10 — Build and push container images

From the repo root:

```bash
export AWS_ACCOUNT_ID=123456789012
export AWS_REGION=ap-southeast-1
export ECR_REPO=pdax/segs

bash deploy/push-images.sh
```

This builds both images, tags them with the current Git SHA and `latest`, and pushes to ECR. The script logs into ECR automatically.

---

## Step 11 — Create security groups

### Dashboard ALB SG (VPN-only HTTPS)
```bash
DASHBOARD_ALB_SG=$(aws ec2 create-security-group \
  --vpc-id $VPC_ID \
  --group-name segs-dashboard-alb \
  --description "SEGS dashboard ALB — VPN only" \
  --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress \
  --group-id $DASHBOARD_ALB_SG \
  --protocol tcp --port 443 --cidr $VPN_CIDR
```

### Receiver ALB SG (Google Pub/Sub IPs)
```bash
RECEIVER_ALB_SG=$(aws ec2 create-security-group \
  --vpc-id $VPC_ID \
  --group-name segs-receiver-alb \
  --description "SEGS receiver ALB — Google IPs via WAF" \
  --query 'GroupId' --output text)

# Allow 443 from all IPs — WAF enforces Google-IP restriction
aws ec2 authorize-security-group-ingress \
  --group-id $RECEIVER_ALB_SG \
  --protocol tcp --port 443 --cidr 0.0.0.0/0
```

> **WAF IP set for receiver**: Because Google Cloud publishes 997+ IP ranges (exceeding the 60-rule security group limit), apply restrictions via AWS WAF. Create a WAF Web ACL on the receiver ALB, add an IP set from `deploy/google-pubsub-ips.txt`, and set the default action to BLOCK. Refresh the IP list quarterly.

### ECS task SGs (private, receive from ALB only)
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

This step is verbose. Use the AWS Console or Terraform for readability. Key settings:

| ALB | Scheme | Subnets | SG | Listener | Protocol |
|-----|--------|---------|-----|----------|---------|
| segs-dashboard-alb | internal | Private subnets | `$DASHBOARD_ALB_SG` | 443 HTTPS → TG port 8765 | HTTP/1.1 |
| segs-receiver-alb | internet-facing | Public subnets | `$RECEIVER_ALB_SG` | 443 HTTPS → TG port 8766 | HTTP/1.1 |

Target group health check paths:
- Dashboard: `GET /api/health` → expect 200
- Receiver: `GET /health` → expect 200

Assign the ACM certificates from Step 5 to the respective HTTPS listeners.

---

## Step 13 — Register task definitions and create services

```bash
export AWS_ACCOUNT_ID=123456789012
export EFS_FILESYSTEM_ID=fs-xxxxxxxxx

bash deploy/update-service.sh
```

`deploy/update-service.sh` registers both task definitions and then runs `aws ecs create-service` (if not yet created) or `aws ecs update-service --force-new-deployment`. It waits for `services-stable` before exiting.

If this is the first deploy (services don't exist yet), create them first:

```bash
# Dashboard service
aws ecs create-service \
  --cluster segs \
  --service-name segs-dashboard \
  --task-definition segs-dashboard \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$PRIVATE_SUBNET_IDS],securityGroups=[$DASHBOARD_TASK_SG],assignPublicIp=DISABLED}" \
  --load-balancers "targetGroupArn=$DASHBOARD_TG_ARN,containerName=segs-dashboard,containerPort=8765"

# Receiver service
aws ecs create-service \
  --cluster segs \
  --service-name segs-receiver \
  --task-definition segs-receiver \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$PRIVATE_SUBNET_IDS],securityGroups=[$RECEIVER_TASK_SG],assignPublicIp=DISABLED}" \
  --load-balancers "targetGroupArn=$RECEIVER_TG_ARN,containerName=segs-receiver,containerPort=8766"
```

---

## Step 14 — Configure DNS

Add A records (ALB alias) in Route 53:

| Name | Type | Value |
|------|------|-------|
| `segs.pdax.ph` | A (Alias) | segs-dashboard-alb DNS name |
| `segs-mail.pdax.ph` | A (Alias) | segs-receiver-alb DNS name |

---

## Step 15 — Configure Pub/Sub push subscription

In GCP Console → Pub/Sub → your topic → Subscriptions:

```
Delivery type: Push
Endpoint URL: https://segs-mail.pdax.ph/pubsub
Authentication: Add authorization header
  Header name: Authorization
  Header value: Bearer <SEG_PUBSUB_TOKEN>
Acknowledgement deadline: 60 seconds
Retry policy: Retry with exponential backoff (minimum 10s, maximum 600s)
Message retention: 7 days
```

---

## Step 16 — Register Gmail watches

For each monitored mailbox, trigger a watch registration:

```bash
# From a machine inside the VPN, or via curl through JumpCloud
curl -X POST https://segs.pdax.ph/watch/security@pdax.ph \
  -H "Cookie: session=<admin session cookie>" \
  -H "Content-Type: application/json"
```

Or access the dashboard → Settings → Gmail Watches → Register.

The watch auto-renews on every ECS task restart via the lifespan hook in `gateway/gmail_receiver.py`. The EventBridge Lambda provides a daily fallback.

---

## Step 17 — Deploy Lambda watch renewal fallback

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

## Step 18 — Create CloudWatch alarms

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

# Watch renewal failed (log-based)
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

## Post-deploy verification

```bash
# 1. Both services stable
aws ecs describe-services \
  --cluster segs --services segs-dashboard segs-receiver \
  --query 'services[*].[serviceName,runningCount,desiredCount,status]' \
  --output table

# 2. Health checks passing (from within VPN)
curl -sf https://segs.pdax.ph/api/health && echo OK
curl -sf https://segs-mail.pdax.ph/health && echo OK

# 3. Security headers on dashboard
curl -I https://segs.pdax.ph/api/health | grep -E "Strict-Transport|X-Frame|Set-Cookie"

# 4. Dashboard blocked without VPN (run from outside network)
# Should timeout or return 403

# 5. Watch renewal logged on receiver startup
aws logs filter-log-events \
  --log-group-name /segs/receiver \
  --filter-pattern "watch renewed" \
  --start-time $(date -d '1 hour ago' +%s000)

# 6. Send a test phishing email to a monitored mailbox
# → Gmail should apply SEGS-Quarantine label within 30 seconds
# → Dashboard feed should show the verdict
```

---

## Ongoing maintenance

### Deploying a code update

```bash
bash deploy/push-images.sh        # rebuild + push
bash deploy/update-service.sh     # register new task def + force deploy
```

### Rotating a secret

```bash
AWS_ACCOUNT_ID=123456789012 bash deploy/setup-secrets.sh
bash deploy/update-service.sh     # restart tasks to pick up new secret
```

### Scaling

```bash
# Scale dashboard service
aws ecs update-service \
  --cluster segs --service segs-dashboard \
  --desired-count 2

# Receiver does not benefit from multiple tasks unless Pub/Sub
# delivery rate exceeds single-task capacity.
```

### Refreshing Google IP list for WAF

```bash
curl -s https://www.gstatic.com/ipranges/cloud.json \
  | python3 -c "import json,sys; [print(p['ipv4Prefix']) for p in json.load(sys.stdin)['prefixes'] if 'ipv4Prefix' in p]" \
  > deploy/google-pubsub-ips.txt
# Then update the WAF IP set in the Console or via aws wafv2 update-ip-set
```

Refresh quarterly. Google publishes changes at `https://www.gstatic.com/ipranges/cloud-services.json` (change notification feed).
