"""AWS Lambda — daily Gmail watch renewal fallback.

Triggered by an EventBridge cron rule: cron(0 16 * * ? *)
(16:00 UTC = 00:00 PHT, runs before the 7-day watch expiry).

The primary renewal mechanism is the lifespan hook in gmail_receiver.py
(runs on every container start). This Lambda is a safety net in case the
service hasn't been redeployed in >7 days.

Deploy:
  1. Zip this file: zip lambda_renew_watches.zip lambda_renew_watches.py
  2. aws lambda create-function --function-name segs-renew-watches \
       --runtime python3.12 --handler lambda_renew_watches.handler \
       --zip-file fileb://lambda_renew_watches.zip \
       --role arn:aws:iam::ACCOUNT:role/segs-lambda-role \
       --environment "Variables={RECEIVER_URL=https://segs-mail.pdax.ph,SECRET_NAME=segs/prod}"
  3. Create an EventBridge rule targeting this Lambda with cron(0 16 * * ? *)

Required Lambda environment variables:
  RECEIVER_URL  — base URL of the gmail_receiver service, e.g. https://segs-mail.pdax.ph
  SECRET_NAME   — Secrets Manager secret name, e.g. segs/prod

Required IAM permissions for the Lambda execution role:
  secretsmanager:GetSecretValue on segs/prod
  (outbound HTTPS to RECEIVER_URL — no VPC needed if receiver ALB is public)
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import boto3


def _get_secret(secret_name: str) -> dict:
    client = boto3.client("secretsmanager", region_name=os.environ.get("AWS_REGION", "ap-southeast-1"))
    resp = client.get_secret_value(SecretId=secret_name)
    return json.loads(resp["SecretString"])


def handler(event, context):
    receiver_url = os.environ["RECEIVER_URL"].rstrip("/")
    secret_name = os.environ.get("SECRET_NAME", "segs/prod")

    secrets = _get_secret(secret_name)
    token = secrets.get("SEG_PUBSUB_TOKEN", "")
    users = [u.strip() for u in secrets.get("SEG_GMAIL_USERS", "").split(",") if u.strip()]

    if not users:
        print("[renew_watches] SEG_GMAIL_USERS is empty — nothing to renew")
        return {"renewed": 0, "failed": 0}

    renewed, failed = 0, 0
    for user in users:
        url = f"{receiver_url}/watch/{user}"
        req = urllib.request.Request(url, method="POST")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode()
                print(f"[renew_watches] {user} → {resp.status} {body[:120]}")
                renewed += 1
        except urllib.error.HTTPError as exc:
            print(f"[renew_watches] FAILED {user} → HTTP {exc.code}: {exc.read().decode()[:200]}")
            failed += 1
        except Exception as exc:
            print(f"[renew_watches] FAILED {user} → {exc}")
            failed += 1

    result = {"renewed": renewed, "failed": failed, "users": users}
    print(f"[renew_watches] done: {result}")
    if failed:
        raise RuntimeError(f"{failed} watch renewal(s) failed — check CloudWatch for details")
    return result
