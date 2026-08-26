#!/bin/bash
# Register updated ECS task definitions and deploy both SEGS services.
# Run from the repo root: bash deploy/update-service.sh
#
# Required env vars:
#   AWS_ACCOUNT_ID   — your 12-digit AWS account ID
#   AWS_REGION       — default: ap-southeast-1
#   ECS_CLUSTER      — default: segs
#   ECR_REPO         — default: pdax/segs

set -euo pipefail

AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:?Set AWS_ACCOUNT_ID}"
AWS_REGION="${AWS_REGION:-ap-southeast-1}"
ECS_CLUSTER="${ECS_CLUSTER:-segs}"
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
ECR_REPO="${ECR_REPO:-pdax/segs}"
GIT_SHA="$(git rev-parse --short HEAD)"

# Substitute placeholders in task definitions with real values
substitute() {
    sed \
      -e "s|REPLACE_AWS_ACCOUNT_ID|${AWS_ACCOUNT_ID}|g" \
      -e "s|REPLACE_EFS_FILESYSTEM_ID|${EFS_FILESYSTEM_ID:?Set EFS_FILESYSTEM_ID}|g" \
      -e "s|:dashboard-latest|:dashboard-${GIT_SHA}|g" \
      -e "s|:receiver-latest|:receiver-${GIT_SHA}|g" \
      "$1"
}

echo "==> Registering segs-dashboard task definition..."
DASH_ARN=$(substitute ecs/task-definition-dashboard.json \
  | aws ecs register-task-definition \
      --region "$AWS_REGION" \
      --cli-input-json file:///dev/stdin \
      --query 'taskDefinition.taskDefinitionArn' \
      --output text)
echo "    $DASH_ARN"

echo "==> Registering segs-receiver task definition..."
RECV_ARN=$(substitute ecs/task-definition-receiver.json \
  | aws ecs register-task-definition \
      --region "$AWS_REGION" \
      --cli-input-json file:///dev/stdin \
      --query 'taskDefinition.taskDefinitionArn' \
      --output text)
echo "    $RECV_ARN"

echo "==> Updating ECS services..."
aws ecs update-service \
  --region "$AWS_REGION" \
  --cluster "$ECS_CLUSTER" \
  --service segs-dashboard \
  --task-definition "$DASH_ARN" \
  --force-new-deployment \
  --query 'service.serviceName' --output text

aws ecs update-service \
  --region "$AWS_REGION" \
  --cluster "$ECS_CLUSTER" \
  --service segs-receiver \
  --task-definition "$RECV_ARN" \
  --force-new-deployment \
  --query 'service.serviceName' --output text

echo "==> Waiting for services to stabilize (this takes ~2 minutes)..."
aws ecs wait services-stable \
  --region "$AWS_REGION" \
  --cluster "$ECS_CLUSTER" \
  --services segs-dashboard segs-receiver

echo "==> Deployment complete."
