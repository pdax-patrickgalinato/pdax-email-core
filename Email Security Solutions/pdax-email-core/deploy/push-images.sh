#!/bin/bash
# Build both SEGS Docker images and push them to ECR.
# Run from the repo root: bash deploy/push-images.sh
#
# Required env vars (set in your shell or a .env.deploy file):
#   AWS_ACCOUNT_ID   — your 12-digit AWS account ID
#   AWS_REGION       — default: ap-southeast-1
#   ECR_REPO         — default: pdax/segs

set -euo pipefail

AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:?Set AWS_ACCOUNT_ID}"
AWS_REGION="${AWS_REGION:-ap-southeast-1}"
ECR_REPO="${ECR_REPO:-pdax/segs}"
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
GIT_SHA="$(git rev-parse --short HEAD)"

echo "==> Logging in to ECR..."
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$ECR_REGISTRY"

echo "==> Building segs-dashboard..."
docker build -t segs-dashboard .

echo "==> Building segs-receiver..."
docker build -f Dockerfile.receiver -t segs-receiver .

echo "==> Tagging and pushing dashboard image (sha=$GIT_SHA)..."
docker tag segs-dashboard:latest "${ECR_REGISTRY}/${ECR_REPO}:dashboard-${GIT_SHA}"
docker tag segs-dashboard:latest "${ECR_REGISTRY}/${ECR_REPO}:dashboard-latest"
docker push "${ECR_REGISTRY}/${ECR_REPO}:dashboard-${GIT_SHA}"
docker push "${ECR_REGISTRY}/${ECR_REPO}:dashboard-latest"

echo "==> Tagging and pushing receiver image (sha=$GIT_SHA)..."
docker tag segs-receiver:latest "${ECR_REGISTRY}/${ECR_REPO}:receiver-${GIT_SHA}"
docker tag segs-receiver:latest "${ECR_REGISTRY}/${ECR_REPO}:receiver-latest"
docker push "${ECR_REGISTRY}/${ECR_REPO}:receiver-${GIT_SHA}"
docker push "${ECR_REGISTRY}/${ECR_REPO}:receiver-latest"

echo "==> Done. Images pushed:"
echo "    ${ECR_REGISTRY}/${ECR_REPO}:dashboard-${GIT_SHA}"
echo "    ${ECR_REGISTRY}/${ECR_REPO}:receiver-${GIT_SHA}"
echo ""
echo "Next step: run bash deploy/update-service.sh to deploy to ECS."
