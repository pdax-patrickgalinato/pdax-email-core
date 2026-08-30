#!/usr/bin/env bash
# Build linux/amd64 images, push to ECR (immutable tags), print Terraform -var lines.
#
# Usage (from repo root, after first terraform apply created the repos):
#   AWS_PROFILE=… bash infra/scripts/push-images.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INFRA="$ROOT/infra"
REGION="${AWS_REGION:-ap-southeast-1}"
GIT_SHA="$(git -C "$ROOT" rev-parse --short HEAD)"
if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
  GIT_SHA="${GIT_SHA}-$(date +%Y%m%d%H%M%S)"
fi
TF="${TERRAFORM:-$INFRA/.bin/terraform}"
if ! command -v "$TF" >/dev/null 2>&1 && [ ! -x "$TF" ]; then
  TF="$(command -v terraform || true)"
fi
if [ -z "$TF" ] || [ ! -x "$TF" ]; then
  echo "terraform not found (expected $INFRA/.bin/terraform)" >&2
  exit 2
fi

cd "$INFRA"
API_REPO="$("$TF" output -raw ecr_api_url)"
RECEIVER_REPO="$("$TF" output -raw ecr_receiver_url)"
WORKER_REPO="$("$TF" output -raw ecr_worker_url)"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

# --provenance=false keeps a single-image digest (BuildKit attestations otherwise
# push an index that Fargate cannot pull by that digest).
docker buildx build --platform linux/amd64 --provenance=false --load \
  -f "$ROOT/deploy/docker/Dockerfile" \
  -t "${API_REPO}:${GIT_SHA}" \
  "$ROOT"
docker push "${API_REPO}:${GIT_SHA}"

docker buildx build --platform linux/amd64 --provenance=false --load \
  -f "$ROOT/deploy/docker/Dockerfile.receiver" \
  -t "${RECEIVER_REPO}:${GIT_SHA}" \
  "$ROOT"
docker push "${RECEIVER_REPO}:${GIT_SHA}"

docker buildx build --platform linux/amd64 --provenance=false --load \
  -f "$ROOT/deploy/docker/Dockerfile.worker" \
  -t "${WORKER_REPO}:${GIT_SHA}" \
  "$ROOT"
docker push "${WORKER_REPO}:${GIT_SHA}"

API_DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "${API_REPO}:${GIT_SHA}" | awk -F@ '{print $2}')"
RECEIVER_DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "${RECEIVER_REPO}:${GIT_SHA}" | awk -F@ '{print $2}')"
WORKER_DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "${WORKER_REPO}:${GIT_SHA}" | awk -F@ '{print $2}')"

cat <<EOF

Images pushed. Re-apply with:

  terraform apply \\
    -var="api_image_digest=${API_DIGEST}" \\
    -var="receiver_image_digest=${RECEIVER_DIGEST}" \\
    -var="worker_image_digest=${WORKER_DIGEST}"

Or add those values to terraform.tfvars.
Set receiver_desired_count=0 after split workers are healthy (the receiver
task then only exists as a fallback; SEG_INLINE_WORKERS is already 0).
EOF
