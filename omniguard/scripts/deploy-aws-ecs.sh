#!/usr/bin/env bash
# OmniGuard Deploy to AWS ECS Fargate
# Prerequisites: AWS CLI configured, ECR repo, ECS cluster
# Usage: VITE_SUPABASE_URL=... VITE_SUPABASE_ANON_KEY=... AWS_ACCOUNT_ID=123456789 bash deploy-aws-ecs.sh

set -euo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${GREEN}[OmniGuard]${NC} $*"; }
err()  { echo -e "${RED}[OmniGuard]${NC} $*" >&2; exit 1; }

[[ -z "${VITE_SUPABASE_URL:-}"      ]] && err "VITE_SUPABASE_URL required"
[[ -z "${VITE_SUPABASE_ANON_KEY:-}" ]] && err "VITE_SUPABASE_ANON_KEY required"
[[ -z "${AWS_ACCOUNT_ID:-}"         ]] && err "AWS_ACCOUNT_ID required"
command -v aws  >/dev/null 2>&1 || err "AWS CLI not found"
command -v docker >/dev/null 2>&1 || err "Docker not found"

REGION="${AWS_REGION:-us-east-1}"
ECR_REPO="${ECR_REPO:-omniguard}"
ECS_CLUSTER="${ECS_CLUSTER:-omniguard}"
ECS_SERVICE="${ECS_SERVICE:-omniguard-dashboard}"
ECS_FAMILY="${ECS_FAMILY:-omniguard-dashboard}"
IMAGE_TAG="$(date +%Y%m%d%H%M%S)"
IMAGE_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}"

info "Logging in to ECR..."
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

# Create ECR repo if it doesn't exist
aws ecr describe-repositories --region "$REGION" --repository-names "$ECR_REPO" >/dev/null 2>&1 \
  || aws ecr create-repository --region "$REGION" --repository-name "$ECR_REPO" >/dev/null

info "Building Docker image..."
docker build \
  --build-arg VITE_SUPABASE_URL="${VITE_SUPABASE_URL}" \
  --build-arg VITE_SUPABASE_ANON_KEY="${VITE_SUPABASE_ANON_KEY}" \
  --platform linux/amd64 \
  -t "$IMAGE_URI" .

info "Pushing to ECR..."
docker push "$IMAGE_URI"

# Create or update ECS task definition
TASK_DEF=$(cat << JSON
{
  "family": "${ECS_FAMILY}",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/ecsTaskExecutionRole",
  "containerDefinitions": [{
    "name": "omniguard",
    "image": "${IMAGE_URI}",
    "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
    "essential": true,
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/omniguard",
        "awslogs-region": "${REGION}",
        "awslogs-stream-prefix": "ecs"
      }
    },
    "healthCheck": {
      "command": ["CMD-SHELL", "wget -qO- http://localhost/health || exit 1"],
      "interval": 30, "timeout": 5, "retries": 3, "startPeriod": 10
    }
  }]
}
JSON
)

info "Registering ECS task definition..."
TASK_ARN=$(aws ecs register-task-definition \
  --region "$REGION" \
  --cli-input-json "$TASK_DEF" \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text)
info "Task definition: $TASK_ARN"

# Update ECS service (or create it)
if aws ecs describe-services --region "$REGION" --cluster "$ECS_CLUSTER" --services "$ECS_SERVICE" --query 'services[0].status' --output text 2>/dev/null | grep -q ACTIVE; then
  info "Updating ECS service..."
  aws ecs update-service \
    --region "$REGION" \
    --cluster "$ECS_CLUSTER" \
    --service "$ECS_SERVICE" \
    --task-definition "$TASK_ARN" \
    --force-new-deployment >/dev/null
else
  warn "ECS service ${ECS_SERVICE} not found. Create it manually in AWS console with:"
  warn "  Cluster: ${ECS_CLUSTER}, Task: ${ECS_TASK_DEF}, Launch: FARGATE"
  warn "  Assign a public subnet + security group allowing port 80/443"
fi

# Create CloudWatch log group if needed
aws logs create-log-group --region "$REGION" --log-group-name "/ecs/omniguard" 2>/dev/null || true

info ""
info "✓ Deployed to AWS ECS Fargate"
info "  Image: ${IMAGE_URI}"
info "  Task:  ${TASK_ARN}"
info "  Check: aws ecs describe-services --cluster ${ECS_CLUSTER} --services ${ECS_SERVICE} --region ${REGION}"
