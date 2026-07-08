#!/usr/bin/env bash
# OmniGuard Deploy to Google Cloud Run
# Prerequisites: gcloud CLI configured, GCP project, Artifact Registry
# Usage: VITE_SUPABASE_URL=... VITE_SUPABASE_ANON_KEY=... GCP_PROJECT=myproject bash deploy-gcp-cloud-run.sh

set -euo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${GREEN}[OmniGuard]${NC} $*"; }
warn() { echo -e "${YELLOW}[OmniGuard]${NC} $*"; }
err()  { echo -e "${RED}[OmniGuard]${NC} $*" >&2; exit 1; }

[[ -z "${VITE_SUPABASE_URL:-}"      ]] && err "VITE_SUPABASE_URL required"
[[ -z "${VITE_SUPABASE_ANON_KEY:-}" ]] && err "VITE_SUPABASE_ANON_KEY required"
[[ -z "${GCP_PROJECT:-}"            ]] && err "GCP_PROJECT required"

command -v gcloud >/dev/null 2>&1 || err "gcloud CLI not found. Install: https://cloud.google.com/sdk/docs/install"
command -v docker >/dev/null 2>&1 || err "Docker not found"

REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-omniguard}"
IMAGE_NAME="${IMAGE_NAME:-omniguard}"
ARTIFACT_REGISTRY="${ARTIFACT_REGISTRY:-${REGION}-docker.pkg.dev/${GCP_PROJECT}/omniguard}"

info "Deploying OmniGuard to Google Cloud Run..."
info "Project: ${GCP_PROJECT}, Region: ${REGION}"

# Enable required APIs
info "Enabling required GCP APIs..."
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com \
  --project="${GCP_PROJECT}" 2>/dev/null || true

# Create Artifact Registry repo if needed
if ! gcloud artifacts repositories describe omniguard --location="${REGION}" --project="${GCP_PROJECT}" >/dev/null 2>&1; then
  info "Creating Artifact Registry repository..."
  gcloud artifacts repositories create omniguard --location="${REGION}" --repository-format=docker \
    --project="${GCP_PROJECT}"
fi

# Build and push to Artifact Registry
IMAGE_TAG="$(date +%Y%m%d%H%M%S)"
IMAGE_URI="${ARTIFACT_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"

info "Building Docker image..."
docker build \
  --build-arg VITE_SUPABASE_URL="${VITE_SUPABASE_URL}" \
  --build-arg VITE_SUPABASE_ANON_KEY="${VITE_SUPABASE_ANON_KEY}" \
  --platform linux/amd64 \
  -t "$IMAGE_URI" .

info "Authenticating to Artifact Registry..."
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --project="${GCP_PROJECT}" --quiet

info "Pushing image to Artifact Registry..."
docker push "$IMAGE_URI"

# Deploy to Cloud Run
info "Deploying to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
  --image "$IMAGE_URI" \
  --platform managed \
  --region "${REGION}" \
  --project "${GCP_PROJECT}" \
  --allow-unauthenticated \
  --port 80 \
  --cpu 1 \
  --memory 512Mi \
  --min-instances 1 \
  --max-instances 10 \
  --set-env-vars "NODE_ENV=production" \
  --set-secrets "VITE_SUPABASE_URL=projects/${GCP_PROJECT}/secrets/omniguard-supabase-url:latest,VITE_SUPABASE_ANON_KEY=projects/${GCP_PROJECT}/secrets/omniguard-supabase-anon-key:latest" \
  2>/dev/null || {
    warn "Could not deploy with secrets. Deploying with environment variables instead (less secure)..."
    gcloud run deploy "${SERVICE_NAME}" \
      --image "$IMAGE_URI" \
      --platform managed \
      --region "${REGION}" \
      --project "${GCP_PROJECT}" \
      --allow-unauthenticated \
      --port 80 \
      --cpu 1 \
      --memory 512Mi \
      --min-instances 1 \
      --max-instances 10 \
      --set-env-vars "^_^NODE_ENV=production,VITE_SUPABASE_URL=${VITE_SUPABASE_URL},VITE_SUPABASE_ANON_KEY=${VITE_SUPABASE_ANON_KEY}"
  }

# Get service URL
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" --platform managed --region "${REGION}" \
  --project "${GCP_PROJECT}" --format 'value(status.url)')

info ""
info "✓ OmniGuard deployed to Google Cloud Run!"
info "  Service URL: ${SERVICE_URL}"
info "  Health: ${SERVICE_URL}/health"
info ""
info "  Next: Configure custom domain via:"
info "    gcloud run domain-mappings create --domain=security.yourcompany.com --service=${SERVICE_NAME} --region=${REGION}"
