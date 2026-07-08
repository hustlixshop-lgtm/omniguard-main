#!/usr/bin/env bash
# OmniGuard Deploy to Azure Container Apps
# Prerequisites: Azure CLI configured, resource group, subscription
# Usage: VITE_SUPABASE_URL=... VITE_SUPABASE_ANON_KEY=... AZURE_SUBSCRIPTION=... bash deploy-azure-container-apps.sh

set -euo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${GREEN}[OmniGuard]${NC} $*"; }
warn() { echo -e "${YELLOW}[OmniGuard]${NC} $*"; }
err()  { echo -e "${RED}[OmniGuard]${NC} $*" >&2; exit 1; }

[[ -z "${VITE_SUPABASE_URL:-}"      ]] && err "VITE_SUPABASE_URL required"
[[ -z "${VITE_SUPABASE_ANON_KEY:-}" ]] && err "VITE_SUPABASE_ANON_KEY required"

command -v az     >/dev/null 2>&1 || err "Azure CLI not found. Install: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
command -v docker >/dev/null 2>&1 || err "Docker not found"

RESOURCE_GROUP="${RESOURCE_GROUP:-omniguard-rg}"
LOCATION="${LOCATION:-eastus}"
REGISTRY_NAME="${REGISTRY_NAME:-omniguardregistry}"
APP_NAME="${APP_NAME:-omniguard}"
ENVIRONMENT_NAME="${ENVIRONMENT_NAME:-omniguard-env}"

info "Deploying OmniGuard to Azure Container Apps..."
info "Location: ${LOCATION}, Resource Group: ${RESOURCE_GROUP}"

# Set subscription if provided
if [[ -n "${AZURE_SUBSCRIPTION:-}" ]]; then
  az account set --subscription "${AZURE_SUBSCRIPTION}"
fi

# Create resource group
if ! az group show --name "${RESOURCE_GROUP}" >/dev/null 2>&1; then
  info "Creating resource group..."
  az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}"
fi

# Register required providers
info "Registering Azure providers..."
az provider register --namespace Microsoft.App --wait 2>/dev/null || true
az provider register --namespace Microsoft.OperationalInsights --wait 2>/dev/null || true

# Create Azure Container Registry
if ! az acr show --name "${REGISTRY_NAME}" --resource-group "${RESOURCE_GROUP}" >/dev/null 2>&1; then
  info "Creating Azure Container Registry..."
  az acr create --resource-group "${RESOURCE_GROUP}" --name "${REGISTRY_NAME}" --sku Basic --admin-enabled true
fi

ACR_LOGIN_SERVER=$(az acr show --name "${REGISTRY_NAME}" --resource-group "${RESOURCE_GROUP}" --query loginServer -o tsv)
ACR_USERNAME=$(az acr credential show --name "${REGISTRY_NAME}" --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name "${REGISTRY_NAME}" --query "passwords[0].value" -o tsv)

IMAGE_TAG="$(date +%Y%m%d%H%M%S)"
IMAGE_URI="${ACR_LOGIN_SERVER}/${APP_NAME}:${IMAGE_TAG}"

# Build and push
info "Building Docker image..."
docker build \
  --build-arg VITE_SUPABASE_URL="${VITE_SUPABASE_URL}" \
  --build-arg VITE_SUPABASE_ANON_KEY="${VITE_SUPABASE_ANON_KEY}" \
  --platform linux/amd64 \
  -t "$IMAGE_URI" .

info "Logging in to Azure Container Registry..."
echo "$ACR_PASSWORD" | docker login "${ACR_LOGIN_SERVER}" -u "$ACR_USERNAME" --password-stdin

info "Pushing image..."
docker push "$IMAGE_URI"

# Create Container Apps environment if needed
if ! az containerapp env show --name "${ENVIRONMENT_NAME}" --resource-group "${RESOURCE_GROUP}" >/dev/null 2>&1; then
  info "Creating Container Apps environment..."
  az containerapp env create \
    --name "${ENVIRONMENT_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --location "${LOCATION}"
fi

# Store secrets in Container Apps
info "Deploying Container App..."
if az containerapp show --name "${APP_NAME}" --resource-group "${RESOURCE_GROUP}" >/dev/null 2>&1; then
  # Update existing
  az containerapp update \
    --name "${APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --image "$IMAGE_URI" \
    --set-env-vars \
      "NODE_ENV=production" \
      "VITE_SUPABASE_URL=secretref:supabase-url" \
      "VITE_SUPABASE_ANON_KEY=secretref:supabase-anon-key" \
    --secrets \
      "supabase-url=${VITE_SUPABASE_URL}" \
      "supabase-anon-key=${VITE_SUPABASE_ANON_KEY}"
else
  # Create new
  az containerapp create \
    --name "${APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --environment "${ENVIRONMENT_NAME}" \
    --image "$IMAGE_URI" \
    --registry-server "${ACR_LOGIN_SERVER}" \
    --registry-username "${ACR_USERNAME}" \
    --registry-password "${ACR_PASSWORD}" \
    --cpu 0.5 \
    --memory 1.0Gi \
    --min-replicas 1 \
    --max-replicas 10 \
    --target-port 80 \
    --ingress external \
    --set-env-vars \
      "NODE_ENV=production" \
      "VITE_SUPABASE_URL=secretref:supabase-url" \
      "VITE_SUPABASE_ANON_KEY=secretref:supabase-anon-key" \
    --secrets \
      "supabase-url=${VITE_SUPABASE_URL}" \
      "supabase-anon-key=${VITE_SUPABASE_ANON_KEY}"
fi

APP_URL=$(az containerapp show \
  --name "${APP_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --query properties.configuration.ingress.fqdn -o tsv)

info ""
info "✓ OmniGuard deployed to Azure Container Apps!"
info "  App URL: https://${APP_URL}"
info "  Health:  https://${APP_URL}/health"
info ""
info "  Next: Configure custom domain via:"
info "    az containerapp hostname add --name ${APP_NAME} --resource-group ${RESOURCE_GROUP} --hostname security.yourcompany.com"
