# OmniGuard Enterprise Setup Guide

Complete deployment guide for OmniGuard - AI-Native Enterprise DevSecOps Platform.

## Prerequisites

- **Supabase Account**: Free tier works for development
- **AI Provider**: Anthropic API key (recommended), or OpenAI/AWS Bedrock/Azure/Gemini/OpenRouter/Ollama
- **GitHub PAT**: For repository scanning (optional but recommended)

---

## Quick Start (5 minutes)

### Option A: Docker (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/your-org/omniguard.git
cd omniguard

# 2. Set environment variables
export VITE_SUPABASE_URL="https://xyz.supabase.co"
export VITE_SUPABASE_ANON_KEY="eyJ..."

# 3. Deploy with Docker
bash scripts/deploy-linux.sh
# or on Windows: .\scripts\deploy-windows.ps1
# or on macOS: bash scripts/deploy-macos.sh

# 4. Open browser
open http://localhost:80
```

### Option B: Direct Build

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env
# Edit .env with your Supabase credentials

# 3. Start development server
npm run dev

# 4. Open browser
open http://localhost:5173
```

---

## Cloud Deployment

### AWS (ECS Fargate)

```bash
# Prerequisites: AWS CLI configured, ECR repo exists
export AWS_ACCOUNT_ID=123456789
export VITE_SUPABASE_URL=https://xyz.supabase.co
export VITE_SUPABASE_ANON_KEY=eyJ...

bash scripts/deploy-aws-ecs.sh

# Output: Load balancer URL
```

### Google Cloud (Cloud Run)

```bash
# Prerequisites: gcloud CLI configured, GCP project created
export GCP_PROJECT=my-project
export VITE_SUPABASE_URL=https://xyz.supabase.co
export VITE_SUPABASE_ANON_KEY=eyJ...

bash scripts/deploy-gcp-cloud-run.sh

# Output: https URL from Cloud Run
```

### Azure (Container Apps)

```bash
# Prerequisites: Azure CLI configured
export AZURE_SUBSCRIPTION=your-subscription-id
export VITE_SUPABASE_URL=https://xyz.supabase.co
export VITE_SUPABASE_ANON_KEY=eyJ...

bash scripts/deploy-azure-container-apps.sh

# Output: https URL from Container Apps
```

### Kubernetes (Any Cloud)

```bash
# Create namespace and secrets
kubectl create namespace omniguard
kubectl create secret generic omniguard-secrets -n omniguard \
  --from-literal=VITE_SUPABASE_URL=https://xyz.supabase.co \
  --from-literal=VITE_SUPABASE_ANON_KEY=eyJ...

# Deploy
kubectl apply -f scripts/k8s.yaml

# Get external IP
kubectl get ingress -n omniguard
```

---

## Supabase Setup

### 1. Create Supabase Project

1. Go to [supabase.com](https://supabase.com) and create a new project
2. Wait for project to be provisioned (~2 minutes)
3. Go to Settings > API and copy:
   - Project URL (your `VITE_SUPABASE_URL`)
   - Anon/Public Key (your `VITE_SUPABASE_ANON_KEY`)

### 2. Database Migrations

The migrations are applied automatically. If you need to verify:

```bash
# Check migrations in Supabase Dashboard
# SQL Editor > Run migrations from supabase/migrations/
```

### 3. Edge Functions

Deploy these functions to Supabase:

```bash
# Functions are deployed automatically via Supabase
# If you need to deploy manually:
supabase functions deploy scan-worker
supabase functions deploy api-v1-scans
supabase functions deploy api-v1-findings
```

Required functions:
- `scan-worker` - Main scanning engine with 3-layer AI pipeline
- `api-v1-scans` - Scan management API
- `api-v1-findings` - Finding management API
- `api-v1-status` - Health status endpoint
- `github-webhook` - GitHub webhook handler

### 4. Set Edge Function Secrets

In Supabase Dashboard > Edge Functions > Settings:

```
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-... (optional, for fallback)
GITHUB_TOKEN=ghp_... (optional, for private repos)
```

---

## AI Provider Configuration

OmniGuard uses a **BYOK (Bring Your Own Key)** model. Your organization's AI keys are stored encrypted in the database.

### Supported Providers

| Provider | Tier 1 (Fast) | Tier 2 (Medium) | Tier 3 (Deep) |
|----------|---------------|-----------------|----------------|
| Anthropic | Claude 3.5 Haiku | Claude 3.5 Sonnet | Claude 3.5 Sonnet |
| OpenAI | GPT-4o-mini | GPT-4o | GPT-4o |
| AWS Bedrock | Claude 3.5 Haiku | Claude 3.5 Sonnet | Claude 3.5 Sonnet |
| Azure OpenAI | GPT-4o-mini | GPT-4o | GPT-4o |
| Google Gemini | Gemini 1.5 Flash | Gemini 1.5 Pro | Gemini 1.5 Pro |
| OpenRouter | Claude 3.5 Haiku | Claude 3.5 Sonnet | Claude 3 Opus |
| Ollama | Llama 3.2 | Llama 3.2 | Llama 3.2 |

### Configuring in Dashboard

1. Sign in to OmniGuard
2. Go to Settings > AI Provider
3. Select your provider
4. Enter your API key
5. Set token limits (optional)
6. Click "Save AI Configuration"

### Cost Estimation

- **Tier 1 (Triage)**: ~$0.001 per scan
- **Tier 2 (Deep Analysis)**: ~$0.02-0.06 per scan
- **Tier 3 (Executive Summary)**: ~$0.03 per scan

You can disable Tier 3 in settings to reduce costs.

---

## Local Agent Installation

The OmniGuard Agent runs as a background service to monitor repositories continuously.

### Linux (systemd)

```bash
# Install
sudo OMNIGUARD_URL=https://... OMNIGUARD_API_KEY=og_... \
  bash agent/install-agent.sh

# Manage
sudo systemctl status omniguard-agent
sudo systemctl logs -u omniguard-agent -f
```

### macOS (launchd)

```bash
# Install
sudo OMNIGUARD_URL=https://... OMNIGUARD_API_KEY=og_... \
  bash agent/install-agent.sh

# Manage
launchctl status io.omniguard.agent
tail -f /var/log/omniguard/agent.log
```

### Windows (Service)

```powershell
# Run as Administrator
$env:OMNIGUARD_URL = "https://..."
$env:OMNIGUARD_API_KEY = "og_..."
.\agent\install-service.ps1 -Action install

# Manage
Get-Service OmniGuardAgent
Start-Service OmniGuardAgent
Stop-Service OmniGuardAgent
```

---

## VS Code Extension

### Installation

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "OmniGuard"
4. Click Install

### Configuration

```json
{
  "omniguard.apiEndpoint": "https://xyz.supabase.co/functions/v1",
  "omniguard.supabaseAnonKey": "eyJ...",
  "omniguard.scanOnSave": true,
  "omniguard.enableRealtimeScanning": true,
  "omniguard.showInlineDiagnostics": true,
  "omniguard.aiEnabled": true
}
```

### Commands

- `OmniGuard: Scan Current File` - Manual scan
- `OmniGuard: Scan Workspace` - Full workspace scan
- `OmniGuard: Sign In` - Authenticate
- `OmniGuard: Get AI Remediation` - Get fix suggestions

---

## CLI Installation

```bash
# Install globally
npm install -g @omniguard/cli

# Or use npx
npx @omniguard/cli scan

# Install git hooks
omniguard install-hooks

# Scan staged files
omniguard scan --staged

# Check connection
omniguard status
```

### Git Hooks

The CLI can install pre-commit and pre-push hooks:

```bash
# Install hooks
omniguard install-hooks

# Hooks will:
# - pre-commit: Block commits with critical secrets
# - pre-push: Run background scan before push
```

---

## GitHub Integration

### Webhook Setup

1. Go to GitHub Repository > Settings > Webhooks
2. Add webhook:
   - **Payload URL**: `https://YOUR_SUPABASE_URL/functions/v1/github-webhook`
   - **Content type**: `application/json`
   - **Secret**: Generate a random string
   - **Events**: Push, Pull Request
3. Save webhook

### GitHub App (Optional)

For more advanced features, create a GitHub App:
- Repository access: All or selected
- Permissions:
  - Contents: Read
  - Pull requests: Write (for checks)
  - Checks: Write

---

## Monitoring

### Health Endpoints

- Dashboard: `GET /health`
- Scan Worker: `GET /functions/v1/scan-worker/health`
- Metrics: `GET /functions/v1/scan-worker/metrics` (Prometheus format)

### Metrics Available

| Metric | Description |
|--------|-------------|
| `omniguard_scans_total` | Total scans processed |
| `omniguard_scans_failed_total` | Failed scans |
| `omniguard_findings_total` | Total findings detected |
| `omniguard_findings_by_severity` | Findings by severity level |
| `omniguard_ai_calls_total` | AI API calls made |
| `omniguard_ai_tokens_total` | AI tokens consumed |
| `omniguard_files_scanned_total` | Files scanned |

### Grafana Dashboard

Import the dashboard from `monitoring/grafana-dashboard.json` for visualization.

---

## Security Considerations

### Production Checklist

- [ ] Enable Row Level Security (RLS) on all tables
- [ ] Configure proper CORS settings
- [ ] Use HTTPS only in production
- [ ] Set up rate limiting
- [ ] Rotate all API keys regularly
- [ ] Enable audit logging
- [ ] Configure backup policies in Supabase
- [ ] Set up monitoring and alerting

### Secrets Management

- **Supabase**: Use Supabase Secrets for edge function environment
- **Production**: Use AWS Secrets Manager / Azure Key Vault / GCP Secret Manager
- **Development**: Use `.env` file (never commit to git)

---

## Troubleshooting

### Common Issues

**"No files fetched" in scans**
- Ensure GitHub integration has a valid PAT
- Check that the repository is connected in Dashboard

**AI not working**
- Verify API key in Settings > AI Provider
- Check edge function logs in Supabase Dashboard

**VS Code extension not scanning**
- Verify `omniguard.apiEndpoint` points to your Supabase functions URL
- Check output panel > OmniGuard for errors

### Getting Help

- Documentation: https://docs.omniguard.io
- GitHub Issues: https://github.com/omniguard/omniguard/issues
- Email Support: support@omniguard.io (Enterprise only)

---

## License

Enterprise license required for production use. Contact sales@omniguard.io for licensing.
