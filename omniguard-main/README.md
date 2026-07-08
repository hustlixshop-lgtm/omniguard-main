# OmniGuard

**AI-Native Enterprise DevSecOps Platform**

OmniGuard is an AI-powered security layer that sits between developers and production deployment. It combines traditional security analysis (secrets, SAST, IaC, dependencies) with AI reasoning to understand code intent, enforce company policies, and automatically generate secure fixes.

---

## Quick Start

### 1. Clone & Install

```bash
cd omniguard-main
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and fill in your Supabase and optional API keys
```

**Required:**
- `VITE_SUPABASE_URL` — your Supabase project URL
- `VITE_SUPABASE_ANON_KEY` — your Supabase anon key

**For AI features (optional but recommended):**
- `ANTHROPIC_API_KEY` — Claude API key for AI classification and remediation

**For repository scanning:**
- `GITHUB_TOKEN` — GitHub PAT with `repo` read scope (add in Settings → Integrations)

### 3. Start the App

```bash
npm run dev
# Open http://localhost:5173
```

### 4. Sign Up

Create an account, then create your organization. The demo scan will work immediately — connect a GitHub repository, trigger a scan, and watch findings appear in real time.

---

## Architecture

```
Browser (React/Vite)
    │
    ├── Supabase Auth (JWT sessions)
    ├── Supabase Realtime (WebSocket — live scan updates)
    └── Supabase Edge Functions (Deno runtime)
            │
            ├── scan-quick          Fast file classification (CLI, pre-commit, VS Code)
            ├── api-v1-scans        Scan CRUD + trigger
            ├── api-v1-findings     Findings CRUD + AI remediation
            ├── api-v1-status       Health check
            ├── github-webhook      Receives push/PR events (HMAC verified)
            └── scan-worker         Full security scanner + GitHub file fetcher
                    │
                    ├── Secret Scanner (15 patterns + entropy)
                    ├── SAST Scanner  (17 rules, 9 languages)
                    ├── IaC Scanner   (Terraform, Docker, K8s, CloudFormation)
                    ├── Dependency Scanner (live OSV API)
                    └── AI Classification (Claude Haiku/Sonnet/Opus)
```

### Database

24 PostgreSQL tables with Row Level Security (multi-tenant isolation):

| Domain | Tables |
|--------|--------|
| Identity | `organizations`, `organization_members`, `user_profiles`, `teams`, `team_members` |
| Scanning | `repositories`, `scans`, `scan_queue`, `scan_artifacts`, `findings`, `scan_configurations` |
| Policy | `policies`, `policy_evaluations`, `compliance_frameworks`, `compliance_mappings` |
| Knowledge | `documents`, `document_chunks` (pgvector) |
| AI | `ai_analyses` |
| Operations | `audit_logs`, `notifications`, `reports`, `worker_heartbeats`, `integrations`, `api_keys` |

---

## Features

### Security Scanners

| Scanner | What It Detects |
|---------|----------------|
| **Secrets** | AWS keys, GitHub PATs, OpenAI keys, Anthropic keys, Stripe keys, SSH private keys, database URLs, JWT secrets, hardcoded passwords, GCP service accounts, Slack tokens, Discord tokens, NPM tokens |
| **SAST** | SQL injection, XSS, command injection, SSRF, path traversal, weak crypto (MD5/SHA1), unsafe deserialization, JWT "none" algorithm, open redirects |
| **IaC** | S3 public ACL, security group open to world, RDS publicly accessible, unencrypted storage, Dockerfile root user, :latest tag, secrets in ENV, K8s privileged containers |
| **Dependencies** | Live CVE lookup via [OSV API](https://osv.dev) for npm, PyPI packages |

### AI Features

- **Layer 1 — Haiku**: Fast file classification (SAFE/LOW/MEDIUM/HIGH/CRITICAL) with confidence score
- **Layer 2 — Sonnet**: Detailed remediation generation per finding with code fixes
- **Layer 3 — Opus**: Executive summaries and architecture-level analysis

### Developer Tools

- **VS Code Extension** — real-time scanning on save, CodeLens annotations, hover tooltips, Problems panel integration
- **CLI** — `omniguard scan`, `omniguard status`, `omniguard suppress`, `omniguard install-hooks`
- **Git Hooks** — pre-commit secret detection (local + API), pre-push scan trigger

### Dashboard

- Real-time scan updates via WebSocket
- Findings by severity with filters
- Repository health scores
- Recent audit activity
- Functional header search (findings + repos)
- Real-time notification bell with unread count

---

## Git Hooks

```bash
# Install hooks in any git repository
node /path/to/omniguard-main/cli/omniguard.js install-hooks

# Configure
export OMNIGUARD_URL="https://your-project.supabase.co/functions/v1"
export OMNIGUARD_API_KEY="og_live_..."   # Generate in Settings → API Keys
export OMNIGUARD_FAIL_ON="critical"       # critical, high, medium, low
```

The pre-commit hook will block commits containing:
- AWS access keys
- GitHub PATs
- OpenAI / Anthropic API keys
- SSH private keys
- Database connection strings with credentials

---

## GitHub Webhook

1. In your GitHub repository: Settings → Webhooks → Add webhook
2. URL: `https://your-project.supabase.co/functions/v1/github-webhook`
3. Content type: `application/json`
4. Events: Push, Pull Request
5. The scan worker will automatically process pushes and create findings

For full file scanning (not just pattern matching on webhook payload), add a GitHub token in **Settings → Integrations → GitHub**.

---

## API

All endpoints require `Authorization: Bearer <token>` where token is either a Supabase JWT or an `og_live_xxx` API key generated in Settings → API Keys.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/functions/v1/api-v1-status` | GET | Health check |
| `/functions/v1/scan-quick` | POST | Fast scan (no persistence) |
| `/functions/v1/api-v1-scans` | POST/GET | Create/list scans |
| `/functions/v1/api-v1-scans/:id` | GET | Get scan details |
| `/functions/v1/api-v1-scans/:id/retry` | POST | Retry failed scan |
| `/functions/v1/api-v1-findings` | GET | List findings (paginated, filterable) |
| `/functions/v1/api-v1-findings/:id` | GET/PATCH | Get/update finding |
| `/functions/v1/api-v1-findings/:id/suppress` | POST | Suppress finding |
| `/functions/v1/api-v1-findings/:id/ai-remediation` | GET | Get/generate AI fix |
| `/functions/v1/github-webhook` | POST | GitHub event receiver |
| `/functions/v1/scan-worker/process` | GET | Trigger worker to process next scan |

### Quick Scan Request

```bash
curl -X POST https://your-project.supabase.co/functions/v1/scan-quick \
  -H "Authorization: Bearer og_live_your_key" \
  -H "Content-Type: application/json" \
  -d '{"path": "config.py", "content": "db_url = \"postgres://admin:secret@db.example.com/app\""}'
```

```json
{
  "success": true,
  "classification": "CRITICAL",
  "confidence": 0.88,
  "findings": [
    {
      "rule_id": "SECRET-DB-001",
      "severity": "critical",
      "title": "Database Connection String detected",
      "file_path": "config.py",
      "line_start": 1,
      "evidence": "post******.com/app"
    }
  ],
  "summary": { "total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0 },
  "duration_ms": 45
}
```

---

## Deployment

### Local Development

```bash
npm run dev
# or with Docker:
docker-compose up -d
```

### Production (AWS)

The `infrastructure/terraform/main.tf` defines:
- VPC (multi-AZ)
- RDS PostgreSQL 15 (encrypted, Multi-AZ)
- ElastiCache Redis
- ECS Fargate (API + scanner workers)
- CloudFront CDN + WAF
- ALB with HTTPS
- ACM certificates
- Secrets Manager
- CloudWatch logging

```bash
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars
# Fill in domain, db password, API keys
terraform init && terraform apply
```

### Deploy Frontend

```bash
npm run build
# dist/ contains the production build
# Deploy to Vercel, Netlify, S3+CloudFront, or any static host
```

### Environment Variables for Production

See `.env.example` for all required variables.

---

## Project Structure

```
omniguard-main/
├── src/                    # React frontend
│   ├── pages/              # Dashboard, Findings, Repositories, Teams, Settings
│   ├── hooks/              # useAuth, useAnalytics, useRepositories, useOrganization
│   ├── components/         # Layout (search, notifications, org switcher)
│   └── lib/supabase.ts     # Typed Supabase client
├── supabase/
│   ├── functions/          # Deno edge functions
│   │   ├── scan-quick/     # Fast file scan (no persistence)
│   │   ├── scan-worker/    # Full scan pipeline with GitHub API
│   │   ├── api-v1-scans/   # Scan CRUD
│   │   ├── api-v1-findings/# Findings CRUD + suppress + AI remediation
│   │   ├── api-v1-status/  # Health check
│   │   └── github-webhook/ # Push/PR event handler
│   └── migrations/         # PostgreSQL schema (24 tables, RLS)
├── scanner/                # TypeScript scanner package
│   └── src/
│       ├── scanners/       # SecretScanner, SASTScanner, IaCScanner, DependencyScanner
│       └── ai/provider.ts  # Claude AI provider (classify, explain, remediate, summarize)
├── vscode-extension/       # VS Code extension source
├── cli/omniguard.js        # CLI tool
├── hooks/                  # Git hook scripts
├── infrastructure/terraform/ # AWS deployment
├── docker-compose.yml      # Local development stack
└── .env.example            # Environment variable documentation
```

---

## RBAC

| Action | Owner | Admin | Engineer | Developer | Auditor |
|--------|:-----:|:-----:|:--------:|:---------:|:-------:|
| View all data | ✓ | ✓ | ✓ | ✓ | ✓ |
| Trigger scans | ✓ | ✓ | ✓ | ✓ | ✗ |
| Resolve findings | ✓ | ✓ | ✓ | ✓ | ✗ |
| Manage integrations | ✓ | ✓ | ✗ | ✗ | ✗ |
| Manage API keys | ✓ | ✓ | ✗ | ✗ | ✗ |
| Manage members | ✓ | ✓ | ✗ | ✗ | ✗ |
| Delete organization | ✓ | ✗ | ✗ | ✗ | ✗ |

---

## Compliance

Schema supports automatic mapping to: SOC 2, ISO 27001, HIPAA, PCI DSS, OWASP ASVS, NIST CSF, MITRE ATT&CK, CIS Controls.

---

## License

MIT
