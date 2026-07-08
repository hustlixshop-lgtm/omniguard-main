# OmniGuard Local Development & Deployment Guide

## Quick Start

### Demo Credentials
- **Email:** `demo@omniguard.dev`
- **Password:** `Demo@OmniGuard2024!`

---

## Part 1: Local Development Setup

### Prerequisites
- Node.js 18+
- Git
- VS Code (for extension testing)
- Supabase account (already configured)

### 1. Clone and Install

```bash
# Navigate to the frontend
cd omniguard-main

# Install dependencies (if not already done)
npm install

# Environment variables are already configured in .env
# VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY are set
```

### 2. Start the Frontend

```bash
# Start the Vite dev server
npm run dev
```

The dashboard will be available at `http://localhost:5173`

### 3. Login with Demo Account

1. Open `http://localhost:5173/auth`
2. Login with:
   - Email: `demo@omniguard.dev`
   - Password: `Demo@OmniGuard2024!`
3. You'll see the dashboard with:
   - 3 sample repositories
   - 4 sample security findings
   - Organization overview

---

## Part 2: VS Code Extension Setup

### Install the Extension

```bash
# From the omniguard-main directory
cd vscode-extension

# Install dependencies
npm install

# Compile the extension
npm run compile

# Package as VSIX
npx vsce package
```

### Install in VS Code

```bash
# Method 1: Command line
code --install-extension omniguard-1.0.0.vsix

# Method 2: VS Code UI
# 1. Open Extensions (Cmd+Shift+X)
# 2. Click "..." menu
# 3. Select "Install from VSIX..."
# 4. Choose the packaged .vsix file
```

### Configure the Extension

Add to your VS Code `settings.json`:

```json
{
  "omniguard.apiEndpoint": "https://kdfhlacefessshjnkhvw.supabase.co/functions/v1",
  "omniguard.supabaseUrl": "https://kdfhlacefessshjnkhvw.supabase.co",
  "omniguard.supabaseAnonKey": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtkZmhsYWNlZmVzc3Noam5raHZ3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODMyMzAyNzMsImV4cCI6MjA5ODgwNjI3M30.eorX_ovLeP9q-OIj_RlVZCFVJV2x3IrDPSXzZDsuWKE",
  "omniguard.enableRealtimeScanning": true,
  "omniguard.scanOnSave": true,
  "omniguard.aiEnabled": true
}
```

### Extension Features

- **Real-time scanning** on file save/open
- **Inline diagnostics** in Problems panel
- **CodeLens** annotations showing finding counts
- **Hover tooltips** with detailed remediation
- **Quick Fix** actions to apply AI suggestions
- **Sidebar** with findings list

---

## Part 3: Git Hooks Installation

### Install Hooks in Your Project

```bash
# Navigate to any git repository
cd /path/to/your/project

# Install OmniGuard hooks
npx @omniguard/cli install-hooks

# Or use the local CLI
node /path/to/omniguard-main/cli/omniguard.js install-hooks
```

### Configure Hooks

Add to your project's `.env` or shell profile:

```bash
export OMNIGUARD_URL="https://kdfhlacefessshjnkhvw.supabase.co/functions/v1"
export OMNIGUARD_API_KEY="og_live_your_api_key_here"
export OMNIGUARD_FAIL_ON="high"  # critical, high, medium, low
export OMNIGUARD_BYPASS="true"   # Enable bypass with justification
```

### Hook Behavior

**Pre-commit:**
- Scans staged files for secrets and SAST issues
- Blocks commit if findings match `OMNIGUARD_FAIL_ON` threshold
- Logs bypass attempts to `.git/omniguard-bypass.log`

**Pre-push:**
- Triggers full repository scan via API
- Waits for scan completion (60s timeout)
- Blocks push if critical/high findings detected

### Bypass Mechanism

```bash
# Bypass with justification (only if OMNIGUARD_BYPASS=true)
git commit --bypass

# You'll be prompted for justification
# All bypasses are logged for audit
```

---

## Part 4: API Endpoints

### Base URL
```
https://kdfhlacefessshjnkhvw.supabase.co/functions/v1
```

### Authentication
```bash
# JWT Token (from login)
Authorization: Bearer <jwt_token>

# API Key
Authorization: Bearer og_live_xxxxx
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api-v1-status` | Health check |
| `POST` | `/api-v1-scans` | Create scan |
| `GET` | `/api-v1-scans` | List scans |
| `GET` | `/api-v1-scans/:id` | Get scan details |
| `POST` | `/api-v1-scans/:id/retry` | Retry failed scan |
| `GET` | `/api-v1-findings` | List findings |
| `GET` | `/api-v1-findings/:id` | Get finding details |
| `PATCH` | `/api-v1-findings/:id` | Update finding |
| `POST` | `/github-webhook` | GitHub webhook receiver |
| `GET` | `/scan-worker/process` | Trigger scan processing |

### Example Requests

```bash
# Get status
curl -X GET \
  -H "Authorization: Bearer YOUR_JWT" \
  "https://kdfhlacefessshjnkhvw.supabase.co/functions/v1/api-v1-status"

# Create scan
curl -X POST \
  -H "Authorization: Bearer YOUR_JWT" \
  -H "Content-Type: application/json" \
  -d '{"repository": "demo/vulnerable-app", "branch": "main"}' \
  "https://kdfhlacefessshjnkhvw.supabase.co/functions/v1/api-v1-scans"

# List findings
curl -X GET \
  -H "Authorization: Bearer YOUR_JWT" \
  "https://kdfhlacefessshjnkhvw.supabase.co/functions/v1/api-v1-findings?severity=critical"
```

---

## Part 5: AWS Deployment

### Prerequisites
- AWS CLI configured with credentials
- Terraform >= 1.5.0
- Domain in Route53 (optional)

### Deploy Infrastructure

```bash
cd infrastructure/terraform

# Initialize
terraform init

# Plan deployment
terraform plan -var-file=production.tfvars

# Apply
terraform apply -var-file=production.tfvars
```

### What Gets Deployed

| Component | Service | Purpose |
|-----------|---------|---------|
| VPC | VPC | Multi-AZ network |
| Database | RDS PostgreSQL | Primary data store + pgvector |
| Cache | ElastiCache Redis | Job queue + caching |
| API | ECS Fargate | REST API + workers |
| CDN | CloudFront | Static assets + API gateway |
| Secrets | Secrets Manager | API keys, credentials |
| Logs | CloudWatch | Structured logging |
| DNS | Route53 | Custom domain |

### Terraform Outputs

After deployment, you'll receive:
- API URL (CloudFront)
- Database endpoint
- Redis endpoint
- ECR repository URLs

---

## Part 6: Testing with a Real Project

### 1. Create a Test Repository

```bash
mkdir ~/test-omniguard
cd ~/test-omniguard
git init

# Create vulnerable files
cat > config.py << 'EOF'
# Vulnerable config with secrets
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgres://admin:password123@db.example.com/app"
EOF

cat > api.py << 'EOF'
from flask import request
import sqlite3

def get_user():
    # SQL Injection vulnerability
    user_id = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect('app.db')
    return conn.execute(query).fetchone()

def render_content():
    # XSS vulnerability
    content = request.form.get('content')
    return f"<div>{content}</div>"
EOF

git add .
```

### 2. Test Git Hooks

```bash
# Install hooks
npx @omniguard/cli install-hooks

# Configure
export OMNIGUARD_URL="https://kdfhlacefessshjnkhvw.supabase.co/functions/v1"
export OMNIGUARD_API_KEY="your_api_key"
export OMNIGUARD_FAIL_ON="critical"

# Try to commit - should be blocked
git commit -m "Add config"
# Output: OmniGuard found 3 critical issues. Commit blocked.
```

### 3. Test in VS Code

```bash
# Open the test project
code ~/test-omniguard

# Open config.py
# - You'll see inline diagnostics for secrets
# - Hover over red squiggles for details
# - Check Problems panel for full list
# - Use Quick Fix to apply remediation suggestions
```

---

## Part 7: Dashboard Functionality

### For Individual Developers

**Dashboard View:**
- Total repositories tracked
- Open findings count by severity
- Average risk score across repos
- Recent activity timeline

**Repository Dashboard:**
- Risk score with visual progress bar
- Open findings per repo
- Last scan timestamp
- Quick links to detailed findings

**Findings View:**
- Filterable by severity, scanner, repository
- Click to see full details
- Remediation suggestions from AI
- Status management (open, resolved, suppressed)

**Settings:**
- API key generation
- Team management
- Organization preferences
- Integrations configuration

### For Security Teams

**Organization Dashboard:**
- Aggregate security posture
- Risk trend over time
- Compliance framework coverage
- Critical findings heatmap

**Team Management:**
- Create teams
- Assign repositories to teams
- Role-based access (owner, admin, engineer, developer, auditor)

**Audit Logs:**
- All actions logged
- Filter by user, action, resource
- Export for compliance reports

---

## Part 8: Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENTS                                  │
├─────────────┬─────────────┬─────────────┬────────────────────────┤
│ VS Code     │ Git Hooks   │ Web App    │ CI/CD Pipeline         │
│ Extension   │ (CLI)       │ (React)    │ (GitHub Actions)        │
└──────┬──────┴──────┬──────┴──────┬──────┴───────────┬────────────┘
       │             │             │                 │
       └─────────────┴──────┬──────┴─────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SUPABASE (BACKEND)                           │
├─────────────────────────────────────────────────────────────────┤
│  Edge Functions (Deno)                                          │
│  ├── api-v1-scans      → Scan CRUD                             │
│  ├── api-v1-findings   → Finding management                     │
│  ├── api-v1-status     → Health checks                         │
│  ├── github-webhook    → Push/PR event processor               │
│  └── scan-worker       → Security scanner + AI classification  │
├─────────────────────────────────────────────────────────────────┤
│  PostgreSQL Database                                            │
│  ├── 16 tables with RLS policies                               │
│  ├── 55+ RLS policies for multi-tenant isolation               │
│  ├── pgvector for semantic search                              │
│  └── Functions: claim_next_scan(), is_org_member()            │
├─────────────────────────────────────────────────────────────────┤
│  Realtime (WebSockets) → Live scan updates                     │
│  Storage (S3)           → Scan artifacts, documents            │
│  Auth                   → Email/password, JWT                  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AI PROVIDERS                                 │
├─────────────────────────────────────────────────────────────────┤
│  Anthropic Claude                                               │
│  ├── Haiku  → Real-time classification (fast, cheap)          │
│  ├── Sonnet → Deep analysis + remediation                      │
│  └── Opus   → Executive summaries                              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Part 9: Security Scanners

### Available Scanners

| Scanner | Category | Detection |
|---------|----------|-----------|
| **Secret Scanner** | Credentials | AWS keys, GitHub tokens, API keys, SSH keys, DB strings |
| **SAST Scanner** | Code | SQL injection, XSS, CMD injection, SSRF, path traversal |
| **IaC Scanner** | Infrastructure | Terraform, CloudFormation, Dockerfile, Kubernetes |
| **Dependency Scanner** | Packages | CVEs in npm, pip, cargo, go modules |

### Detection Rules

**Secret Patterns (50+):**
- AWS Access Keys (`AKIA...`)
- GitHub PATs (`ghp_...`)
- OpenAI Keys (`sk-...`)
- Anthropic Keys (`sk-ant-...`)
- Slack Tokens (`xoxb-...`)
- JWT Secrets
- SSH Private Keys
- Database URLs
- Hardcoded Passwords

**SAST Rules:**
- SQL Injection (string concatenation in queries)
- Cross-Site Scripting (innerHTML with user input)
- Command Injection (eval, exec with user input)
- Path Traversal (path.join with user input)
- SSRF (fetch with user-controlled URL)
- Weak Cryptography (MD5, SHA1)

---

## Part 10: Compliance Coverage

| Framework | Coverage |
|-----------|----------|
| SOC 2 Type II | RBAC, RLS, notifications, audit |
| ISO 27001:2022 | Policy engine, vulnerability mgmt |
| HIPAA | PHI detection, access controls |
| PCI DSS 4.0 | Vulnerability identification |
| OWASP ASVS | Application security controls |
| NIST CSF | Framework controls mapped |
| MITRE ATT&CK | Adversary techniques indexed |
| CIS Controls | Benchmark controls loaded |

---

## Support

- **Documentation:** https://docs.omniguard.io
- **GitHub Issues:** https://github.com/omniguard/omniguard/issues
- **API Status:** https://status.omniguard.io
