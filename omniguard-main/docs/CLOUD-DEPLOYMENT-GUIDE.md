# OmniGuard Cloud Deployment & Production Setup Guide

## Current Status Summary

**Working Components:**
- Database: 16 tables, 55+ RLS policies
- Edge Functions: 5 deployed and active
- Scanner: Real secret detection working (found 2 critical issues in test)
- API: All endpoints responding

**Test Results:**
```json
{
  "success": true,
  "scan_id": "e82e9980-a2f0-4967-b227-cd355b3eed42",
  "findings": 2,
  "summary": {"critical": 2, "high": 0, "medium": 0, "low": 0},
  "duration_seconds": 1
}
```

---

## Step 1: Enable AI Classification (Required)

### Add Anthropic API Key to Supabase

1. Go to [Supabase Dashboard](https://supabase.com/dashboard)
2. Select your project: `kdfhlacefessshjnkhvw`
3. Navigate to **Edge Functions** → **Settings**
4. Add a new secret:
   - Name: `ANTHROPIC_API_KEY`
   - Value: `sk-ant-api03-...` (your key from .env)
5. Click **Save**

**Alternative via Supabase CLI:**
```bash
supabase secrets set ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

### Verify AI Secret is Set

After setting the secret, the scan-worker will have access to Anthropic API for:
- **Haiku**: Fast classification per file (real-time)
- **Sonnet**: Deep analysis + remediation suggestions
- **Opus**: Executive summaries (when explicitly enabled)

---

## Step 2: Production Backend Architecture

### Current Supabase Setup

```
┌─────────────────────────────────────────────────────────────┐
│                    SUPABASE CLOUD                           │
├─────────────────────────────────────────────────────────────┤
│  Project: kdfhlacefessshjnkhvw                              │
│  Region: AWS us-east-1                                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  EDGE FUNCTIONS (Deno)                             │   │
│  │  github-webhook   ✓ ACTIVE - Push/PR processing   │   │
│  │  scan-worker      ✓ ACTIVE - Scanner + AI         │   │
│  │  api-v1-scans     ✓ ACTIVE - Scan CRUD             │   │
│  │  api-v1-findings  ✓ ACTIVE - Finding management    │   │
│  │  api-v1-status    ✓ ACTIVE - Health checks         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  POSTGRESQL DATABASE                                │   │
│  │  - 16 tables with multi-tenant RLS                 │   │
│  │  - pgvector extension enabled                       │   │
│  │  - Worker queue functions                          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  REALTIME (WebSocket)                              │   │
│  │  - Live scan status updates                        │   │
│  │  - Finding notifications                           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### API Endpoints (Live Now)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/functions/v1/api-v1-status` | GET | Health check |
| `/functions/v1/api-v1-scans` | POST | Create scan |
| `/functions/v1/api-v1-scans/:id` | GET | Get scan status |
| `/functions/v1/api-v1-findings` | GET | List findings |
| `/functions/v1/api-v1-findings/:id` | PATCH | Update finding |
| `/functions/v1/github-webhook` | POST | GitHub webhook receiver |
| `/functions/v1/scan-worker/process` | GET | Trigger scan processing |

---

## Step 3: Access from Anywhere

### Dashboard Access

**Live Web App:**
```
https://kdfhlacefessshjnkhvw.supabase.co
```

Or deploy the frontend to Vercel/Netlify:

```bash
# Build frontend
cd omniguard-main
npm run build

# Deploy to Vercel
npx vercel deploy

# Or Netlify
npx netlify deploy --prod --dir=dist
```

### VS Code Extension Configuration

Add to VS Code `settings.json`:

```json
{
  "omniguard.supabaseUrl": "https://kdfhlacefessshjnkhvw.supabase.co",
  "omniguard.supabaseAnonKey": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtkZmhsYWNlZmVzc3Noam5raHZ3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODMyMzAyNzMsImV4cCI6MjA5ODgwNjI3M30.eorX_ovLeP9q-OIj_RlVZCFVJV2x3IrDPSXzZDsuWKE",
  "omniguard.scanOnSave": true,
  "omniguard.enableRealtimeScanning": true,
  "omniguard.aiEnabled": true
}
```

### Git Hooks Configuration

Set environment variables on your machine:

```bash
# Add to ~/.bashrc or ~/.zshrc
export OMNIGUARD_URL="https://kdfhlacefessshjnkhvw.supabase.co/functions/v1"
export OMNIGUARD_API_KEY="your_api_key_here"  # Generate in dashboard
export OMNIGUARD_FAIL_ON="high"
```

---

## Step 4: AWS Production Deployment

### Option A: Full AWS Deployment (Terraform)

```bash
cd omniguard-main/infrastructure/terraform

# Create terraform.tfvars
cat > terraform.tfvars << 'EOF'
aws_region = "us-east-1"
project_name = "omniguard"
environment = "production"
domain_name = "omniguard.yourdomain.com"

# Secret ARNs (create in AWS Secrets Manager first)
anthropic_api_key_arn = "arn:aws:secretsmanager:us-east-1:ACCOUNT:secret:anthropic-key"
github_app_secret_arn = "arn:aws:secretsmanager:us-east-1:ACCOUNT:secret:github-secret"
EOF

# Initialize and deploy
terraform init
terraform plan
terraform apply
```

**What gets deployed:**

| Resource | Type | Purpose |
|----------|------|---------|
| VPC | Custom VPC | Multi-AZ network |
| RDS | PostgreSQL 15 | Primary database with pgvector |
| ElastiCache | Redis 7.2 | Job queue + caching |
| ECS Fargate | API + Worker | Container orchestration |
| CloudFront | CDN | Static assets + API gateway |
| ALB | Load Balancer | HTTPS termination |
| Route53 | DNS | Custom domain |
| ACM | Certificate | SSL/TLS |
| Secrets Manager | Secrets | API keys |
| CloudWatch | Logs | Monitoring |

### Option B: Deploy Only Frontend (Keep Supabase Backend)

```bash
# Build with Supabase backend
cd omniguard-main

# Vercel
npx vercel deploy --prod

# Or Netlify
npx netlify deploy --prod

# Set environment variables in hosting platform:
# VITE_SUPABASE_URL=https://kdfhlacefessshjnkhvw.supabase.co
# VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## Step 5: Running Locally

### Backend (Supabase - Already Running)

The backend is hosted on Supabase Cloud and accessible from anywhere:
- Database: `https://kdfhlacefessshjnkhvw.supabase.co`
- Edge Functions: Same base URL
- Realtime: WebSocket connections auto-handled

### Frontend (Local Development)

```bash
cd omniguard-main

# Install dependencies
npm install

# Start dev server
npm run dev

# Access at http://localhost:5173
# Login: demo@omniguard.dev / Demo@OmniGuard2024!
```

### Local API Testing

```bash
# Health check
curl https://kdfhlacefessshjnkhvw.supabase.co/functions/v1/api-v1-status

# Trigger scan
curl "https://kdfhlacefessshjnkhvw.supabase.co/functions/v1/scan-worker/process" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# List findings (requires auth)
curl "https://kdfhlacefessshjnkhvw.supabase.co/functions/v1/api-v1-findings" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

---

## Step 6: Multi-Tier AI Pipeline

### How It Works

```
┌────────────────────────────────────────────────────────────┐
│                    AI CLASSIFICATION                        │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  TIER 1: Claude Haiku (Fast Classification)        │  │
│  │  - Triggered: Every file save/open                  │  │
│  │  - Speed: <500ms                                    │  │
│  │  - Cost: ~$0.0001 per file                          │  │
│  │  - Output: Classification (SAFE/LOW/MEDIUM/HIGH/)  │  │
│  │           + confidence score                        │  │
│  └─────────────────────────────────────────────────────┘  │
│                          │                                 │
│                          ▼                                 │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  TIER 2: Claude Sonnet (Deep Analysis)             │  │
│  │  - Triggered: Critical/High findings only          │  │
│  │  - Speed: 2-5 seconds                              │  │
│  │  - Cost: ~$0.01 per finding                         │  │
│  │  - Output: Detailed remediation steps               │  │
│  │           + code fix suggestions                    │  │
│  └─────────────────────────────────────────────────────┘  │
│                          │                                 │
│                          ▼                                 │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  TIER 3: Claude Opus (Executive Summary)            │  │
│  │  - Triggered: Weekly/monthly reports                │  │
│  │  - Speed: 10-30 seconds                             │  │
│  │  - Cost: ~$0.50 per report                          │  │
│  │  - Output: Executive-level summary                   │  │
│  │           + compliance mapping                      │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### Current Implementation

The scan-worker uses Haiku for real-time classification when `ANTHROPIC_API_KEY` is set:

```typescript
// In scan-worker/index.ts (already implemented)
const response = await fetch("https://api.anthropic.com/v1/messages", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-api-key": anthropicApiKey,
    "anthropic-version": "2023-06-01"
  },
  body: JSON.stringify({
    model: "claude-3-5-haiku-20241022",
    max_tokens: 100,
    messages: [{ role: "user", content: classificationPrompt }]
  })
});
```

### Enable AI Classification

1. Set `ANTHROPIC_API_KEY` secret in Supabase Dashboard
2. The scan-worker will automatically:
   - Detect finding severity
   - Classify overall security risk
   - Add confidence scores
   - Generate AI summaries

---

## Step 7: Testing the Complete Pipeline

### Test 1: API Health
```bash
curl https://kdfhlacefessshjnkhvw.supabase.co/functions/v1/api-v1-status
```

### Test 2: Trigger Scan
```bash
curl "https://kdfhlacefessshjnkhvw.supabase.co/functions/v1/scan-worker/process" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

### Test 3: Web Dashboard
1. Open http://localhost:5173 (after `npm run dev`)
2. Login: `demo@omniguard.dev` / `Demo@OmniGuard2024!`
3. View dashboard with:
   - 3 repositories
   - 4+ findings (varying severity)
   - Repository health scores
   - Recent activity

### Test 4: VS Code Extension
1. Install extension from `omniguard-main/vscode-extension`
2. Open a project with secrets/vulnerabilities
3. Save a file → triggers scan
4. View findings in Problems panel
5. Hover for remediation details

---

## Step 8: Production Checklist

### Before Going Live

- [ ] Set `ANTHROPIC_API_KEY` in Supabase secrets
- [ ] Generate production API keys in dashboard
- [ ] Configure custom domain in Supabase
- [ ] Set up GitHub webhook with secret
- [ ] Enable email notifications (configure SMTP)
- [ ] Review RLS policies for your org structure
- [ ] Set up backup schedule for database
- [ ] Configure rate limiting (per-org limits)
- [ ] Enable audit logging
- [ ] Set up monitoring/alerts (CloudWatch)

### Security Recommendations

1. **Rotate demo credentials** after testing
2. **Use API keys** with limited scopes for CI/CD
3. **Enable MFA** for organization owners
4. **Review RLS policies** before adding sensitive data
5. **Set up IP allowlisting** if required

---

## Troubleshooting

### "No pending scans" Error
- Check `scan_queue` table has pending items
- Check scan status is `queued` (not `completed`)
- Run: `UPDATE scans SET status = 'queued' WHERE id = 'scan_id'`

### AI Not Running
- Verify `ANTHROPIC_API_KEY` is set in Supabase secrets
- Check edge function logs in Supabase dashboard
- Test with simple curl to verify key works

### VS Code Extension Not Connecting
- Check Supabase URL and key in settings
- Verify network connectivity
- Check extension output panel for errors

### Findings Not Showing
- Check RLS policies for organization membership
- Verify user is in `organization_members` table
- Check findings have correct `organization_id`

---

## Support & Resources

- **Supabase Dashboard**: https://supabase.com/dashboard
- **Edge Function Logs**: Dashboard → Edge Functions → [function] → Logs
- **Database Query Editor**: Dashboard → SQL Editor
- **Realtime Monitor**: Dashboard → Database → Replication

---

## Quick Reference

### Supabase Project Details
- **URL**: `https://kdfhlacefessshjnkhvw.supabase.co`
- **Anon Key**: In `.env` file
- **Service Role Key**: In Supabase dashboard

### Demo Credentials
- **Email**: `demo@omniguard.dev`
- **Password**: `Demo@OmniGuard2024!`
- **Organization**: Demo Organization

### API Base URL
```
https://kdfhlacefessshjnkhvw.supabase.co/functions/v1
```
