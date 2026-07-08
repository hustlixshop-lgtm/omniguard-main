# OmniGuard Enterprise Platform

## Complete Feature List & Integration Guide

---

## 1. Platform Overview

OmniGuard is an enterprise AI security platform that provides continuous monitoring of software repositories, cloud infrastructure, and development workflows.

### Core Capabilities

| Feature | Description | Status |
|---------|-------------|--------|
| Multi-Tenant Architecture | Organization-scoped data isolation | ✅ Active |
| Row-Level Security | Database-level access control | ✅ Active |
| Role-Based Access Control | 5-tier permission system | ✅ Active |
| Repository Scanning | Multi-provider repo analysis | ✅ Active |
| Findings Management | Vulnerability tracking & remediation | ✅ Active |
| Team Management | Cross-functional team organization | ✅ Active |
| Audit Logging | Complete action history | ✅ Active |
| API Access | RESTful endpoints with API keys | ✅ Active |
| GitHub Webhooks | Real-time push event processing | ✅ Active |
| Vector Search | Semantic document search | ✅ Ready |

---

## 2. Database Schema (17 Tables)

### Core Tables

```
organizations          - Tenant entities
├── organization_members - User-organization junction
├── teams               - Team groupings
│   └── team_members    - User-team junction
├── repositories        - Connected code repos
│   ├── scans           - Security scan records
│   └── findings        - Discovered vulnerabilities
├── documents           - Uploaded policies/docs
│   └── document_chunks - Vector-searchable chunks
├── policies            - Governance policies
├── notifications       - User alerts
├── reports             - Generated reports
├── audit_logs          - Action history
├── integrations        - External connections
└── api_keys            - API authentication
```

### RLS Policies: 70 Total

| Table | SELECT | INSERT | UPDATE | DELETE |
|-------|--------|--------|--------|--------|
| organizations | Member check | Open | Owner only | Owner only |
| repositories | Member check | Member check | Engineer+ | Admin+ |
| findings | Member check | System | Member check | - |
| scans | Member check | Member check | Engineer+ | - |
| policies | Member check | Engineer+ | Engineer+ | Admin+ |
| notifications | Owner only | System | Owner only | Owner only |
| integrations | Admin+ | Admin+ | Admin+ | Admin+ |
| api_keys | Admin+ | Admin+ | Admin+ | Admin+ |

---

## 3. Role Permission Matrix

| Action | Owner | Admin | Engineer | Developer | Auditor |
|--------|-------|-------|----------|-----------|---------|
| View Dashboard | ✅ | ✅ | ✅ | ✅ | ✅ |
| Manage Integrations | ✅ | ✅ | ❌ | ❌ | ❌ |
| Connect Repositories | ✅ | ✅ | ✅ | ✅ | ❌ |
| Run Scans | ✅ | ✅ | ✅ | ✅ | ❌ |
| Resolve Findings | ✅ | ✅ | ✅ | ✅ | ❌ |
| Delete Repositories | ✅ | ✅ | ❌ | ❌ | ❌ |
| Manage API Keys | ✅ | ✅ | ❌ | ❌ | ❌ |
| Invite Members | ✅ | ✅ | ❌ | ❌ | ❌ |
| Create Teams | ✅ | ✅ | ❌ | ❌ | ❌ |
| Edit Policies | ✅ | ✅ | ✅ | ❌ | ❌ |
| Delete Organization | ✅ | ❌ | ❌ | ❌ | ❌ |

---

## 4. Edge Functions API

### Deployed Functions

| Function | URL | Purpose |
|----------|-----|---------|
| `github-webhook` | `/functions/v1/github-webhook` | Receive GitHub push events |
| `api-v1-findings` | `/functions/v1/api-v1-findings` | RESTful findings API |
| `api-v1-status` | `/functions/v1/api-v1-status` | Health check endpoint |

### GitHub Webhook Integration

**Endpoint:** `POST /functions/v1/github-webhook`

**Headers Required:**
```
X-GitHub-Event: push
X-Hub-Signature-256: sha256=<signature>
Content-Type: application/json
```

**Flow:**
1. GitHub sends push event to webhook URL
2. Edge function verifies signature using repository's `webhook_secret`
3. Creates `scan` record with status `queued`
4. Logs audit event
5. Scanning workers pick up queued scans (simulated in current version)

**Response:**
```json
{
  "received": true,
  "scan_id": "uuid",
  "repository": "owner/repo",
  "branch": "main",
  "commits": 3
}
```

### Findings API

**Endpoint:** `GET /functions/v1/api-v1-findings`

**Authentication:** Bearer token (JWT or API key)

**Query Parameters:**
- `severity` - Filter by critical/high/medium/low
- `status` - Filter by open/resolved/suppressed
- `scanner` - Filter by secret/dependency/iac/container/license/sast
- `repository_id` - Filter by specific repository
- `limit` - Results per page (max 100)
- `offset` - Pagination offset

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "uuid",
      "severity": "critical",
      "title": "Hardcoded AWS Secret Key",
      "file_path": "config/aws.py",
      "line_start": 42,
      "scanner": "secret",
      "status": "open",
      "cvss_score": 9.1,
      "repository": { "full_name": "acme/app" }
    }
  ],
  "meta": {
    "total": 150,
    "limit": 50,
    "offset": 0,
    "has_more": true
  }
}
```

### Health Check

**Endpoint:** `GET /functions/v1/api-v1-status`

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "timestamp": "2026-07-05T12:00:00Z",
    "checks": [
      { "component": "database", "status": "healthy", "latency_ms": 5 },
      { "component": "auth", "status": "healthy", "latency_ms": 12 },
      { "component": "storage", "status": "healthy", "latency_ms": 8 }
    ]
  }
}
```

---

## 5. Frontend Application

### Build Output
```
dist/index.html           0.80 kB │ gzip: 0.46 kB
dist/assets/index.css    29.97 kB │ gzip: 5.66 kB
dist/assets/index.js    453.50 kB │ gzip: 124.40 kB
```

### Pages Implemented

| Route | Component | Features |
|-------|-----------|----------|
| `/auth` | Auth.tsx | Sign in/up, password reset |
| `/` | Dashboard.tsx | Stats, health chart, activity |
| `/repositories` | Repositories.tsx | Connect, scan, manage repos |
| `/findings` | Findings.tsx | Filter, resolve, assign |
| `/teams` | Teams.tsx | Create teams, manage members |
| `/settings` | Settings.tsx | Org config, integrations, API |

### Real-time Features

- **Scan Updates:** WebSocket subscription on `scans:{repository_id}`
- **Organization Switching:** Context-based org selector
- **Theme:** Dark mode enterprise UI

---

## 6. CI/CD Integration (Pre-Pipeline)

### How Enterprises Would Use This

**Before CI/CD (Shift-Left Security):**

```
Developer Code → Local Scan → Git Hook → OmniGuard Analysis → Block/Allow → Push
```

**Integration Points:**

1. **Pre-commit Hook (Local)**
   ```bash
   # .git/hooks/pre-commit
   #!/bin/bash
   # Scan staged files before commit
   omniguard scan --staged --fail-on critical
   ```

2. **Pre-push Hook (Local)**
   ```bash
   # .git/hooks/pre-push
   #!/bin/bash
   # Full scan before push
   omniguard scan --branch $(git branch --show-current) --fail-on high
   ```

3. **GitHub Webhook (Server-side)**
   - Configure webhook in GitHub repo settings
   - URL: `https://<project>.supabase.co/functions/v1/github-webhook`
   - Events: `push`, `pull_request`
   - OmniGuard creates scan record automatically
   - Results visible in dashboard within seconds

4. **GitHub Actions Integration**
   ```yaml
   # .github/workflows/omniguard.yml
   name: OmniGuard Security Scan
   on: [push, pull_request]
   jobs:
     scan:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - name: OmniGuard Scan
           env:
             OMNIGUARD_API_KEY: ${{ secrets.OMNIGUARD_API_KEY }}
           run: |
             curl -X POST \
               https://<project>.supabase.co/functions/v1/api-v1-scans \
               -H "Authorization: Bearer $OMNIGUARD_API_KEY" \
               -H "Content-Type: application/json" \
               -d '{"repository": "${{ github.repository }}", "commit": "${{ github.sha }}"}'
   ```

5. **IDE Integration (VS Code)**
   - Install OmniGuard extension (future)
   - Real-time inline findings
   - AI remediation suggestions
   - Quick-fix actions

---

## 7. AWS Deployment Architecture

### Recommended Infrastructure

```
┌──────────────────────────────────────────────────────────────┐
│                        AWS CloudFront                         │
│                    (CDN + WAF + SSL)                          │
└──────────────────────────────────────────────────────────────┘
                              │
┌──────────────────────────────────────────────────────────────┐
│                   Application Load Balancer                   │
│                 (Routing + Health Checks)                     │
└──────────────────────────────────────────────────────────────┘
                    │                    │
        ┌───────────┘                    └───────────┐
        │                                            │
┌───────▼───────┐                         ┌─────────▼─────────┐
│  ECS Fargate  │                         │   ECS Fargate     │
│   (Frontend)  │                         │    (Backend)      │
│  React SPA    │                         │  Edge Functions   │
│  S3 + CDN     │                         │  (Supabase-hosted)│
└───────────────┘                         └───────────────────┘
                                                    │
                                    ┌───────────────┼───────────────┐
                                    │               │               │
                            ┌───────▼───────┐ ┌─────▼─────┐ ┌───────▼───────┐
                            │  ElastiCache │ │    RDS    │ │     SES       │
                            │   (Redis)     │ │(PostgreSQL)│ │   (Email)     │
                            └──────────────┘ └───────────┘ └───────────────┘
```

### Deployment Steps

**Option 1: Supabase-Hosted (Current)**
- Frontend: Build → Deploy to Vercel/Netlify/CloudFront S3
- Backend: Already hosted on Supabase
- Database: Managed Supabase PostgreSQL
- Edge Functions: Auto-deployed via `deploy_edge_function`

**Option 2: Self-Hosted AWS**

1. **Database (RDS PostgreSQL)**
   ```bash
   # Create RDS instance
   aws rds create-db-instance \
     --db-instance-identifier omniguard-db \
     --db-instance-class db.t3.medium \
     --engine postgres \
     --master-username omniguard \
     --master-user-password <secure-password> \
     --allocated-storage 100

   # Enable pgvector extension
   psql -c "CREATE EXTENSION vector;"
   ```

2. **Redis (ElastiCache)**
   ```bash
   aws elasticache create-replication-group \
     --replication-group-id omniguard-redis \
     --replication-group-description "OmniGuard cache" \
     --cache-node-type cache.t3.medium \
     --num-cache-clusters 2
   ```

3. **Frontend (S3 + CloudFront)**
   ```bash
   # Build and deploy
   npm run build
   aws s3 sync dist/ s3://omniguard-frontend/
   aws cloudfront create-invalidation --distribution-id <id>
   ```

4. **Environment Variables**
   ```
   SUPABASE_URL=https://xxx.supabase.co
   SUPABASE_ANON_KEY=eyJxxx
   SUPABASE_SERVICE_ROLE_KEY=eyJxxx
   DATABASE_URL=postgresql://...
   REDIS_URL=redis://...
   ```

---

## 8. Enterprise Readiness Checklist

### ✅ Security
- [x] Multi-tenant data isolation (RLS)
- [x] Row-Level Security on all tables
- [x] Role-based access control
- [x] Supabase Auth (email/password)
- [x] API key authentication
- [x] Webhook signature verification
- [ ] MFA (roadmap)
- [ ] SSO/SAML (roadmap)

### ✅ Observability
- [x] Health check endpoint
- [x] Audit logging
- [ ] Prometheus metrics (roadmap)
- [ ] OpenTelemetry tracing (roadmap)
- [ ] Sentry integration (roadmap)

### ✅ Scalability
- [x] Indexed queries (70+ indexes)
- [x] Soft deletes
- [x] Pagination
- [x] Connection pooling (Supabase)
- [x] Edge functions (auto-scaling)

### ✅ Developer Experience
- [x] TypeScript frontend
- [x] Type-safe Supabase client
- [x] RESTful API
- [x] OpenAPI-ready (Supabase)
- [ ] CLI tool (roadmap)
- [ ] VS Code extension (roadmap)

### ✅ Compliance Ready
- [x] Audit logs table
- [x] Soft deletes
- [x] Data versioning
- [ ] SOC 2 config (roadmap)
- [ ] HIPAA audit (roadmap)
- [ ] GDPR exports (roadmap)

---

## 9. Real-Time Execution Flow

### User Journey: Connect Repository and Scan

```
1. User signs in → Supabase Auth validates credentials
   └── Frontend receives JWT + Refresh token
   └── AuthContext stores session
   └── Redirect to Dashboard

2. User creates organization → INSERT into organizations
   └── RLS policy allows (user is creator)
   └── INSERT into organization_members (role: owner)
   └── Frontend updates context

3. User connects repository → INSERT into repositories
   └── RLS policy checks org membership
   └── Frontend shows repository card

4. User clicks "Run Scan" → INSERT into scans (status: queued)
   └── Audit log entry created
   └── WebSocket subscription listens for updates
   └── (Simulated scan completes after 100ms)
   └── UPDATE scan (status: completed)
   └── Frontend receives real-time update
   └── Dashboard refreshes stats

5. GitHub push event → POST /functions/v1/github-webhook
   └── Edge function validates signature
   └── Creates scan record
   └── (Future: Worker processes scan)
   └── Findings generated
   └── Notifications sent
   └── Dashboard updates in real-time
```

### Data Flow Architecture

```
Frontend (React)          Supabase Backend
     │                         │
     ├─ Auth (email/pass) ────►│ Supabase Auth
     │                         │    └─ JWT Token
     │◄────────────────────────┤
     │                         │
     ├─ Query repositories ──►│ PostgreSQL + RLS
     │◄────────────────────────┤
     │                         │
     ├─ Subscribe realtime ───►│ WebSocket Channel
     │                         │    └─ broadcasts changes
     │                         │
     │                         │
   Edge Functions          Supabase Services
     │                         │
     ├─ GitHub webhook ──────►│ PostgreSQL
     │   └─ verify sig         │    └─ INSERT scan
     │   └─ create scan        │
     │                         │
     ├─ API findings ─────────►│ PostgreSQL + RLS
     │   └─ validate JWT       │    └─ return data
     │                         │
     └─ Health check ─────────►│ Multiple services
         └─ db, auth, storage  │    └─ status report
```

---

## 10. Current Limitations & Roadmap

### Not Yet Implemented

| Feature | Status | Effort |
|---------|--------|--------|
| Actual scanning engine | Not built | High |
| AI provider integration | Not built | Medium |
| Email notifications | Not configured | Low |
| SSO/SAML | Not built | Medium |
| CLI tool | Not built | Medium |
| VS Code extension | Not built | Medium |
| Mobile app | Not built | High |
| Billing/payments | Not built | High |
| Plugin system | Designed | Medium |

### What IS Working Today

✅ Full authentication flow
✅ Organization creation and management
✅ Team creation and member invites
✅ Repository connection (manual entry)
✅ Scan record creation
✅ GitHub webhook reception
✅ API endpoints for findings
✅ Real-time dashboard updates
✅ Complete audit logging
✅ Health monitoring

---

## 11. Quick Start for Enterprises

### 1. Deploy Frontend
```bash
npm install
npm run build
# Deploy dist/ to any static host
```

### 2. Configure GitHub Webhook
1. Go to Repository Settings → Webhooks
2. Add webhook URL: `https://<project>.supabase.co/functions/v1/github-webhook`
3. Set secret to match `webhook_secret` in database
4. Select events: Push, Pull Request

### 3. Create API Key
```sql
-- In Supabase SQL editor
INSERT INTO api_keys (organization_id, name, key_hash, key_prefix, scopes)
VALUES (
  '<your-org-id>',
  'CI/CD Key',
  '<sha256-hash-of-key>',
  'og_live_abc',
  ARRAY['findings:read', 'findings:write']
);
```

### 4. Query Findings via API
```bash
curl https://<project>.supabase.co/functions/v1/api-v1-findings \
  -H "Authorization: Bearer og_live_yourkeyhere" \
  -H "Apikey: <anon-key>"
```

---

## Support

For issues or feature requests, use the in-app feedback or contact support.
