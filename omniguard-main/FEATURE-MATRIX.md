# OmniGuard Enterprise Feature Matrix

## Platform Capabilities

| Category | Feature | Status | Notes |
|----------|---------|--------|-------|
| **Core Infrastructure** | | | |
| Multi-tenant Architecture | ✅ Complete | Full org isolation with RLS |
| Row-Level Security (RLS) | ✅ Complete | 55+ policies across 16 tables |
| Role-Based Access Control | ✅ Complete | 5-tier: Owner, Admin, Engineer, Developer, Auditor |
| Audit Logging | ✅ Complete | Full action history with IP/tracking |
| API Authentication | ✅ Complete | JWT + API Key with org scope |

| **Repository Management** | | | |
| Multi-Provider Support | ✅ Complete | GitHub, GitLab, Bitbucket, Azure DevOps |
| Repository Connection | ✅ Complete | Manual + Webhook automated |
| Risk Scoring | ✅ Complete | Dynamic per-repo scoring |
| Team Assignment | ✅ Complete | Teams linked to repositories |

| **Security Scanners** | | | |
| Secret Detection | ✅ Complete | 50+ patterns (AWS, GitHub, OpenAI, Anthropic, etc.) |
| SAST (Static Analysis) | ✅ Complete | SQL Injection, XSS, CMD Injection, SSRF, etc. |
| IaC Scanning | ✅ Complete | Terraform, CloudFormation, Dockerfile, Kubernetes |
| Dependency Scanner | ✅ Complete | Known CVEs, package versioning |
| Container Scanner | 🔄 In Progress | Dockerfile analysis (Docker/SBOM planned) |
| License Checker | 📋 Planned | SPDX license detection |

| **AI Integration** | | | |
| Claude Haiku Classifier | ✅ Complete | Real-time code classification |
| Claude Sonnet Analysis | ✅ Complete | Deep context analysis, remediation |
| Claude Opus Summaries | ✅ Complete | Executive reports, architecture reviews |
| AI Remediation Suggestions | ✅ Complete | Per-finding code fixes |
| False Positive Detection | ✅ Complete | Confidence scoring + filtering |

| **Policy Engine** | | | |
| YAML Policy Support | ✅ Complete | In database, evaluated by worker |
| JSON Policy Support | ✅ Complete | Structured policy definition |
| Built-in Policies | ✅ Complete | No-public-S3, encryption required, etc. |
| Policy Bypass | ✅ Complete | Audited bypass with justification |
| Auto-mapping to Findings | ✅ Complete | Policy violations become findings |

| **Compliance** | | | |
| SOC2 Mapping | ✅ Complete | Auto-mapped to findings |
| ISO27001 Mapping | ✅ Complete | Control framework loaded |
| HIPAA Mapping | ✅ Complete | Healthcare controls |
| PCI DSS Mapping | ✅ Complete | Payment card controls |
| OWASP ASVS | ✅ Complete | Application security controls |
| NIST CSF | ✅ Complete | Framework controls |
| MITRE ATT&CK | ✅ Complete | Adversary techniques |
| CIS Controls | ✅ Complete | Benchmark controls |

| **Document Intelligence** | | | |
| Document Upload | ✅ Ready | Infrastructure ready |
| PDF Parsing | 📋 Planned | Needs worker library |
| Vector Embeddings | ✅ Ready | pgvector enabled (1536 dims) |
| Semantic Search | 🔨 Partial | Schema ready, embedding pipeline needed |
| Policy Q&A | 📋 Planned | AI-powered policy search |

| **VS Code Extension** | | | |
| Real-time Scanning | ✅ Complete | On-save, on-open triggers |
| Inline Diagnostics | ✅ Complete | Problems panel integration |
| CodeLens Annotations | ✅ Complete | Security annotations in editor |
| Hover Explanations | ✅ Complete | Detailed finding info |
| Sidebar Findings View | ✅ Complete | Filtered findings list |
| AI Chat Integration | 🔄 In Progress | Sidebar chat for remediation |
| Quick Fix Actions | ✅ Complete | Apply AI suggestions |

| **Git Integration** | | | |
| Pre-commit Hook | ✅ Complete | Secrets + SAST blocking |
| Pre-push Hook | ✅ Complete | Full scan before push |
| Bypass Mechanism | ✅ Complete | Audited bypass with reason |
| CLI Installation | ✅ Complete | `omniguard install-hooks` |

| **API & Webhooks** | | | |
| REST API | ✅ Complete | 4 edge functions deployed |
| GitHub Webhook | ✅ Complete | Push/PR events processed |
| API Keys | ✅ Complete | Scoped API key management |
| Rate Limiting | ✅ Complete | Per-org rate limits |

| **Real-time** | | | |
| WebSocket Subscriptions | ✅ Complete | Real-time scan updates |
| Live Dashboard | ✅ Complete | Auto-refreshing stats |

| **Worker System** | | | |
| Job Queue | ✅ Complete | Priority queue with retry |
| Worker Heartbeats | ✅ Complete | Health monitoring |
| Scan Processing | ✅ Complete | Async scan execution |
| AI Classification Pipeline | ✅ Complete | Haiku classifier on all findings |

| **Notifications** | | | |
| In-app Notifications | ✅ Complete | Database + frontend |
| Email | 📋 Planned | SES configuration |
| Slack | 📋 Planned | Webhook integration |

| **Reports** | | | |
| Report Generation | ✅ Ready | Schema + API ready |
| PDF Export | 📋 Planned | Report generation |
| CSV Export | 📋 Planned | Data extraction |
| Executive Summary | ✅ Complete | AI-generated with Opus |

| **AWS Deployment** | | | |
| Terraform IaC | ✅ Complete | Full production setup |
| RDS PostgreSQL | ✅ Defined | Multi-AZ, encrypted |
| ElastiCache Redis | ✅ Defined | Clustered, encrypted |
| ECS Fargate | ✅ Defined | API + Worker services |
| CloudFront CDN | ✅ Defined | WAF + SSL |
| Secrets Manager | ✅ Defined | API key storage |
| CloudWatch Logging | ✅ Defined | Structured logs |

---

## Integration Guide

### VS Code Extension

**Installation:**
1. Install from VS Code Marketplace: `omniguard.omniguard`
2. Configure connection:
   ```json
   {
     "omniguard.apiEndpoint": "https://api.omniguard.io",
     "omniguard.enableRealtimeScanning": true,
     "omniguard.scanOnSave": true,
     "omniguard.aiEnabled": true,
     "omniguard.aiModel": "haiku"
   }
   ```

**Demo Credentials:**
- Email: `demo@omniguard.dev`
- Password: `Demo@OmniGuard2024!`

**Features:**
- Real-time classification on file open
- Full scan on file save
- Inline diagnostics with severity icons
- CodeLens security annotations
- Hover tooltips with remediation

### Git Hooks

**Installation:**
```bash
# Clone and run installer
git clone https://github.com/omniguard/omniguard.git
cd omniguard
./install.sh

# Or use npm
npx @omniguard/cli install-hooks
```

**Configuration:**
```bash
# Set environment variables
export OMNIGUARD_URL="https://api.omniguard.io"
export OMNIGUARD_API_KEY="og_live_yourkey"
export OMNIGUARD_FAIL_ON="high"  # critical, high, medium, low
export OMNIGUARD_BYPASS="true"   # Enable bypass for admins
```

**Bypass Usage:**
```bash
# With bypass enabled and audit:
git commit --bypass
# Prompts for justification, logs to audit trail
```

### GitHub Integration

**Webhook Setup:**
1. Go to Repository → Settings → Webhooks
2. Add: `https://<project>.supabase.co/functions/v1/github-webhook`
3. Secret: Generate secure random string
4. Events: Push, Pull Request

**PR Gating:**
- GitHub Checks API integration
- Blocks PR on critical/high findings
- Displays findings as PR annotations

### AWS Deployment

**Prerequisites:**
- Terraform >= 1.5.0
- AWS CLI configured
- Domain in Route53

**Deploy:**
```bash
cd infrastructure/terraform
terraform init
terraform plan -var-file=production.tfvars
terraform apply
```

**Outputs:**
- API URL (CloudFront)
- Database endpoint (RDS)
- Redis endpoint (ElastiCache)
- ECR repositories

---

## Compliance Coverage

### SOC 2 Type II
| Control | Coverage |
|---------|----------|
| CC6.1 - Logical Access | ✅ RBAC + RLS |
| CC6.6 - Incident Management | ✅ Notifications + Audit |
| CC6.7 - Vulnerability Management | ✅ Full scanning pipeline |
| CC7.1 - System Monitoring | ✅ Worker heartbeats |
| CC7.2 - Incident Response | ✅ Alert routing |

### ISO 27001:2022
| Control | Coverage |
|---------|----------|
| A.5.1 - Security Policies | ✅ Policy engine |
| A.8.8 - Vulnerability Management | ✅ CVE scanning |
| A.8.25 - Secure Development | ✅ SAST + IaC scanning |
| A.8.28 - Secure Coding | ✅ AI remediation |

### PCI DSS 4.0
| Control | Coverage |
|---------|----------|
| 6.2 - Vulnerability Identification | ✅ Dependency + SAST |
| 6.3 - Secure Development | ✅ Code scanning |
| 11.3 - Penetration Testing | 📋 Planned |

---

## Demo Account

**Login:**
- URL: https://app.omniguard.io
- Email: `demo@omniguard.dev`
- Password: `Demo@OmniGuard2024!`

**Features Available:**
- Full scanning capabilities
- AI classification (Haiku)
- Sample repositories with findings
- Policy compliance dashboard

**Sample Repositories:**
- `demo/vulnerable-app` - SQL injection, XSS
- `demo/infrastructure` - IaC misconfigurations
- `demo/secrets-leak` - Hardcoded credentials

---

## API Reference

### Base URL
```
https://api.omniguard.io
```

### Authentication
```bash
# JWT (from login)
Authorization: Bearer <jwt_token>

# API Key
Authorization: Bearer og_live_xxxxx
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/scan/file` | Scan single file |
| `POST` | `/scan/quick` | Quick classify file |
| `POST` | `/scans` | Create scan |
| `GET` | `/scans/:id` | Get scan status |
| `GET` | `/findings` | List findings |
| `GET` | `/findings/:id` | Get finding details |
| `PATCH` | `/findings/:id` | Update finding |
| `POST` | `/findings/:id/suppress` | Suppress finding |

---

## Support

**Documentation:** https://docs.omniguard.io
**GitHub Issues:** https://github.com/omniguard/omniguard/issues
**Status:** https://status.omniguard.io

---

## Remaining Implementation Items

| Item | Priority | Effort |
|------|----------|--------|
| Email notifications (SES) | High | Low |
| Slack webhook integration | Medium | Low |
| PDF report generation | Medium | Medium |
| SBOM generation | High | Medium |
| Docker image CVE scanner | High | High |
| Advanced policy editor UI | Medium | Medium |
| Mobile app | Low | High |
