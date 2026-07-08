# OmniGuard — Complete Setup, Deployment & Publishing Guide

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Node.js | ≥ 18 | https://nodejs.org |
| npm | ≥ 9 | bundled with Node |
| Git | any | for hooks feature |
| VS Code | ≥ 1.80 | for extension feature |
| Supabase account | free tier works | https://supabase.com |

---

## 1. Repository Structure

```
omniguard/
├── omniguard/          # React frontend (Vite + TypeScript + Tailwind)
├── supabase/
│   ├── functions/      # Deno edge functions
│   │   ├── _shared/ai.ts          # AI provider abstraction (vault-aware)
│   │   ├── secrets-proxy/         # AI key vault storage (replaces client-side key storage)
│   │   ├── scan-quick/            # Fast file scan (no DB required)
│   │   ├── scan-worker/           # Full async scan worker
│   │   ├── api-v1-findings/       # Findings CRUD + AI remediation
│   │   ├── api-v1-scans/          # Scan management
│   │   ├── api-v1-status/         # Health check
│   │   ├── policy-ingest/         # Document → policy ingestion
│   │   ├── github-webhook/        # GitHub push/PR webhooks
│   │   └── enterprise-integrations/
│   └── migrations/     # PostgreSQL migrations (applied in order)
├── cli/                # npm package — omniguard CLI
│   ├── package.json
│   └── src/index.js    # Single-file CLI, no external deps
├── vscode-extension/   # VS Code extension
│   ├── package.json
│   ├── src/extension.ts
│   └── out/extension.js (compiled)
└── omniguard-main/
    ├── scanner/        # TypeScript scanner engine
    ├── install.sh      # One-shot local installer
    └── docs/           # Additional documentation
```

---

## 2. Supabase Project Setup

### 2a. Create a project

1. Go to https://supabase.com/dashboard
2. Click **New Project**
3. Choose a name, database password, and region
4. Wait ~2 minutes for provisioning

### 2b. Get your credentials

From **Project Settings → API**:
- `Project URL` → your `SUPABASE_URL`
- `anon public` key → your `SUPABASE_ANON_KEY`
- `service_role` key → your `SUPABASE_SERVICE_ROLE_KEY` (keep secret)

### 2c. Apply the database schema

The schema is applied via Supabase MCP tools (already done if you cloned a configured project). If setting up fresh:

1. Open Supabase dashboard → **SQL Editor**
2. Run each migration file from `supabase/migrations/` in order:
   - `001_omniguard_security_platform_schema.sql`
   - `002_rls_policies.sql`
   - `003_functions_triggers_seeds.sql` (empty — superseded by 008)
   - `004_worker_queue_functions.sql`
   - `005_add_scan_metadata_and_indexes.sql`
   - `006_scan_worker_scheduler.sql`
   - `007_helper_functions.sql`
   - `008_omniguard_v1_critical_fixes.sql` ← critical, apply this
   - `009_ai_keys_vault_ref.sql`

---

## 3. Frontend (Dashboard) Setup

```bash
cd omniguard/

# Copy environment template
cp .env.example .env    # or create .env manually

# Edit .env
VITE_SUPABASE_URL=https://your-project-id.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-key-here

# Install dependencies
npm install

# Start development server (http://localhost:5173)
npm run dev

# Build for production
npm run build
# Output: omniguard/dist/
```

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `VITE_SUPABASE_URL` | Yes | Your Supabase project URL |
| `VITE_SUPABASE_ANON_KEY` | Yes | Your Supabase anon public key |

---

## 4. Edge Functions Deployment

Edge functions are deployed to your Supabase project. They run on Deno.

### Deploy all functions

```bash
# Install Supabase CLI (optional — only needed for local dev)
npm install -g supabase

# Or deploy via the Supabase MCP tool (recommended in Bolt/Claude)
# The functions are already deployed if you used the provided setup
```

### Manual deploy via Supabase CLI

```bash
cd supabase/

# Login to Supabase
supabase login

# Link to your project
supabase link --project-ref your-project-id

# Deploy all functions
supabase functions deploy secrets-proxy
supabase functions deploy scan-quick
supabase functions deploy scan-worker
supabase functions deploy api-v1-findings
supabase functions deploy api-v1-scans
supabase functions deploy api-v1-status
supabase functions deploy policy-ingest
supabase functions deploy github-webhook
supabase functions deploy enterprise-integrations
```

### Function URLs

After deploying, functions are available at:
```
https://your-project-id.supabase.co/functions/v1/<function-name>
```

---

## 5. CLI Setup

### Local development (no npm publish needed)

```bash
cd cli/

# Make executable
chmod +x src/index.js

# Install globally from local source (npm link)
npm link

# Verify installation
omniguard version
omniguard doctor
```

### Usage

```bash
# Authenticate (run once)
omniguard login
# Enter your Supabase Functions URL and API key when prompted

# Scan current directory
omniguard scan .

# Scan specific file
omniguard scan src/app.ts

# Scan staged files (for pre-commit)
omniguard scan --staged

# Install git hooks in current repo
omniguard install-hooks

# Watch for changes
omniguard watch

# Check status
omniguard status
omniguard doctor
```

### Environment variables (alternative to login)

```bash
export OMNIGUARD_URL="https://your-project.supabase.co/functions/v1"
export OMNIGUARD_API_KEY="og_live_..."       # from Dashboard → Settings → API Keys
export OMNIGUARD_FAIL_ON="critical"          # critical|high|medium|low
```

### Offline mode

The CLI works without any Supabase connection. It runs the built-in secret scanner locally:
- AWS access keys, GitHub PATs, OpenAI keys, Anthropic keys, Stripe keys
- SSH private keys, database connection strings, JWT tokens, npm tokens
- Hardcoded passwords, Google API keys, Azure connection strings

---

## 6. VS Code Extension

### Install from packaged .vsix (local)

```bash
cd vscode-extension/

# The .vsix is already built at:
# vscode-extension/omniguard-1.0.0.vsix

# Install in VS Code
code --install-extension omniguard-1.0.0.vsix

# Or via VS Code UI: Extensions → ... → Install from VSIX
```

### Build from source

```bash
cd vscode-extension/

npm install
npm run compile     # TypeScript → out/extension.js
npm run package     # Packages as omniguard-1.0.0.vsix
```

### Configure in VS Code

1. Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Run **OmniGuard: Configure**
3. Enter your Supabase Functions URL
4. Enter your API key

Or edit VS Code settings directly:
```json
{
  "omniguard.supabaseUrl": "https://your-project.supabase.co/functions/v1",
  "omniguard.apiKey": "og_live_...",
  "omniguard.enableOnSave": true,
  "omniguard.failOnSeverity": "high"
}
```

### Features

| Feature | Description |
|---|---|
| On-save scanning | Automatic scan every time you save |
| On-type scanning | Optional, debounced (set `enableOnType: true`) |
| Inline diagnostics | Red/yellow underlines on vulnerable lines |
| Hover explanations | Hover over a finding for details + AI explanation |
| Quick fixes | Suppress a rule or apply AI fix via lightbulb menu |
| Findings panel | Activity bar panel showing all findings across workspace |
| Workspace scan | Scan all files via Command Palette |
| Offline mode | Works without Supabase (local secret scanner) |

---

## 7. AI Key Configuration (Secure — via Vault)

AI keys are **never stored as plaintext** in the database. They are stored in Supabase Vault and only read server-side by edge functions.

1. Open the Dashboard
2. Go to **Settings → AI Configuration**
3. Select your provider (Anthropic, OpenAI, Bedrock, Azure, Gemini, OpenRouter, Ollama)
4. Enter your API key
5. Click **Save AI Settings**

The key is:
- Posted to the `secrets-proxy` edge function (HTTPS)
- Stored in Supabase Vault (encrypted at rest using pgsodium)
- Only a vault reference ID is saved in the `organizations` table
- Raw keys are never returned to the browser

**Supported providers:**

| Provider | Key field | Notes |
|---|---|---|
| Anthropic | `anthropic_api_key` | Claude 3.5 Haiku / Sonnet |
| OpenAI | `openai_api_key` | GPT-4o / GPT-4o mini |
| AWS Bedrock | `aws_access_key_id` + `aws_secret_access_key` | Claude via Bedrock |
| Azure OpenAI | `azure_openai_endpoint` + `azure_openai_key` | Custom deployments |
| Google Gemini | `gemini_api_key` | Gemini 1.5 Flash / Pro |
| OpenRouter | `openrouter_api_key` | Multi-provider routing |
| Ollama | `ollama_url` | Self-hosted, no key needed |

---

## 8. GitHub Webhook Setup

1. Go to your GitHub repo → **Settings → Webhooks → Add webhook**
2. Payload URL: `https://your-project.supabase.co/functions/v1/github-webhook`
3. Content type: `application/json`
4. Secret: generate a random string and save it as `GITHUB_WEBHOOK_SECRET` in Supabase Edge Function secrets
5. Events: select **Push** and **Pull requests**

Then connect the repository in the OmniGuard dashboard under **Repositories**.

---

## 9. Production Deployment

### Option A: Static hosting (frontend only)

Deploy `omniguard/dist/` to any static host:

```bash
# Vercel
cd omniguard && npx vercel --prod

# Netlify
cd omniguard && npx netlify-cli deploy --prod --dir=dist

# Any static server
npx serve omniguard/dist
```

The backend is entirely Supabase (managed) — no server needed for the frontend.

### Option B: Docker

```bash
# From omniguard/ directory
docker build -f Dockerfile -t omniguard-frontend .
docker run -p 3000:80 \
  -e VITE_SUPABASE_URL=https://your-project.supabase.co \
  -e VITE_SUPABASE_ANON_KEY=your-anon-key \
  omniguard-frontend
```

### Option C: Render / Railway

1. Connect your GitHub repository
2. Set root directory to `omniguard/`
3. Build command: `npm install && npm run build`
4. Publish directory: `dist`
5. Set environment variables: `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`

### Option D: AWS / GCP / Azure

Deploy `omniguard/dist/` to S3+CloudFront, Cloud Storage, or Azure Static Web Apps. All backend infrastructure is Supabase.

---

## 10. Publishing the CLI to npm

When ready to publish `omniguard` CLI publicly:

```bash
cd cli/

# Update version in package.json
npm version patch   # or minor/major

# Ensure you're logged in to npm
npm login

# Publish
npm publish --access public

# Users can then install with:
# npm install -g omniguard
```

Until published, users use `npm link` for local development (see section 5).

---

## 11. Publishing the VS Code Extension to Marketplace

When ready to publish publicly:

```bash
cd vscode-extension/

# Install vsce
npm install -g @vscode/vsce

# Create a publisher account at https://marketplace.visualstudio.com/manage
# Then create a Personal Access Token in Azure DevOps

# Login with your publisher name
vsce login your-publisher-name

# Update publisher in package.json to match your account
# Then publish:
vsce publish

# Or publish a specific version:
npm version patch
vsce publish patch
```

Until published, distribute via `.vsix` file (already built at `vscode-extension/omniguard-1.0.0.vsix`).

---

## 12. API Keys (for external integrations)

Create API keys for the CLI and external tools from the dashboard:

1. Dashboard → **Settings → API Keys**
2. Click **Generate New Key**
3. Copy the key (shown once)
4. Use it as `OMNIGUARD_API_KEY` in CLI or VS Code extension

API keys use the format `og_live_...` and are hashed (SHA-256) before storage — raw keys are never stored.

---

## 13. Troubleshooting

### "No findings" when expecting results

- The scanner skips lines with `// test`, `example`, `placeholder`, `changeme` in the match
- Lines preceded by `// omniguard-suppress RULE-ID` are suppressed
- Check `OMNIGUARD_FAIL_ON` — if set to `critical`, `high` findings won't block

### "Connection failed" in CLI

```bash
omniguard doctor    # runs full diagnostics
omniguard status    # tests Supabase connection
```

Check:
- `OMNIGUARD_URL` ends with `/functions/v1` (no trailing slash)
- API key starts with `og_live_` or is a Supabase JWT
- Edge functions are deployed and not paused

### VS Code extension not scanning

- Check Output panel → OmniGuard channel for errors
- Run **OmniGuard: Configure** to re-enter credentials
- File must be saved for on-save scanning to trigger
- Run **OmniGuard: Scan Current File** manually to test

### AI not working

- Go to Settings → AI Configuration → Test Connection
- Verify the key is saved (look for ✓ configured badge)
- Check provider is set (not "None")
- Ollama: ensure `ollama serve` is running and `ollama_url` is reachable from the edge function

### Database errors

- Check that all migrations have been applied (001–009)
- Run the health check: `GET /functions/v1/api-v1-status`
- Check Supabase dashboard → Logs for edge function errors

---

## 14. Quick Reference

```bash
# Full local setup from scratch:
git clone <this-repo>
cd omniguard && npm install && npm run dev     # Dashboard at :5173

# CLI:
cd ../cli && npm link && omniguard doctor

# VS Code extension:
cd ../vscode-extension && npm install && npm run compile && npm run package
code --install-extension omniguard-1.0.0.vsix

# Run install script (does CLI + hooks automatically):
cd ../omniguard-main && bash install.sh
```
