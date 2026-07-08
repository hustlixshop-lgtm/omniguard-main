/*
# OmniGuard Security Platform - Complete Schema

1. Core Tables
- `organizations` - Multi-tenant organization entities
- `organization_members` - User-organization membership with roles
- `user_profiles` - Extended user profile data
- `teams` - Team groupings within organizations
- `team_members` - User-team membership

2. Repository & Scanning Tables
- `repositories` - Connected code repositories
- `scans` - Security scan records with status tracking
- `findings` - Security findings/vulnerabilities
- `scan_artifacts` - Files and data produced by scans

3. Policy & Compliance Tables
- `policies` - Security policies and rules
- `policy_evaluations` - Policy evaluation results
- `compliance_mappings` - Mapping findings to compliance controls
- `compliance_frameworks` - SOC2, ISO27001, HIPAA, PCI DSS, etc.

4. Document Intelligence Tables
- `documents` - Uploaded policy/security documents
- `document_chunks` - Vector-searchable document chunks

5. AI & Configuration Tables
- `ai_analyses` - AI analysis records
- `scan_configurations` - Scanner configurations
- `api_keys` - API key management
- `integrations` - External service integrations

6. Operations Tables
- `audit_logs` - Comprehensive audit trail
- `notifications` - User notifications
- `reports` - Generated reports
- `worker_heartbeats` - Worker health monitoring
- `scan_queue` - Priority queue for scans

7. Security Features
- RLS enabled on all tables
- Multi-tenant isolation
- Role-based access control (owner/admin/engineer/developer/auditor)
- Audit logging for all operations
*/

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "vector";

-- =============================================================================
-- ORGANIZATION & USER MANAGEMENT
-- =============================================================================

CREATE TABLE IF NOT EXISTS organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  slug text UNIQUE NOT NULL,
  logo_url text,
  plan text NOT NULL DEFAULT 'free',
  settings jsonb DEFAULT '{}',
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  deleted_at timestamptz
);

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS user_profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email text NOT NULL,
  first_name text,
  last_name text,
  avatar_url text,
  preferences jsonb DEFAULT '{}',
  last_login_at timestamptz,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS organization_members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'developer' CHECK (role IN ('owner', 'admin', 'engineer', 'developer', 'auditor')),
  invited_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  invited_at timestamptz,
  joined_at timestamptz,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pending', 'suspended')),
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  UNIQUE(organization_id, user_id)
);

ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS teams (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text,
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE teams ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS team_members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'member',
  created_at timestamptz DEFAULT now(),
  UNIQUE(team_id, user_id)
);

ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- REPOSITORIES & SCANNING
-- =============================================================================

CREATE TABLE IF NOT EXISTS repositories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  team_id uuid REFERENCES teams(id) ON DELETE SET NULL,
  provider text NOT NULL CHECK (provider IN ('github', 'gitlab', 'bitbucket', 'azuredevops', 'local')),
  provider_id text NOT NULL,
  owner text NOT NULL,
  name text NOT NULL,
  full_name text NOT NULL,
  description text,
  default_branch text NOT NULL DEFAULT 'main',
  visibility text NOT NULL DEFAULT 'private' CHECK (visibility IN ('public', 'private', 'internal')),
  language text,
  languages jsonb DEFAULT '{}',
  size integer DEFAULT 0,
  risk_score real DEFAULT 0,
  last_scan_at timestamptz,
  last_sync_at timestamptz,
  sync_status text DEFAULT 'pending',
  webhook_id text,
  webhook_secret text,
  is_active boolean DEFAULT true,
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  deleted_at timestamptz,
  UNIQUE(provider, provider_id)
);

ALTER TABLE repositories ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  repository_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
  trigger text NOT NULL CHECK (trigger IN ('manual', 'webhook', 'api', 'scheduled', 'pre-commit', 'pre-push', 'pr', 'ide')),
  scan_type text NOT NULL DEFAULT 'full' CHECK (scan_type IN ('full', 'quick', 'secrets', 'dependencies', 'sast', 'iac', 'container', 'policy')),
  branch text,
  commit_sha text,
  commit_message text,
  commit_author text,
  priority integer DEFAULT 5,
  started_at timestamptz,
  completed_at timestamptz,
  duration_seconds integer,
  summary jsonb DEFAULT '{}',
  error_message text,
  worker_id text,
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
  repository_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  scanner text NOT NULL CHECK (scanner IN ('secret', 'dependency', 'sast', 'iac', 'container', 'license', 'policy', 'compliance', 'ai')),
  category text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  cvss_score real,
  cvss_vector text,
  title text NOT NULL,
  description text,
  evidence text,
  file_path text,
  line_start integer,
  line_end integer,
  column_start integer,
  column_end integer,
  rule_id text,
  rule_name text,
  owasp text[] DEFAULT '{}',
  cwe text[] DEFAULT '{}',
  mitre text[] DEFAULT '{}',
  package_name text,
  package_version text,
  package_fixed_version text,
  cve_id text,
  remediation text,
  ai_summary text,
  ai_remediation text,
  ai_confidence real,
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'assigned', 'in_progress', 'resolved', 'suppressed', 'false_positive', 'wont_fix')),
  assigned_to uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  assigned_at timestamptz,
  resolved_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  resolved_at timestamptz,
  resolution_note text,
  suppressed_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  suppressed_at timestamptz,
  suppress_reason text,
  suppress_expiry timestamptz,
  risk_score real DEFAULT 0,
  confidence_score real DEFAULT 0.8,
  false_positive_likelihood real DEFAULT 0,
  metadata jsonb DEFAULT '{}',
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS scan_artifacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  artifact_type text NOT NULL CHECK (artifact_type IN ('sbom', 'sarif', 'dependency_tree', 'secret_report', 'iac_report', 'container_report', 'policy_report')),
  filename text NOT NULL,
  storage_path text NOT NULL,
  size_bytes integer,
  mime_type text,
  metadata jsonb DEFAULT '{}',
  created_at timestamptz DEFAULT now()
);

ALTER TABLE scan_artifacts ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- SCAN QUEUE & WORKER MANAGEMENT
-- =============================================================================

CREATE TABLE IF NOT EXISTS scan_queue (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  priority integer NOT NULL DEFAULT 5,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
  worker_id text,
  claimed_at timestamptz,
  completed_at timestamptz,
  retry_count integer DEFAULT 0,
  max_retries integer DEFAULT 3,
  error_message text,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE scan_queue ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS worker_heartbeats (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  worker_id text NOT NULL UNIQUE,
  worker_type text NOT NULL DEFAULT 'scanner',
  status text NOT NULL DEFAULT 'idle' CHECK (status IN ('idle', 'busy', 'error', 'offline')),
  current_scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
  last_heartbeat timestamptz DEFAULT now(),
  started_at timestamptz DEFAULT now(),
  scans_completed integer DEFAULT 0,
  errors_count integer DEFAULT 0,
  metadata jsonb DEFAULT '{}'
);

ALTER TABLE worker_heartbeats ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- POLICIES & COMPLIANCE
-- =============================================================================

CREATE TABLE IF NOT EXISTS policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  name text NOT NULL,
  description text,
  policy_type text NOT NULL CHECK (policy_type IN ('yaml', 'json', 'rego', 'builtin')),
  category text NOT NULL DEFAULT 'security' CHECK (category IN ('security', 'compliance', 'operational', 'governance')),
  content text NOT NULL,
  severity text NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  enabled boolean DEFAULT true,
  enforcement_mode text NOT NULL DEFAULT 'block' CHECK (enforcement_mode IN ('block', 'warn', 'audit')),
  tags text[] DEFAULT '{}',
  compliance_mappings jsonb DEFAULT '{}',
  version integer DEFAULT 1,
  approved_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  approved_at timestamptz,
  owner_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  deleted_at timestamptz
);

ALTER TABLE policies ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS policy_evaluations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id uuid NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
  scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  repository_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  result text NOT NULL CHECK (result IN ('pass', 'fail', 'error', 'skip')),
  severity text NOT NULL,
  message text,
  resource_type text,
  resource_id text,
  resource_name text,
  details jsonb DEFAULT '{}',
  bypass_used boolean DEFAULT false,
  bypass_reason text,
  bypass_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  bypass_at timestamptz,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE policy_evaluations ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS compliance_frameworks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  version text NOT NULL,
  description text,
  controls jsonb NOT NULL DEFAULT '[]',
  categories text[] DEFAULT '{}',
  enabled boolean DEFAULT true,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE compliance_frameworks ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS compliance_mappings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  framework_id uuid NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
  control_id text NOT NULL,
  control_name text,
  relevance_score real DEFAULT 1.0,
  auto_mapped boolean DEFAULT true,
  verified_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  verified_at timestamptz,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE compliance_mappings ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- DOCUMENT INTELLIGENCE
-- =============================================================================

CREATE TABLE IF NOT EXISTS documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  uploaded_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  title text NOT NULL,
  filename text NOT NULL,
  mime_type text NOT NULL,
  size_bytes integer,
  storage_path text NOT NULL,
  document_type text CHECK (document_type IN ('policy', 'procedure', 'standard', 'audit', 'report', 'other')),
  category text,
  tags text[] DEFAULT '{}',
  version integer DEFAULT 1,
  status text DEFAULT 'active' CHECK (status IN ('active', 'archived', 'deleted')),
  embedding_status text DEFAULT 'pending' CHECK (embedding_status IN ('pending', 'processing', 'completed', 'failed')),
  chunk_count integer DEFAULT 0,
  metadata jsonb DEFAULT '{}',
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  deleted_at timestamptz
);

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS document_chunks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  chunk_index integer NOT NULL,
  content text NOT NULL,
  embedding vector(1536),
  token_count integer,
  start_char integer,
  end_char integer,
  metadata jsonb DEFAULT '{}',
  created_at timestamptz DEFAULT now(),
  UNIQUE(document_id, chunk_index)
);

ALTER TABLE document_chunks ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- AI ANALYSES
-- =============================================================================

CREATE TABLE IF NOT EXISTS ai_analyses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id uuid REFERENCES scans(id) ON DELETE SET NULL,
  finding_id uuid REFERENCES findings(id) ON DELETE SET NULL,
  repository_id uuid REFERENCES repositories(id) ON DELETE SET NULL,
  analysis_type text NOT NULL CHECK (analysis_type IN ('classify', 'explain', 'remediate', 'summarize', 'policy_check', 'compliance_check', 'architecture_review')),
  model_used text NOT NULL,
  input_tokens integer,
  output_tokens integer,
  cost_cents real DEFAULT 0,
  input_context text,
  output_result jsonb NOT NULL DEFAULT '{}',
  confidence_score real,
  processing_time_ms integer,
  status text DEFAULT 'completed' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
  error_message text,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE ai_analyses ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- API KEYS & INTEGRATIONS
-- =============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  name text NOT NULL,
  key_hash text NOT NULL,
  key_prefix text NOT NULL,
  scopes text[] NOT NULL DEFAULT '{}',
  expires_at timestamptz,
  last_used_at timestamptz,
  is_active boolean DEFAULT true,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS integrations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  provider text NOT NULL CHECK (provider IN ('github', 'gitlab', 'bitbucket', 'azuredevops', 'slack', 'jira', 'pagerduty', 'sentry', 'custom')),
  name text NOT NULL,
  config jsonb DEFAULT '{}',
  secrets_ref text,
  status text DEFAULT 'active' CHECK (status IN ('active', 'error', 'disabled')),
  error_message text,
  last_sync_at timestamptz,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  deleted_at timestamptz
);

ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- AUDIT LOGS & NOTIFICATIONS
-- =============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid REFERENCES organizations(id) ON DELETE SET NULL,
  user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  request_id text,
  session_id text,
  ip_address text,
  user_agent text,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id text,
  resource_name text,
  old_values jsonb,
  new_values jsonb,
  metadata jsonb DEFAULT '{}',
  created_at timestamptz DEFAULT now()
);

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  type text NOT NULL,
  title text NOT NULL,
  body text,
  data jsonb DEFAULT '{}',
  read boolean DEFAULT false,
  read_at timestamptz,
  action_url text,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- REPORTS
-- =============================================================================

CREATE TABLE IF NOT EXISTS reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  report_type text NOT NULL CHECK (report_type IN ('security_summary', 'compliance', 'audit', 'vulnerability', 'policy', 'executive', 'custom')),
  title text NOT NULL,
  description text,
  format text DEFAULT 'pdf' CHECK (format IN ('pdf', 'csv', 'json', 'html')),
  status text DEFAULT 'pending' CHECK (status IN ('pending', 'generating', 'completed', 'failed')),
  storage_path text,
  parameters jsonb DEFAULT '{}',
  generated_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE reports ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- SCAN CONFIGURATIONS
-- =============================================================================

CREATE TABLE IF NOT EXISTS scan_configurations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  repository_id uuid REFERENCES repositories(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text,
  scanners text[] NOT NULL DEFAULT '{}',
  excludes text[] DEFAULT '{}',
  includes text[] DEFAULT '{}',
  fail_on text DEFAULT 'high' CHECK (fail_on IN ('critical', 'high', 'medium', 'low', 'none')),
  schedule text,
  enabled boolean DEFAULT true,
  settings jsonb DEFAULT '{}',
  created_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE scan_configurations ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- INDEXES FOR PERFORMANCE
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);
CREATE INDEX IF NOT EXISTS idx_org_members_org ON organization_members(organization_id);
CREATE INDEX IF NOT EXISTS idx_repositories_org ON repositories(organization_id);
CREATE INDEX IF NOT EXISTS idx_repositories_provider ON repositories(provider, provider_id);
CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repository_id);
CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(organization_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(organization_id);
CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repository_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_scanner ON findings(scanner);
CREATE INDEX IF NOT EXISTS idx_scan_queue_status ON scan_queue(status, priority);
CREATE INDEX IF NOT EXISTS idx_document_chunks_embedding ON document_chunks USING ivfflat (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS idx_policies_org ON policies(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_org ON audit_logs(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);