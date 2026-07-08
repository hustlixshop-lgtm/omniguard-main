/*
# OmniGuard Security Platform - RLS Policies and Functions

1. Row Level Security Policies
- Organization access control based on membership
- Repository access based on org membership
- Scan/finding access based on org membership
- Role-based permissions (owner, admin, engineer, developer, auditor)

2. Helper Functions
- update_timestamp() - Auto-update timestamps
- handle_new_user() - Create user profile on auth
- is_org_member() - Check org membership
- is_org_admin() - Check admin role

3. Triggers
- Auto-update timestamps on table updates
- Auto-create user profile on auth user creation
*/

-- =============================================================================
-- ROW LEVEL SECURITY POLICIES
-- =============================================================================

-- Organization policies
DROP POLICY IF EXISTS "org_select_member" ON organizations;
CREATE POLICY "org_select_member" ON organizations FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = organizations.id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "org_insert_open" ON organizations;
CREATE POLICY "org_insert_open" ON organizations FOR INSERT
  TO authenticated
  WITH CHECK (true);

DROP POLICY IF EXISTS "org_update_owner" ON organizations;
CREATE POLICY "org_update_owner" ON organizations FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = organizations.id
      AND user_id = auth.uid()
      AND role = 'owner'
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "org_delete_owner" ON organizations;
CREATE POLICY "org_delete_owner" ON organizations FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = organizations.id
      AND user_id = auth.uid()
      AND role = 'owner'
      AND status = 'active'
    )
  );

-- User profiles policies
DROP POLICY IF EXISTS "profile_select_own" ON user_profiles;
CREATE POLICY "profile_select_own" ON user_profiles FOR SELECT
  TO authenticated
  USING (auth.uid() = id);

DROP POLICY IF EXISTS "profile_insert_own" ON user_profiles;
CREATE POLICY "profile_insert_own" ON user_profiles FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = id);

DROP POLICY IF EXISTS "profile_update_own" ON user_profiles;
CREATE POLICY "profile_update_own" ON user_profiles FOR UPDATE
  TO authenticated
  USING (auth.uid() = id);

-- Organization members policies
DROP POLICY IF EXISTS "member_select_org_member" ON organization_members;
CREATE POLICY "member_select_org_member" ON organization_members FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members om
      WHERE om.organization_id = organization_members.organization_id
      AND om.user_id = auth.uid()
      AND om.status = 'active'
    )
  );

DROP POLICY IF EXISTS "member_insert_admin" ON organization_members;
CREATE POLICY "member_insert_admin" ON organization_members FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = organization_members.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "member_update_admin" ON organization_members;
CREATE POLICY "member_update_admin" ON organization_members FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = organization_members.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "member_delete_admin" ON organization_members;
CREATE POLICY "member_delete_admin" ON organization_members FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = organization_members.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

-- Teams policies
DROP POLICY IF EXISTS "team_select_member" ON teams;
CREATE POLICY "team_select_member" ON teams FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = teams.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "team_insert_admin" ON teams;
CREATE POLICY "team_insert_admin" ON teams FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = teams.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "team_update_admin" ON teams;
CREATE POLICY "team_update_admin" ON teams FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = teams.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "team_delete_admin" ON teams;
CREATE POLICY "team_delete_admin" ON teams FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = teams.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

-- Team members policies
DROP POLICY IF EXISTS "team_member_select_member" ON team_members;
CREATE POLICY "team_member_select_member" ON team_members FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM teams
      JOIN organization_members om ON om.organization_id = teams.organization_id
      WHERE teams.id = team_members.team_id
      AND om.user_id = auth.uid()
      AND om.status = 'active'
    )
  );

DROP POLICY IF EXISTS "team_member_insert_admin" ON team_members;
CREATE POLICY "team_member_insert_admin" ON team_members FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM teams
      JOIN organization_members om ON om.organization_id = teams.organization_id
      WHERE teams.id = team_members.team_id
      AND om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
      AND om.status = 'active'
    )
  );

DROP POLICY IF EXISTS "team_member_delete_admin" ON team_members;
CREATE POLICY "team_member_delete_admin" ON team_members FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM teams
      JOIN organization_members om ON om.organization_id = teams.organization_id
      WHERE teams.id = team_members.team_id
      AND om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
      AND om.status = 'active'
    )
  );

-- Repositories policies
DROP POLICY IF EXISTS "repo_select_member" ON repositories;
CREATE POLICY "repo_select_member" ON repositories FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = repositories.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    ) AND deleted_at IS NULL
  );

DROP POLICY IF EXISTS "repo_insert_member" ON repositories;
CREATE POLICY "repo_insert_member" ON repositories FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = repositories.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "repo_update_engineer" ON repositories;
CREATE POLICY "repo_update_engineer" ON repositories FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = repositories.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin', 'engineer')
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "repo_delete_admin" ON repositories;
CREATE POLICY "repo_delete_admin" ON repositories FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = repositories.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

-- Scans policies
DROP POLICY IF EXISTS "scan_select_member" ON scans;
CREATE POLICY "scan_select_member" ON scans FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = scans.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "scan_insert_member" ON scans;
CREATE POLICY "scan_insert_member" ON scans FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = scans.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "scan_update_engineer" ON scans;
CREATE POLICY "scan_update_engineer" ON scans FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = scans.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin', 'engineer')
      AND status = 'active'
    )
  );

-- Findings policies
DROP POLICY IF EXISTS "finding_select_member" ON findings;
CREATE POLICY "finding_select_member" ON findings FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = findings.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "finding_insert_system" ON findings;
CREATE POLICY "finding_insert_system" ON findings FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = findings.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "finding_update_member" ON findings;
CREATE POLICY "finding_update_member" ON findings FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = findings.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

-- Scan artifacts policies
DROP POLICY IF EXISTS "artifact_select_member" ON scan_artifacts;
CREATE POLICY "artifact_select_member" ON scan_artifacts FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = scan_artifacts.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "artifact_insert_member" ON scan_artifacts;
CREATE POLICY "artifact_insert_member" ON scan_artifacts FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = scan_artifacts.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

-- Scan queue policies
DROP POLICY IF EXISTS "queue_select_member" ON scan_queue;
CREATE POLICY "queue_select_member" ON scan_queue FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = scan_queue.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "queue_insert_member" ON scan_queue;
CREATE POLICY "queue_insert_member" ON scan_queue FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = scan_queue.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "queue_update_engineer" ON scan_queue;
CREATE POLICY "queue_update_engineer" ON scan_queue FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = scan_queue.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin', 'engineer')
      AND status = 'active'
    )
  );

-- Worker heartbeats policies (open for workers)
DROP POLICY IF EXISTS "worker_select_all" ON worker_heartbeats;
CREATE POLICY "worker_select_all" ON worker_heartbeats FOR SELECT
  TO authenticated
  USING (true);

DROP POLICY IF EXISTS "worker_insert_all" ON worker_heartbeats;
CREATE POLICY "worker_insert_all" ON worker_heartbeats FOR INSERT
  TO authenticated
  WITH CHECK (true);

DROP POLICY IF EXISTS "worker_update_all" ON worker_heartbeats;
CREATE POLICY "worker_update_all" ON worker_heartbeats FOR UPDATE
  TO authenticated
  USING (true);

-- Policies table policies
DROP POLICY IF EXISTS "policy_select_member" ON policies;
CREATE POLICY "policy_select_member" ON policies FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = policies.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    ) AND deleted_at IS NULL
  );

DROP POLICY IF EXISTS "policy_insert_engineer" ON policies;
CREATE POLICY "policy_insert_engineer" ON policies FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = policies.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin', 'engineer')
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "policy_update_engineer" ON policies;
CREATE POLICY "policy_update_engineer" ON policies FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = policies.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin', 'engineer')
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "policy_delete_admin" ON policies;
CREATE POLICY "policy_delete_admin" ON policies FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = policies.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

-- Policy evaluations policies
DROP POLICY IF EXISTS "policy_eval_select_member" ON policy_evaluations;
CREATE POLICY "policy_eval_select_member" ON policy_evaluations FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = policy_evaluations.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "policy_eval_insert_member" ON policy_evaluations;
CREATE POLICY "policy_eval_insert_member" ON policy_evaluations FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = policy_evaluations.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "policy_eval_update_engineer" ON policy_evaluations;
CREATE POLICY "policy_eval_update_engineer" ON policy_evaluations FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = policy_evaluations.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin', 'engineer')
      AND status = 'active'
    )
  );

-- Compliance frameworks (read-only for authenticated users)
DROP POLICY IF EXISTS "framework_select_all" ON compliance_frameworks;
CREATE POLICY "framework_select_all" ON compliance_frameworks FOR SELECT
  TO authenticated
  USING (true);

-- Compliance mappings
DROP POLICY IF EXISTS "mapping_select_member" ON compliance_mappings;
CREATE POLICY "mapping_select_member" ON compliance_mappings FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM findings f
      JOIN organization_members om ON om.organization_id = f.organization_id
      WHERE f.id = compliance_mappings.finding_id
      AND om.user_id = auth.uid()
      AND om.status = 'active'
    )
  );

DROP POLICY IF EXISTS "mapping_insert_member" ON compliance_mappings;
CREATE POLICY "mapping_insert_member" ON compliance_mappings FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM findings f
      JOIN organization_members om ON om.organization_id = f.organization_id
      WHERE f.id = compliance_mappings.finding_id
      AND om.user_id = auth.uid()
      AND om.status = 'active'
    )
  );

-- Documents policies
DROP POLICY IF EXISTS "doc_select_member" ON documents;
CREATE POLICY "doc_select_member" ON documents FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = documents.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    ) AND deleted_at IS NULL
  );

DROP POLICY IF EXISTS "doc_insert_member" ON documents;
CREATE POLICY "doc_insert_member" ON documents FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = documents.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "doc_update_member" ON documents;
CREATE POLICY "doc_update_member" ON documents FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = documents.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

-- Document chunks policies
DROP POLICY IF EXISTS "chunk_select_member" ON document_chunks;
CREATE POLICY "chunk_select_member" ON document_chunks FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM documents d
      JOIN organization_members om ON om.organization_id = d.organization_id
      WHERE d.id = document_chunks.document_id
      AND om.user_id = auth.uid()
      AND om.status = 'active'
    )
  );

DROP POLICY IF EXISTS "chunk_insert_member" ON document_chunks;
CREATE POLICY "chunk_insert_member" ON document_chunks FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM documents d
      JOIN organization_members om ON om.organization_id = d.organization_id
      WHERE d.id = document_chunks.document_id
      AND om.user_id = auth.uid()
      AND om.status = 'active'
    )
  );

-- AI analyses policies
DROP POLICY IF EXISTS "ai_select_member" ON ai_analyses;
CREATE POLICY "ai_select_member" ON ai_analyses FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = ai_analyses.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "ai_insert_member" ON ai_analyses;
CREATE POLICY "ai_insert_member" ON ai_analyses FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = ai_analyses.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

-- API keys policies
DROP POLICY IF EXISTS "apikey_select_admin" ON api_keys;
CREATE POLICY "apikey_select_admin" ON api_keys FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = api_keys.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "apikey_insert_admin" ON api_keys;
CREATE POLICY "apikey_insert_admin" ON api_keys FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = api_keys.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "apikey_delete_admin" ON api_keys;
CREATE POLICY "apikey_delete_admin" ON api_keys FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = api_keys.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

-- Integrations policies
DROP POLICY IF EXISTS "integration_select_admin" ON integrations;
CREATE POLICY "integration_select_admin" ON integrations FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = integrations.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin', 'engineer')
      AND status = 'active'
    ) AND deleted_at IS NULL
  );

DROP POLICY IF EXISTS "integration_insert_admin" ON integrations;
CREATE POLICY "integration_insert_admin" ON integrations FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = integrations.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "integration_update_admin" ON integrations;
CREATE POLICY "integration_update_admin" ON integrations FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = integrations.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
    )
  );

-- Audit logs policies
DROP POLICY IF EXISTS "audit_select_admin" ON audit_logs;
CREATE POLICY "audit_select_admin" ON audit_logs FOR SELECT
  TO authenticated
  USING (
    organization_id IS NULL OR
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = audit_logs.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin', 'auditor')
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "audit_insert_system" ON audit_logs;
CREATE POLICY "audit_insert_system" ON audit_logs FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- Notifications policies
DROP POLICY IF EXISTS "notif_select_own" ON notifications;
CREATE POLICY "notif_select_own" ON notifications FOR SELECT
  TO authenticated
  USING (user_id = auth.uid());

DROP POLICY IF EXISTS "notif_insert_system" ON notifications;
CREATE POLICY "notif_insert_system" ON notifications FOR INSERT
  TO authenticated
  WITH CHECK (true);

DROP POLICY IF EXISTS "notif_update_own" ON notifications;
CREATE POLICY "notif_update_own" ON notifications FOR UPDATE
  TO authenticated
  USING (user_id = auth.uid());

-- Reports policies
DROP POLICY IF EXISTS "report_select_member" ON reports;
CREATE POLICY "report_select_member" ON reports FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = reports.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "report_insert_member" ON reports;
CREATE POLICY "report_insert_member" ON reports FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = reports.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

-- Scan configurations policies
DROP POLICY IF EXISTS "config_select_member" ON scan_configurations;
CREATE POLICY "config_select_member" ON scan_configurations FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = scan_configurations.organization_id
      AND user_id = auth.uid()
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "config_insert_engineer" ON scan_configurations;
CREATE POLICY "config_insert_engineer" ON scan_configurations FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = scan_configurations.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin', 'engineer')
      AND status = 'active'
    )
  );

DROP POLICY IF EXISTS "config_update_engineer" ON scan_configurations;
CREATE POLICY "config_update_engineer" ON scan_configurations FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM organization_members
      WHERE organization_id = scan_configurations.organization_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin', 'engineer')
      AND status = 'active'
    )
  );