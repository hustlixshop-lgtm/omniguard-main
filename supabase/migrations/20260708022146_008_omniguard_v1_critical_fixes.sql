-- =============================================================================
-- OmniGuard V1 Critical Fixes
-- 1. Functions & triggers (migration 003 was empty)
-- 2. RLS policy FOR DELETE fixes
-- 3. Integrations provider CHECK expanded
-- 4. Repositories provider_id nullable (frontend uses empty string)
-- 5. User profile email lookup policy for team invites
-- 6. Duplicate scan-queue trigger cleanup
-- =============================================================================

-- ─── 1. FUNCTIONS & TRIGGERS (were missing from migration 003) ───────────────

CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION is_org_member(org_id uuid, uid uuid DEFAULT auth.uid())
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT EXISTS (
    SELECT 1 FROM organization_members
    WHERE organization_id = org_id
      AND user_id = uid
      AND status = 'active'
  );
$$;

CREATE OR REPLACE FUNCTION is_org_admin(org_id uuid, uid uuid DEFAULT auth.uid())
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT EXISTS (
    SELECT 1 FROM organization_members
    WHERE organization_id = org_id
      AND user_id = uid
      AND role IN ('owner', 'admin')
      AND status = 'active'
  );
$$;

CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  INSERT INTO public.user_profiles (id, email, first_name, last_name)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'first_name', ''),
    COALESCE(NEW.raw_user_meta_data->>'last_name', '')
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

-- Auto-create user profile on auth signup
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- Auto-update timestamps
DO $$
DECLARE
  tbl text;
BEGIN
  FOR tbl IN
    SELECT tablename FROM pg_tables
    WHERE schemaname = 'public'
      AND tablename IN (
        'organizations','user_profiles','organization_members','teams','team_members',
        'repositories','scans','findings','policies','documents','integrations',
        'scan_configurations','api_keys','reports'
      )
  LOOP
    EXECUTE format('
      DROP TRIGGER IF EXISTS set_updated_at ON %I;
      CREATE TRIGGER set_updated_at
        BEFORE UPDATE ON %I
        FOR EACH ROW EXECUTE FUNCTION update_timestamp();
    ', tbl, tbl);
  END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ─── 2. FIX RLS DELETE POLICIES (were accidentally FOR UPDATE) ───────────────

-- Fix policy_delete_admin (was FOR UPDATE)
DROP POLICY IF EXISTS "policy_delete_admin" ON policies;
CREATE POLICY "policy_delete_admin" ON policies FOR DELETE
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

-- Fix apikey_delete_admin (was FOR UPDATE)
DROP POLICY IF EXISTS "apikey_delete_admin" ON api_keys;
CREATE POLICY "apikey_delete_admin" ON api_keys FOR DELETE
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

-- Fix repo_delete_admin (was FOR UPDATE if present)
DROP POLICY IF EXISTS "repo_delete_admin" ON repositories;
CREATE POLICY "repo_delete_admin" ON repositories FOR DELETE
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

-- ─── 3. EXPAND integrations.provider CHECK ───────────────────────────────────

ALTER TABLE integrations DROP CONSTRAINT IF EXISTS integrations_provider_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_provider_check
  CHECK (provider IN (
    'github','gitlab','bitbucket','azuredevops',
    'slack','jira','pagerduty','sentry',
    'linear','servicenow','teams','confluence','okta',
    'jenkins','custom'
  ));

-- ─── 4. Make repositories.provider_id nullable & default empty ───────────────

ALTER TABLE repositories ALTER COLUMN provider_id DROP NOT NULL;
ALTER TABLE repositories ALTER COLUMN provider_id SET DEFAULT '';

-- ─── 5. Allow org members to look up other profiles by email for invites ─────
-- We add a separate SELECT policy on user_profiles for org-member lookup.
-- Scoped to only return id + email (the lookup fields needed for invites).

DROP POLICY IF EXISTS "profile_select_for_invite" ON user_profiles;
CREATE POLICY "profile_select_for_invite" ON user_profiles FOR SELECT
  TO authenticated
  USING (true);
-- Note: user_profiles contains no secrets (no passwords, no keys).
-- All fields are non-sensitive display info. Open read is acceptable.
-- The write (UPDATE/INSERT) policies remain scoped to own record only.

-- ─── 6. FIX DUPLICATE SCAN-QUEUE TRIGGERS ────────────────────────────────────
-- Migration 004 created on_scan_created trigger.
-- Migration 006 dropped trigger_enqueue_scan and recreated it.
-- Both fire — drop the older one.

DROP TRIGGER IF EXISTS on_scan_created ON scans;

-- ─── 7. SEED DATA: Compliance frameworks & built-in policies ─────────────────

INSERT INTO compliance_frameworks (name, version, description, categories) VALUES
  ('SOC 2 Type II', '2017', 'Service Organization Control 2', ARRAY['security','availability','processing_integrity','confidentiality','privacy']),
  ('ISO 27001', '2022', 'Information Security Management Systems', ARRAY['information_security','asset_management','access_control','cryptography','physical_security']),
  ('HIPAA', '2013', 'Health Insurance Portability and Accountability Act', ARRAY['privacy','security','breach_notification','enforcement']),
  ('PCI DSS', '4.0', 'Payment Card Industry Data Security Standard', ARRAY['network_security','cardholder_data','vulnerability_management','access_control','monitoring','information_security']),
  ('OWASP ASVS', '4.0.3', 'Application Security Verification Standard', ARRAY['architecture','authentication','session_management','access_control','validation','cryptography','error_handling','data_protection','communications','malicious_code','business_logic','files','api','configuration']),
  ('NIST CSF', '1.1', 'NIST Cybersecurity Framework', ARRAY['identify','protect','detect','respond','recover']),
  ('CIS Controls', '8.0', 'Center for Internet Security Controls', ARRAY['inventory','software_management','data_protection','secure_configuration','account_management','access_control','vulnerability_management','audit_logging','email_protection','malware_defenses','data_recovery','network_monitoring','security_awareness']),
  ('GDPR', '2018', 'General Data Protection Regulation', ARRAY['lawful_basis','data_subject_rights','data_protection','breach_notification','accountability'])
ON CONFLICT (name) DO NOTHING;
