-- Helper functions used by RLS policies and application code

CREATE OR REPLACE FUNCTION is_org_member(org_id uuid)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM organization_members
    WHERE organization_id = org_id
      AND user_id = auth.uid()
      AND status = 'active'
  );
$$;

CREATE OR REPLACE FUNCTION is_org_admin(org_id uuid)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM organization_members
    WHERE organization_id = org_id
      AND user_id = auth.uid()
      AND role IN ('owner', 'admin')
      AND status = 'active'
  );
$$;

CREATE OR REPLACE FUNCTION generate_slug(name text)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT lower(regexp_replace(regexp_replace(trim(name), '[^a-zA-Z0-9\s-]', '', 'g'), '[\s-]+', '-', 'g'));
$$;

-- Fix claim_next_scan to return table (not INOUT params)
CREATE OR REPLACE FUNCTION claim_next_scan(p_worker_id text)
RETURNS TABLE(scan_id uuid, repository_id uuid, organization_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_queue_id uuid;
  v_scan_id uuid;
  v_repo_id uuid;
  v_org_id uuid;
BEGIN
  -- Atomically claim next pending scan
  SELECT q.id, q.scan_id, q.repository_id, q.organization_id
  INTO v_queue_id, v_scan_id, v_repo_id, v_org_id
  FROM scan_queue q
  WHERE q.status = 'pending'
  ORDER BY q.priority DESC, q.created_at ASC
  LIMIT 1
  FOR UPDATE SKIP LOCKED;

  IF v_queue_id IS NULL THEN
    RETURN;
  END IF;

  -- Mark as processing
  UPDATE scan_queue
  SET status = 'processing', worker_id = p_worker_id, claimed_at = now()
  WHERE id = v_queue_id;

  RETURN QUERY SELECT v_scan_id, v_repo_id, v_org_id;
END;
$$;

COMMENT ON FUNCTION is_org_member(uuid) IS 'Returns true if the current user is an active member of the given organization';
COMMENT ON FUNCTION is_org_admin(uuid) IS 'Returns true if the current user is an owner or admin of the given organization';
COMMENT ON FUNCTION generate_slug(text) IS 'Converts a name to a URL-safe slug';
COMMENT ON FUNCTION claim_next_scan(text) IS 'Atomically claims the next pending scan from the queue for a worker';
