-- Add policy_chunks (RAG) and missing columns
CREATE TABLE IF NOT EXISTS policy_chunks (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  policy_id       UUID REFERENCES policies(id) ON DELETE CASCADE,
  chunk_index     INTEGER NOT NULL DEFAULT 0,
  content         TEXT NOT NULL,
  embedding       vector(1536),
  metadata        JSONB NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE policy_chunks ENABLE ROW LEVEL SECURITY;
CREATE POLICY "chunk_select" ON policy_chunks FOR SELECT TO authenticated USING (
  organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = auth.uid() AND status = 'active')
);
CREATE POLICY "chunk_insert" ON policy_chunks FOR INSERT TO authenticated WITH CHECK (
  organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = auth.uid() AND status = 'active')
);
CREATE POLICY "chunk_update" ON policy_chunks FOR UPDATE TO authenticated USING (
  organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = auth.uid() AND status = 'active')
);
CREATE POLICY "chunk_delete" ON policy_chunks FOR DELETE TO authenticated USING (
  organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin') AND status = 'active')
);

-- Vector similarity search for RAG policy retrieval
CREATE OR REPLACE FUNCTION match_policy_chunks(
  p_org_id UUID, query_embedding vector(1536), match_count INTEGER DEFAULT 5
)
RETURNS TABLE(id UUID, content TEXT, policy_id UUID, similarity FLOAT)
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  RETURN QUERY
  SELECT pc.id, pc.content, pc.policy_id,
    1 - (pc.embedding <=> query_embedding) AS similarity
  FROM policy_chunks pc
  WHERE pc.organization_id = p_org_id AND pc.embedding IS NOT NULL
  ORDER BY pc.embedding <=> query_embedding
  LIMIT match_count;
END;
$$;

-- Add missing columns to findings
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_provider TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_model TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS policy_violations TEXT[] NOT NULL DEFAULT '{}';

-- Add missing columns to scans
ALTER TABLE scans ADD COLUMN IF NOT EXISTS commit_message TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS commit_author TEXT;

-- Add ai_config to organizations (encrypted provider configs per org)
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS ai_config JSONB NOT NULL DEFAULT '{}';

-- Indexes
CREATE INDEX IF NOT EXISTS idx_policy_chunks_org ON policy_chunks(organization_id);
CREATE INDEX IF NOT EXISTS idx_findings_org_status ON findings(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(organization_id, severity);
CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(organization_id, created_at DESC);

-- Auto-enqueue scan trigger
CREATE OR REPLACE FUNCTION enqueue_scan()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  IF NEW.status = 'queued' THEN
    INSERT INTO scan_queue (scan_id, repository_id, organization_id)
    VALUES (NEW.id, NEW.repository_id, NEW.organization_id)
    ON CONFLICT DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trigger_enqueue_scan ON scans;
CREATE TRIGGER trigger_enqueue_scan AFTER INSERT ON scans FOR EACH ROW EXECUTE FUNCTION enqueue_scan();
