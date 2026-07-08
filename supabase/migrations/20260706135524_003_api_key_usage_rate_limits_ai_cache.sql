-- ── API Key Usage Tracking ───────────────────────────────────
CREATE TABLE IF NOT EXISTS api_key_usage (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_id          UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  endpoint        TEXT NOT NULL,
  method          TEXT NOT NULL DEFAULT 'GET',
  status_code     INTEGER NOT NULL DEFAULT 200,
  response_ms     INTEGER,
  ip_address      TEXT,
  user_agent      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE api_key_usage ENABLE ROW LEVEL SECURITY;
CREATE POLICY "usage_select" ON api_key_usage FOR SELECT TO authenticated USING (
  organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = auth.uid() AND role IN ('owner','admin') AND status = 'active')
);
CREATE POLICY "usage_insert" ON api_key_usage FOR INSERT TO service_role WITH CHECK (true);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_key ON api_key_usage(key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_key_usage_org ON api_key_usage(organization_id, created_at DESC);

-- ── Rate Limit Windows ────────────────────────────────────────
-- Atomic rate limit check using sliding window counter
CREATE TABLE IF NOT EXISTS rate_limit_counters (
  key             TEXT NOT NULL,         -- e.g. "key:<uuid>:scans:1h"
  window_start    TIMESTAMPTZ NOT NULL,
  count           INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key, window_start)
);
ALTER TABLE rate_limit_counters ENABLE ROW LEVEL SECURITY;
CREATE POLICY "rl_service" ON rate_limit_counters FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Atomic increment + check function
CREATE OR REPLACE FUNCTION check_rate_limit(
  p_key TEXT, p_window_seconds INTEGER, p_max_count INTEGER
) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE
  v_window TIMESTAMPTZ;
  v_count  INTEGER;
BEGIN
  v_window := date_trunc('second', NOW()) - (NOW() - date_trunc('second', NOW())) 
              + (EXTRACT(EPOCH FROM NOW())::BIGINT / p_window_seconds * p_window_seconds || ' seconds')::INTERVAL;
  v_window := to_timestamp(EXTRACT(EPOCH FROM NOW())::BIGINT / p_window_seconds * p_window_seconds);
  
  INSERT INTO rate_limit_counters(key, window_start, count) VALUES(p_key, v_window, 1)
  ON CONFLICT (key, window_start) DO UPDATE SET count = rate_limit_counters.count + 1
  RETURNING count INTO v_count;
  
  RETURN v_count <= p_max_count;
END;
$$;

-- Cleanup old windows automatically
CREATE OR REPLACE FUNCTION cleanup_rate_limits() RETURNS void LANGUAGE sql AS $$
  DELETE FROM rate_limit_counters WHERE window_start < NOW() - INTERVAL '2 hours';
$$;

-- ── AI Response Cache ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_cache (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cache_key       TEXT NOT NULL UNIQUE,   -- SHA-256(provider+model+prompt)
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  provider        TEXT NOT NULL,
  model           TEXT NOT NULL,
  prompt_hash     TEXT NOT NULL,
  response_text   TEXT NOT NULL,
  tokens_used     INTEGER NOT NULL DEFAULT 0,
  hit_count       INTEGER NOT NULL DEFAULT 0,
  expires_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '7 days'),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE ai_cache ENABLE ROW LEVEL SECURITY;
CREATE POLICY "cache_service" ON ai_cache FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE INDEX IF NOT EXISTS idx_ai_cache_key ON ai_cache(cache_key);
CREATE INDEX IF NOT EXISTS idx_ai_cache_expires ON ai_cache(expires_at);

-- ── AI Usage Metering ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_usage (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id         UUID REFERENCES scans(id) ON DELETE SET NULL,
  provider        TEXT NOT NULL,
  model           TEXT NOT NULL,
  tier            TEXT NOT NULL DEFAULT 'medium',  -- fast/medium/deep
  prompt_tokens   INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens    INTEGER NOT NULL DEFAULT 0,
  cache_hit       BOOLEAN NOT NULL DEFAULT false,
  latency_ms      INTEGER,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE ai_usage ENABLE ROW LEVEL SECURITY;
CREATE POLICY "ai_usage_select" ON ai_usage FOR SELECT TO authenticated USING (
  organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = auth.uid() AND status = 'active')
);
CREATE POLICY "ai_usage_service" ON ai_usage FOR INSERT TO service_role WITH CHECK (true);
CREATE INDEX IF NOT EXISTS idx_ai_usage_org ON ai_usage(organization_id, created_at DESC);

-- ── Rate limit config per org plan ───────────────────────────
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS rate_limits JSONB NOT NULL DEFAULT '{
  "scans_per_hour": 20,
  "scans_per_day": 100,
  "api_requests_per_minute": 60,
  "api_requests_per_hour": 1000
}';

-- ── Enterprise Integrations extended config ───────────────────
-- Already have integrations table, just ensuring columns exist
ALTER TABLE integrations ADD COLUMN IF NOT EXISTS last_sync_at TIMESTAMPTZ;
ALTER TABLE integrations ADD COLUMN IF NOT EXISTS error_message TEXT;
ALTER TABLE integrations ADD COLUMN IF NOT EXISTS webhook_secret TEXT;

-- ── Integration events log ────────────────────────────────────
CREATE TABLE IF NOT EXISTS integration_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  integration_id  UUID REFERENCES integrations(id) ON DELETE CASCADE,
  provider        TEXT NOT NULL,
  event_type      TEXT NOT NULL,
  payload         JSONB NOT NULL DEFAULT '{}',
  status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivered','failed')),
  error           TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE integration_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "ie_select" ON integration_events FOR SELECT TO authenticated USING (
  organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = auth.uid() AND status = 'active')
);
CREATE POLICY "ie_service" ON integration_events FOR ALL TO service_role USING (true) WITH CHECK (true);
