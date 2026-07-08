-- Add metadata column to scans for webhook payload data
ALTER TABLE scans ADD COLUMN IF NOT EXISTS metadata jsonb DEFAULT '{}';

-- Add index for faster worker queue claims
CREATE INDEX IF NOT EXISTS idx_scan_queue_status_priority 
  ON scan_queue(status, priority DESC, created_at ASC) 
  WHERE status = 'pending';

-- Add index for findings by scanner type
CREATE INDEX IF NOT EXISTS idx_findings_scanner 
  ON findings(organization_id, scanner) 
  WHERE status = 'open';

-- Add index for notifications by user+read status
CREATE INDEX IF NOT EXISTS idx_notifications_user_unread 
  ON notifications(user_id, read, created_at DESC) 
  WHERE read = false;

-- Add index for audit_logs by org + time (dashboard activity)  
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_time 
  ON audit_logs(organization_id, created_at DESC);

-- Add index for repositories with active status
CREATE INDEX IF NOT EXISTS idx_repositories_org_active 
  ON repositories(organization_id, risk_score DESC) 
  WHERE deleted_at IS NULL;
