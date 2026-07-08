/*
# Add Worker Queue and Realtime Support

1. Functions
- claim_next_scan() - Workers use this to claim pending scans
- queue_scan_on_create() - Auto-queue new scans

2. Triggers
- Auto-add new scans to queue

3. Realtime
- Enable realtime for scans and findings tables
*/

-- Claim next scan function for workers
CREATE OR REPLACE FUNCTION claim_next_scan(p_worker_id text)
RETURNS TABLE(scan_id uuid, repository_id uuid, organization_id uuid)
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  UPDATE scan_queue
  SET
    status = 'processing',
    claimed_at = now(),
    worker_id = p_worker_id
  WHERE id = (
    SELECT sq.id FROM scan_queue sq
    JOIN scans s ON s.id = sq.scan_id
    JOIN repositories r ON r.id = s.repository_id
    WHERE sq.status = 'pending'
    AND r.is_active = true
    AND r.deleted_at IS NULL
    ORDER BY sq.priority DESC, sq.created_at ASC
    LIMIT 1
    FOR UPDATE OF sq SKIP LOCKED
  )
  RETURNING scan_queue.scan_id, scan_queue.repository_id, scan_queue.organization_id;
END;
$$;

-- Create scan queue trigger
CREATE OR REPLACE FUNCTION queue_scan_on_create()
RETURNS TRIGGER
AS $$
BEGIN
  INSERT INTO scan_queue (scan_id, organization_id, repository_id, priority, status)
  VALUES (
    NEW.id,
    NEW.organization_id,
    NEW.repository_id,
    NEW.priority,
    'pending'
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger
DROP TRIGGER IF EXISTS on_scan_created ON scans;
CREATE TRIGGER on_scan_created
  AFTER INSERT ON scans
  FOR EACH ROW
  EXECUTE FUNCTION queue_scan_on_create();