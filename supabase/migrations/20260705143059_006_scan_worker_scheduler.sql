-- Enable pg_cron extension for scheduled jobs
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Scheduled job: poll scan-worker every 60 seconds to process queued scans
-- This invokes the scan-worker edge function via pg_net (Supabase's HTTP extension)
CREATE EXTENSION IF NOT EXISTS pg_net;

-- Create a function that calls the scan-worker /process endpoint
CREATE OR REPLACE FUNCTION trigger_scan_worker()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  pending_count integer;
  fn_url text;
  service_key text;
BEGIN
  -- Only trigger if there are pending scans
  SELECT COUNT(*) INTO pending_count
  FROM scan_queue
  WHERE status = 'pending';

  IF pending_count = 0 THEN
    RETURN;
  END IF;

  -- Get Supabase config
  SELECT current_setting('app.settings.supabase_url', true) INTO fn_url;
  SELECT current_setting('app.settings.service_role_key', true) INTO service_key;

  IF fn_url IS NULL OR service_key IS NULL THEN
    RETURN;
  END IF;

  -- Call scan-worker via pg_net (fire-and-forget)
  PERFORM net.http_get(
    url := fn_url || '/functions/v1/scan-worker/process',
    headers := jsonb_build_object(
      'Authorization', 'Bearer ' || service_key,
      'Content-Type', 'application/json'
    ),
    timeout_milliseconds := 25000
  );
END;
$$;

-- Schedule: check for pending scans every minute
-- (Only works if pg_cron and pg_net are available in your Supabase plan)
DO $$
BEGIN
  -- Try to create cron job, but don't fail if pg_cron is not available
  BEGIN
    PERFORM cron.schedule(
      'omniguard-scan-worker',
      '* * * * *',
      'SELECT trigger_scan_worker()'
    );
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pg_cron not available — scan worker must be triggered manually or via external scheduler';
  END;
END;
$$;

-- Fallback: auto-mark stale running scans as failed after 10 minutes
CREATE OR REPLACE FUNCTION cleanup_stale_scans()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  UPDATE scans
  SET
    status = 'failed',
    error_message = 'Scan timed out — worker did not complete within 10 minutes',
    completed_at = now()
  WHERE
    status = 'running'
    AND started_at < now() - interval '10 minutes';

  -- Also clean up stale pending scans older than 24h
  UPDATE scan_queue
  SET status = 'failed'
  WHERE
    status IN ('pending', 'processing')
    AND created_at < now() - interval '24 hours';
END;
$$;

-- Schedule stale scan cleanup every 5 minutes
DO $$
BEGIN
  BEGIN
    PERFORM cron.schedule(
      'omniguard-cleanup-stale-scans',
      '*/5 * * * *',
      'SELECT cleanup_stale_scans()'
    );
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pg_cron not available — stale scan cleanup must be triggered manually';
  END;
END;
$$;

COMMENT ON FUNCTION trigger_scan_worker() IS 'Called by pg_cron every minute to process queued security scans';
COMMENT ON FUNCTION cleanup_stale_scans() IS 'Marks stale running/pending scans as failed to prevent queue starvation';
