/*
# AI Keys Vault Reference

## Summary
Replaces storing raw AI API keys in organizations.ai_config with a secure pattern:
- Adds `ai_keys_vault_id` column to organizations (stores pgsodium vault secret ID)
- The ai_config column retains only NON-SECRET provider settings (provider name, model prefs, flags)
- Actual API keys are stored in Supabase Vault via the secrets-proxy edge function
- Adds user_secrets table for per-user encrypted secret storage (CLI tokens etc)

## Changes
1. organizations: add ai_keys_vault_id (uuid, nullable) - references vault.secrets
2. New table: user_secrets - per-user key/value secret store via vault
3. RLS on user_secrets: owner-only CRUD

## Security
- AI keys never stored as plaintext in any table
- vault.secrets is inaccessible to the anon/authenticated roles directly
- Edge functions use service_role to read vault secrets
*/

-- Add vault reference column to organizations
ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS ai_keys_vault_id uuid;

-- Per-user secrets table (CLI auth tokens, personal API keys)
CREATE TABLE IF NOT EXISTS user_secrets (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  key         text NOT NULL,
  vault_id    uuid,           -- reference to vault.secrets entry
  created_at  timestamptz DEFAULT now(),
  updated_at  timestamptz DEFAULT now(),
  UNIQUE (user_id, key)
);

ALTER TABLE user_secrets ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "user_secrets_select_own" ON user_secrets;
CREATE POLICY "user_secrets_select_own" ON user_secrets FOR SELECT
  TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "user_secrets_insert_own" ON user_secrets;
CREATE POLICY "user_secrets_insert_own" ON user_secrets FOR INSERT
  TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "user_secrets_update_own" ON user_secrets;
CREATE POLICY "user_secrets_update_own" ON user_secrets FOR UPDATE
  TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "user_secrets_delete_own" ON user_secrets;
CREATE POLICY "user_secrets_delete_own" ON user_secrets FOR DELETE
  TO authenticated USING (auth.uid() = user_id);

-- Trigger for updated_at
DROP TRIGGER IF EXISTS set_updated_at ON user_secrets;
CREATE TRIGGER set_updated_at
  BEFORE UPDATE ON user_secrets
  FOR EACH ROW EXECUTE FUNCTION update_timestamp();
