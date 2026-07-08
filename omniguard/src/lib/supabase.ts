import { createClient } from '@supabase/supabase-js'

const url = import.meta.env.VITE_SUPABASE_URL
const key = import.meta.env.VITE_SUPABASE_ANON_KEY

if (!url || !key) throw new Error('Missing VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY')

export const supabase = createClient(url, key)

// Lightweight type helpers — generated from schema
export type Tables<T extends keyof Database['public']['Tables']> =
  Database['public']['Tables'][T]['Row']

export interface Database {
  public: {
    Tables: {
      organizations: { Row: { id: string; name: string; slug: string; plan: string; settings: Record<string,unknown>; ai_config: Record<string,unknown>; created_at: string; updated_at: string } }
      user_profiles: { Row: { id: string; email: string; first_name: string | null; last_name: string | null; avatar_url: string | null; role: string; created_at: string; updated_at: string } }
      organization_members: { Row: { id: string; organization_id: string; user_id: string; role: string; status: string; invited_by: string | null; created_at: string; updated_at: string } }
      api_keys: { Row: { id: string; organization_id: string; name: string; key_prefix: string; key_hash: string; scopes: string[]; is_active: boolean; last_used_at: string | null; expires_at: string | null; created_by: string | null; created_at: string } }
      repositories: { Row: { id: string; organization_id: string; provider: string; provider_id: string | null; owner: string; name: string; full_name: string; description: string | null; default_branch: string; visibility: string; language: string | null; risk_score: number; webhook_secret: string | null; last_scan_at: string | null; last_sync_at: string | null; is_archived: boolean; deleted_at: string | null; created_by: string | null; created_at: string; updated_at: string } }
      scans: { Row: { id: string; organization_id: string; repository_id: string; status: string; trigger: string; branch: string | null; commit_sha: string | null; commit_message: string | null; commit_author: string | null; worker_id: string | null; summary: Record<string,unknown> | null; error_message: string | null; started_at: string | null; completed_at: string | null; duration_seconds: number | null; metadata: Record<string,unknown>; created_by: string | null; created_at: string } }
      findings: { Row: { id: string; organization_id: string; repository_id: string; scan_id: string | null; scanner: string; category: string | null; severity: string; status: string; title: string; description: string | null; evidence: string | null; file_path: string | null; line_start: number | null; line_end: number | null; rule_id: string | null; rule_name: string | null; owasp: string[]; cwe: string[]; cve_id: string | null; risk_score: number; confidence_score: number; remediation: string | null; ai_summary: string | null; ai_remediation: string | null; ai_provider: string | null; ai_model: string | null; suppression_note: string | null; policy_violations: string[]; assigned_to: string | null; assigned_at: string | null; resolved_by: string | null; resolved_at: string | null; resolution_note: string | null; created_at: string; updated_at: string } }
      policies: { Row: { id: string; organization_id: string; title: string; category: string | null; description: string | null; content: string; severity: string; status: string; version: number; tags: string[]; source_type: string | null; source_url: string | null; approved_by: string | null; approved_at: string | null; deleted_at: string | null; created_by: string | null; created_at: string; updated_at: string } }
      policy_chunks: { Row: { id: string; organization_id: string; policy_id: string | null; chunk_index: number; content: string; embedding: number[] | null; metadata: Record<string,unknown>; created_at: string } }
      integrations: { Row: { id: string; organization_id: string; provider: string; status: string; config: Record<string,unknown>; metadata: Record<string,unknown>; created_by: string | null; created_at: string; updated_at: string } }
      notifications: { Row: { id: string; organization_id: string; user_id: string | null; type: string; title: string; body: string | null; data: Record<string,unknown>; read_at: string | null; created_at: string } }
      audit_logs: { Row: { id: string; organization_id: string; user_id: string | null; action: string; resource_type: string; resource_id: string | null; resource_name: string | null; ip_address: string | null; user_agent: string | null; metadata: Record<string,unknown>; created_at: string } }
      teams: { Row: { id: string; organization_id: string; name: string; description: string | null; created_by: string | null; created_at: string } }
      compliance_frameworks: { Row: { id: string; organization_id: string; framework: string; score: number; details: Record<string,unknown>; calculated_at: string } }
      worker_heartbeats: { Row: { worker_id: string; worker_type: string; status: string; current_scan_id: string | null; last_heartbeat: string; metadata: Record<string,unknown> } }
    }
  }
}
