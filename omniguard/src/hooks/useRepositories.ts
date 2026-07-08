import { useState, useEffect, useCallback } from 'react'
import { supabase, Tables } from '../lib/supabase'
import { useAuth } from './useAuth'

type Repository = Tables<'repositories'>
type Scan = Tables<'scans'>
type Finding = Tables<'findings'>

const API = import.meta.env.VITE_SUPABASE_URL + '/functions/v1'

// ── Repositories ──────────────────────────────────────────────

export function useRepositories(organizationId: string | null) {
  const { user } = useAuth()
  const [repositories, setRepositories] = useState<Repository[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetch_ = useCallback(async () => {
    if (!organizationId) { setRepositories([]); setLoading(false); return }
    setLoading(true)
    const { data, error: e } = await supabase.from('repositories').select('*')
      .eq('organization_id', organizationId).is('deleted_at', null).order('created_at', { ascending: false })
    if (e) setError(e.message); else setRepositories(data || [])
    setLoading(false)
  }, [organizationId])

  useEffect(() => { fetch_() }, [fetch_])

  const connect = async (r: { provider: string; provider_id?: string; owner: string; name: string; full_name: string; description?: string; default_branch?: string; visibility?: string; language?: string }) => {
    if (!organizationId) return { error: 'No organization' }
    const { data, error: e } = await supabase.from('repositories').insert({
      organization_id: organizationId, created_by: user?.id,
      ...r, default_branch: r.default_branch || 'main', visibility: r.visibility || 'private',
    }).select().single()
    if (e) return { error: e.message }
    setRepositories(prev => [data!, ...prev])
    return { error: null, data }
  }

  const triggerScan = async (repositoryId: string) => {
    const { data: { session } } = await supabase.auth.getSession()
    if (!session) return { error: 'Not authenticated' }
    try {
      const res = await fetch(`${API}/api-v1-scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}` },
        body: JSON.stringify({ repository: repositoryId, trigger: 'manual' }),
      })
      const json = await res.json()
      if (!res.ok) return { error: json.error?.message || 'Scan failed' }
      return { error: null, data: json.data }
    } catch (err) { return { error: String(err) } }
  }

  const remove = async (id: string) => {
    await supabase.from('repositories').update({ deleted_at: new Date().toISOString() }).eq('id', id)
    setRepositories(prev => prev.filter(r => r.id !== id))
    return { error: null }
  }

  return { repositories, loading, error, connect, triggerScan, remove, refetch: fetch_ }
}

// ── Scans (per-repo) ──────────────────────────────────────────

export function useScans(repositoryId: string | null) {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!repositoryId) { setScans([]); setLoading(false); return }
    supabase.from('scans').select('*').eq('repository_id', repositoryId)
      .order('created_at', { ascending: false }).limit(50)
      .then(({ data }) => { setScans(data || []); setLoading(false) })

    const ch = supabase.channel(`scans:${repositoryId}`)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'scans', filter: `repository_id=eq.${repositoryId}` },
        p => {
          if (p.eventType === 'INSERT') setScans(prev => [p.new as Scan, ...prev])
          else if (p.eventType === 'UPDATE') setScans(prev => prev.map(s => s.id === (p.new as Scan).id ? p.new as Scan : s))
        }).subscribe()
    return () => { supabase.removeChannel(ch) }
  }, [repositoryId])

  return { scans, loading }
}

// ── All scans (org-wide) ──────────────────────────────────────

export function useAllScans(organizationId: string | null) {
  const [scans, setScans] = useState<Array<Scan & { repository_name?: string }>>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!organizationId) { setScans([]); setLoading(false); return }
    supabase.from('scans').select('*, repositories(name, full_name)')
      .eq('organization_id', organizationId).order('created_at', { ascending: false }).limit(100)
      .then(({ data }) => {
        setScans((data || []).map(s => ({ ...s, repository_name: (s.repositories as { full_name?: string } | null)?.full_name })))
        setLoading(false)
      })

    const ch = supabase.channel(`all-scans:${organizationId}`)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'scans', filter: `organization_id=eq.${organizationId}` },
        p => {
          if (p.eventType === 'INSERT') setScans(prev => [p.new as Scan, ...prev])
          else if (p.eventType === 'UPDATE') setScans(prev => prev.map(s => s.id === (p.new as Scan).id ? { ...(p.new as Scan), repository_name: s.repository_name } : s))
        }).subscribe()
    return () => { supabase.removeChannel(ch) }
  }, [organizationId])

  return { scans, loading }
}

// ── Findings ──────────────────────────────────────────────────

export function useFindings(
  organizationId: string | null,
  filters?: { repositoryId?: string; severity?: string; status?: string; scanner?: string }
) {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [totalCount, setTotalCount] = useState(0)

  useEffect(() => {
    if (!organizationId) { setFindings([]); setLoading(false); return }
    let q = supabase.from('findings').select('*', { count: 'exact' }).eq('organization_id', organizationId)
    if (filters?.repositoryId) q = q.eq('repository_id', filters.repositoryId)
    if (filters?.severity) q = q.eq('severity', filters.severity)
    if (filters?.status) q = q.eq('status', filters.status)
    if (filters?.scanner) q = q.eq('scanner', filters.scanner)
    q.order('risk_score', { ascending: false }).limit(200)
      .then(({ data, count }) => { setFindings(data || []); setTotalCount(count || 0); setLoading(false) })

    const ch = supabase.channel(`findings:${organizationId}`)
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'findings', filter: `organization_id=eq.${organizationId}` },
        p => { setFindings(prev => [p.new as Finding, ...prev]); setTotalCount(c => c + 1) })
      .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'findings', filter: `organization_id=eq.${organizationId}` },
        p => setFindings(prev => prev.map(f => f.id === (p.new as Finding).id ? p.new as Finding : f)))
      .subscribe()
    return () => { supabase.removeChannel(ch) }
  }, [organizationId, filters?.repositoryId, filters?.severity, filters?.status, filters?.scanner])

  const resolveFinding = async (id: string, note?: string) => {
    const { data: { user } } = await supabase.auth.getUser()
    await supabase.from('findings').update({ status: 'resolved', resolved_by: user?.id, resolved_at: new Date().toISOString(), resolution_note: note || null }).eq('id', id)
    return { error: null }
  }

  const suppressFinding = async (id: string, reason: string) => {
    const { data: { session } } = await supabase.auth.getSession()
    if (!session) return { error: 'Not authenticated' }
    try {
      const res = await fetch(`${API}/api-v1-findings/${id}/suppress`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}` },
        body: JSON.stringify({ reason }),
      })
      return { error: res.ok ? null : 'Suppress failed' }
    } catch (err) { return { error: String(err) } }
  }

  const getAIRemediation = async (id: string) => {
    const { data: { session } } = await supabase.auth.getSession()
    if (!session) return { ai_remediation: null, remediation: null }
    try {
      const res = await fetch(`${API}/api-v1-findings/${id}/ai-remediation`, {
        headers: { Authorization: `Bearer ${session.access_token}` },
      })
      if (!res.ok) return { ai_remediation: null, remediation: null }
      const j = await res.json()
      return j.data || { ai_remediation: null, remediation: null }
    } catch { return { ai_remediation: null, remediation: null } }
  }

  return { findings, loading, totalCount, resolveFinding, suppressFinding, getAIRemediation }
}

// ── Notifications ─────────────────────────────────────────────

export function useNotifications(userId: string | null) {
  const [notifications, setNotifications] = useState<Tables<'notifications'>[]>([])
  const [unreadCount, setUnreadCount] = useState(0)

  useEffect(() => {
    if (!userId) return
    supabase.from('notifications').select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(50)
      .then(({ data }) => {
        setNotifications(data || [])
        setUnreadCount((data || []).filter(n => !n.read_at).length)
      })

    const ch = supabase.channel(`notifs:${userId}`)
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'notifications', filter: `user_id=eq.${userId}` },
        p => {
          setNotifications(prev => [p.new as Tables<'notifications'>, ...prev])
          setUnreadCount(c => c + 1)
        }).subscribe()
    return () => { supabase.removeChannel(ch) }
  }, [userId])

  const markAllRead = async () => {
    if (!userId) return
    await supabase.from('notifications').update({ read_at: new Date().toISOString() }).eq('user_id', userId).is('read_at', null)
    setNotifications(prev => prev.map(n => ({ ...n, read_at: n.read_at || new Date().toISOString() })))
    setUnreadCount(0)
  }

  return { notifications, unreadCount, markAllRead }
}

// ── Dashboard stats ───────────────────────────────────────────

export function useDashboardStats(organizationId: string | null) {
  const [stats, setStats] = useState({ critical: 0, high: 0, medium: 0, low: 0, total: 0, resolved: 0, repos: 0, avgRisk: 0 })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!organizationId) { setLoading(false); return }
    Promise.all([
      supabase.from('findings').select('severity, status', { count: 'exact' }).eq('organization_id', organizationId),
      supabase.from('repositories').select('risk_score', { count: 'exact' }).eq('organization_id', organizationId).is('deleted_at', null),
    ]).then(([{ data: f, count: total }, { data: r, count: repos }]) => {
      const findings = f || []
      const open = findings.filter(x => !['resolved','suppressed','false_positive'].includes(x.status))
      const risks = (r || []).map(x => x.risk_score)
      setStats({
        critical: open.filter(x => x.severity === 'critical').length,
        high: open.filter(x => x.severity === 'high').length,
        medium: open.filter(x => x.severity === 'medium').length,
        low: open.filter(x => x.severity === 'low').length,
        total: total || 0,
        resolved: findings.filter(x => x.status === 'resolved').length,
        repos: repos || 0,
        avgRisk: risks.length ? Math.round(risks.reduce((a, b) => a + b, 0) / risks.length) : 0,
      })
      setLoading(false)
    })
  }, [organizationId])

  return { stats, loading }
}
