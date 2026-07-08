import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { supabase, Tables } from '../lib/supabase'
import { Shield, Plus, CircleCheck as CheckCircle, FileText, Trash2, Archive, Upload, X } from 'lucide-react'

type Policy = Tables<'policies'>

const API = import.meta.env.VITE_SUPABASE_URL + '/functions/v1'

export function Policies() {
  const { currentOrganizationId, user } = useAuth()
  const [policies, setPolicies] = useState<Policy[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const [form, setForm] = useState({ title: '', category: '', description: '', content: '', severity: 'high' })
  const [saving, setSaving] = useState(false)
  const [uploadLoading, setUploadLoading] = useState(false)

  useEffect(() => {
    if (!currentOrganizationId) return
    supabase.from('policies').select('*').eq('organization_id', currentOrganizationId).is('deleted_at', null)
      .order('created_at', { ascending: false })
      .then(({ data }) => { setPolicies((data as Policy[]) || []); setLoading(false) })
  }, [currentOrganizationId])

  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!currentOrganizationId || !form.title.trim() || !form.content.trim()) return
    setSaving(true)
    const { data, error } = await supabase.from('policies').insert({
      organization_id: currentOrganizationId, created_by: user?.id,
      title: form.title, category: form.category || null, description: form.description || null,
      content: form.content, severity: form.severity, status: 'draft',
    }).select().single()
    setSaving(false)
    if (!error && data) {
      setPolicies(prev => [data as Policy, ...prev])
      setShowCreate(false); setForm({ title: '', category: '', description: '', content: '', severity: 'high' })
      // Trigger embedding generation
      const { data: { session } } = await supabase.auth.getSession()
      if (session) {
        fetch(`${API}/policy-ingest`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}` },
          body: JSON.stringify({ policy_id: data.id, organization_id: currentOrganizationId }),
        }).catch(() => {})
      }
    }
  }

  const uploadDoc = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]; if (!file || !currentOrganizationId) return
    setUploadLoading(true)
    const { data: { session } } = await supabase.auth.getSession()
    if (!session) { setUploadLoading(false); return }
    const formData = new FormData(); formData.append('file', file); formData.append('organization_id', currentOrganizationId)
    try {
      const res = await fetch(`${API}/policy-ingest`, { method: 'POST', headers: { Authorization: `Bearer ${session.access_token}` }, body: formData })
      const json = await res.json()
      if (json.policy) setPolicies(prev => [json.policy as Policy, ...prev])
    } catch { /* non-fatal */ }
    setUploadLoading(false); e.target.value = ''
  }

  const activate = async (id: string) => {
    await supabase.from('policies').update({ status: 'active', approved_by: user?.id, approved_at: new Date().toISOString() }).eq('id', id)
    setPolicies(prev => prev.map(p => p.id === id ? { ...p, status: 'active' as const } : p))
  }
  const archive = async (id: string) => {
    await supabase.from('policies').update({ status: 'archived' }).eq('id', id)
    setPolicies(prev => prev.map(p => p.id === id ? { ...p, status: 'archived' as const } : p))
  }
  const del = async (id: string) => {
    if (!confirm('Delete policy?')) return
    await supabase.from('policies').update({ deleted_at: new Date().toISOString() }).eq('id', id)
    setPolicies(prev => prev.filter(p => p.id !== id))
  }

  const sColor: Record<string, string> = { draft: 'bg-slate-600 text-slate-300', active: 'bg-green-500/20 text-green-400', archived: 'bg-slate-700 text-slate-500' }

  return (
    <div className="p-8 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div><h1 className="text-3xl font-bold text-white">Security Policies</h1><p className="text-slate-400 mt-1">Rules enforced across all repositories</p></div>
        <div className="flex gap-2">
          <label className={`btn-secondary cursor-pointer ${uploadLoading ? 'opacity-50' : ''}`}>
            <Upload className="w-4 h-4" />{uploadLoading ? 'Processing…' : 'Upload Document'}
            <input type="file" accept=".pdf,.docx,.md,.txt,.html" className="hidden" onChange={uploadDoc} disabled={uploadLoading} />
          </label>
          <button onClick={() => setShowCreate(true)} className="btn-primary"><Plus className="w-4 h-4" />New Policy</button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {[['Active', policies.filter(p => p.status === 'active').length, 'text-green-400'],
          ['Draft', policies.filter(p => p.status === 'draft').length, 'text-yellow-400'],
          ['Archived', policies.filter(p => p.status === 'archived').length, 'text-slate-500']].map(([l, n, c]) => (
          <div key={String(l)} className="stat-card"><p className={`text-3xl font-bold font-mono ${c}`}>{n}</p><p className="text-slate-400 text-sm mt-1">{l} Policies</p></div>
        ))}
      </div>

      {loading ? <div className="flex justify-center py-12"><div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" /></div>
      : policies.length === 0 ? (
        <div className="card p-16 text-center"><Shield className="w-16 h-16 mx-auto mb-4 text-slate-600" /><h3 className="text-lg font-semibold text-slate-300 mb-2">No policies yet</h3>
          <p className="text-slate-500 mb-6">Create security policies or upload documents (PDF, DOCX, Markdown) to define your standards.</p>
          <button onClick={() => setShowCreate(true)} className="btn-primary"><Plus className="w-4 h-4" />Create First Policy</button>
        </div>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {policies.map(p => (
            <div key={p.id} className={`card p-5 cursor-pointer hover:border-slate-600 transition-all ${selected === p.id ? 'border-blue-500/30' : ''}`} onClick={() => setSelected(selected === p.id ? null : p.id)}>
              <div className="flex items-start gap-3">
                <FileText className="w-5 h-5 text-slate-400 mt-0.5 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <h3 className="text-slate-100 font-medium">{p.title}</h3>
                    <span className={`badge text-xs ${sColor[p.status]}`}>{p.status}</span>
                    {p.source_type && p.source_type !== 'manual' && <span className="badge text-xs bg-blue-500/20 text-blue-400">{p.source_type}</span>}
                  </div>
                  {p.description && <p className="text-slate-500 text-sm">{p.description}</p>}
                  {selected === p.id && (
                    <div className="mt-3 pt-3 border-t border-slate-700 animate-fade-in" onClick={e => e.stopPropagation()}>
                      <pre className="text-slate-300 text-xs bg-slate-900 p-3 rounded overflow-x-auto whitespace-pre-wrap font-mono border border-slate-800 max-h-48">{p.content}</pre>
                      <div className="flex gap-2 mt-3">
                        {p.status === 'draft' && <button onClick={() => activate(p.id)} className="btn-primary text-xs"><CheckCircle className="w-3 h-3" />Activate</button>}
                        {p.status === 'active' && <button onClick={() => archive(p.id)} className="btn-secondary text-xs"><Archive className="w-3 h-3" />Archive</button>}
                        <button onClick={() => del(p.id)} className="btn-ghost text-red-400 text-xs"><Trash2 className="w-3 h-3" />Delete</button>
                      </div>
                    </div>
                  )}
                </div>
                <p className="text-xs text-slate-600 flex-shrink-0">{new Date(p.created_at).toLocaleDateString()}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {showCreate && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setShowCreate(false)}>
          <div className="card-elevated p-6 w-full max-w-2xl animate-slide-up" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4"><h2 className="text-xl font-semibold text-white">Create Security Policy</h2><button onClick={() => setShowCreate(false)} className="text-slate-500"><X className="w-5 h-5" /></button></div>
            <form onSubmit={create} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div><label className="label">Title</label><input className="input" value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} placeholder="No Hardcoded Secrets" required autoFocus /></div>
                <div><label className="label">Category</label><input className="input" value={form.category} onChange={e => setForm({ ...form, category: e.target.value })} placeholder="Secrets, Access Control…" /></div>
              </div>
              <div><label className="label">Description</label><input className="input" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Brief summary" /></div>
              <div><label className="label">Severity</label><select className="input max-w-xs" value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
              <div><label className="label">Policy Content</label><textarea className="input font-mono text-sm" rows={8} value={form.content} onChange={e => setForm({ ...form, content: e.target.value })} placeholder={`DENY: secrets in source code\nDENY: API keys in committed files\nALLOW: environment variables via secrets manager\n\nRATIONALE:\nHardcoded credentials expose services if source is leaked.`} required /></div>
              {saving && <p className="text-xs text-blue-400">Creating and generating embeddings…</p>}
              <div className="flex gap-3"><button type="button" onClick={() => setShowCreate(false)} className="btn-secondary flex-1">Cancel</button><button type="submit" disabled={saving} className="btn-primary flex-1 justify-center">{saving ? 'Creating…' : 'Create Policy'}</button></div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
