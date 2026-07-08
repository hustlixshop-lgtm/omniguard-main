import { useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import { useRepositories } from '../hooks/useRepositories'
import { GitBranch, Plus, Play, Trash2, RefreshCw, TriangleAlert as AlertTriangle, CircleCheck as CheckCircle, X } from 'lucide-react'

export function Repositories() {
  const { currentOrganizationId } = useAuth()
  const { repositories, loading, connect, triggerScan, remove, refetch } = useRepositories(currentOrganizationId)
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({ provider: 'github', owner: '', name: '' })
  const [saving, setSaving] = useState(false)
  const [scanning, setScanning] = useState<string | null>(null)
  const [error, setError] = useState('')

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault(); setError('')
    if (!form.owner.trim() || !form.name.trim()) { setError('Owner and name required'); return }
    setSaving(true)
    const full_name = `${form.owner.trim()}/${form.name.trim()}`
    const { error: err } = await connect({ provider: form.provider, owner: form.owner.trim(), name: form.name.trim(), full_name, provider_id: '' })
    setSaving(false)
    if (err) setError(err)
    else { setShowAdd(false); setForm({ provider: 'github', owner: '', name: '' }) }
  }

  const handleScan = async (id: string) => {
    setScanning(id)
    await triggerScan(id)
    setScanning(null)
  }

  const riskColor = (score: number) => score >= 70 ? 'text-red-400' : score >= 40 ? 'text-orange-400' : score >= 20 ? 'text-yellow-400' : 'text-green-400'

  return (
    <div className="p-8 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Repositories</h1>
          <p className="text-slate-400 mt-1">{repositories.length} connected</p>
        </div>
        <div className="flex gap-2">
          <button onClick={refetch} className="btn-secondary"><RefreshCw className="w-4 h-4" /></button>
          <button onClick={() => setShowAdd(true)} className="btn-primary"><Plus className="w-4 h-4" />Connect Repository</button>
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center py-16"><div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" /></div>
      ) : repositories.length === 0 ? (
        <div className="card p-16 text-center">
          <GitBranch className="w-16 h-16 mx-auto mb-4 text-slate-600" />
          <h3 className="text-xl font-semibold text-slate-300 mb-2">No repositories connected</h3>
          <p className="text-slate-500 mb-6">Connect a GitHub, GitLab, or Bitbucket repository to start scanning.</p>
          <button onClick={() => setShowAdd(true)} className="btn-primary"><Plus className="w-4 h-4" />Connect First Repository</button>
        </div>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {repositories.map(repo => (
            <div key={repo.id} className="card p-5 hover:border-slate-600 transition-all">
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <GitBranch className="w-4 h-4 text-slate-400 flex-shrink-0" />
                    <h3 className="text-slate-100 font-medium font-mono text-sm truncate">{repo.full_name}</h3>
                    <span className="badge" style={{ background: '#1e293b', color: '#94a3b8' }}>{repo.provider}</span>
                    <span className="badge" style={{ background: '#1e293b', color: '#94a3b8' }}>{repo.visibility}</span>
                  </div>
                  {repo.description && <p className="text-xs text-slate-500 mb-2 line-clamp-1">{repo.description}</p>}
                  <div className="flex items-center gap-3 text-xs text-slate-500">
                    <span>branch: {repo.default_branch}</span>
                    {repo.language && <span>{repo.language}</span>}
                    {repo.last_scan_at && <span>Last scan: {new Date(repo.last_scan_at).toLocaleDateString()}</span>}
                  </div>
                </div>
                <div className="text-right ml-3 flex-shrink-0">
                  <div className={`text-2xl font-bold font-mono ${riskColor(repo.risk_score)}`}>{Math.round(repo.risk_score)}</div>
                  <div className="text-xs text-slate-600">risk</div>
                </div>
              </div>
              <div className="flex gap-2 mt-4">
                <button onClick={() => handleScan(repo.id)} disabled={scanning === repo.id} className="btn-primary text-xs flex-1 justify-center">
                  {scanning === repo.id ? <><RefreshCw className="w-3 h-3 animate-spin" />Scanning…</> : <><Play className="w-3 h-3" />Scan</>}
                </button>
                <button onClick={() => remove(repo.id)} className="btn-ghost text-red-400 text-xs p-2">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {showAdd && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setShowAdd(false)}>
          <div className="card-elevated p-6 w-full max-w-md animate-slide-up" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-xl font-semibold text-white">Connect Repository</h2>
              <button onClick={() => setShowAdd(false)} className="text-slate-500 hover:text-slate-300"><X className="w-5 h-5" /></button>
            </div>
            <form onSubmit={handleAdd} className="space-y-4">
              <div>
                <label className="label">Provider</label>
                <select value={form.provider} onChange={e => setForm({ ...form, provider: e.target.value })} className="input">
                  <option value="github">GitHub</option>
                  <option value="gitlab">GitLab</option>
                  <option value="bitbucket">Bitbucket</option>
                  <option value="azure-devops">Azure DevOps</option>
                </select>
              </div>
              <div>
                <label className="label">Owner (username or org)</label>
                <input className="input" value={form.owner} onChange={e => setForm({ ...form, owner: e.target.value })} placeholder="e.g. your-company" required />
              </div>
              <div>
                <label className="label">Repository Name</label>
                <input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="e.g. api-service" required />
              </div>
              {error && <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">{error}</div>}
              <div className="flex gap-3">
                <button type="button" onClick={() => setShowAdd(false)} className="btn-secondary flex-1">Cancel</button>
                <button type="submit" disabled={saving} className="btn-primary flex-1 justify-center">{saving ? 'Connecting…' : 'Connect'}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
