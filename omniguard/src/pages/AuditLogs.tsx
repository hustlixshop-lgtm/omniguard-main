import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { supabase, Tables } from '../lib/supabase'
import { User, Layers, Search, X } from 'lucide-react'

type Log = Tables<'audit_logs'>

const AC: Record<string, string> = {
  scan_triggered: 'text-blue-400', scan_completed: 'text-green-400', finding_resolved: 'text-green-400',
  finding_suppressed: 'text-slate-400', api_key_created: 'text-yellow-400', api_key_revoked: 'text-red-400',
  webhook_received: 'text-blue-300', pr_scan_triggered: 'text-blue-300', policy_created: 'text-blue-400',
}

export function AuditLogs() {
  const { currentOrganizationId } = useAuth()
  const [logs, setLogs] = useState<Log[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [af, setAf] = useState(''); const [rf, setRf] = useState('')
  const [page, setPage] = useState(0); const [total, setTotal] = useState(0)
  const P = 50

  useEffect(() => {
    if (!currentOrganizationId) return; setLoading(true)
    let q = supabase.from('audit_logs').select('*', { count: 'exact' }).eq('organization_id', currentOrganizationId).order('created_at', { ascending: false }).range(page * P, (page + 1) * P - 1)
    if (af) q = q.eq('action', af); if (rf) q = q.eq('resource_type', rf)
    q.then(({ data, count }) => { setLogs(data || []); setTotal(count || 0); setLoading(false) })
  }, [currentOrganizationId, page, af, rf])

  const shown = search ? logs.filter(l => l.action.includes(search) || l.resource_name?.toLowerCase().includes(search.toLowerCase())) : logs
  const uA = [...new Set(logs.map(l => l.action))].sort()
  const uR = [...new Set(logs.map(l => l.resource_type))].sort()

  return (
    <div className="p-8 space-y-6 animate-fade-in">
      <div><h1 className="text-3xl font-bold text-white">Audit Logs</h1><p className="text-slate-400 mt-1">Tamper-proof record · {total} events</p></div>
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative"><Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" /><input className="input pl-9 w-56" placeholder="Search…" value={search} onChange={e => setSearch(e.target.value)} />{search && <button onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500"><X className="w-4 h-4" /></button>}</div>
        <select className="input w-44" value={af} onChange={e => { setAf(e.target.value); setPage(0) }}><option value="">All Actions</option>{uA.map(a => <option key={a} value={a}>{a.replace(/_/g,' ')}</option>)}</select>
        <select className="input w-36" value={rf} onChange={e => { setRf(e.target.value); setPage(0) }}><option value="">All Resources</option>{uR.map(r => <option key={r} value={r}>{r}</option>)}</select>
        {(af || rf) && <button onClick={() => { setAf(''); setRf(''); setPage(0) }} className="btn-ghost text-sm text-slate-400">Clear</button>}
      </div>
      <div className="card overflow-hidden">
        {loading ? <div className="flex justify-center py-12"><div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" /></div>
        : shown.length === 0 ? <div className="p-12 text-center text-slate-500">No events found</div>
        : <>
          <table className="w-full text-sm"><thead><tr className="border-b border-slate-700">{['Timestamp','Action','Resource','Actor','Details'].map(h => <th key={h} className="px-4 py-3 text-left text-slate-400 font-medium text-xs uppercase tracking-wider">{h}</th>)}</tr></thead>
          <tbody>
            {shown.map(l => (
              <tr key={l.id} className="border-b border-slate-800 hover:bg-slate-800/30 transition-colors">
                <td className="px-4 py-3 text-slate-500 text-xs font-mono whitespace-nowrap">{new Date(l.created_at).toLocaleString()}</td>
                <td className="px-4 py-3"><span className={`text-xs font-mono font-medium ${AC[l.action] || 'text-slate-300'}`}>{l.action.replace(/_/g,' ')}</span></td>
                <td className="px-4 py-3"><div className="flex items-center gap-1.5"><Layers className="w-3 h-3 text-slate-600" /><span className="badge text-xs" style={{background:'#1e293b',color:'#94a3b8'}}>{l.resource_type}</span>{l.resource_name && <span className="text-slate-400 text-xs truncate max-w-32">{l.resource_name}</span>}</div></td>
                <td className="px-4 py-3">{l.user_id ? <span className="flex items-center gap-1 text-slate-400 text-xs"><User className="w-3 h-3" /><span className="font-mono">{l.user_id.slice(0,8)}…</span></span> : <span className="text-slate-600 text-xs">System</span>}</td>
                <td className="px-4 py-3 text-slate-600 text-xs font-mono">{l.metadata && Object.keys(l.metadata).length > 0 ? JSON.stringify(l.metadata).slice(0,60) + (JSON.stringify(l.metadata).length > 60 ? '…' : '') : '—'}</td>
              </tr>
            ))}
          </tbody></table>
          {total > P && <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700"><button onClick={() => setPage(p => Math.max(0,p-1))} disabled={page===0} className="btn-secondary text-sm">Previous</button><span className="text-slate-500 text-sm">Page {page+1} of {Math.ceil(total/P)}</span><button onClick={() => setPage(p => p+1)} disabled={(page+1)*P >= total} className="btn-secondary text-sm">Next</button></div>}
        </>}
      </div>
    </div>
  )
}
