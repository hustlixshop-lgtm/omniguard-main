import { useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import { useAllScans } from '../hooks/useRepositories'
import { CircleCheck as CheckCircle, CircleAlert as AlertCircle, Clock, RefreshCw, GitBranch, Calendar, Play } from 'lucide-react'

const S = { completed: { icon: CheckCircle, color: 'text-green-400' }, failed: { icon: AlertCircle, color: 'text-red-400' }, running: { icon: RefreshCw, color: 'text-blue-400', spin: true }, queued: { icon: Clock, color: 'text-yellow-400' } }

export function Scans() {
  const { currentOrganizationId } = useAuth()
  const { scans, loading } = useAllScans(currentOrganizationId)
  const [f, setF] = useState('')
  const shown = f ? scans.filter(s => s.status === f) : scans
  const counts = { queued: scans.filter(s => s.status === 'queued').length, running: scans.filter(s => s.status === 'running').length, completed: scans.filter(s => s.status === 'completed').length, failed: scans.filter(s => s.status === 'failed').length }

  return (
    <div className="p-8 space-y-6 animate-fade-in">
      <div><h1 className="text-3xl font-bold text-white">Scan History</h1><p className="text-slate-400 mt-1">All security scans — live</p></div>
      <div className="grid grid-cols-4 gap-4">
        {[['queued','text-yellow-400'],['running','text-blue-400'],['completed','text-green-400'],['failed','text-red-400']].map(([k,c]) => (
          <button key={k} onClick={() => setF(f === k ? '' : k)} className={`stat-card text-left hover:border-slate-500 transition-all ${f === k ? 'border-blue-500/50' : ''}`}>
            <p className={`text-3xl font-bold font-mono ${c}`}>{counts[k as keyof typeof counts]}</p>
            <p className="text-slate-400 text-sm capitalize mt-1">{k}</p>
          </button>
        ))}
      </div>
      {loading ? <div className="flex justify-center py-16"><div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" /></div>
      : shown.length === 0 ? (
        <div className="card p-16 text-center"><Play className="w-14 h-14 mx-auto mb-4 text-slate-600" /><h3 className="text-lg font-semibold text-slate-300">No scans yet</h3><p className="text-slate-500 mt-2">Connect a repository and trigger a scan.</p></div>
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-slate-700">{['Repository','Status','Trigger','Branch','Findings','Duration','Started'].map(h => <th key={h} className="px-4 py-3 text-left text-slate-400 font-medium text-xs uppercase tracking-wider">{h}</th>)}</tr></thead>
            <tbody>
              {shown.map(scan => {
                const sum = scan.summary as Record<string,number> | null
                const St = S[scan.status as keyof typeof S] || S.queued
                return (
                  <tr key={scan.id} className="border-b border-slate-800 hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3"><div className="flex items-center gap-2"><GitBranch className="w-4 h-4 text-slate-500" /><span className="font-mono text-xs text-slate-200">{scan.repository_name || scan.id.slice(0,8)}</span></div></td>
                    <td className="px-4 py-3"><div className="flex items-center gap-1.5"><St.icon className={`w-4 h-4 ${St.color} ${'spin' in St ? 'animate-spin' : ''}`} /><span className={St.color + ' text-xs'}>{scan.status}</span></div></td>
                    <td className="px-4 py-3"><span className="badge text-xs" style={{background:'#1e293b',color:'#94a3b8'}}>{scan.trigger}</span></td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">{scan.branch || 'main'}</td>
                    <td className="px-4 py-3">{sum?.total ? <span className={`font-mono text-sm font-bold ${(sum.critical||0) > 0 ? 'text-red-400' : 'text-slate-300'}`}>{sum.total}</span> : scan.status === 'completed' ? <span className="text-green-400 text-xs">✓ clean</span> : <span className="text-slate-600">—</span>}</td>
                    <td className="px-4 py-3 text-slate-400 text-xs">{scan.duration_seconds ? `${scan.duration_seconds}s` : '—'}</td>
                    <td className="px-4 py-3 text-slate-500 text-xs"><div className="flex items-center gap-1"><Calendar className="w-3 h-3" />{new Date(scan.created_at).toLocaleString()}</div></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
