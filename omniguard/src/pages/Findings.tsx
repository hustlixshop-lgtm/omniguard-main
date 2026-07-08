import { useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import { useFindings } from '../hooks/useRepositories'
import { TriangleAlert as AlertTriangle, CircleCheck as CheckCircle, Search, ListFilter as Filter, ChevronDown, FileCode, Clock, Sparkles, Ban, X, Loader as Loader2, Copy } from 'lucide-react'

type Finding = ReturnType<typeof useFindings>['findings'][0]

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_BADGE: Record<string, string> = {
  critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low', info: 'badge-info',
}

export function Findings() {
  const { currentOrganizationId } = useAuth()
  const [filters, setFilters] = useState({ severity: '', status: '', scanner: '' })
  const [search, setSearch] = useState('')
  const [showFilters, setShowFilters] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const { findings, loading, totalCount, resolveFinding, suppressFinding, getAIRemediation } = useFindings(currentOrganizationId, filters)

  const displayed = findings.filter(f =>
    !search || f.title.toLowerCase().includes(search.toLowerCase()) || f.file_path?.toLowerCase().includes(search.toLowerCase())
  ).sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))

  return (
    <div className="p-8 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-3xl font-bold text-white">Findings</h1>
          <p className="text-slate-400 mt-1">{totalCount} total · live updates</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          {['critical','high'].map(s => {
            const n = findings.filter(f => f.severity === s && !['resolved','suppressed'].includes(f.status)).length
            return n > 0 ? <span key={s} className={`badge-${s}`}>{n} {s}</span> : null
          })}
        </div>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-48 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input className="input pl-9" placeholder="Search findings…" value={search} onChange={e => setSearch(e.target.value)} />
          {search && <button onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500"><X className="w-4 h-4" /></button>}
        </div>
        <button onClick={() => setShowFilters(!showFilters)} className={`btn-secondary ${showFilters ? 'border-blue-500/50' : ''}`}>
          <Filter className="w-4 h-4" />Filters<ChevronDown className={`w-4 h-4 transition-transform ${showFilters ? 'rotate-180' : ''}`} />
        </button>
        {(filters.severity || filters.status || filters.scanner) && (
          <button onClick={() => setFilters({ severity: '', status: '', scanner: '' })} className="btn-ghost text-sm text-slate-400">Clear filters</button>
        )}
      </div>

      {showFilters && (
        <div className="card p-4 animate-fade-in grid grid-cols-3 gap-4">
          {[
            { key: 'severity', opts: ['', 'critical', 'high', 'medium', 'low', 'info'], label: 'Severity' },
            { key: 'status', opts: ['', 'open', 'assigned', 'in_progress', 'resolved', 'suppressed', 'false_positive'], label: 'Status' },
            { key: 'scanner', opts: ['', 'secret', 'sast', 'dependency', 'iac', 'container', 'license'], label: 'Scanner' },
          ].map(({ key, opts, label }) => (
            <div key={key}>
              <label className="label">{label}</label>
              <select className="input" value={filters[key as keyof typeof filters]} onChange={e => setFilters({ ...filters, [key]: e.target.value })}>
                {opts.map(o => <option key={o} value={o}>{o ? o.charAt(0).toUpperCase() + o.slice(1).replace(/_/g,' ') : `All ${label}s`}</option>)}
              </select>
            </div>
          ))}
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-16"><div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" /></div>
      ) : displayed.length === 0 ? (
        <div className="card p-16 text-center">
          <CheckCircle className="w-14 h-14 mx-auto mb-4 text-green-400" />
          <h3 className="text-lg font-semibold text-slate-300 mb-2">No findings</h3>
          <p className="text-slate-500">{search || filters.severity ? 'No findings match your filters' : 'Run a scan to detect vulnerabilities'}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {displayed.map(f => (
            <FindingRow key={f.id} f={f} expanded={selected === f.id} onToggle={() => setSelected(selected === f.id ? null : f.id)}
              onResolve={resolveFinding} onSuppress={suppressFinding} onGetAI={getAIRemediation} />
          ))}
        </div>
      )}
    </div>
  )
}

function FindingRow({ f, expanded, onToggle, onResolve, onSuppress, onGetAI }: {
  f: Finding; expanded: boolean; onToggle: () => void
  onResolve: (id: string, note?: string) => Promise<{error: string | null}>
  onSuppress: (id: string, reason: string) => Promise<{error: string | null}>
  onGetAI: (id: string) => Promise<{ai_remediation: string | null; remediation: string | null}>
}) {
  const [aiText, setAiText] = useState<string | null>(f.ai_remediation)
  const [aiLoading, setAiLoading] = useState(false)
  const [suppressInput, setSuppressInput] = useState('')
  const [showSuppress, setShowSuppress] = useState(false)
  const [actionLoading, setActionLoading] = useState(false)

  const isResolved = ['resolved', 'suppressed', 'false_positive'].includes(f.status)

  return (
    <div className={`card p-4 cursor-pointer hover:border-slate-600 transition-all ${expanded ? 'border-slate-600' : ''} ${isResolved ? 'opacity-60' : ''}`} onClick={onToggle}>
      <div className="flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={SEV_BADGE[f.severity] || 'badge-info'}>{f.severity.toUpperCase()}</span>
            <span className="badge" style={{ background: '#1e293b', color: '#64748b' }}>{f.scanner}</span>
            {f.rule_id && <span className="text-xs font-mono text-slate-500">{f.rule_id}</span>}
            {isResolved && <span className="badge" style={{ background: '#1e293b', color: '#64748b' }}>{f.status}</span>}
          </div>
          <h3 className="text-sm font-medium text-slate-100 mt-1.5">{f.title}</h3>
          {f.file_path && (
            <div className="flex items-center gap-1 mt-1 text-xs text-slate-500">
              <FileCode className="w-3 h-3" /><span className="font-mono">{f.file_path}{f.line_start ? `:${f.line_start}` : ''}</span>
            </div>
          )}
        </div>
        <div className="text-right flex-shrink-0">
          <p className="text-xl font-bold font-mono text-slate-200">{Math.round(f.risk_score)}</p>
          <p className="text-xs text-slate-600">risk</p>
        </div>
      </div>

      {expanded && (
        <div className="mt-4 pt-4 border-t border-slate-700/50 space-y-3 animate-fade-in" onClick={e => e.stopPropagation()}>
          {f.description && <p className="text-sm text-slate-300">{f.description}</p>}
          {f.owasp?.length > 0 && <p className="text-xs text-slate-500">OWASP: {f.owasp.join(', ')}</p>}
          {f.cwe?.length > 0 && <p className="text-xs text-slate-500">CWE: {f.cwe.join(', ')}</p>}
          {f.evidence && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <p className="text-xs text-slate-500 uppercase tracking-wide">Evidence</p>
                <button onClick={() => navigator.clipboard.writeText(f.evidence!)} className="text-slate-600 hover:text-slate-400"><Copy className="w-3 h-3" /></button>
              </div>
              <pre className="bg-slate-900 p-2 rounded text-xs font-mono text-slate-300 overflow-x-auto border border-slate-800">{f.evidence}</pre>
            </div>
          )}
          {f.ai_summary && (
            <div className="p-3 bg-blue-500/5 border border-blue-500/20 rounded-lg">
              <p className="text-xs text-blue-400 uppercase tracking-wide mb-1 flex items-center gap-1"><Sparkles className="w-3 h-3" />AI Analysis</p>
              <p className="text-sm text-slate-300">{f.ai_summary}</p>
            </div>
          )}
          {aiText ? (
            <div className="p-3 bg-green-500/5 border border-green-500/20 rounded-lg">
              <p className="text-xs text-green-400 uppercase tracking-wide mb-1 flex items-center gap-1"><Sparkles className="w-3 h-3" />AI Remediation</p>
              <div className="text-sm text-slate-300 whitespace-pre-wrap">{aiText}</div>
            </div>
          ) : (
            <button onClick={async () => { setAiLoading(true); const r = await onGetAI(f.id); setAiText(r.ai_remediation || r.remediation); setAiLoading(false) }}
              disabled={aiLoading} className="flex items-center gap-2 text-sm text-blue-400 hover:text-blue-300 transition-colors">
              {aiLoading ? <><Loader2 className="w-4 h-4 animate-spin" />Generating fix…</> : <><Sparkles className="w-4 h-4" />Get AI Remediation</>}
            </button>
          )}
          {showSuppress && (
            <div className="p-3 bg-slate-800 rounded-lg border border-slate-700 space-y-2">
              <input type="text" value={suppressInput} onChange={e => setSuppressInput(e.target.value)} placeholder="Suppression reason (required)" className="input text-sm" autoFocus />
              <div className="flex gap-2">
                <button onClick={async () => { if (!suppressInput.trim()) return; setActionLoading(true); await onSuppress(f.id, suppressInput); setActionLoading(false); setShowSuppress(false) }}
                  disabled={!suppressInput.trim() || actionLoading} className="btn-secondary text-xs">
                  {actionLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Ban className="w-3 h-3" />}Confirm
                </button>
                <button onClick={() => setShowSuppress(false)} className="btn-ghost text-xs">Cancel</button>
              </div>
            </div>
          )}
          <div className="flex items-center gap-2 flex-wrap pt-1">
            {!isResolved && <button onClick={async () => { setActionLoading(true); await onResolve(f.id); setActionLoading(false) }} disabled={actionLoading} className="btn-primary text-xs"><CheckCircle className="w-3 h-3" />Resolve</button>}
            {f.status === 'open' && !showSuppress && <button onClick={() => setShowSuppress(true)} className="btn-ghost text-slate-400 text-xs"><Ban className="w-3 h-3" />Suppress</button>}
          </div>
        </div>
      )}
    </div>
  )
}
