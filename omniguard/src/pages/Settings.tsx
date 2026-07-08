import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { supabase, Tables } from '../lib/supabase'
import { Copy, Plus, Trash2, Check, ExternalLink, CircleAlert as AlertCircle, CircleCheck as CheckCircle, Loader as Loader2, ChevronDown, ChevronRight } from 'lucide-react'

type ApiKey = Tables<'api_keys'>
type Integration = Tables<'integrations'>

const TABS = ['API Keys', 'Integrations', 'AI Provider', 'Notifications', 'Organization'] as const
type Tab = typeof TABS[number]

const API = import.meta.env.VITE_SUPABASE_URL + '/functions/v1'

// Integration definitions
const INTEGRATIONS = [
  { provider: 'github',       name: 'GitHub',          category: 'SCM',          fields: [{ key: 'access_token', label: 'Personal Access Token', placeholder: 'ghp_...', help: 'Requires repo + read:org + checks:write scopes' }] },
  { provider: 'gitlab',       name: 'GitLab',          category: 'SCM',          fields: [{ key: 'gitlab_url', label: 'GitLab URL', placeholder: 'https://gitlab.com' }, { key: 'access_token', label: 'Access Token', placeholder: 'glpat-...' }] },
  { provider: 'bitbucket',    name: 'Bitbucket',       category: 'SCM',          fields: [{ key: 'username', label: 'Username', placeholder: '' }, { key: 'app_password', label: 'App Password', placeholder: '' }] },
  { provider: 'azure-devops', name: 'Azure DevOps',    category: 'SCM',          fields: [{ key: 'organization', label: 'Organization', placeholder: 'your-org' }, { key: 'personal_access_token', label: 'PAT', placeholder: '' }, { key: 'project', label: 'Default Project', placeholder: 'MyProject' }] },
  { provider: 'jira',         name: 'Jira',            category: 'Ticketing',    fields: [{ key: 'domain', label: 'Domain', placeholder: 'yourco.atlassian.net' }, { key: 'email', label: 'Email', placeholder: 'you@company.com' }, { key: 'api_token', label: 'API Token', placeholder: 'ATATT3x...' }, { key: 'project_key', label: 'Project Key', placeholder: 'SEC' }] },
  { provider: 'linear',       name: 'Linear',          category: 'Ticketing',    fields: [{ key: 'api_key', label: 'API Key', placeholder: 'lin_api_...' }, { key: 'team_id', label: 'Team ID', placeholder: 'UUID from Linear settings' }] },
  { provider: 'servicenow',   name: 'ServiceNow',      category: 'Ticketing',    fields: [{ key: 'instance', label: 'Instance', placeholder: 'yourco (for yourco.service-now.com)' }, { key: 'username', label: 'Username', placeholder: '' }, { key: 'password', label: 'Password', placeholder: '', secret: true }, { key: 'assignment_group', label: 'Assignment Group', placeholder: 'Security Operations (optional)' }] },
  { provider: 'pagerduty',    name: 'PagerDuty',       category: 'Alerting',     fields: [{ key: 'integration_key', label: 'Integration Key', placeholder: 'Events API v2 key' }] },
  { provider: 'teams',        name: 'Microsoft Teams', category: 'Alerting',     fields: [{ key: 'webhook_url', label: 'Incoming Webhook URL', placeholder: 'https://yourco.webhook.office.com/...' }] },
  { provider: 'slack',        name: 'Slack',           category: 'Alerting',     fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/services/...' }] },
  { provider: 'confluence',   name: 'Confluence',      category: 'Docs',         fields: [{ key: 'domain', label: 'Domain', placeholder: 'yourco.atlassian.net' }, { key: 'email', label: 'Email', placeholder: '' }, { key: 'api_token', label: 'API Token', placeholder: '' }, { key: 'space_key', label: 'Space Key', placeholder: 'SEC' }] },
  { provider: 'okta',         name: 'Okta',            category: 'SSO',          fields: [{ key: 'domain', label: 'Okta Domain', placeholder: 'yourco.okta.com' }, { key: 'api_token', label: 'API Token', placeholder: '00...' }] },
]

const CATEGORY_ORDER = ['SCM', 'Ticketing', 'Alerting', 'Docs', 'SSO']

function IntegrationCard({ def, existing, onSave, onRemove }: {
  def: typeof INTEGRATIONS[0]
  existing?: Integration
  onSave: (provider: string, config: Record<string, string>) => Promise<{ ok: boolean; message: string }>
  onRemove: (provider: string) => Promise<void>
}) {
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const isConnected = existing?.status === 'active'

  const test = async () => {
    setTesting(true); setMsg(null)
    const { data: { session } } = await supabase.auth.getSession()
    if (!session) { setTesting(false); return }
    try {
      const res = await fetch(`${API}/enterprise-integrations/test`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}` },
        body: JSON.stringify({ provider: def.provider, config: form }),
      })
      const json = await res.json()
      setMsg({ ok: json.success, text: json.message })
    } catch (e) { setMsg({ ok: false, text: String(e) }) }
    setTesting(false)
  }

  const save = async () => {
    setSaving(true); setMsg(null)
    const result = await onSave(def.provider, form)
    setMsg({ ok: result.ok, text: result.message })
    if (result.ok) setOpen(false)
    setSaving(false)
  }

  return (
    <div className={`card overflow-hidden transition-all ${isConnected ? 'border-green-500/20' : ''}`}>
      <div className="flex items-center justify-between p-4 cursor-pointer" onClick={() => setOpen(!open)}>
        <div className="flex items-center gap-3">
          {isConnected ? <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" /> : <div className="w-4 h-4 rounded-full border border-slate-600 flex-shrink-0" />}
          <span className="text-slate-200 font-medium">{def.name}</span>
          <span className="badge text-xs" style={{ background: '#1e293b', color: '#64748b' }}>{def.category}</span>
          {isConnected && <span className="badge text-xs bg-green-500/20 text-green-400">Connected</span>}
        </div>
        <div className="flex items-center gap-2">
          {isConnected && (
            <button onClick={e => { e.stopPropagation(); onRemove(def.provider) }} className="btn-ghost text-red-400 text-xs p-1">
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
          {open ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
        </div>
      </div>
      {open && (
        <div className="border-t border-slate-700/50 p-4 space-y-3 animate-fade-in">
          {def.fields.map(f => (
            <div key={f.key}>
              <label className="label">{f.label}</label>
              <input type={(f as { secret?: boolean }).secret ? 'password' : 'text'} className="input" placeholder={f.placeholder} value={form[f.key] ?? ''} onChange={e => setForm({ ...form, [f.key]: e.target.value })} />
            </div>
          ))}
          {msg && (
            <div className={`flex items-center gap-2 p-2 rounded text-sm ${msg.ok ? 'text-green-400 bg-green-500/10 border border-green-500/20' : 'text-red-400 bg-red-500/10 border border-red-500/20'}`}>
              {msg.ok ? <CheckCircle className="w-4 h-4 flex-shrink-0" /> : <AlertCircle className="w-4 h-4 flex-shrink-0" />}
              {msg.text}
            </div>
          )}
          <div className="flex gap-2 pt-1">
            <button onClick={test} disabled={testing} className="btn-secondary text-sm">
              {testing ? <Loader2 className="w-3 h-3 animate-spin" /> : null} Test
            </button>
            <button onClick={save} disabled={saving} className="btn-primary text-sm">
              {saving ? 'Saving…' : isConnected ? 'Update' : 'Connect'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export function Settings() {
  const { currentOrganizationId, user, profile } = useAuth()
  const [tab, setTab] = useState<Tab>('API Keys')
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([])
  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [newKeyName, setNewKeyName] = useState('')
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [loading, setLoading] = useState(true)

  // AI
  const [aiProvider, setAiProvider] = useState('none')
  const [aiKeys, setAiKeys] = useState({ anthropic: '', openai: '', bedrock_key: '', bedrock_secret: '', bedrock_region: 'us-east-1', azure_endpoint: '', azure_key: '', gemini_key: '', openrouter: '', ollama_url: 'http://localhost:11434', fallback_provider: '', disable_deep: false, max_tokens: '50000' })
  const [aiSaving, setAiSaving] = useState(false); const [aiSaved, setAiSaved] = useState(false)

  // Notifs
  const [notif, setNotif] = useState({ slack_webhook: '', notify_critical: true, notify_high: false, weekly_digest: true })
  const [notifSaving, setNotifSaving] = useState(false); const [notifSaved, setNotifSaved] = useState(false)

  // Rate limits (display only for now)
  const [rateLimits, setRateLimits] = useState({ scans_per_hour: 20, scans_per_day: 100, api_requests_per_minute: 60, api_requests_per_hour: 1000 })

  useEffect(() => {
    if (!currentOrganizationId) return
    setLoading(true)
    Promise.all([
      supabase.from('api_keys').select('*').eq('organization_id', currentOrganizationId).order('created_at', { ascending: false }),
      supabase.from('integrations').select('*').eq('organization_id', currentOrganizationId),
      supabase.from('organizations').select('settings, ai_config, rate_limits').eq('id', currentOrganizationId).single(),
    ]).then(([{ data: keys }, { data: ints }, { data: org }]) => {
      setApiKeys((keys as ApiKey[]) || [])
      setIntegrations((ints as Integration[]) || [])
      const ai = (org?.ai_config as Record<string, unknown>) || {}
      setAiProvider((ai.provider as string) || 'none')
      setAiKeys(prev => ({ ...prev, fallback_provider: (ai.fallback_provider as string) || '', disable_deep: ai.disable_deep_tier === true, max_tokens: String(ai.max_tokens_per_scan || 50000) }))
      const notifSettings = ((org?.settings as Record<string, unknown>)?.notifications as Record<string, unknown>) || {}
      setNotif(prev => ({ ...prev, slack_webhook: (notifSettings.slack_webhook as string) || '', notify_critical: notifSettings.notify_critical !== false, notify_high: notifSettings.notify_high === true, weekly_digest: notifSettings.weekly_digest !== false }))
      const rl = (org?.rate_limits as Record<string, number>) || {}
      setRateLimits({ scans_per_hour: rl.scans_per_hour || 20, scans_per_day: rl.scans_per_day || 100, api_requests_per_minute: rl.api_requests_per_minute || 60, api_requests_per_hour: rl.api_requests_per_hour || 1000 })
      setLoading(false)
    })
  }, [currentOrganizationId])

  const generateApiKey = async () => {
    if (!currentOrganizationId || !newKeyName.trim()) return
    const raw = 'og_live_' + Array.from(crypto.getRandomValues(new Uint8Array(24))).map(b => b.toString(16).padStart(2,'0')).join('')
    const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw))
    const hash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2,'0')).join('')
    const { data, error } = await supabase.from('api_keys').insert({ organization_id: currentOrganizationId, name: newKeyName.trim(), key_prefix: raw.slice(0, 12), key_hash: hash, created_by: user?.id }).select().single()
    if (!error && data) { setApiKeys(prev => [data as ApiKey, ...prev]); setCreatedKey(raw); setNewKeyName('') }
  }

  const revokeKey = async (id: string) => {
    await supabase.from('api_keys').update({ is_active: false }).eq('id', id)
    setApiKeys(prev => prev.map(k => k.id === id ? { ...k, is_active: false } : k))
  }

  const saveIntegration = async (provider: string, config: Record<string, string>): Promise<{ ok: boolean; message: string }> => {
    const { data: { session } } = await supabase.auth.getSession()
    if (!session) return { ok: false, message: 'Not authenticated' }
    try {
      const res = await fetch(`${API}/enterprise-integrations/connect`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}` },
        body: JSON.stringify({ provider, config, test_connection: true }),
      })
      const json = await res.json()
      if (json.success) {
        setIntegrations(prev => { const next = prev.filter(i => i.provider !== provider); return [...next, json.data] })
        return { ok: true, message: json.message || 'Connected' }
      }
      return { ok: false, message: json.error || 'Failed' }
    } catch (e) { return { ok: false, message: String(e) } }
  }

  const removeIntegration = async (provider: string) => {
    const { data: { session } } = await supabase.auth.getSession()
    if (!session) return
    await fetch(`${API}/enterprise-integrations/${provider}`, { method: 'DELETE', headers: { Authorization: `Bearer ${session.access_token}` } })
    setIntegrations(prev => prev.map(i => i.provider === provider ? { ...i, status: 'inactive' } : i))
  }

  const saveAI = async () => {
    if (!currentOrganizationId) return
    setAiSaving(true)
    const config: Record<string, unknown> = { provider: aiProvider, fallback_provider: aiKeys.fallback_provider || null, disable_deep_tier: aiKeys.disable_deep, max_tokens_per_scan: parseInt(aiKeys.max_tokens) || 50000 }
    if (aiKeys.anthropic) config.anthropic_api_key = aiKeys.anthropic
    if (aiKeys.openai) config.openai_api_key = aiKeys.openai
    if (aiKeys.bedrock_key) { config.aws_access_key_id = aiKeys.bedrock_key; config.aws_secret_access_key = aiKeys.bedrock_secret; config.aws_region = aiKeys.bedrock_region }
    if (aiKeys.azure_endpoint) { config.azure_openai_endpoint = aiKeys.azure_endpoint; config.azure_openai_key = aiKeys.azure_key }
    if (aiKeys.gemini_key) config.gemini_api_key = aiKeys.gemini_key
    if (aiKeys.openrouter) config.openrouter_api_key = aiKeys.openrouter
    if (aiKeys.ollama_url) config.ollama_url = aiKeys.ollama_url
    await supabase.from('organizations').update({ ai_config: config }).eq('id', currentOrganizationId)
    setAiSaving(false); setAiSaved(true); setTimeout(() => setAiSaved(false), 2000)
  }

  const saveNotifs = async () => {
    if (!currentOrganizationId) return
    setNotifSaving(true)
    await supabase.from('organizations').update({ settings: { notifications: notif } }).eq('id', currentOrganizationId)
    setNotifSaving(false); setNotifSaved(true); setTimeout(() => setNotifSaved(false), 2000)
  }

  const copy = (text: string) => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000) }

  const byCategory = CATEGORY_ORDER.map(cat => ({ cat, defs: INTEGRATIONS.filter(i => i.category === cat) }))
  const existingMap = Object.fromEntries(integrations.filter(i => i.status === 'active').map(i => [i.provider, i]))

  return (
    <div className="p-8 space-y-6 animate-fade-in">
      <div><h1 className="text-3xl font-bold text-white">Settings</h1><p className="text-slate-400 mt-1">Configure integrations, AI, and security policies</p></div>
      <div className="flex gap-1 border-b border-slate-700 pb-px overflow-x-auto">
        {TABS.map(t => <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 text-sm font-medium whitespace-nowrap transition-colors border-b-2 -mb-px ${tab === t ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>{t}</button>)}
      </div>

      {/* ── API Keys ──────────────────────────────────────────── */}
      {tab === 'API Keys' && (
        <div className="space-y-4">
          <div className="card p-4">
            <h3 className="text-slate-200 font-medium mb-3">Generate API Key</h3>
            <p className="text-slate-500 text-sm mb-3">API keys allow CI/CD pipelines, the CLI, and external tools to authenticate.</p>
            <div className="flex gap-3">
              <input className="input max-w-sm" placeholder="Key name (e.g. GitHub Actions)" value={newKeyName} onChange={e => setNewKeyName(e.target.value)} onKeyDown={e => e.key === 'Enter' && generateApiKey()} />
              <button onClick={generateApiKey} disabled={!newKeyName.trim()} className="btn-primary"><Plus className="w-4 h-4" />Generate</button>
            </div>
            {createdKey && (
              <div className="mt-3 p-3 bg-green-500/5 border border-green-500/30 rounded-lg">
                <p className="text-green-400 text-sm font-medium mb-2">Copy now — shown only once:</p>
                <div className="flex items-center gap-2">
                  <code className="text-green-300 font-mono text-sm bg-slate-900 px-3 py-1.5 rounded flex-1 break-all">{createdKey}</code>
                  <button onClick={() => copy(createdKey)} className="btn-secondary text-xs">{copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}</button>
                </div>
                <p className="text-slate-500 text-xs mt-2">CLI: <code className="font-mono bg-slate-800 px-1 rounded">export OMNIGUARD_API_KEY="{createdKey}"</code></p>
                <button onClick={() => setCreatedKey(null)} className="btn-ghost text-xs mt-1 text-slate-500">Dismiss</button>
              </div>
            )}
          </div>
          <div className="card p-4">
            <div className="grid grid-cols-4 gap-3 text-xs mb-3">
              {[['Free', '60/min · 1k/hr'], ['Pro', '300/min · 10k/hr'], ['Enterprise', '1k/min · 100k/hr'], ['Custom', 'Contact us']].map(([plan, limits]) => (
                <div key={plan} className="bg-slate-900 p-2 rounded border border-slate-800"><p className="text-slate-200 font-medium">{plan}</p><p className="text-slate-500">{limits}</p></div>
              ))}
            </div>
            <p className="text-slate-500 text-xs">Rate limit headers returned: <code className="font-mono bg-slate-800 px-1 rounded">X-RateLimit-Limit</code> <code className="font-mono bg-slate-800 px-1 rounded">X-RateLimit-Remaining</code> <code className="font-mono bg-slate-800 px-1 rounded">X-RateLimit-Reset</code></p>
          </div>
          <div className="card overflow-hidden">
            {apiKeys.length === 0 ? <p className="p-8 text-center text-slate-500 text-sm">No API keys yet</p>
            : <table className="w-full text-sm"><thead><tr className="border-b border-slate-700">{['Name','Prefix','Status','Last Used','Created',''].map(h => <th key={h} className="px-4 py-3 text-left text-slate-400 font-medium text-xs uppercase">{h}</th>)}</tr></thead>
              <tbody>{apiKeys.map(k => (
                <tr key={k.id} className="border-b border-slate-800 hover:bg-slate-800/30">
                  <td className="px-4 py-3 text-slate-200 font-medium">{k.name}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">{k.key_prefix}…</td>
                  <td className="px-4 py-3"><span className={`badge text-xs ${k.is_active ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-500'}`}>{k.is_active ? 'Active' : 'Revoked'}</span></td>
                  <td className="px-4 py-3 text-slate-500 text-xs">{k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : 'Never'}</td>
                  <td className="px-4 py-3 text-slate-500 text-xs">{new Date(k.created_at).toLocaleDateString()}</td>
                  <td className="px-4 py-3">{k.is_active && <button onClick={() => revokeKey(k.id)} className="btn-ghost text-red-400 text-xs p-1"><Trash2 className="w-3 h-3" /></button>}</td>
                </tr>
              ))}</tbody></table>}
          </div>
          <div className="card p-4">
            <h4 className="text-slate-300 font-medium mb-2 text-sm">Webhook URL</h4>
            <div className="flex items-center gap-2">
              <code className="text-blue-300 text-xs font-mono bg-slate-900 px-3 py-2 rounded border border-slate-800 flex-1 break-all">{import.meta.env.VITE_SUPABASE_URL}/functions/v1/github-webhook</code>
              <button onClick={() => copy(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/github-webhook`)} className="btn-secondary text-xs">{copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}</button>
            </div>
          </div>
        </div>
      )}

      {/* ── Integrations ─────────────────────────────────────── */}
      {tab === 'Integrations' && (
        <div className="space-y-6">
          {byCategory.map(({ cat, defs }) => (
            <div key={cat}>
              <h3 className="text-slate-400 text-xs font-semibold uppercase tracking-widest mb-3">{cat}</h3>
              <div className="space-y-2">
                {defs.map(def => (
                  <IntegrationCard key={def.provider} def={def} existing={existingMap[def.provider]} onSave={saveIntegration} onRemove={removeIntegration} />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── AI Provider ──────────────────────────────────────── */}
      {tab === 'AI Provider' && (
        <div className="space-y-4">
          <div className="card p-5 bg-blue-500/5 border-blue-500/20">
            <p className="text-blue-300 text-sm font-medium mb-1">BYOK — Bring Your Own Key</p>
            <p className="text-slate-400 text-sm">Keys are stored encrypted per organization. The OmniGuard platform never pays for your AI usage. Without a key, scans run without AI (regex only).</p>
          </div>
          <div className="card p-5 space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label">Primary Provider</label>
                <select className="input" value={aiProvider} onChange={e => setAiProvider(e.target.value)}>
                  <option value="none">None (disable AI features)</option>
                  <option value="anthropic">Anthropic (Claude) — Recommended</option>
                  <option value="openai">OpenAI (GPT-4o)</option>
                  <option value="bedrock">AWS Bedrock (Claude via IAM)</option>
                  <option value="azure">Azure OpenAI</option>
                  <option value="gemini">Google Gemini</option>
                  <option value="openrouter">OpenRouter (any model)</option>
                  <option value="ollama">Ollama (local / air-gapped)</option>
                </select>
              </div>
              <div>
                <label className="label">Fallback Provider (on failure)</label>
                <select className="input" value={aiKeys.fallback_provider} onChange={e => setAiKeys({ ...aiKeys, fallback_provider: e.target.value })}>
                  <option value="">None</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="openai">OpenAI</option>
                  <option value="gemini">Gemini</option>
                  <option value="openrouter">OpenRouter</option>
                </select>
              </div>
            </div>
            {aiProvider === 'anthropic' && <div><label className="label">Anthropic API Key</label><input className="input max-w-lg" type="password" placeholder="sk-ant-api03-..." value={aiKeys.anthropic} onChange={e => setAiKeys({ ...aiKeys, anthropic: e.target.value })} /></div>}
            {aiProvider === 'openai' && <div><label className="label">OpenAI API Key</label><input className="input max-w-lg" type="password" placeholder="sk-proj-..." value={aiKeys.openai} onChange={e => setAiKeys({ ...aiKeys, openai: e.target.value })} /></div>}
            {aiProvider === 'bedrock' && <div className="space-y-3"><div><label className="label">AWS Access Key ID</label><input className="input max-w-lg" type="password" placeholder="AKIA..." value={aiKeys.bedrock_key} onChange={e => setAiKeys({ ...aiKeys, bedrock_key: e.target.value })} /></div><div><label className="label">AWS Secret Access Key</label><input className="input max-w-lg" type="password" value={aiKeys.bedrock_secret} onChange={e => setAiKeys({ ...aiKeys, bedrock_secret: e.target.value })} /></div><div><label className="label">Region</label><input className="input max-w-xs" placeholder="us-east-1" value={aiKeys.bedrock_region} onChange={e => setAiKeys({ ...aiKeys, bedrock_region: e.target.value })} /></div></div>}
            {aiProvider === 'azure' && <div className="space-y-3"><div><label className="label">Azure Endpoint</label><input className="input max-w-lg" placeholder="https://your-resource.openai.azure.com" value={aiKeys.azure_endpoint} onChange={e => setAiKeys({ ...aiKeys, azure_endpoint: e.target.value })} /></div><div><label className="label">Azure Key</label><input className="input max-w-lg" type="password" value={aiKeys.azure_key} onChange={e => setAiKeys({ ...aiKeys, azure_key: e.target.value })} /></div></div>}
            {aiProvider === 'gemini' && <div><label className="label">Gemini API Key</label><input className="input max-w-lg" type="password" placeholder="AIza..." value={aiKeys.gemini_key} onChange={e => setAiKeys({ ...aiKeys, gemini_key: e.target.value })} /></div>}
            {aiProvider === 'openrouter' && <div><label className="label">OpenRouter API Key</label><input className="input max-w-lg" type="password" placeholder="sk-or-..." value={aiKeys.openrouter} onChange={e => setAiKeys({ ...aiKeys, openrouter: e.target.value })} /></div>}
            {aiProvider === 'ollama' && <div><label className="label">Ollama Base URL</label><input className="input max-w-lg" placeholder="http://localhost:11434" value={aiKeys.ollama_url} onChange={e => setAiKeys({ ...aiKeys, ollama_url: e.target.value })} /></div>}
            <div className="grid grid-cols-2 gap-4 pt-2 border-t border-slate-700">
              <div><label className="label">Max Tokens Per Scan</label><input className="input" type="number" value={aiKeys.max_tokens} onChange={e => setAiKeys({ ...aiKeys, max_tokens: e.target.value })} /><p className="text-slate-500 text-xs mt-1">Cap total AI tokens per scan to control cost</p></div>
              <div className="flex items-start gap-3 pt-5"><label className="flex items-center gap-2 cursor-pointer"><div onClick={() => setAiKeys({ ...aiKeys, disable_deep: !aiKeys.disable_deep })} className={`w-10 h-6 rounded-full relative transition-colors ${aiKeys.disable_deep ? 'bg-blue-500' : 'bg-slate-700'}`}><div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${aiKeys.disable_deep ? 'translate-x-5' : 'translate-x-1'}`} /></div><div><span className="text-slate-300 text-sm">Disable Layer 3 (executive summary)</span><p className="text-slate-500 text-xs">Saves ~$0.03/scan · disables CISO report</p></div></label></div>
            </div>
            <button onClick={saveAI} disabled={aiSaving} className="btn-primary">
              {aiSaved ? <><Check className="w-4 h-4" />Saved!</> : aiSaving ? 'Saving…' : 'Save AI Configuration'}
            </button>
          </div>
          <div className="card p-4">
            <h4 className="text-slate-200 font-medium mb-3">Model Routing</h4>
            <div className="grid grid-cols-3 gap-3 text-xs">
              {[['Layer 1 — Triage','Runs first. Fast, cheap. Removes false positives.','Haiku · GPT-4o-mini · Gemini Flash','~$0.001/scan'],
                ['Layer 2 — Analysis','Top 12 critical/high findings. Specific code fixes + RAG policy context.','Sonnet · GPT-4o · Gemini Pro','~$0.02–0.06/scan'],
                ['Layer 3 — Summary','CISO executive report. Optional.','Opus · GPT-4o · Gemini Pro','~$0.03/scan']].map(([l,d,m,c]) => (
                <div key={l} className="bg-slate-900 p-3 rounded border border-slate-800">
                  <p className="text-blue-400 font-semibold mb-1">{l}</p>
                  <p className="text-slate-500 mb-2">{d}</p>
                  <p className="text-slate-300">{m}</p>
                  <p className="text-green-400 mt-1">{c}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Notifications ─────────────────────────────────────── */}
      {tab === 'Notifications' && (
        <div className="space-y-4">
          <div className="card p-5 space-y-3">
            <h3 className="text-white font-semibold">Slack</h3>
            <div><label className="label">Incoming Webhook URL</label><input className="input max-w-lg" placeholder="https://hooks.slack.com/services/..." value={notif.slack_webhook} onChange={e => setNotif({ ...notif, slack_webhook: e.target.value })} /></div>
          </div>
          <div className="card p-5 space-y-4">
            <h3 className="text-white font-semibold">Preferences</h3>
            {[['notify_critical','Immediate alert on critical findings (recommended)'],['notify_high','Alert on high findings'],['weekly_digest','Weekly security digest summary']].map(([k,l]) => (
              <label key={k} className="flex items-center gap-3 cursor-pointer">
                <div onClick={() => setNotif({ ...notif, [k]: !(notif as Record<string,unknown>)[k] })} className={`w-10 h-6 rounded-full relative transition-colors ${(notif as Record<string,unknown>)[k] ? 'bg-blue-500' : 'bg-slate-700'}`}><div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${(notif as Record<string,unknown>)[k] ? 'translate-x-5' : 'translate-x-1'}`} /></div>
                <span className="text-slate-300 text-sm">{l}</span>
              </label>
            ))}
          </div>
          <button onClick={saveNotifs} disabled={notifSaving} className="btn-primary">{notifSaved ? <><Check className="w-4 h-4" />Saved!</> : notifSaving ? 'Saving…' : 'Save'}</button>
        </div>
      )}

      {/* ── Organization ─────────────────────────────────────── */}
      {tab === 'Organization' && (
        <div className="space-y-4">
          <div className="card p-5">
            <h3 className="text-white font-semibold mb-4">Details</h3>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div><p className="label">Organization ID</p><p className="font-mono text-slate-300 text-xs">{currentOrganizationId}</p></div>
              <div><p className="label">Your Email</p><p className="text-slate-300">{profile?.email}</p></div>
            </div>
          </div>
          <div className="card p-5">
            <h3 className="text-white font-semibold mb-4">Rate Limits</h3>
            <div className="grid grid-cols-2 gap-4 text-sm">
              {[['Scans / hour', rateLimits.scans_per_hour],['Scans / day', rateLimits.scans_per_day],['API requests / minute', rateLimits.api_requests_per_minute],['API requests / hour', rateLimits.api_requests_per_hour]].map(([l,v]) => (
                <div key={String(l)} className="bg-slate-900 p-3 rounded border border-slate-800"><p className="text-slate-500 text-xs">{l}</p><p className="text-slate-200 font-mono font-bold text-lg">{v}</p></div>
              ))}
            </div>
            <p className="text-slate-500 text-xs mt-3">To increase limits, upgrade your plan or contact support.</p>
          </div>
        </div>
      )}
    </div>
  )
}
