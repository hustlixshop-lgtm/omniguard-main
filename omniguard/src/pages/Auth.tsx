import { useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import { supabase } from '../lib/supabase'
import { Shield, Eye, EyeOff } from 'lucide-react'

export function Auth() {
  const { signIn, signUp } = useAuth()
  const [mode, setMode] = useState<'signin' | 'signup'>('signin')
  const [form, setForm] = useState({ email: '', password: '', firstName: '', lastName: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [success, setSuccess] = useState('')

  const handle = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(''); setLoading(true)
    if (mode === 'signin') {
      const { error: err } = await signIn(form.email, form.password)
      if (err) setError(err)
    } else {
      if (!form.firstName.trim()) { setError('First name required'); setLoading(false); return }
      const { error: err } = await signUp(form.email, form.password, form.firstName, form.lastName)
      if (err) setError(err)
      else {
        // After signup, create org and membership
        const slug = form.email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '-') + '-' + Date.now().toString(36)
        const { data: org } = await supabase.from('organizations').insert({ name: `${form.firstName}'s Organization`, slug }).select().single()
        if (org) {
          const { data: { user } } = await supabase.auth.getUser()
          if (user) await supabase.from('organization_members').insert({ organization_id: org.id, user_id: user.id, role: 'owner', status: 'active' })
        }
        setSuccess('Account created! Signing you in...')
        const { error: si } = await signIn(form.email, form.password)
        if (si) { setError(si); setSuccess('') }
      }
    }
    setLoading(false)
  }

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: '#0a0f1e' }}>
      <div className="w-full max-w-md px-4">
        <div className="card-elevated p-8">
          <div className="flex items-center gap-3 mb-8">
            <div className="w-10 h-10 bg-blue-500/20 rounded-xl flex items-center justify-center border border-blue-500/30">
              <Shield className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">OmniGuard</h1>
              <p className="text-xs text-slate-400">AI-Powered Security Platform</p>
            </div>
          </div>

          <h2 className="text-2xl font-bold text-white mb-1">{mode === 'signin' ? 'Sign in' : 'Create account'}</h2>
          <p className="text-slate-400 text-sm mb-6">{mode === 'signin' ? 'Welcome back' : 'Start securing your code'}</p>

          <form onSubmit={handle} className="space-y-4">
            {mode === 'signup' && (
              <div className="grid grid-cols-2 gap-3">
                <div><label className="label">First name</label><input className="input" value={form.firstName} onChange={e => setForm({ ...form, firstName: e.target.value })} placeholder="Jane" required /></div>
                <div><label className="label">Last name</label><input className="input" value={form.lastName} onChange={e => setForm({ ...form, lastName: e.target.value })} placeholder="Smith" /></div>
              </div>
            )}
            <div>
              <label className="label">Email</label>
              <input type="email" className="input" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} placeholder="you@company.com" required autoComplete="email" />
            </div>
            <div>
              <label className="label">Password</label>
              <div className="relative">
                <input type={showPw ? 'text' : 'password'} className="input pr-10" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} placeholder="Min 6 characters" required minLength={6} autoComplete={mode === 'signup' ? 'new-password' : 'current-password'} />
                <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {error && <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">{error}</div>}
            {success && <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg text-green-400 text-sm">{success}</div>}

            <button type="submit" disabled={loading} className="btn-primary w-full justify-center py-2.5">
              {loading ? 'Please wait...' : mode === 'signin' ? 'Sign in' : 'Create account'}
            </button>
          </form>

          <p className="text-center text-sm text-slate-500 mt-4">
            {mode === 'signin' ? "Don't have an account? " : 'Already have an account? '}
            <button onClick={() => { setMode(mode === 'signin' ? 'signup' : 'signin'); setError('') }} className="text-blue-400 hover:text-blue-300">
              {mode === 'signin' ? 'Sign up' : 'Sign in'}
            </button>
          </p>
        </div>
      </div>
    </div>
  )
}
