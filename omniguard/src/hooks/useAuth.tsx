import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { User, Session } from '@supabase/supabase-js'
import { supabase, Tables } from '../lib/supabase'

type Profile = Tables<'user_profiles'>
type Membership = Tables<'organization_members'>

interface AuthCtx {
  user: User | null
  profile: Profile | null
  session: Session | null
  memberships: Membership[]
  currentOrganizationId: string | null
  setCurrentOrganizationId: (id: string) => void
  loading: boolean
  signIn: (email: string, password: string) => Promise<{ error: string | null }>
  signUp: (email: string, password: string, firstName: string, lastName: string) => Promise<{ error: string | null }>
  signOut: () => Promise<void>
}

const Ctx = createContext<AuthCtx>({} as AuthCtx)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [profile, setProfile] = useState<Profile | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [memberships, setMemberships] = useState<Membership[]>([])
  const [currentOrganizationId, setCurrentOrganizationId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session)
      setUser(session?.user ?? null)
      if (session?.user) fetchProfile(session.user.id)
      else setLoading(false)
    })
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session)
      setUser(session?.user ?? null)
      if (session?.user) fetchProfile(session.user.id)
      else { setProfile(null); setMemberships([]); setCurrentOrganizationId(null); setLoading(false) }
    })
    return () => subscription.unsubscribe()
  }, [])

  async function fetchProfile(userId: string) {
    const [{ data: prof }, { data: mems }] = await Promise.all([
      supabase.from('user_profiles').select('*').eq('id', userId).maybeSingle(),
      supabase.from('organization_members').select('*').eq('user_id', userId).eq('status', 'active'),
    ])
    setProfile(prof)
    setMemberships(mems || [])
    if (mems?.length) setCurrentOrganizationId(mems[0].organization_id)
    setLoading(false)
  }

  async function signIn(email: string, password: string) {
    const { error } = await supabase.auth.signInWithPassword({ email, password })
    return { error: error?.message || null }
  }

  async function signUp(email: string, password: string, firstName: string, lastName: string) {
    const { data, error } = await supabase.auth.signUp({
      email, password,
      options: { data: { first_name: firstName, last_name: lastName } },
    })
    if (error) return { error: error.message }
    if (data.user && !error) {
      await supabase.from('user_profiles').upsert({ id: data.user.id, email, first_name: firstName, last_name: lastName })
    }
    return { error: null }
  }

  async function signOut() {
    await supabase.auth.signOut()
    setUser(null); setProfile(null); setSession(null); setMemberships([]); setCurrentOrganizationId(null)
  }

  return (
    <Ctx.Provider value={{ user, profile, session, memberships, currentOrganizationId, setCurrentOrganizationId, loading, signIn, signUp, signOut }}>
      {children}
    </Ctx.Provider>
  )
}

export const useAuth = () => useContext(Ctx)
