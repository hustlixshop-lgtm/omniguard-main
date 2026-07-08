import { useState, useEffect } from 'react'
import { NavLink, useNavigate, useLocation, useParams } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { useNotifications } from '../hooks/useRepositories'
import { Shield, LayoutDashboard, GitBranch, TriangleAlert, Play, ClipboardList, ShieldCheck, Users, FileText, Settings, LogOut, Bell, X, ChevronDown, ChevronRight, Search, Building2, Projector as Projects, Server, Lock, Key, Globe, Activity, ChartBar as BarChart3, Cloud, Code, Package, Layers, Brain, BookOpen, CreditCard, UserCog, Puzzle, Zap, ExternalLink, Command, Menu, Moon, Sun, Circle as HelpCircle, Briefcase, Target, CircleAlert as AlertCircle, TrendingUp, BadgeCheck } from 'lucide-react'

interface NavGroup {
  label: string
  items: NavItem[]
}

interface NavItem {
  to: string
  icon: any
  label: string
  badge?: string | number
  badgeColor?: string
  exact?: boolean
  children?: NavItem[]
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Overview',
    items: [
      { to: '/', icon: LayoutDashboard, label: 'Dashboard', exact: true },
      { to: '/security-posture', icon: Shield, label: 'Security Posture' },
      { to: '/attack-surface', icon: Target, label: 'Attack Surface' },
      { to: '/threat-insights', icon: AlertCircle, label: 'Threat Insights', badge: 'New', badgeColor: 'bg-blue-500' },
    ]
  },
  {
    label: 'Assets',
    items: [
      { to: '/organizations', icon: Building2, label: 'Organizations' },
      { to: '/projects', icon: Projects, label: 'Projects' },
      { to: '/repositories', icon: GitBranch, label: 'Repositories' },
      { to: '/cloud-assets', icon: Cloud, label: 'Cloud Assets' },
      { to: '/sbom', icon: Package, label: 'SBOM Inventory' },
    ]
  },
  {
    label: 'Security',
    items: [
      { to: '/findings', icon: TriangleAlert, label: 'Findings' },
      { to: '/scans', icon: Play, label: 'Scans' },
      { to: '/policies', icon: ClipboardList, label: 'Policies' },
      { to: '/compliance', icon: ShieldCheck, label: 'Compliance' },
      { to: '/risk-analysis', icon: TrendingUp, label: 'Risk Analysis' },
    ]
  },
  {
    label: 'AI Center',
    items: [
      { to: '/ai-center', icon: Brain, label: 'AI Analysis' },
      { to: '/knowledge-base', icon: BookOpen, label: 'Knowledge Base' },
      { to: '/policy-marketplace', icon: Puzzle, label: 'Policy Marketplace', badge: 'Beta', badgeColor: 'bg-purple-500' },
    ]
  },
  {
    label: 'Team',
    items: [
      { to: '/developers', icon: Code, label: 'Developers' },
      { to: '/teams', icon: Users, label: 'Teams' },
      { to: '/scorecards', icon: BadgeCheck, label: 'Developer Scorecards' },
    ]
  },
  {
    label: 'Integrations',
    items: [
      { to: '/integrations', icon: Layers, label: 'Integrations' },
      { to: '/webhooks', icon: Zap, label: 'Webhooks' },
      { to: '/api-keys', icon: Key, label: 'API Keys' },
      { to: '/agents', icon: Server, label: 'Agents' },
    ]
  },
  {
    label: 'Administration',
    items: [
      { to: '/audit-logs', icon: FileText, label: 'Audit Logs' },
      { to: '/reports', icon: BarChart3, label: 'Reports' },
      { to: '/billing', icon: CreditCard, label: 'Billing' },
      { to: '/settings', icon: Settings, label: 'Settings' },
    ]
  },
]

function CollapsibleGroup({ label, items, defaultExpanded }: { label: string; items: NavItem[]; defaultExpanded?: boolean }) {
  const [expanded, setExpanded] = useState(defaultExpanded ?? true)
  const location = useLocation()

  // Auto-expand if any child is active
  useEffect(() => {
    const isActive = items.some(item => {
      if (item.exact) return location.pathname === item.to
      return location.pathname.startsWith(item.to)
    })
    if (isActive) setExpanded(true)
  }, [location.pathname, items])

  return (
    <div className="mb-1">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-2 text-xs font-semibold text-slate-500 uppercase tracking-wider hover:text-slate-400 transition-colors"
      >
        <span>{label}</span>
        {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
      </button>
      {expanded && (
        <nav className="space-y-0.5">
          {items.map((item) => (
            <NavItem key={item.to} item={item} />
          ))}
        </nav>
      )}
    </div>
  )
}

function NavItem({ item }: { item: NavItem }) {
  const location = useLocation()
  const isActive = item.exact
    ? location.pathname === item.to
    : location.pathname.startsWith(item.to) && item.to !== '/'

  return (
    <NavLink
      to={item.to}
      end={item.exact}
      className={({ isActive }) =>
        `sidebar-link ${isActive ? 'sidebar-link-active' : ''}`
      }
    >
      <item.icon className="w-4 h-4 flex-shrink-0" />
      <span className="flex-1 truncate">{item.label}</span>
      {item.badge && (
        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${item.badgeColor || 'bg-slate-600'} text-white`}>
          {item.badge}
        </span>
      )}
    </NavLink>
  )
}

function SearchModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState('')
  const navigate = useNavigate()

  const allItems = NAV_GROUPS.flatMap(g => g.items)
  const filtered = query
    ? allItems.filter(item => item.label.toLowerCase().includes(query.toLowerCase()))
    : allItems.slice(0, 6)

  useEffect(() => {
    if (open) setQuery('')
  }, [open])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-24 px-4" onClick={onClose}>
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" />
      <div
        className="relative w-full max-w-xl bg-slate-800 border border-slate-700 rounded-xl shadow-2xl overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 p-4 border-b border-slate-700">
          <Search className="w-5 h-5 text-slate-500" />
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search commands, pages, settings..."
            className="flex-1 bg-transparent text-white text-lg outline-none placeholder:text-slate-500"
            autoFocus
          />
          <kbd className="hidden md:inline-flex items-center gap-1 px-2 py-1 text-xs text-slate-500 bg-slate-900 rounded">
            <Command className="w-3 h-3" />K
          </kbd>
        </div>
        <div className="max-h-80 overflow-y-auto">
          {filtered.length === 0 ? (
            <div className="p-8 text-center text-slate-500">
              <Search className="w-8 h-8 mx-auto mb-2" />
              <p>No results found</p>
            </div>
          ) : (
            <div className="p-2">
              {filtered.map((item) => (
                <button
                  key={item.to}
                  onClick={() => {
                    navigate(item.to)
                    onClose()
                  }}
                  className="w-full flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-slate-700/50 transition-colors text-left"
                >
                  <item.icon className="w-5 h-5 text-slate-400" />
                  <span className="text-slate-200">{item.label}</span>
                  {item.badge && (
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${item.badgeColor || 'bg-slate-600'} text-white`}>
                      {item.badge}
                    </span>
                  )}
                  <ChevronRight className="w-4 h-4 text-slate-600 ml-auto" />
                </button>
              ))}
            </div>
          )}
        </div>
        <div className="p-3 border-t border-slate-700 flex items-center gap-4 text-xs text-slate-500">
          <span className="flex items-center gap-1"><kbd className="px-1.5 py-0.5 bg-slate-900 rounded">↑</kbd><kbd className="px-1.5 py-0.5 bg-slate-900 rounded">↓</kbd> Navigate</span>
          <span className="flex items-center gap-1"><kbd className="px-1.5 py-0.5 bg-slate-900 rounded">Enter</kbd> Select</span>
          <span className="flex items-center gap-1"><kbd className="px-1.5 py-0.5 bg-slate-900 rounded">Esc</kbd> Close</span>
        </div>
      </div>
    </div>
  )
}

export function Layout({ children }: { children: React.ReactNode }) {
  const { user, profile, memberships, currentOrganizationId, setCurrentOrganizationId, signOut } = useAuth()
  const { notifications, unreadCount, markAllRead } = useNotifications(user?.id || null)
  const [showNotifs, setShowNotifs] = useState(false)
  const [showOrgMenu, setShowOrgMenu] = useState(false)
  const [showUserMenu, setShowUserMenu] = useState(false)
  const [showSearch, setShowSearch] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const navigate = useNavigate()

  const orgs = memberships.map(m => ({ id: m.organization_id, name: m.organization_id.slice(0, 8), role: m.role }))
  const displayName = profile ? `${profile.first_name || ''} ${profile.last_name || ''}`.trim() || profile.email : user?.email || ''
  const initials = displayName.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2) || 'U'

  // Keyboard shortcut for search
  useEffect(() => {
    const handleKeydown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setShowSearch(true)
      }
      if (e.key === 'Escape') {
        setShowSearch(false)
        setShowNotifs(false)
        setShowOrgMenu(false)
        setShowUserMenu(false)
      }
    }
    window.addEventListener('keydown', handleKeydown)
    return () => window.removeEventListener('keydown', handleKeydown)
  }, [])

  return (
    <div className="flex min-h-screen bg-[#0a0f1e]">
      {/* Mobile Menu Overlay */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 flex flex-col bg-[#0f172a] border-r border-[#1e293b] transition-all duration-300 ${
          sidebarCollapsed ? 'w-16' : 'w-60'
        } ${mobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}
      >
        {/* Logo Header */}
        <div className="flex items-center gap-2 px-4 h-14 border-b border-[#1e293b]">
          <Shield className="w-7 h-7 text-blue-500 flex-shrink-0" />
          {!sidebarCollapsed && (
            <span className="text-white font-bold text-lg tracking-tight">OmniGuard</span>
          )}
          <button
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="hidden lg:flex ml-auto p-1 rounded hover:bg-slate-800 text-slate-500 hover:text-slate-300 transition-colors"
          >
            <Menu className="w-4 h-4" />
          </button>
        </div>

        {/* Organization Switcher */}
        {!sidebarCollapsed && orgs.length > 1 && (
          <div className="px-3 py-2 border-b border-[#1e293b]">
            <div className="relative">
              <button
                onClick={() => setShowOrgMenu(!showOrgMenu)}
                className="w-full flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800/50 hover:bg-slate-800 text-left transition-colors"
              >
                <Building2 className="w-4 h-4 text-slate-400 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="text-xs text-slate-500">Organization</div>
                  <div className="text-sm text-slate-200 truncate">
                    {currentOrganizationId?.slice(0, 12)}...
                  </div>
                </div>
                <ChevronDown className={`w-4 h-4 text-slate-500 transition-transform ${showOrgMenu ? 'rotate-180' : ''}`} />
              </button>
              {showOrgMenu && (
                <div className="absolute top-full left-0 right-0 mt-1 bg-slate-800 border border-slate-700 rounded-lg shadow-xl z-50 overflow-hidden">
                  {orgs.map(o => (
                    <button
                      key={o.id}
                      onClick={() => {
                        setCurrentOrganizationId(o.id)
                        setShowOrgMenu(false)
                      }}
                      className={`w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-slate-700/50 transition-colors ${
                        currentOrganizationId === o.id ? 'bg-blue-500/10 text-blue-400' : 'text-slate-300'
                      }`}
                    >
                      <Building2 className="w-4 h-4" />
                      <div className="flex-1 min-w-0">
                        <div className="text-sm truncate">{o.id.slice(0, 12)}...</div>
                        <div className="text-xs text-slate-500 capitalize">{o.role}</div>
                      </div>
                      {currentOrganizationId === o.id && (
                        <BadgeCheck className="w-4 h-4 text-blue-400" />
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Navigation */}
        <div className="flex-1 overflow-y-auto py-2">
          {NAV_GROUPS.map((group, i) => (
            <CollapsibleGroup
              key={group.label}
              label={group.label}
              items={group.items}
              defaultExpanded={i < 3}
            />
          ))}
        </div>

        {/* User Section */}
        <div className="border-t border-[#1e293b] p-3">
          {!sidebarCollapsed ? (
            <div className="relative">
              <button
                onClick={() => setShowUserMenu(!showUserMenu)}
                className="w-full flex items-center gap-3 px-2 py-2 rounded-lg hover:bg-slate-800/50 transition-colors"
              >
                <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-sm font-bold">
                  {initials}
                </div>
                <div className="flex-1 min-w-0 text-left">
                  <div className="text-sm text-slate-200 truncate">{displayName}</div>
                  <div className="text-xs text-slate-500 truncate">{user?.email}</div>
                </div>
                <ChevronDown className={`w-4 h-4 text-slate-500 transition-transform ${showUserMenu ? 'rotate-180' : ''}`} />
              </button>
              {showUserMenu && (
                <div className="absolute bottom-full left-0 right-0 mb-1 bg-slate-800 border border-slate-700 rounded-lg shadow-xl z-50 overflow-hidden">
                  <NavLink
                    to="/settings"
                    onClick={() => setShowUserMenu(false)}
                    className="flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:bg-slate-700/50 transition-colors"
                  >
                    <UserCog className="w-4 h-4" />
                    Account Settings
                  </NavLink>
                  <button
                    onClick={() => { signOut().then(() => navigate('/auth')) }}
                    className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-400 hover:bg-slate-700/50 transition-colors"
                  >
                    <LogOut className="w-4 h-4" />
                    Sign out
                  </button>
                </div>
              )}
            </div>
          ) : (
            <button
              onClick={() => setSidebarCollapsed(false)}
              className="w-8 h-8 mx-auto rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-sm font-bold"
            >
              {initials}
            </button>
          )}
        </div>
      </aside>

      {/* Main Content */}
      <div className={`flex-1 flex flex-col min-h-screen transition-all duration-300 ${sidebarCollapsed ? 'lg:ml-16' : 'lg:ml-60'}`}>
        {/* Top Bar */}
        <header className="sticky top-0 z-40 flex items-center justify-between gap-4 px-4 md:px-6 h-14 border-b border-[#1e293b] bg-[#0a0f1e]/80 backdrop-blur-sm">
          {/* Mobile Menu Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="lg:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <Menu className="w-5 h-5" />
          </button>

          {/* Search */}
          <button
            onClick={() => setShowSearch(true)}
            className="hidden md:flex items-center gap-3 px-4 py-2 w-72 bg-slate-800/50 border border-slate-700/50 rounded-lg text-slate-500 hover:border-slate-600 transition-colors"
          >
            <Search className="w-4 h-4" />
            <span className="text-sm">Search...</span>
            <kbd className="ml-auto text-xs text-slate-600 bg-slate-900 px-1.5 py-0.5 rounded">⌘K</kbd>
          </button>

          {/* Right Side */}
          <div className="flex items-center gap-2">
            {/* Quick Links */}
            <div className="hidden md:flex items-center gap-1 mr-2">
              <a
                href="https://docs.omniguard.io"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                title="Documentation"
              >
                <BookOpen className="w-4 h-4" />
              </a>
              <a
                href="https://github.com/omniguard/omniguard"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                title="GitHub"
              >
                <GitBranch className="w-4 h-4" />
              </a>
            </div>

            {/* Notifications */}
            <div className="relative">
              <button
                onClick={() => {
                  setShowNotifs(!showNotifs)
                  if (!showNotifs && unreadCount > 0) markAllRead()
                }}
                className="relative p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <Bell className="w-5 h-5" />
                {unreadCount > 0 && (
                  <span className="absolute top-0.5 right-0.5 w-4 h-4 bg-red-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center">
                    {unreadCount > 9 ? '9+' : unreadCount}
                  </span>
                )}
              </button>

              {/* Notifications Dropdown */}
              {showNotifs && (
                <div className="absolute right-0 top-full mt-2 w-80 bg-slate-800 border border-slate-700 rounded-xl shadow-2xl z-50 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
                    <span className="text-sm font-medium text-slate-200">Notifications</span>
                    <button
                      onClick={() => setShowNotifs(false)}
                      className="p-1 rounded text-slate-500 hover:text-slate-300 hover:bg-slate-700 transition-colors"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="max-h-96 overflow-y-auto">
                    {notifications.length === 0 ? (
                      <div className="px-4 py-8 text-center">
                        <Bell className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                        <p className="text-sm text-slate-500">No notifications</p>
                      </div>
                    ) : (
                      notifications.slice(0, 20).map(n => (
                        <div
                          key={n.id}
                          className={`px-4 py-3 border-b border-slate-800 hover:bg-slate-750 transition-colors ${!n.read_at ? 'bg-blue-500/5' : ''}`}
                        >
                          <div className="flex items-start gap-2">
                            {!n.read_at && (
                              <div className="w-2 h-2 bg-blue-500 rounded-full mt-1.5 flex-shrink-0" />
                            )}
                            <div className="flex-1 min-w-0">
                              <p className="text-sm text-slate-200 font-medium">{n.title}</p>
                              {n.body && (
                                <p className="text-xs text-slate-400 mt-0.5 line-clamp-2">{n.body}</p>
                              )}
                              <p className="text-xs text-slate-600 mt-1">
                                {new Date(n.created_at).toLocaleString()}
                              </p>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                  {notifications.length > 0 && (
                    <div className="p-3 border-t border-slate-700">
                      <Link
                        to="/notifications"
                        onClick={() => setShowNotifs(false)}
                        className="block text-center text-sm text-blue-400 hover:text-blue-300"
                      >
                        View all notifications
                      </Link>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Quick Actions */}
            <Link
              to="/scans"
              className="hidden md:flex btn-primary text-sm py-1.5"
            >
              <Play className="w-4 h-4" />
              New Scan
            </Link>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-auto">{children}</main>

        {/* Footer */}
        <footer className="hidden md:flex items-center justify-between px-6 py-3 border-t border-[#1e293b] text-xs text-slate-600">
          <div className="flex items-center gap-4">
            <span>OmniGuard v1.0.0</span>
            <span>·</span>
            <a href="https://status.omniguard.io" target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 hover:text-slate-400">
              <Activity className="w-3 h-3" />
              System Status
            </a>
          </div>
          <div className="flex items-center gap-4">
            <a href="https://docs.omniguard.io" target="_blank" rel="noopener noreferrer" className="hover:text-slate-400">
              Docs
            </a>
            <a href="https://github.com/omniguard/omniguard" target="_blank" rel="noopener noreferrer" className="hover:text-slate-400">
              GitHub
            </a>
            <a href="mailto:support@omniguard.io" className="hover:text-slate-400">
              Support
            </a>
          </div>
        </footer>
      </div>

      {/* Search Modal */}
      <SearchModal open={showSearch} onClose={() => setShowSearch(false)} />
    </div>
  )
}
