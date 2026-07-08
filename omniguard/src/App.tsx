import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './hooks/useAuth'
import { Layout } from './components/Layout'
import { Auth } from './pages/Auth'
import { Dashboard } from './pages/Dashboard'
import { Repositories } from './pages/Repositories'
import { Findings } from './pages/Findings'
import { Scans } from './pages/Scans'
import { Policies } from './pages/Policies'
import { Compliance } from './pages/Compliance'
import { Teams } from './pages/Teams'
import { AuditLogs } from './pages/AuditLogs'
import { Settings } from './pages/Settings'
import { ComingSoon } from './pages/ComingSoon'

function Guard({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: '#0a0f1e' }}>
      <div className="flex flex-col items-center gap-4">
        <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-slate-400 text-sm">Loading OmniGuard…</p>
      </div>
    </div>
  )
  if (!user) return <Navigate to="/auth" replace />
  return <>{children}</>
}

function AppRoutes() {
  const { user, loading } = useAuth()
  if (loading) return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: '#0a0f1e' }}>
      <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
    </div>
  )
  return (
    <Routes>
      <Route path="/auth" element={user ? <Navigate to="/" replace /> : <Auth />} />
      <Route path="/*" element={
        <Guard>
          <Layout>
            <Routes>
              {/* Overview */}
              <Route path="/" element={<Dashboard />} />
              <Route path="/security-posture" element={<ComingSoon title="Security Posture" description="Comprehensive security posture assessment with historical trends and benchmarking." />} />
              <Route path="/attack-surface" element={<ComingSoon title="Attack Surface" description="Visualize and manage your organization's attack surface across all assets." />} />
              <Route path="/threat-insights" element={<ComingSoon title="Threat Insights" description="Real-time threat intelligence and security event correlation." />} />

              {/* Assets */}
              <Route path="/organizations" element={<ComingSoon title="Organizations" description="Manage your organizations and their security settings." />} />
              <Route path="/projects" element={<ComingSoon title="Projects" description="Group repositories into projects for easier management." />} />
              <Route path="/repositories" element={<Repositories />} />
              <Route path="/cloud-assets" element={<ComingSoon title="Cloud Assets" description="Inventory and security assessment of cloud infrastructure assets." />} />
              <Route path="/sbom" element={<ComingSoon title="SBOM Inventory" description="Software Bill of Materials management and vulnerability tracking." />} />

              {/* Security */}
              <Route path="/findings" element={<Findings />} />
              <Route path="/scans" element={<Scans />} />
              <Route path="/policies" element={<Policies />} />
              <Route path="/compliance" element={<Compliance />} />
              <Route path="/risk-analysis" element={<ComingSoon title="Risk Analysis" description="Advanced risk scoring and prioritization based on business context." />} />

              {/* AI Center */}
              <Route path="/ai-center" element={<ComingSoon title="AI Analysis Center" description="AI-powered security analysis, remediation suggestions, and pattern recognition." />} />
              <Route path="/knowledge-base" element={<ComingSoon title="Knowledge Base" description="Custom security policies, rules, and organizational context for AI analysis." />} />
              <Route path="/policy-marketplace" element={<ComingSoon title="Policy Marketplace" description="Community-curated security policies and detection rules." />} />

              {/* Team */}
              <Route path="/developers" element={<ComingSoon title="Developers" description="View and manage developer access and security metrics." />} />
              <Route path="/teams" element={<Teams />} />
              <Route path="/scorecards" element={<ComingSoon title="Developer Scorecards" description="Security awareness metrics and developer training progress." />} />

              {/* Integrations */}
              <Route path="/integrations" element={<ComingSoon title="Integrations" description="Connect with GitHub, GitLab, Jira, Slack, and more." />} />
              <Route path="/webhooks" element={<ComingSoon title="Webhooks" description="Configure webhooks for real-time security event notifications." />} />
              <Route path="/api-keys" element={<ComingSoon title="API Keys" description="Manage API keys for programmatic access to OmniGuard." />} />
              <Route path="/agents" element={<ComingSoon title="Agents" description="Manage local agents and daemon configurations." />} />

              {/* Administration */}
              <Route path="/audit-logs" element={<AuditLogs />} />
              <Route path="/reports" element={<ComingSoon title="Reports" description="Generate and schedule security reports for stakeholders." />} />
              <Route path="/billing" element={<ComingSoon title="Billing" description="Manage subscription, usage, and billing information." />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/notifications" element={<ComingSoon title="Notifications" description="Configure notification preferences and delivery settings." />} />

              {/* Catch-all */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Layout>
        </Guard>
      } />
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  )
}
