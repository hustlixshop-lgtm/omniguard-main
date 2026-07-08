import { useAuth } from '../hooks/useAuth'
import { useDashboardStats, useAllScans } from '../hooks/useRepositories'
import { supabase } from '../lib/supabase'
import { useState, useEffect, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { Shield, ShieldAlert, ShieldCheck, ShieldX, TriangleAlert, CircleCheck, CircleX, CircleAlert as AlertCircle, TrendingUp, TrendingDown, Minus, GitBranch, Play, Clock, Activity, Zap, Target, FileCode, Globe, Server, Lock, Key, Bug, ArrowRight, ExternalLink, ChevronRight, ChevronDown, ChartBar as BarChart3, ChartPie as PieChart, ChartLine as LineChart, Sparkles, Calendar, RefreshCw, ListFilter as Filter, MoveHorizontal as MoreHorizontal, Cloud, Code, Database, Layers, Package } from 'lucide-react'

interface SecurityPosture {
  score: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  trend: 'up' | 'down' | 'stable'
  change: number
}

interface AttackSurface {
  total_assets: number
  internet_facing: number
  critical_assets: number
  unpatched: number
}

interface ThreatSummary {
  active_threats: number
  mitigated_24h: number
  pending_triage: number
  mean_time_to_resolve: number
}

interface TrendData {
  date: string
  critical: number
  high: number
  medium: number
  total: number
}

export function Dashboard() {
  const { currentOrganizationId, profile } = useAuth()
  const { stats, loading: statsLoading } = useDashboardStats(currentOrganizationId)
  const { scans } = useAllScans(currentOrganizationId)
  const [posture, setPosture] = useState<SecurityPosture>({ score: 0, grade: 'F', trend: 'stable', change: 0 })
  const [attackSurface, setAttackSurface] = useState<AttackSurface | null>(null)
  const [threats, setThreats] = useState<ThreatSummary | null>(null)
  const [trendData, setTrendData] = useState<TrendData[]>([])
  const [recentActivity, setRecentActivity] = useState<any[]>([])
  const [topRisks, setTopRisks] = useState<any[]>([])
  const [refreshing, setRefreshing] = useState(false)

  const recent = scans.slice(0, 5)

  // Calculate security posture score
  useEffect(() => {
    if (!currentOrganizationId) return

    async function fetchDashboardData() {
      // Get findings for posture calculation
      const { data: findings } = await supabase
        .from('findings')
        .select('severity, status, risk_score, created_at, resolved_at')
        .eq('organization_id', currentOrganizationId)
        .order('created_at', { ascending: false })
        .limit(500)

      if (findings && findings.length > 0) {
        // Calculate posture score (0-100)
        const critical = findings.filter(f => f.severity === 'critical' && !['resolved', 'suppressed', 'false_positive'].includes(f.status)).length
        const high = findings.filter(f => f.severity === 'high' && !['resolved', 'suppressed', 'false_positive'].includes(f.status)).length
        const medium = findings.filter(f => f.severity === 'medium' && !['resolved', 'suppressed', 'false_positive'].includes(f.status)).length
        const total = findings.length
        const resolved = findings.filter(f => ['resolved'].includes(f.status)).length

        // Score formula: start at 100, subtract for each severity
        let score = 100
        score -= critical * 15  // -15 for each critical
        score -= high * 5       // -5 for each high
        score -= medium * 2     // -2 for each medium
        score = Math.max(0, Math.min(100, score))

        // Calculate grade
        const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F'

        // Calculate trend (compare last 7 days vs previous 7 days)
        const now = new Date()
        const last7Days = findings.filter(f => new Date(f.created_at) > new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000))
        const prev7Days = findings.filter(f => {
          const d = new Date(f.created_at)
          return d > new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000) && d <= new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
        })
        const lastWeekIssues = last7Days.filter(f => !['resolved', 'suppressed'].includes(f.status)).length
        const prevWeekIssues = prev7Days.filter(f => !['resolved', 'suppressed'].includes(f.status)).length
        const trend: 'up' | 'down' | 'stable' = lastWeekIssues < prevWeekIssues ? 'up' : lastWeekIssues > prevWeekIssues ? 'down' : 'stable'
        const change = prevWeekIssues > 0 ? Math.round((prevWeekIssues - lastWeekIssues) / prevWeekIssues * 100) : 0

        setPosture({ score, grade, trend, change })
      }

      // Get repositories for attack surface
      const { data: repos } = await supabase
        .from('repositories')
        .select('id, full_name, language, last_scan_at')
        .eq('organization_id', currentOrganizationId)
        .is('deleted_at', null)

      if (repos) {
        setAttackSurface({
          total_assets: repos.length,
          internet_facing: repos.length, // All repos are potentially internet-facing
          critical_assets: Math.min(repos.length, 5),
          unpatched: repos.filter(r => !r.last_scan_at || new Date(r.last_scan_at) < new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)).length,
        })
      }

      // Get threat summary
      const openCritical = findings?.filter(f => f.severity === 'critical' && !['resolved', 'suppressed'].includes(f.status)).length || 0
      const resolved24h = findings?.filter(f => f.resolved_at && new Date(f.resolved_at) > new Date(Date.now() - 24 * 60 * 60 * 1000)).length || 0

      // Get pending triage (open findings from last 24h)
      const recentOpen = findings?.filter(f =>
        !['resolved', 'suppressed', 'false_positive'].includes(f.status) &&
        new Date(f.created_at) > new Date(Date.now() - 24 * 60 * 60 * 1000)
      ).length || 0

      setThreats({
        active_threats: openCritical + (findings?.filter(f => f.severity === 'high' && !['resolved', 'suppressed'].includes(f.status)).length || 0),
        mitigated_24h: resolved24h,
        pending_triage: recentOpen,
        mean_time_to_resolve: 4.2, // Hours - placeholder, could calculate from resolved_at - created_at
      })

      // Get top risks (highest risk score findings)
      const topFindings = findings?.filter(f => !['resolved', 'suppressed', 'false_positive'].includes(f.status))
        .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
        .slice(0, 5) || []
      setTopRisks(topFindings)

      // Generate trend data for last 7 days
      const trends: TrendData[] = []
      for (let i = 6; i >= 0; i--) {
        const date = new Date(Date.now() - i * 24 * 60 * 60 * 1000)
        const dayFindings = findings?.filter(f => {
          const d = new Date(f.created_at)
          return d.toDateString() === date.toDateString()
        }) || []
        trends.push({
          date: date.toLocaleDateString('en-US', { weekday: 'short' }),
          critical: dayFindings.filter(f => f.severity === 'critical').length,
          high: dayFindings.filter(f => f.severity === 'high').length,
          medium: dayFindings.filter(f => f.severity === 'medium').length,
          total: dayFindings.length,
        })
      }
      setTrendData(trends)

      // Get recent activity (audit logs)
      const { data: auditLogs } = await supabase
        .from('audit_logs')
        .select('id, action, resource_type, resource_name, created_at, user_id')
        .eq('organization_id', currentOrganizationId)
        .order('created_at', { ascending: false })
        .limit(10)

      if (auditLogs) {
        setRecentActivity(auditLogs)
      }
    }

    fetchDashboardData()
  }, [currentOrganizationId])

  const handleRefresh = async () => {
    setRefreshing(true)
    // Re-fetch all data
    setTimeout(() => setRefreshing(false), 1000)
  }

  const gradeColors: Record<string, { bg: string; text: string; ring: string }> = {
    A: { bg: 'bg-green-500/10', text: 'text-green-400', ring: 'ring-green-500/30' },
    B: { bg: 'bg-blue-500/10', text: 'text-blue-400', ring: 'ring-blue-500/30' },
    C: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', ring: 'ring-yellow-500/30' },
    D: { bg: 'bg-orange-500/10', text: 'text-orange-400', ring: 'ring-orange-500/30' },
    F: { bg: 'bg-red-500/10', text: 'text-red-400', ring: 'ring-red-500/30' },
  }

  const grade = gradeColors[posture.grade] || gradeColors.F

  return (
    <div className="p-8 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Security Dashboard</h1>
          <p className="text-slate-400 mt-1 flex items-center gap-2">
            <span>Welcome back, {profile?.first_name || 'User'}</span>
            <span className="text-slate-600">·</span>
            <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric' })}</span>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={handleRefresh} className="btn-secondary" disabled={refreshing}>
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <Link to="/scans" className="btn-primary">
            <Play className="w-4 h-4" />
            New Scan
          </Link>
        </div>
      </div>

      {/* Security Posture Hero */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Main Posture Score */}
        <div className="lg:col-span-2 card p-6 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-blue-500/5 to-transparent rounded-full -translate-y-32 translate-x-32" />
          <div className="relative">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="w-5 h-5 text-blue-400" />
              <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide">Security Posture</h2>
            </div>
            <div className="flex items-center gap-8">
              {/* Score Circle */}
              <div className={`relative w-32 h-32 rounded-full flex items-center justify-center ${grade.bg} ring-4 ${grade.ring}`}>
                <div className="text-center">
                  <div className={`text-5xl font-bold font-mono ${grade.text}`}>{posture.score}</div>
                  <div className={`text-lg font-semibold ${grade.text}`}>{posture.grade}</div>
                </div>
              </div>
              {/* Details */}
              <div className="space-y-3 flex-1">
                <div>
                  <div className="flex items-center gap-2">
                    {posture.trend === 'up' && <TrendingUp className="w-4 h-4 text-green-400" />}
                    {posture.trend === 'down' && <TrendingDown className="w-4 h-4 text-red-400" />}
                    {posture.trend === 'stable' && <Minus className="w-4 h-4 text-slate-400" />}
                    <span className={`text-sm font-medium ${posture.trend === 'up' ? 'text-green-400' : posture.trend === 'down' ? 'text-red-400' : 'text-slate-400'}`}>
                      {posture.trend === 'up' ? 'Improving' : posture.trend === 'down' ? 'Declining' : 'Stable'}
                      {posture.change !== 0 && ` (${posture.change > 0 ? '+' : ''}${posture.change}% this week)`}
                    </span>
                  </div>
                </div>
                <p className="text-sm text-slate-500">
                  {posture.score >= 90 ? 'Excellent security posture. Keep maintaining best practices.' :
                   posture.score >= 80 ? 'Good posture with room for improvement. Address remaining findings.' :
                   posture.score >= 70 ? 'Moderate risk level. Prioritize critical and high findings.' :
                   posture.score >= 60 ? 'Elevated risk. Immediate action required on critical issues.' :
                   'Critical risk. Urgent remediation needed across multiple areas.'}
                </p>
                <Link to="/findings?severity=critical" className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1">
                  View details <ChevronRight className="w-4 h-4" />
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="card p-6">
          <div className="flex items-center gap-2 mb-4">
            <AlertCircle className="w-4 h-4 text-red-400" />
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Active Threats</h3>
          </div>
          <div className="space-y-4">
            <div>
              <div className="text-4xl font-bold font-mono text-white">{stats.critical + stats.high}</div>
              <div className="text-sm text-slate-500">Critical + High findings</div>
            </div>
            <div className="flex items-center gap-4 text-sm">
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-red-400" />
                <span className="text-slate-400">{stats.critical} critical</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-orange-400" />
                <span className="text-slate-400">{stats.high} high</span>
              </div>
            </div>
          </div>
          {stats.critical > 0 && (
            <Link to="/findings?severity=critical" className="btn-danger text-xs mt-4 w-full justify-center">
              <TriangleAlert className="w-3 h-3" />
              {stats.critical} Critical Issues
            </Link>
          )}
        </div>

        {/* Resolved This Week */}
        <div className="card p-6">
          <div className="flex items-center gap-2 mb-4">
            <CircleCheck className="w-4 h-4 text-green-400" />
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Resolved</h3>
          </div>
          <div className="space-y-4">
            <div>
              <div className="text-4xl font-bold font-mono text-green-400">{stats.resolved}</div>
              <div className="text-sm text-slate-500">Total resolved</div>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <TrendingUp className="w-4 h-4 text-green-400" />
              <span className="text-green-400">+{threats?.mitigated_24h || 0}</span>
              <span className="text-slate-500">in last 24h</span>
            </div>
          </div>
          <div className="mt-4 pt-4 border-t border-slate-800">
            <div className="text-xs text-slate-500">Mean time to resolve</div>
            <div className="text-lg font-bold text-slate-200">{threats?.mean_time_to_resolve || 0}h</div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Trend Chart */}
        <div className="lg:col-span-2 card p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-slate-400" />
              <h2 className="text-sm font-semibold text-slate-300">Findings Trend</h2>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-red-400" />
                <span className="text-slate-500">Critical</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-orange-400" />
                <span className="text-slate-500">High</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 rounded-full bg-yellow-400" />
                <span className="text-slate-500">Medium</span>
              </div>
            </div>
          </div>

          {/* Simple Bar Chart */}
          <div className="h-48 flex items-end gap-2 bg-slate-900/50 rounded-lg p-4">
            {trendData.map((day, i) => {
              const maxVal = Math.max(...trendData.map(d => d.critical + d.high + d.medium), 1)
              const criticalH = (day.critical / maxVal) * 100
              const highH = (day.high / maxVal) * 100
              const mediumH = (day.medium / maxVal) * 100
              return (
                <div key={i} className="flex-1 flex flex-col items-center gap-1">
                  <div className="w-full flex flex-col justify-end h-36 gap-0.5">
                    <div className="w-full bg-red-400/80 rounded-t transition-all" style={{ height: `${criticalH}%`, minHeight: day.critical ? '4px' : '0' }} />
                    <div className="w-full bg-orange-400/80 transition-all" style={{ height: `${highH}%`, minHeight: day.high ? '4px' : '0' }} />
                    <div className="w-full bg-yellow-400/80 rounded-b transition-all" style={{ height: `${mediumH}%`, minHeight: day.medium ? '4px' : '0' }} />
                  </div>
                  <span className="text-xs text-slate-500">{day.date}</span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="card p-6">
          <div className="flex items-center gap-2 mb-4">
            <PieChart className="w-4 h-4 text-slate-400" />
            <h2 className="text-sm font-semibold text-slate-300">By Severity</h2>
          </div>
          <div className="space-y-3">
            {[
              { label: 'Critical', value: stats.critical, color: 'bg-red-400', textColor: 'text-red-400' },
              { label: 'High', value: stats.high, color: 'bg-orange-400', textColor: 'text-orange-400' },
              { label: 'Medium', value: stats.total - stats.critical - stats.high - stats.resolved, color: 'bg-yellow-400', textColor: 'text-yellow-400' },
              { label: 'Low/Info', value: Math.max(0, stats.total - stats.critical - stats.high), color: 'bg-slate-400', textColor: 'text-slate-400' },
            ].map(({ label, value, color, textColor }) => {
              const pct = stats.total > 0 ? Math.round((value / stats.total) * 100) : 0
              return (
                <div key={label}>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span className="text-slate-400">{label}</span>
                    <span className={`font-mono font-bold ${textColor}`}>{value}</span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
          <div className="mt-4 pt-4 border-t border-slate-800">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-500">Total Open</span>
              <span className="text-xl font-bold font-mono text-white">{stats.total - stats.resolved}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Surface & Top Risks */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Attack Surface */}
        <div className="card p-6">
          <div className="flex items-center gap-2 mb-4">
            <Target className="w-4 h-4 text-purple-400" />
            <h2 className="text-sm font-semibold text-slate-300">Attack Surface</h2>
          </div>
          {attackSurface ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-slate-800/50 rounded-lg">
                  <div className="text-2xl font-bold font-mono text-white">{attackSurface.total_assets}</div>
                  <div className="text-xs text-slate-500">Total Assets</div>
                </div>
                <div className="p-3 bg-slate-800/50 rounded-lg">
                  <div className="text-2xl font-bold font-mono text-blue-400">{attackSurface.internet_facing}</div>
                  <div className="text-xs text-slate-500">Internet-Facing</div>
                </div>
                <div className="p-3 bg-slate-800/50 rounded-lg">
                  <div className="text-2xl font-bold font-mono text-red-400">{attackSurface.unpatched}</div>
                  <div className="text-xs text-slate-500">Unscanned 7d+</div>
                </div>
                <div className="p-3 bg-slate-800/50 rounded-lg">
                  <div className="text-2xl font-bold font-mono text-orange-400">{attackSurface.critical_assets}</div>
                  <div className="text-xs text-slate-500">Critical Assets</div>
                </div>
              </div>
              <Link to="/repositories" className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1">
                Manage repositories <ChevronRight className="w-4 h-4" />
              </Link>
            </div>
          ) : (
            <div className="py-8 text-center">
              <Cloud className="w-8 h-8 mx-auto mb-2 text-slate-600" />
              <p className="text-sm text-slate-500">Connect repositories to map attack surface</p>
            </div>
          )}
        </div>

        {/* Top Risks */}
        <div className="lg:col-span-2 card p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <TriangleAlert className="w-4 h-4 text-red-400" />
              <h2 className="text-sm font-semibold text-slate-300">Highest Risk Findings</h2>
            </div>
            <Link to="/findings" className="text-xs text-blue-400 hover:text-blue-300">View all</Link>
          </div>
          {topRisks.length > 0 ? (
            <div className="space-y-2">
              {topRisks.map((f, i) => (
                <Link key={f.id} to={`/findings?highlight=${f.id}`} className="flex items-center gap-3 p-3 bg-slate-800/30 hover:bg-slate-800/50 rounded-lg transition-colors group">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold ${
                    f.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                    f.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                    f.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-slate-500/20 text-slate-400'
                  }`}>
                    #{i + 1}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-slate-200 truncate">{f.title}</div>
                    <div className="flex items-center gap-2 text-xs text-slate-500">
                      <span className="font-mono">{f.file_path?.split('/').pop()}</span>
                      {f.line_start && <span>:{f.line_start}</span>}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-lg font-bold font-mono text-white">{Math.round(f.risk_score || 0)}</div>
                    <div className="text-xs text-slate-500">risk</div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-slate-400 transition-colors" />
                </Link>
              ))}
            </div>
          ) : (
            <div className="py-8 text-center">
              <CircleCheck className="w-8 h-8 mx-auto mb-2 text-green-400" />
              <p className="text-sm text-slate-500">No open findings. Great job!</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent Activity & Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent Scans */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-slate-400" />
              <h2 className="text-sm font-semibold text-slate-300">Recent Scans</h2>
            </div>
            <Link to="/scans" className="text-xs text-blue-400 hover:text-blue-300">View all</Link>
          </div>
          {recent.length === 0 ? (
            <div className="py-8 text-center">
              <Play className="w-8 h-8 mx-auto mb-2 text-slate-600" />
              <p className="text-sm text-slate-500">No scans yet. <Link to="/repositories" className="text-blue-400">Connect a repository</Link> to start.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {recent.map(scan => {
                const sum = scan.summary as Record<string, number> | null
                const statusColors: Record<string, string> = {
                  completed: 'text-green-400 bg-green-400',
                  failed: 'text-red-400 bg-red-400',
                  running: 'text-blue-400 bg-blue-400',
                  queued: 'text-yellow-400 bg-yellow-400',
                }
                const statusColor = statusColors[scan.status] || statusColors.queued
                return (
                  <Link key={scan.id} to={`/scans?id=${scan.id}`} className="flex items-center gap-3 p-3 bg-slate-800/30 hover:bg-slate-800/50 rounded-lg transition-colors group">
                    <div className={`w-2 h-2 rounded-full ${statusColor.split(' ')[1]}`} />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-slate-200 truncate">{scan.repository_name || 'Unknown repo'}</div>
                      <div className="text-xs text-slate-500">{scan.branch || 'main'} · {scan.commit_sha?.slice(0, 7)}</div>
                    </div>
                    <div className="text-right">
                      {sum?.total ? (
                        <div className={`text-sm font-mono font-bold ${(sum.critical || 0) > 0 ? 'text-red-400' : 'text-slate-300'}`}>
                          {sum.total} findings
                        </div>
                      ) : (
                        <div className={`text-xs ${statusColor.split(' ')[0]}`}>{scan.status}</div>
                      )}
                    </div>
                    <Clock className="w-3 h-3 text-slate-600" />
                  </Link>
                )
              })}
            </div>
          )}
        </div>

        {/* Recent Activity */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-slate-400" />
              <h2 className="text-sm font-semibold text-slate-300">Recent Activity</h2>
            </div>
            <Link to="/audit-logs" className="text-xs text-blue-400 hover:text-blue-300">View all</Link>
          </div>
          {recentActivity.length === 0 ? (
            <div className="py-8 text-center">
              <Activity className="w-8 h-8 mx-auto mb-2 text-slate-600" />
              <p className="text-sm text-slate-500">No recent activity</p>
            </div>
          ) : (
            <div className="space-y-2">
              {recentActivity.slice(0, 5).map((activity, i) => {
                const actionIcons: Record<string, any> = {
                  scan_completed: Play,
                  finding_created: TriangleAlert,
                  finding_resolved: CircleCheck,
                  repository_added: GitBranch,
                  policy_updated: Shield,
                }
                const Icon = actionIcons[activity.action] || Activity
                const actionLabels: Record<string, string> = {
                  scan_completed: 'Scan completed',
                  finding_created: 'Finding detected',
                  finding_resolved: 'Finding resolved',
                  repository_added: 'Repository added',
                  policy_updated: 'Policy updated',
                  integration_created: 'Integration connected',
                  user_invited: 'User invited',
                }
                return (
                  <div key={activity.id || i} className="flex items-center gap-3 p-3 bg-slate-800/30 rounded-lg">
                    <Icon className="w-4 h-4 text-slate-500" />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-slate-200">{actionLabels[activity.action] || activity.action}</div>
                      {activity.resource_name && (
                        <div className="text-xs text-slate-500 truncate">{activity.resource_name}</div>
                      )}
                    </div>
                    <div className="text-xs text-slate-600">
                      {new Date(activity.created_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* Scanner Types Summary */}
      <div className="card p-6">
        <div className="flex items-center gap-2 mb-4">
          <Layers className="w-4 h-4 text-slate-400" />
          <h2 className="text-sm font-semibold text-slate-300">Security Scanners</h2>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            { icon: Key, label: 'Secrets', desc: 'API keys, tokens', color: 'text-red-400' },
            { icon: Bug, label: 'SAST', desc: 'Code analysis', color: 'text-orange-400' },
            { icon: Package, label: 'Dependencies', desc: 'Vulnerabilities', color: 'text-blue-400' },
            { icon: Server, label: 'IaC', desc: 'Misconfigurations', color: 'text-purple-400' },
            { icon: Container, label: 'Container', desc: 'Image scans', color: 'text-cyan-400' },
            { icon: FileCode, label: 'License', desc: 'Compliance', color: 'text-green-400' },
          ].map(({ icon: Icon, label, desc, color }) => (
            <div key={label} className="p-4 bg-slate-800/30 rounded-lg hover:bg-slate-800/50 transition-colors cursor-pointer">
              <Icon className={`w-6 h-6 ${color} mb-2`} />
              <div className="text-sm font-medium text-slate-200">{label}</div>
              <div className="text-xs text-slate-500">{desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
