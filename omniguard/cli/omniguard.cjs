#!/usr/bin/env node
/**
 * OmniGuard CLI
 * Commands: scan, status, suppress, install-hooks, help
 */

'use strict'
const { execSync, spawnSync } = require('child_process')
const fs = require('fs')
const path = require('path')
const https = require('https')
const http = require('http')

const API = process.env.OMNIGUARD_URL || ''
const KEY = process.env.OMNIGUARD_API_KEY || ''
const FAIL_ON = process.env.OMNIGUARD_FAIL_ON || 'critical'

function colors(c) {
  const m = { red: '\x1b[31m', orange: '\x1b[33m', green: '\x1b[32m', blue: '\x1b[34m', reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m' }
  return (s) => `${m[c]}${s}${m.reset}`
}
const red = colors('red'), orange = colors('orange'), green = colors('green'), blue = colors('blue'), bold = colors('bold'), dim = colors('dim')

function request(url, options = {}, body = null) {
  return new Promise((resolve, reject) => {
    const u = new URL(url)
    const lib = u.protocol === 'https:' ? https : http
    const req = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method: options.method || 'GET', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${KEY}`, ...options.headers } }, (res) => {
      let data = ''
      res.on('data', (c) => data += c)
      res.on('end', () => { try { resolve({ ok: res.statusCode < 300, status: res.statusCode, body: JSON.parse(data) }) } catch { resolve({ ok: false, status: res.statusCode, body: data }) } })
    })
    req.on('error', reject)
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body))
    req.end()
  })
}

// Local regex scanners (offline mode)
const SECRETS = [
  { id: 'SECRET-AWS-001', name: 'AWS Access Key', re: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, sev: 'critical' },
  { id: 'SECRET-GITHUB-001', name: 'GitHub PAT', re: /gh[pousr]_[A-Za-z0-9_]{36,}/g, sev: 'critical' },
  { id: 'SECRET-OPENAI-001', name: 'OpenAI Key', re: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, sev: 'critical' },
  { id: 'SECRET-OPENAI-002', name: 'OpenAI Project Key', re: /sk-proj-[A-Za-z0-9_-]{40,}/g, sev: 'critical' },
  { id: 'SECRET-ANTHROPIC-001', name: 'Anthropic Key', re: /sk-ant-[A-Za-z0-9\-_]{95,}/g, sev: 'critical' },
  { id: 'SECRET-STRIPE-001', name: 'Stripe Live Key', re: /sk_live_[0-9a-zA-Z]{24,}/g, sev: 'critical' },
  { id: 'SECRET-SSH-001', name: 'SSH Private Key', re: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g, sev: 'critical' },
  { id: 'SECRET-DB-001', name: 'Database Credentials', re: /(postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s'"]{5,}/gi, sev: 'critical' },
  { id: 'SECRET-PASS-001', name: 'Hardcoded Password', re: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{8,})["']/gim, sev: 'high' },
]

function mask(v) { return v.length <= 8 ? '****' : v.slice(0, 4) + '****' + v.slice(-4) }

function localScan(filePath, content) {
  const findings = []
  for (const r of SECRETS) {
    r.re.lastIndex = 0; let m
    const seen = new Set()
    while ((m = r.re.exec(content)) !== null) {
      const line = content.slice(0, m.index).split('\n').length
      if (seen.has(line)) continue; seen.add(line)
      const lt = content.split('\n')[line - 1]?.trim() || ''
      if (/^\s*(\/\/|#|\*)/.test(lt)) continue
      if (/(?:test|example|sample|placeholder|changeme|your[-_]|xxx)/i.test(m[0])) continue
      findings.push({ scanner: 'secret', rule_id: r.id, severity: r.sev, title: `${r.name} detected`, evidence: mask(m[0]), file_path: filePath, line_start: line })
    }
  }
  return findings
}

async function scanFiles(files) {
  const allFindings = []
  for (const f of files) {
    let content; try { content = fs.readFileSync(f, 'utf8') } catch { continue }
    if (!content.trim()) continue
    // Try remote scan first if configured
    if (API && KEY) {
      try {
        const res = await request(`${API}/scan-quick`, { method: 'POST' }, { path: f, content })
        if (res.ok && res.body.findings) { allFindings.push(...res.body.findings); continue }
      } catch { /* fall through to local */ }
    }
    allFindings.push(...localScan(f, content))
  }
  return allFindings
}

function getStagedFiles() {
  try { return execSync('git diff --cached --name-only', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).split('\n').filter(f => f.trim() && !f.includes('node_modules') && !f.includes('dist/') && !f.includes('.git/')) }
  catch { return [] }
}

function getAllTrackedFiles(dir = '.') {
  try { return execSync('git ls-files', { encoding: 'utf8', cwd: dir }).split('\n').filter(f => f.trim()) }
  catch {
    const exts = new Set(['.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.go', '.rb', '.php', '.cs', '.rs', '.env', '.yaml', '.yml'])
    const files = []
    function walk(d) {
      if (!fs.existsSync(d)) return
      for (const entry of fs.readdirSync(d)) {
        const full = path.join(d, entry)
        const stat = fs.statSync(full)
        if (stat.isDirectory() && !['node_modules', '.git', 'dist', 'build', '__pycache__'].includes(entry)) walk(full)
        else if (exts.has(path.extname(entry))) files.push(full)
      }
    }
    walk(dir); return files
  }
}

function printFinding(f) {
  const color = { critical: red, high: orange, medium: orange, low: (s) => s, info: dim }[f.severity] || (s => s)
  console.log(`  ${color(`[${f.severity.toUpperCase()}]`)} ${bold(f.title)}`)
  console.log(`    ${dim('File:')} ${f.file_path}:${f.line_start}  ${dim('Rule:')} ${f.rule_id}`)
  if (f.evidence) console.log(`    ${dim('Evidence:')} ${f.evidence}`)
}

function shouldFail(findings) {
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
  const threshold = severityOrder[FAIL_ON] || 4
  return findings.some(f => (severityOrder[f.severity] || 0) >= threshold)
}

const PRECOMMIT_HOOK = `#!/bin/sh
# OmniGuard pre-commit hook
OMNIGUARD_URL="${API}" OMNIGUARD_API_KEY="${KEY}" OMNIGUARD_FAIL_ON="${FAIL_ON}" node "$(npm root -g)/omniguard/cli/omniguard.cjs" scan --staged
exit $?
`

const PREPUSH_HOOK = `#!/bin/sh
# OmniGuard pre-push hook (non-blocking)
OMNIGUARD_URL="${API}" OMNIGUARD_API_KEY="${KEY}" node "$(npm root -g)/omniguard/cli/omniguard.cjs" scan &
`

const commands = {
  async scan(args) {
    const staged = args.includes('--staged')
    const targetFiles = staged ? getStagedFiles() : args.filter(a => !a.startsWith('-')).flatMap(a => {
      if (fs.existsSync(a) && fs.statSync(a).isDirectory()) return getAllTrackedFiles(a)
      return fs.existsSync(a) ? [a] : []
    })
    const files = targetFiles.length > 0 ? targetFiles : (staged ? getStagedFiles() : getAllTrackedFiles())

    if (!files.length) { console.log(green('✓ No files to scan')); return 0 }
    console.log(blue(`Scanning ${files.length} files...`))
    const findings = await scanFiles(files)
    const active = findings.filter(f => f.severity !== 'info')

    if (active.length === 0) { console.log(green('\n✓ OmniGuard: No security issues found\n')); return 0 }

    const crit = active.filter(f => f.severity === 'critical').length
    const high = active.filter(f => f.severity === 'high').length
    console.log(red(`\n⚠  OmniGuard found ${active.length} security issue${active.length > 1 ? 's' : ''}:\n`))
    for (const f of active.sort((a, b) => ({ critical: 4, high: 3, medium: 2, low: 1 }[b.severity] - { critical: 4, high: 3, medium: 2, low: 1 }[a.severity]))) {
      printFinding(f)
    }
    console.log(`\n  Summary: ${crit > 0 ? red(`${crit} critical`) : ''}${high > 0 ? ` ${orange(`${high} high`)}` : ''} · FAIL_ON=${FAIL_ON}`)
    if (shouldFail(active)) {
      console.log(red('\n  Commit blocked. Fix the issues above or set OMNIGUARD_FAIL_ON=info to allow.\n'))
      return 1
    }
    console.log(orange('\n  Findings present but below FAIL_ON threshold. Proceeding.\n'))
    return 0
  },

  async status() {
    if (!API || !KEY) { console.log(orange('OmniGuard not configured. Set OMNIGUARD_URL and OMNIGUARD_API_KEY.')); return 1 }
    try {
      const res = await request(`${API}/api-v1-status`)
      if (res.ok) { console.log(green(`✓ OmniGuard connected · ${res.body.status}`)); console.log(dim(`  AI: ${res.body.checks?.ai?.provider || 'none'} · DB: ${res.body.checks?.database?.status || 'unknown'}`)) }
      else console.log(red(`✗ OmniGuard unreachable (${res.status})`))
    } catch (e) { console.log(red(`✗ Connection failed: ${e.message}`)) }
  },

  async suppress(args) {
    const [id, ...reasonParts] = args
    const reason = reasonParts.join(' ')
    if (!id || !reason) { console.log(orange('Usage: omniguard suppress <finding-id> <reason>')); return 1 }
    if (!API || !KEY) { console.log(orange('Set OMNIGUARD_URL and OMNIGUARD_API_KEY')); return 1 }
    const res = await request(`${API}/api-v1-findings/${id}/suppress`, { method: 'POST' }, { reason })
    console.log(res.ok ? green(`✓ Finding ${id} suppressed`) : red(`✗ Failed: ${res.body?.error?.message || 'unknown error'}`))
  },

  'install-hooks'() {
    const hooksDir = '.git/hooks'
    if (!fs.existsSync('.git')) { console.log(red('Not a git repository')); return 1 }
    if (!fs.existsSync(hooksDir)) fs.mkdirSync(hooksDir, { recursive: true })
    fs.writeFileSync(path.join(hooksDir, 'pre-commit'), PRECOMMIT_HOOK)
    fs.chmodSync(path.join(hooksDir, 'pre-commit'), '755')
    fs.writeFileSync(path.join(hooksDir, 'pre-push'), PREPUSH_HOOK)
    fs.chmodSync(path.join(hooksDir, 'pre-push'), '755')
    console.log(green('✓ OmniGuard git hooks installed'))
    console.log(dim('  Pre-commit: blocks commits with secrets'))
    console.log(dim('  Pre-push: triggers background scan on push'))
  },

  help() {
    console.log(bold('\nOmniGuard - AI-Powered Security Scanner\n'))
    console.log('Usage: omniguard <command> [options]\n')
    console.log('Commands:')
    console.log('  install-hooks               Install pre-commit and pre-push git hooks')
    console.log('  scan [files/dirs...]         Scan files or git-tracked files')
    console.log('  scan --staged               Scan only staged files (for pre-commit)')
    console.log('  status                      Check connection to OmniGuard')
    console.log('  suppress <id> <reason>      Suppress a finding by ID')
    console.log('  help                        Show this help\n')
    console.log('Environment Variables:')
    console.log('  OMNIGUARD_URL              Supabase functions URL (https://xyz.supabase.co/functions/v1)')
    console.log('  OMNIGUARD_API_KEY          API key (og_live_...) from Dashboard → Settings → API Keys')
    console.log('  OMNIGUARD_FAIL_ON          Minimum severity to block: critical|high|medium|low (default: critical)\n')
    console.log('Without OMNIGUARD_URL/KEY: runs local secret scanner (offline mode)\n')
  }
}

async function main() {
  const [,, cmd, ...args] = process.argv
  const fn = commands[cmd]
  if (!fn) { if (cmd) console.log(orange(`Unknown command: ${cmd}\n`)); commands.help(); process.exit(cmd ? 1 : 0) }
  const result = await fn(args)
  process.exit(typeof result === 'number' ? result : 0)
}

main().catch(err => { console.error(red(`Fatal: ${err.message}`)); process.exit(1) })
