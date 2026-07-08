#!/usr/bin/env node
'use strict'

// ─── OmniGuard CLI v1.0.0 ────────────────────────────────────────────────────
// Self-contained single-file CLI. No external runtime deps.
// Commands: login logout scan watch status doctor config install-hooks
//           policy docs daemon serve auth report remediate diff monitor version

const { execSync, spawnSync, spawn } = require('child_process')
const fs = require('fs')
const path = require('path')
const os = require('os')
const https = require('https')
const http = require('http')
const readline = require('readline')

const VERSION = '1.0.0'
const CONFIG_DIR = path.join(os.homedir(), '.omniguard')
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json')
const DAEMON_PID = path.join(CONFIG_DIR, 'daemon.pid')
const DAEMON_LOG = path.join(CONFIG_DIR, 'daemon.log')

// ─── Colours ─────────────────────────────────────────────────────────────────

const c = {
  red:    s => `\x1b[31m${s}\x1b[0m`,
  orange: s => `\x1b[33m${s}\x1b[0m`,
  green:  s => `\x1b[32m${s}\x1b[0m`,
  blue:   s => `\x1b[34m${s}\x1b[0m`,
  cyan:   s => `\x1b[36m${s}\x1b[0m`,
  bold:   s => `\x1b[1m${s}\x1b[0m`,
  dim:    s => `\x1b[2m${s}\x1b[0m`,
  reset:  s => s,
}

// ─── Config ───────────────────────────────────────────────────────────────────

function loadConfig() {
  if (!fs.existsSync(CONFIG_FILE)) return {}
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) } catch { return {} }
}

function saveConfig(cfg) {
  if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 })
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), { mode: 0o600 })
}

function getConfig() {
  const cfg = loadConfig()
  return {
    url: process.env.OMNIGUARD_URL || cfg.url || '',
    apiKey: process.env.OMNIGUARD_API_KEY || cfg.api_key || '',
    orgId: process.env.OMNIGUARD_ORG_ID || cfg.org_id || '',
    failOn: process.env.OMNIGUARD_FAIL_ON || cfg.fail_on || 'critical',
    profile: cfg.profile || 'default',
  }
}

// ─── HTTP helper ─────────────────────────────────────────────────────────────

function request(url, opts = {}, body = null) {
  return new Promise((resolve, reject) => {
    const u = new URL(url)
    const lib = u.protocol === 'https:' ? https : http
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) }
    const cfg = getConfig()
    if (cfg.apiKey && !headers['Authorization']) headers['Authorization'] = `Bearer ${cfg.apiKey}`
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: opts.method || 'GET', headers,
    }, res => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        try { resolve({ ok: res.statusCode < 300, status: res.statusCode, body: JSON.parse(data) }) }
        catch { resolve({ ok: res.statusCode < 300, status: res.statusCode, body: data }) }
      })
    })
    req.on('error', reject)
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body))
    req.end()
  })
}

// ─── Secret scanner (offline) ────────────────────────────────────────────────

const SECRET_PATTERNS = [
  { id: 'SECRET-AWS-001',       name: 'AWS Access Key',         re: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,     sev: 'critical' },
  { id: 'SECRET-AWS-002',       name: 'AWS Secret Key',         re: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,                    sev: 'high'     },
  { id: 'SECRET-GH-001',        name: 'GitHub PAT',             re: /gh[pousr]_[A-Za-z0-9_]{36,}/g,                                                 sev: 'critical' },
  { id: 'SECRET-OPENAI-001',    name: 'OpenAI Key',             re: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g,                                  sev: 'critical' },
  { id: 'SECRET-OPENAI-002',    name: 'OpenAI Project Key',     re: /sk-proj-[A-Za-z0-9_-]{40,}/g,                                                  sev: 'critical' },
  { id: 'SECRET-ANTHROPIC-001', name: 'Anthropic Key',          re: /sk-ant-[A-Za-z0-9\-_]{95,}/g,                                                  sev: 'critical' },
  { id: 'SECRET-STRIPE-001',    name: 'Stripe Live Key',        re: /sk_live_[0-9a-zA-Z]{24,}/g,                                                    sev: 'critical' },
  { id: 'SECRET-STRIPE-002',    name: 'Stripe Restricted Key',  re: /rk_live_[0-9a-zA-Z]{24,}/g,                                                    sev: 'critical' },
  { id: 'SECRET-SSH-001',       name: 'SSH Private Key',        re: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,                      sev: 'critical' },
  { id: 'SECRET-DB-001',        name: 'Database URL',           re: /(postgres|mysql|mongodb|redis|mssql):\/\/[^:\s]+:[^@\s]+@[^\s'"]{5,}/gi,       sev: 'critical' },
  { id: 'SECRET-PASS-001',      name: 'Hardcoded Password',     re: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{8,})["']/gim,                    sev: 'high'     },
  { id: 'SECRET-JWT-001',       name: 'JWT Token',              re: /eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}/g,             sev: 'high'     },
  { id: 'SECRET-SLACK-001',     name: 'Slack Webhook',          re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g, sev: 'high' },
  { id: 'SECRET-GOOGLE-001',    name: 'Google API Key',         re: /AIza[0-9A-Za-z\-_]{35}/g,                                                     sev: 'high'     },
  { id: 'SECRET-TWILIO-001',    name: 'Twilio Token',           re: /SK[0-9a-fA-F]{32}/g,                                                           sev: 'high'     },
  { id: 'SECRET-NPM-001',       name: 'npm Access Token',       re: /npm_[A-Za-z0-9]{36,}/g,                                                        sev: 'critical' },
  { id: 'SECRET-AZURE-001',     name: 'Azure Connection String', re: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/g, sev: 'critical' },
  { id: 'SECRET-PEM-001',       name: 'PEM Certificate',        re: /-----BEGIN CERTIFICATE-----/g,                                                 sev: 'medium'   },
  { id: 'SECRET-API-001',       name: 'Generic API Key',        re: /(?:api[_-]?key|apikey)\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']/gim,           sev: 'high'     },
  { id: 'SECRET-TOKEN-001',     name: 'Access Token',           re: /(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']/gim, sev: 'high'   },
]

const SKIP_FALSE_POSITIVE = /(?:test|example|sample|placeholder|changeme|your[-_]?api|xxx|<|>|\$\{|\$\(|foobar|xxxxxxxx|00000000)/i
const SKIP_COMMENT = /^\s*(\/\/|#|\*|<!--)/

function mask(v) {
  return v.length <= 8 ? '****' : v.slice(0, 4) + '...(' + v.length + ')...' + v.slice(-4)
}

function localScan(filePath, content) {
  const findings = []
  const lines = content.split('\n')
  for (const rule of SECRET_PATTERNS) {
    rule.re.lastIndex = 0
    let m
    const seen = new Set()
    while ((m = rule.re.exec(content)) !== null) {
      const lineNum = content.slice(0, m.index).split('\n').length
      if (seen.has(lineNum)) continue
      seen.add(lineNum)
      const lineText = lines[lineNum - 1] || ''
      if (SKIP_COMMENT.test(lineText)) continue
      if (SKIP_FALSE_POSITIVE.test(m[0])) continue
      findings.push({
        scanner: 'secret', rule_id: rule.id, severity: rule.sev,
        title: `${rule.name} detected`, evidence: mask(m[0]),
        file_path: filePath, line_start: lineNum,
      })
    }
  }
  return findings
}

// ─── File helpers ─────────────────────────────────────────────────────────────

const SCAN_EXTS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.go', '.rb', '.php',
  '.cs', '.rs', '.swift', '.kt', '.scala', '.c', '.cpp', '.h',
  '.env', '.yaml', '.yml', '.json', '.toml', '.ini', '.conf', '.config',
  '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.psd1', '.xml', '.properties',
  '.tf', '.tfvars', '.hcl', '.dockerfile', '.Dockerfile',
])
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'vendor', 'coverage', '.nyc_output'])

function walkDir(dir) {
  const files = []
  function walk(d) {
    if (!fs.existsSync(d)) return
    for (const entry of fs.readdirSync(d)) {
      const full = path.join(d, entry)
      try {
        const st = fs.statSync(full)
        if (st.isDirectory()) { if (!SKIP_DIRS.has(entry)) walk(full) }
        else if (SCAN_EXTS.has(path.extname(entry).toLowerCase()) || entry === 'Dockerfile') files.push(full)
      } catch { /* skip permission errors */ }
    }
  }
  walk(dir)
  return files
}

function getStagedFiles() {
  try {
    return execSync('git diff --cached --name-only', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      .split('\n').filter(f => f.trim() && !f.includes('node_modules') && !f.includes('/dist/'))
      .map(f => path.resolve(f))
      .filter(f => fs.existsSync(f))
  } catch { return [] }
}

function getGitTrackedFiles() {
  try {
    return execSync('git ls-files', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      .split('\n').filter(f => f.trim()).map(f => path.resolve(f))
  } catch { return walkDir('.') }
}

// ─── Remote scan ─────────────────────────────────────────────────────────────

async function remoteScanFile(filePath, content) {
  const cfg = getConfig()
  if (!cfg.url || !cfg.apiKey) return null
  try {
    const res = await request(`${cfg.url}/scan-quick`, { method: 'POST' }, {
      path: filePath, content, organization_id: cfg.orgId || undefined,
    })
    if (res.ok && res.body.findings) return res.body.findings
  } catch { /* fall back to local */ }
  return null
}

async function scanFiles(files) {
  const findings = []
  for (const f of files) {
    let content
    try { content = fs.readFileSync(f, 'utf8') } catch { continue }
    if (!content.trim()) continue
    const remote = await remoteScanFile(f, content)
    if (remote !== null) { findings.push(...remote); continue }
    findings.push(...localScan(f, content))
  }
  return findings
}

// ─── Output helpers ───────────────────────────────────────────────────────────

function printFinding(f) {
  const colour = { critical: c.red, high: c.orange, medium: c.orange, low: c.reset, info: c.dim }[f.severity] || c.reset
  console.log(`  ${colour(`[${(f.severity || 'info').toUpperCase()}]`)} ${c.bold(f.title)}`)
  console.log(`    ${c.dim('File:')} ${f.file_path}:${f.line_start}  ${c.dim('Rule:')} ${f.rule_id}`)
  if (f.evidence) console.log(`    ${c.dim('Evidence:')} ${f.evidence}`)
  if (f.ai_explanation) console.log(`    ${c.dim('AI:')} ${f.ai_explanation}`)
}

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

function shouldFail(findings) {
  const cfg = getConfig()
  const threshold = SEVERITY_ORDER[cfg.failOn] ?? 4
  return findings.some(f => (SEVERITY_ORDER[f.severity] ?? 0) >= threshold)
}

// ─── Interactive prompt ───────────────────────────────────────────────────────

function prompt(question, mask = false) {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    if (mask) {
      process.stdout.write(question)
      const stdin = process.openStdin()
      process.stdin.on('data', char => {
        char = char + ''
        if (char === '\n' || char === '\r') { process.stdout.write('\n'); rl.close(); stdin.pause() }
        else process.stdout.write('*')
      })
      process.stdin.resume()
      process.stdin.setRawMode && process.stdin.setRawMode(false)
      rl.question('', answer => { rl.close(); resolve(answer) })
    } else {
      rl.question(question, answer => { rl.close(); resolve(answer) })
    }
  })
}

// ─── COMMANDS ─────────────────────────────────────────────────────────────────

const commands = {

  // ── login ────────────────────────────────────────────────────────────────
  async login(args) {
    console.log(c.bold('\nOmniGuard Login\n'))
    const cfg = loadConfig()

    const url = args[0] || await prompt(`Supabase URL (${cfg.url || 'https://xyz.supabase.co/functions/v1'}): `)
    const apiKey = await prompt('API Key (from Dashboard → Settings → API Keys): ')

    if (!url.trim() || !apiKey.trim()) {
      console.log(c.red('URL and API key are required')); return 1
    }

    // Verify connection
    process.stdout.write(c.dim('Verifying connection... '))
    try {
      const res = await request(`${url.trim()}/api-v1-status`, { headers: { Authorization: `Bearer ${apiKey.trim()}` } })
      if (!res.ok) { console.log(c.red(`FAIL (${res.status})`)); return 1 }
      console.log(c.green('OK'))
      const newCfg = { ...cfg, url: url.trim(), api_key: apiKey.trim() }
      if (res.body.organization_id) newCfg.org_id = res.body.organization_id
      saveConfig(newCfg)
      console.log(c.green('✓ Logged in and config saved to ~/.omniguard/config.json'))
      if (res.body.checks) {
        console.log(c.dim(`  AI: ${res.body.checks.ai?.provider || 'not configured'}  DB: ${res.body.checks.database?.status || 'unknown'}`))
      }
    } catch (e) {
      console.log(c.red(`FAIL: ${e.message}`)); return 1
    }
  },

  // ── logout ───────────────────────────────────────────────────────────────
  async logout() {
    const cfg = loadConfig()
    delete cfg.api_key; delete cfg.org_id
    saveConfig(cfg)
    console.log(c.green('✓ Logged out (config cleared)'))
  },

  // ── scan ─────────────────────────────────────────────────────────────────
  async scan(args) {
    const staged = args.includes('--staged')
    const json = args.includes('--json')
    const positional = args.filter(a => !a.startsWith('-'))

    let files
    if (staged) {
      files = getStagedFiles()
      if (!files.length) { console.log(c.green('✓ No staged files to scan')); return 0 }
    } else if (positional.length > 0) {
      files = positional.flatMap(p => {
        if (!fs.existsSync(p)) { console.log(c.orange(`Not found: ${p}`)); return [] }
        return fs.statSync(p).isDirectory() ? walkDir(p) : [path.resolve(p)]
      })
    } else {
      files = getGitTrackedFiles()
    }

    if (!files.length) { console.log(c.green('✓ No files to scan')); return 0 }

    if (!json) console.log(c.blue(`Scanning ${files.length} file${files.length !== 1 ? 's' : ''}...`))
    const findings = await scanFiles(files)
    const active = findings.filter(f => f.severity !== 'info')

    if (json) { console.log(JSON.stringify({ findings: active, total: active.length }, null, 2)); return shouldFail(active) ? 1 : 0 }

    if (!active.length) { console.log(c.green('\n✓ OmniGuard: No security issues found\n')); return 0 }

    const counts = {}
    for (const f of active) counts[f.severity] = (counts[f.severity] || 0) + 1
    const summary = ['critical', 'high', 'medium', 'low'].filter(s => counts[s]).map(s => {
      const col = { critical: c.red, high: c.orange, medium: c.orange, low: c.reset }[s]
      return col(`${counts[s]} ${s}`)
    }).join('  ')

    console.log(c.red(`\n⚠  OmniGuard: ${active.length} security issue${active.length !== 1 ? 's' : ''} found\n`))
    const sorted = active.sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0))
    for (const f of sorted) printFinding(f)
    console.log(`\n  ${summary}  ${c.dim(`FAIL_ON=${getConfig().failOn}`)}`)

    if (shouldFail(active)) {
      console.log(c.red(`\n  Blocked. Resolve issues or set OMNIGUARD_FAIL_ON=info to allow.\n`))
      return 1
    }
    console.log(c.orange('\n  Findings below FAIL_ON threshold. Proceeding.\n'))
    return 0
  },

  // ── watch ────────────────────────────────────────────────────────────────
  async watch(args) {
    const dir = args[0] || '.'
    console.log(c.blue(`Watching ${path.resolve(dir)} for changes...`))
    console.log(c.dim('Press Ctrl+C to stop\n'))

    const WATCH_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.py', '.go', '.java', '.rb', '.php', '.cs', '.rs', '.env', '.yml', '.yaml', '.json', '.tf'])
    const debounce = {}

    function onFile(fp) {
      clearTimeout(debounce[fp])
      debounce[fp] = setTimeout(async () => {
        if (!WATCH_EXTS.has(path.extname(fp))) return
        let content; try { content = fs.readFileSync(fp, 'utf8') } catch { return }
        const findings = await scanFiles([fp])
        const active = findings.filter(f => ['critical', 'high'].includes(f.severity))
        if (!active.length) { console.log(c.green(`✓ ${path.relative(dir, fp)}`)); return }
        console.log(c.orange(`\n⚠ ${path.relative(dir, fp)}:`))
        for (const f of active) printFinding(f)
        console.log()
      }, 400)
    }

    try {
      fs.watch(path.resolve(dir), { recursive: true }, (_, filename) => {
        if (filename) onFile(path.join(path.resolve(dir), filename))
      })
    } catch {
      // Fallback: poll every 5s on systems without recursive watch support
      const known = {}
      const pollDir = d => {
        for (const f of walkDir(d)) {
          try {
            const mt = fs.statSync(f).mtimeMs
            if (known[f] !== undefined && known[f] !== mt) onFile(f)
            known[f] = mt
          } catch { /* skip */ }
        }
      }
      pollDir(path.resolve(dir))
      setInterval(() => pollDir(path.resolve(dir)), 5000)
    }

    await new Promise(() => {}) // block forever
  },

  // ── status ───────────────────────────────────────────────────────────────
  async status() {
    const cfg = getConfig()
    if (!cfg.url || !cfg.apiKey) {
      console.log(c.orange('OmniGuard not configured. Run: omniguard login'))
      console.log(c.dim('  Or set OMNIGUARD_URL and OMNIGUARD_API_KEY env vars'))
      return 1
    }
    try {
      const res = await request(`${cfg.url}/api-v1-status`)
      if (res.ok) {
        console.log(c.green(`✓ OmniGuard connected`))
        const ch = res.body.checks || {}
        console.log(`  DB:      ${ch.database?.status === 'ok' ? c.green('healthy') : c.red(ch.database?.status || 'unknown')}`)
        console.log(`  AI:      ${ch.ai?.provider ? c.green(ch.ai.provider) : c.dim('not configured')}`)
        console.log(`  Version: ${res.body.version || 'unknown'}`)
        if (cfg.orgId) console.log(`  Org:     ${cfg.orgId}`)
      } else {
        console.log(c.red(`✗ OmniGuard unreachable (HTTP ${res.status})`))
        return 1
      }
    } catch (e) {
      console.log(c.red(`✗ Connection failed: ${e.message}`)); return 1
    }
  },

  // ── doctor ───────────────────────────────────────────────────────────────
  async doctor() {
    console.log(c.bold('\nOmniGuard Doctor\n'))
    const checks = []
    const ok = label => { console.log(c.green(`  ✓ ${label}`)); checks.push({ label, ok: true }) }
    const warn = (label, msg) => { console.log(c.orange(`  ⚠ ${label}: ${msg}`)); checks.push({ label, ok: false }) }
    const fail = (label, msg) => { console.log(c.red(`  ✗ ${label}: ${msg}`)); checks.push({ label, ok: false }) }

    // Node version
    const nodeVer = process.versions.node.split('.').map(Number)
    nodeVer[0] >= 18 ? ok(`Node.js ${process.version}`) : fail('Node.js', `${process.version} (requires >=18)`)

    // Git
    try { execSync('git --version', { stdio: 'ignore' }); ok('git') } catch { warn('git', 'not found') }

    // Config
    const cfg = getConfig()
    cfg.url ? ok(`OMNIGUARD_URL: ${cfg.url}`) : warn('OMNIGUARD_URL', 'not set — run: omniguard login')
    cfg.apiKey ? ok('API key configured') : warn('API Key', 'not set — run: omniguard login')

    // Git hooks
    const inGit = fs.existsSync(path.join(process.cwd(), '.git'))
    if (inGit) {
      const precommit = path.join(process.cwd(), '.git', 'hooks', 'pre-commit')
      const prepush = path.join(process.cwd(), '.git', 'hooks', 'pre-push')
      fs.existsSync(precommit) ? ok('pre-commit hook installed') : warn('pre-commit hook', 'not installed — run: omniguard install-hooks')
      fs.existsSync(prepush) ? ok('pre-push hook installed') : warn('pre-push hook', 'not installed — run: omniguard install-hooks')
    } else {
      warn('git hooks', 'not in a git repository')
    }

    // Remote connectivity
    if (cfg.url && cfg.apiKey) {
      process.stdout.write(c.dim('  Checking remote connection... '))
      try {
        const res = await request(`${cfg.url}/api-v1-status`)
        res.ok ? (console.log(c.green('OK')), ok('Remote connectivity')) : (console.log(c.red(`FAIL (${res.status})`)), fail('Remote connectivity', `HTTP ${res.status}`))
      } catch (e) {
        console.log(c.red('FAIL'))
        fail('Remote connectivity', e.message)
      }
    }

    const failed = checks.filter(ch => !ch.ok).length
    console.log(failed === 0 ? c.green('\n✓ All checks passed\n') : c.orange(`\n${failed} issue(s) found\n`))
    return failed > 0 ? 1 : 0
  },

  // ── config ───────────────────────────────────────────────────────────────
  config(args) {
    const [sub, ...rest] = args
    const cfg = loadConfig()

    if (!sub || sub === 'show') {
      console.log(c.bold('\nOmniGuard Configuration\n'))
      console.log(`  Config file: ${CONFIG_FILE}`)
      const display = { ...cfg }
      if (display.api_key) display.api_key = display.api_key.slice(0, 8) + '...'
      console.log(JSON.stringify(display, null, 2))
      return
    }

    if (sub === 'set') {
      const [key, ...valParts] = rest
      if (!key) { console.log(c.orange('Usage: omniguard config set <key> <value>')); return 1 }
      const val = valParts.join(' ')
      const allowed = ['url', 'api_key', 'org_id', 'fail_on', 'profile']
      if (!allowed.includes(key)) { console.log(c.orange(`Unknown key. Allowed: ${allowed.join(', ')}`)); return 1 }
      cfg[key] = val; saveConfig(cfg)
      console.log(c.green(`✓ Set ${key}`))
      return
    }

    if (sub === 'unset') {
      const [key] = rest
      delete cfg[key]; saveConfig(cfg)
      console.log(c.green(`✓ Unset ${key}`))
      return
    }

    console.log(c.orange('Usage: omniguard config [show|set <key> <value>|unset <key>]'))
    return 1
  },

  // ── install-hooks ─────────────────────────────────────────────────────────
  'install-hooks'(args) {
    if (!fs.existsSync('.git')) { console.log(c.red('Not in a git repository')); return 1 }
    const hooksDir = path.join('.git', 'hooks')
    if (!fs.existsSync(hooksDir)) fs.mkdirSync(hooksDir, { recursive: true })

    // Hooks read env vars at runtime, not at install time
    const precommit = `#!/bin/sh
# OmniGuard pre-commit security scan
# Env: OMNIGUARD_URL, OMNIGUARD_API_KEY, OMNIGUARD_FAIL_ON
omniguard scan --staged
exit $?
`
    const prepush = `#!/bin/sh
# OmniGuard pre-push scan (non-blocking background scan)
omniguard scan &
`
    fs.writeFileSync(path.join(hooksDir, 'pre-commit'), precommit)
    fs.chmodSync(path.join(hooksDir, 'pre-commit'), '755')
    fs.writeFileSync(path.join(hooksDir, 'pre-push'), prepush)
    fs.chmodSync(path.join(hooksDir, 'pre-push'), '755')
    console.log(c.green('✓ Git hooks installed'))
    console.log(c.dim('  .git/hooks/pre-commit — blocks commits with secrets (FAIL_ON=critical by default)'))
    console.log(c.dim('  .git/hooks/pre-push   — background scan on push (non-blocking)'))
  },

  // ── policy ────────────────────────────────────────────────────────────────
  async policy(args) {
    const [sub, ...rest] = args
    const cfg = getConfig()
    if (!cfg.url || !cfg.apiKey) { console.log(c.orange('Run omniguard login first')); return 1 }

    if (!sub || sub === 'list') {
      try {
        const res = await request(`${cfg.url}/api-v1-status`)
        if (res.ok) {
          console.log(c.bold('\nPolicy management is available in the OmniGuard dashboard.'))
          console.log(c.dim(`  Dashboard → Policies`))
        }
      } catch (e) { console.log(c.red(e.message)); return 1 }
      return
    }

    if (sub === 'check') {
      const [filePath] = rest
      if (!filePath) { console.log(c.orange('Usage: omniguard policy check <file>')); return 1 }
      if (!fs.existsSync(filePath)) { console.log(c.red(`File not found: ${filePath}`)); return 1 }
      const content = fs.readFileSync(filePath, 'utf8')
      const findings = await scanFiles([filePath])
      if (!findings.length) { console.log(c.green(`✓ ${filePath}: No policy violations`)); return 0 }
      console.log(c.orange(`\n${filePath}: ${findings.length} violation(s)\n`))
      for (const f of findings) printFinding(f)
      return findings.some(f => f.severity === 'critical') ? 1 : 0
    }

    console.log('Usage: omniguard policy [list|check <file>]')
    return 1
  },

  // ── auth ──────────────────────────────────────────────────────────────────
  async auth(args) {
    const [sub] = args
    if (sub === 'status' || !sub) {
      const cfg = getConfig()
      if (!cfg.url || !cfg.apiKey) {
        console.log(c.orange('Not authenticated. Run: omniguard login')); return 1
      }
      try {
        const res = await request(`${cfg.url}/api-v1-status`)
        console.log(res.ok ? c.green('✓ Authenticated') : c.red(`✗ Auth failed (${res.status})`))
        return res.ok ? 0 : 1
      } catch (e) { console.log(c.red(e.message)); return 1 }
    }
    console.log('Usage: omniguard auth [status]')
    return 1
  },

  // ── report ────────────────────────────────────────────────────────────────
  async report(args) {
    const outputFile = args.find(a => a.startsWith('--output='))?.split('=')[1] || 'omniguard-report.json'
    const files = getGitTrackedFiles()
    console.log(c.blue(`Generating security report for ${files.length} files...`))
    const findings = await scanFiles(files)
    const counts = {}
    for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1
    const report = {
      generated_at: new Date().toISOString(),
      directory: process.cwd(),
      files_scanned: files.length,
      total_findings: findings.length,
      by_severity: counts,
      findings,
    }
    fs.writeFileSync(outputFile, JSON.stringify(report, null, 2))
    console.log(c.green(`✓ Report written to ${outputFile}`))
    console.log(`  ${findings.length} total findings: ${Object.entries(counts).map(([s, n]) => `${n} ${s}`).join(', ')}`)
  },

  // ── remediate ─────────────────────────────────────────────────────────────
  async remediate(args) {
    const [findingId] = args
    if (!findingId) { console.log(c.orange('Usage: omniguard remediate <finding-id>')); return 1 }
    const cfg = getConfig()
    if (!cfg.url || !cfg.apiKey) { console.log(c.orange('Run omniguard login first')); return 1 }
    try {
      const res = await request(`${cfg.url}/api-v1-findings/${findingId}/ai-remediation`)
      if (!res.ok) { console.log(c.red(`Failed: ${res.body?.error?.message || 'unknown'}`)); return 1 }
      const d = res.body.data || {}
      console.log(c.bold('\nAI Remediation\n'))
      if (d.ai_remediation) console.log(d.ai_remediation)
      else if (d.remediation) console.log(d.remediation)
      else console.log(c.dim('No AI remediation available'))
    } catch (e) { console.log(c.red(e.message)); return 1 }
  },

  // ── diff ──────────────────────────────────────────────────────────────────
  async diff(args) {
    const from = args[0] || 'HEAD~1'
    const to = args[1] || 'HEAD'
    let changedFiles
    try {
      changedFiles = execSync(`git diff --name-only ${from} ${to}`, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
        .split('\n').filter(f => f.trim()).map(f => path.resolve(f)).filter(f => fs.existsSync(f))
    } catch (e) { console.log(c.red(`git diff failed: ${e.message}`)); return 1 }

    if (!changedFiles.length) { console.log(c.green('✓ No changed files to scan')); return 0 }
    console.log(c.blue(`Scanning ${changedFiles.length} changed files (${from}..${to})...`))
    const findings = await scanFiles(changedFiles)
    const active = findings.filter(f => f.severity !== 'info')
    if (!active.length) { console.log(c.green('\n✓ No new security issues in diff\n')); return 0 }
    console.log(c.red(`\n⚠  ${active.length} issue(s) in changed files:\n`))
    for (const f of active.sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0))) printFinding(f)
    return 1
  },

  // ── monitor ────────────────────────────────────────────────────────────────
  async monitor(args) {
    const interval = parseInt(args.find(a => a.startsWith('--interval='))?.split('=')[1] || '60') * 1000
    const dir = args.find(a => !a.startsWith('-')) || '.'
    console.log(c.blue(`Monitoring ${path.resolve(dir)} every ${interval / 1000}s...`))
    console.log(c.dim('Press Ctrl+C to stop\n'))

    async function runScan() {
      const files = walkDir(path.resolve(dir))
      const findings = await scanFiles(files)
      const active = findings.filter(f => ['critical', 'high'].includes(f.severity))
      const ts = new Date().toLocaleTimeString()
      if (!active.length) console.log(c.green(`[${ts}] ✓ No critical/high issues (${files.length} files)`))
      else {
        console.log(c.red(`[${ts}] ⚠ ${active.length} critical/high issue(s):`))
        for (const f of active.slice(0, 5)) console.log(c.dim(`  ${f.severity}: ${f.title} — ${f.file_path}:${f.line_start}`))
        if (active.length > 5) console.log(c.dim(`  ...and ${active.length - 5} more`))
      }
    }

    await runScan()
    const timer = setInterval(runScan, interval)
    process.on('SIGINT', () => { clearInterval(timer); console.log('\n' + c.dim('Monitor stopped.')); process.exit(0) })
    await new Promise(() => {})
  },

  // ── daemon ────────────────────────────────────────────────────────────────
  daemon(args) {
    const [sub] = args
    if (sub === 'start') {
      if (fs.existsSync(DAEMON_PID)) {
        const pid = parseInt(fs.readFileSync(DAEMON_PID, 'utf8').trim())
        try { process.kill(pid, 0); console.log(c.orange(`Daemon already running (PID ${pid})`)); return } catch { /* stale pid */ }
      }
      const child = spawn(process.execPath, [__filename, 'monitor', '--interval=60'], {
        detached: true, stdio: ['ignore', fs.openSync(DAEMON_LOG, 'a'), fs.openSync(DAEMON_LOG, 'a')],
      })
      child.unref()
      if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true })
      fs.writeFileSync(DAEMON_PID, String(child.pid))
      console.log(c.green(`✓ Daemon started (PID ${child.pid})`))
      console.log(c.dim(`  Logs: ${DAEMON_LOG}`))
      return
    }
    if (sub === 'stop') {
      if (!fs.existsSync(DAEMON_PID)) { console.log(c.orange('Daemon not running')); return 1 }
      const pid = parseInt(fs.readFileSync(DAEMON_PID, 'utf8').trim())
      try { process.kill(pid, 'SIGTERM'); fs.unlinkSync(DAEMON_PID); console.log(c.green('✓ Daemon stopped')) }
      catch { fs.unlinkSync(DAEMON_PID); console.log(c.orange('Daemon was not running (stale PID removed)')) }
      return
    }
    if (sub === 'status') {
      if (!fs.existsSync(DAEMON_PID)) { console.log(c.dim('Daemon: not running')); return }
      const pid = parseInt(fs.readFileSync(DAEMON_PID, 'utf8').trim())
      try { process.kill(pid, 0); console.log(c.green(`Daemon: running (PID ${pid})`)) }
      catch { console.log(c.dim('Daemon: not running (stale PID)')); fs.unlinkSync(DAEMON_PID) }
      return
    }
    if (sub === 'logs') {
      if (!fs.existsSync(DAEMON_LOG)) { console.log(c.dim('No logs found')); return }
      const lines = fs.readFileSync(DAEMON_LOG, 'utf8').split('\n').slice(-50)
      console.log(lines.join('\n'))
      return
    }
    console.log('Usage: omniguard daemon [start|stop|status|logs]')
  },

  // ── serve ─────────────────────────────────────────────────────────────────
  serve(args) {
    const port = parseInt(args.find(a => a.startsWith('--port='))?.split('=')[1] || '7373')
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url, `http://localhost:${port}`)
      res.setHeader('Content-Type', 'application/json')
      res.setHeader('Access-Control-Allow-Origin', '*')

      if (req.method === 'GET' && url.pathname === '/health') {
        return res.end(JSON.stringify({ status: 'ok', version: VERSION }))
      }

      if (req.method === 'POST' && url.pathname === '/scan') {
        let body = ''
        req.on('data', c => body += c)
        req.on('end', async () => {
          try {
            const { files } = JSON.parse(body)
            const findings = await scanFiles((files || []).map(f => path.resolve(f)))
            res.end(JSON.stringify({ findings, total: findings.length }))
          } catch (e) { res.statusCode = 400; res.end(JSON.stringify({ error: e.message })) }
        })
        return
      }

      res.statusCode = 404
      res.end(JSON.stringify({ error: 'Not found' }))
    })

    server.listen(port, () => {
      console.log(c.green(`✓ OmniGuard local server running on http://localhost:${port}`))
      console.log(c.dim(`  GET  /health      — health check`))
      console.log(c.dim(`  POST /scan        — { files: [...] } → { findings: [...] }`))
      console.log(c.dim('\nPress Ctrl+C to stop'))
    })
    server.on('error', e => { console.log(c.red(e.message)); process.exit(1) })
    process.on('SIGINT', () => { server.close(); console.log('\n' + c.dim('Server stopped.')); process.exit(0) })
  },

  // ── docs ──────────────────────────────────────────────────────────────────
  docs() {
    console.log(c.bold('\nOmniGuard Documentation\n'))
    console.log('  README:          ./README.md')
    console.log('  Local setup:     ./docs/LOCAL-DEVELOPMENT-GUIDE.md')
    console.log('  Cloud deploy:    ./docs/CLOUD-DEPLOYMENT-GUIDE.md')
    console.log('  Enterprise:      ./docs/ENTERPRISE-GUIDE.md')
    console.log('  Feature matrix:  ./FEATURE-MATRIX.md')
    console.log(c.dim('\n  All docs are included in the repository in /docs/'))
  },

  // ── version ───────────────────────────────────────────────────────────────
  version() {
    console.log(`omniguard/${VERSION} node/${process.version} ${process.platform}`)
  },

  // ── help ──────────────────────────────────────────────────────────────────
  help() {
    console.log(c.bold('\nOmniGuard CLI — AI-Powered Application Security\n'))
    console.log(`  Version: ${VERSION}  Node: ${process.version}\n`)
    console.log('Usage: omniguard <command> [options]\n')
    const cmds = [
      ['login',           'Authenticate with OmniGuard dashboard'],
      ['logout',          'Clear stored credentials'],
      ['scan [files]',    'Scan files/directory for security issues'],
      ['scan --staged',   'Scan only git-staged files (use in pre-commit)'],
      ['scan --json',     'Output findings as JSON'],
      ['watch [dir]',     'Watch directory for changes and scan in real-time'],
      ['status',          'Check connection to OmniGuard'],
      ['doctor',          'Run diagnostics on your OmniGuard setup'],
      ['config show',     'Show current configuration'],
      ['config set k v',  'Set a configuration value'],
      ['install-hooks',   'Install git pre-commit and pre-push hooks'],
      ['policy check f',  'Check a file against policies'],
      ['auth status',     'Check authentication status'],
      ['report',          'Generate a JSON security report'],
      ['remediate <id>',  'Get AI remediation for a finding'],
      ['diff [A] [B]',    'Scan files changed between git refs'],
      ['monitor [dir]',   'Continuously monitor directory'],
      ['daemon start',    'Start background monitor daemon'],
      ['daemon stop',     'Stop background daemon'],
      ['daemon status',   'Check daemon status'],
      ['daemon logs',     'Show daemon logs'],
      ['serve',           'Start local scan HTTP server'],
      ['docs',            'Show documentation paths'],
      ['version',         'Print version'],
    ]
    for (const [cmd, desc] of cmds) console.log(`  ${c.bold(cmd.padEnd(22))}${desc}`)
    console.log('\nEnvironment Variables:')
    console.log('  OMNIGUARD_URL         Supabase Functions URL (or use omniguard login)')
    console.log('  OMNIGUARD_API_KEY     API key from Dashboard → Settings → API Keys')
    console.log('  OMNIGUARD_FAIL_ON     Severity to block on: critical|high|medium|low (default: critical)')
    console.log('\nOffline mode: scan/watch/report work without OMNIGUARD_URL (local secret scanner)\n')
  },
}

// ─── Entry point ─────────────────────────────────────────────────────────────

async function main() {
  const [,, cmd, ...args] = process.argv
  const fn = commands[cmd]
  if (!fn) {
    if (cmd) console.log(c.orange(`Unknown command: ${cmd}\n`))
    commands.help()
    process.exit(cmd ? 1 : 0)
  }
  const result = await fn.call(commands, args)
  process.exit(typeof result === 'number' ? result : 0)
}

main().catch(err => { console.error(c.red(`Fatal: ${err.message}`)); process.exit(1) })
