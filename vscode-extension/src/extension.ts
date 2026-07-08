// OmniGuard VS Code Extension — Main Entry Point
// Features: inline diagnostics, on-save scanning, on-type scanning,
// AI remediation hovers, quick-fix code actions, status bar, findings panel

import * as vscode from 'vscode'
import * as https from 'https'
import * as http from 'http'
import * as crypto from 'crypto'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Finding {
  rule_id:        string
  severity:       'critical' | 'high' | 'medium' | 'low' | 'info'
  title:          string
  evidence?:      string
  file_path:      string
  line_start:     number
  line_end?:      number
  col_start?:     number
  col_end?:       number
  scanner:        string
  ai_explanation?: string
  ai_fix?:        string
  id?:            string
}

interface ScanResult {
  findings:   Finding[]
  total:      number
  ai_enabled: boolean
}

// ─── Secret patterns (offline mode) ──────────────────────────────────────────

const SECRET_RULES: Array<{ id: string; name: string; re: RegExp; sev: Finding['severity'] }> = [
  { id: 'SECRET-AWS-001',       name: 'AWS Access Key',        re: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,     sev: 'critical' },
  { id: 'SECRET-GITHUB-001',    name: 'GitHub PAT',            re: /gh[pousr]_[A-Za-z0-9_]{36,}/g,                                                sev: 'critical' },
  { id: 'SECRET-OPENAI-001',    name: 'OpenAI Key',            re: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g,                                 sev: 'critical' },
  { id: 'SECRET-OPENAI-002',    name: 'OpenAI Project Key',    re: /sk-proj-[A-Za-z0-9_-]{40,}/g,                                                 sev: 'critical' },
  { id: 'SECRET-ANTHROPIC-001', name: 'Anthropic Key',         re: /sk-ant-[A-Za-z0-9\-_]{95,}/g,                                                 sev: 'critical' },
  { id: 'SECRET-STRIPE-001',    name: 'Stripe Live Key',       re: /sk_live_[0-9a-zA-Z]{24,}/g,                                                   sev: 'critical' },
  { id: 'SECRET-SSH-001',       name: 'SSH Private Key',       re: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,                     sev: 'critical' },
  { id: 'SECRET-DB-001',        name: 'DB Connection String',  re: /(postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s'"]{5,}/gi,             sev: 'critical' },
  { id: 'SECRET-NPM-001',       name: 'npm Token',             re: /npm_[A-Za-z0-9]{36,}/g,                                                       sev: 'critical' },
  { id: 'SECRET-PASS-001',      name: 'Hardcoded Password',    re: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{8,})["']/gim,                   sev: 'high'     },
  { id: 'SECRET-JWT-001',       name: 'JWT Bearer Token',      re: /eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}/g,            sev: 'high'     },
  { id: 'SECRET-GOOGLE-001',    name: 'Google API Key',        re: /AIza[0-9A-Za-z\-_]{35}/g,                                                    sev: 'high'     },
]

const SAST_RULES: Array<{ id: string; name: string; re: RegExp; sev: Finding['severity'] }> = [
  { id: 'SAST-SQL-001',    name: 'SQL Injection Risk',      re: /(?:execute|query)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)[^)]*\+/gi,     sev: 'critical' },
  { id: 'SAST-XSS-001',    name: 'XSS via innerHTML',       re: /\.innerHTML\s*[+]?=\s*[^"';\n]{1,80}(?:req\.|request\.|params\.|\$\{)/gm, sev: 'high'     },
  { id: 'SAST-CMD-001',    name: 'Command Injection Risk',  re: /(?:exec|execSync|spawn)\s*\([^)]*(?:req\.|params\.|query\.)/gi,           sev: 'critical' },
  { id: 'SAST-EVAL-001',   name: 'eval() Usage',            re: /\beval\s*\(/g,                                                             sev: 'high'     },
  { id: 'SAST-CRYPTO-001', name: 'Weak Hash (MD5)',         re: /createHash\s*\(\s*["']md5["']/gi,                                          sev: 'high'     },
  { id: 'SAST-JWT-001',    name: 'JWT None Algorithm',      re: /algorithm[s]?\s*[:=]\s*["']none["']/gi,                                    sev: 'critical' },
  { id: 'SAST-PATH-001',   name: 'Path Traversal Risk',     re: /path\.join\([^)]*(?:req\.|params\.)/gi,                                    sev: 'high'     },
]

const SKIP_FP = /(?:test|example|sample|placeholder|changeme|your[-_]?api|xxx|<|>|\$\{|\$\(|foobar|00000000)/i
const SKIP_COMMENT = /^\s*(\/\/|#|\*|<!--)/

function mask(v: string): string {
  return v.length <= 8 ? '****' : `${v.slice(0, 4)}...(${v.length})...${v.slice(-4)}`
}

function localScan(filePath: string, content: string): Finding[] {
  const findings: Finding[] = []
  const lines = content.split('\n')
  for (const rule of [...SECRET_RULES, ...SAST_RULES]) {
    rule.re.lastIndex = 0
    let m: RegExpExecArray | null
    const seen = new Set<number>()
    while ((m = rule.re.exec(content)) !== null) {
      const lineNum = content.slice(0, m.index).split('\n').length
      if (seen.has(lineNum)) continue
      seen.add(lineNum)
      const lineText = lines[lineNum - 1] || ''
      if (SKIP_COMMENT.test(lineText)) continue
      if (SKIP_FP.test(m[0])) continue
      const isSecret = SECRET_RULES.some(s => s.id === rule.id)
      findings.push({
        rule_id: rule.id, severity: rule.sev,
        title: `${rule.name} detected`,
        evidence: isSecret ? mask(m[0]) : m[0].slice(0, 60),
        file_path: filePath, line_start: lineNum,
        scanner: isSecret ? 'secret' : 'sast',
      })
    }
  }
  return findings
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

function httpRequest(url: string, opts: { method?: string; headers?: Record<string, string> }, body?: string): Promise<{ ok: boolean; status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url)
    const lib = u.protocol === 'https:' ? https : http
    const req = lib.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: opts.method || 'GET',
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    }, res => {
      let data = ''
      res.on('data', c => data += c)
      res.on('end', () => {
        try { resolve({ ok: (res.statusCode || 0) < 300, status: res.statusCode || 0, body: JSON.parse(data) }) }
        catch { resolve({ ok: (res.statusCode || 0) < 300, status: res.statusCode || 0, body: data }) }
      })
    })
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

async function scanDocument(document: vscode.TextDocument, config: vscode.WorkspaceConfiguration): Promise<Finding[]> {
  const url  = config.get<string>('supabaseUrl', '').trim()
  const key  = config.get<string>('apiKey', '').trim()
  const text = document.getText()
  const path = document.uri.fsPath

  if (url && key) {
    try {
      const res = await httpRequest(`${url}/scan-quick`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      }, JSON.stringify({ path, content: text }))
      if (res.ok && typeof res.body === 'object' && res.body !== null) {
        const body = res.body as ScanResult
        if (Array.isArray(body.findings)) return body.findings
      }
    } catch { /* fall through to local */ }
  }
  return localScan(path, text)
}

// ─── Diagnostics ─────────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<Finding['severity'], number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

function findingToDiagnostic(finding: Finding, document: vscode.TextDocument, failOn: string): vscode.Diagnostic {
  const line = Math.max(0, (finding.line_start || 1) - 1)
  const lineText = document.lineAt(Math.min(line, document.lineCount - 1)).text
  const start = lineText.search(/\S/) || 0

  const range = new vscode.Range(
    new vscode.Position(line, start),
    new vscode.Position(line, lineText.length),
  )

  const threshold = SEVERITY_ORDER[failOn as Finding['severity']] ?? 3
  const isError = (SEVERITY_ORDER[finding.severity] ?? 0) >= threshold

  const diag = new vscode.Diagnostic(
    range,
    `[OmniGuard ${finding.severity.toUpperCase()}] ${finding.title}${finding.evidence ? ` — ${finding.evidence}` : ''}`,
    isError ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning,
  )
  diag.source = 'OmniGuard'
  diag.code = finding.rule_id
  if (finding.ai_explanation) {
    diag.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(document.uri, range),
        `AI: ${finding.ai_explanation}`,
      ),
    ]
  }
  return diag
}

// ─── Hover provider ───────────────────────────────────────────────────────────

class OmniGuardHoverProvider implements vscode.HoverProvider {
  constructor(private findingMap: Map<string, Finding[]>) {}

  async provideHover(document: vscode.TextDocument, position: vscode.Position): Promise<vscode.Hover | null> {
    const key = document.uri.fsPath
    const findings = this.findingMap.get(key)
    if (!findings) return null

    const matching = findings.filter(f => {
      const line = (f.line_start || 1) - 1
      return line === position.line
    })
    if (!matching.length) return null

    const md = new vscode.MarkdownString()
    md.isTrusted = true
    for (const f of matching) {
      md.appendMarkdown(`### 🔒 OmniGuard: ${f.title}\n\n`)
      md.appendMarkdown(`**Severity:** \`${f.severity.toUpperCase()}\`  **Rule:** \`${f.rule_id}\`\n\n`)
      if (f.evidence) md.appendMarkdown(`**Evidence:** \`${f.evidence}\`\n\n`)
      if (f.ai_explanation) md.appendMarkdown(`**AI Analysis:** ${f.ai_explanation}\n\n`)
      if (f.ai_fix) {
        md.appendMarkdown(`**Suggested Fix:**\n\`\`\`\n${f.ai_fix}\n\`\`\`\n\n`)
      }
      md.appendMarkdown(`---\n`)
    }
    return new vscode.Hover(md)
  }
}

// ─── Code action provider ─────────────────────────────────────────────────────

class OmniGuardCodeActionProvider implements vscode.CodeActionProvider {
  constructor(private findingMap: Map<string, Finding[]>) {}

  provideCodeActions(document: vscode.TextDocument, range: vscode.Range): vscode.CodeAction[] {
    const findings = this.findingMap.get(document.uri.fsPath) || []
    const actions: vscode.CodeAction[] = []

    for (const f of findings) {
      const line = (f.line_start || 1) - 1
      if (!range.intersection(new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER))) continue

      if (f.ai_fix) {
        const fix = new vscode.CodeAction(`OmniGuard: Apply AI fix for ${f.rule_id}`, vscode.CodeActionKind.QuickFix)
        fix.edit = new vscode.WorkspaceEdit()
        const lineText = document.lineAt(line).text
        fix.edit.replace(document.uri, new vscode.Range(line, 0, line, lineText.length), `// OmniGuard fix: ${f.ai_fix}`)
        fix.isPreferred = false
        actions.push(fix)
      }

      const suppress = new vscode.CodeAction(`OmniGuard: Suppress ${f.rule_id} on this line`, vscode.CodeActionKind.QuickFix)
      suppress.edit = new vscode.WorkspaceEdit()
      const lineText = document.lineAt(line).text
      const indent = lineText.match(/^\s*/)?.[0] || ''
      const commentChar = document.languageId === 'python' ? '#' : '//'
      suppress.edit.insert(document.uri, new vscode.Position(line, 0), `${indent}${commentChar} omniguard-suppress ${f.rule_id}\n`)
      actions.push(suppress)
    }

    return actions
  }
}

// ─── Findings tree view ───────────────────────────────────────────────────────

class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly finding: Finding,
    public readonly uri: vscode.Uri,
  ) {
    super(`[${finding.severity.toUpperCase()}] ${finding.title}`, vscode.TreeItemCollapsibleState.None)
    this.description = `${uri.fsPath.split('/').pop()}:${finding.line_start}`
    this.tooltip = finding.ai_explanation || finding.evidence || ''
    this.iconPath = new vscode.ThemeIcon(
      finding.severity === 'critical' || finding.severity === 'high' ? 'error' : 'warning'
    )
    this.command = {
      command: 'vscode.open',
      arguments: [uri, { selection: new vscode.Range(Math.max(0, (finding.line_start || 1) - 1), 0, Math.max(0, (finding.line_start || 1) - 1), 0) }],
      title: 'Go to Finding',
    }
  }
}

class OmniGuardTreeProvider implements vscode.TreeDataProvider<FindingItem> {
  private _onDidChange = new vscode.EventEmitter<void>()
  readonly onDidChangeTreeData = this._onDidChange.event
  private findingMap: Map<string, { uri: vscode.Uri; findings: Finding[] }> = new Map()

  update(uri: vscode.Uri, findings: Finding[]) {
    this.findingMap.set(uri.fsPath, { uri, findings })
    this._onDidChange.fire()
  }

  clear(uri: vscode.Uri) {
    this.findingMap.delete(uri.fsPath)
    this._onDidChange.fire()
  }

  clearAll() { this.findingMap.clear(); this._onDidChange.fire() }

  getTreeItem(element: FindingItem) { return element }

  getChildren(): FindingItem[] {
    const items: FindingItem[] = []
    for (const { uri, findings } of this.findingMap.values()) {
      for (const f of findings) items.push(new FindingItem(f, uri))
    }
    return items.sort((a, b) => {
      const sa = SEVERITY_ORDER[a.finding.severity] ?? 0
      const sb = SEVERITY_ORDER[b.finding.severity] ?? 0
      return sb - sa
    })
  }
}

// ─── Extension activation ─────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  const diagCollection = vscode.languages.createDiagnosticCollection('omniguard')
  const findingMap = new Map<string, Finding[]>()
  const treeProvider = new OmniGuardTreeProvider()

  // Status bar item
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100)
  statusBar.text = '$(shield) OmniGuard'
  statusBar.tooltip = 'OmniGuard Security Scanner'
  statusBar.command = 'omniguard.showFindings'
  statusBar.show()

  // Register tree view
  const treeView = vscode.window.createTreeView('omniguardFindings', {
    treeDataProvider: treeProvider,
    showCollapseAll: true,
  })

  // Register providers
  const hoverProvider = vscode.languages.registerHoverProvider(
    { scheme: 'file' },
    new OmniGuardHoverProvider(findingMap),
  )
  const codeActionProvider = vscode.languages.registerCodeActionsProvider(
    { scheme: 'file' },
    new OmniGuardCodeActionProvider(findingMap),
    { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
  )

  context.subscriptions.push(diagCollection, statusBar, treeView, hoverProvider, codeActionProvider)

  // ── Core scan function ──────────────────────────────────────────────────

  const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>()

  async function runScan(document: vscode.TextDocument, showProgress = false) {
    const config = vscode.workspace.getConfiguration('omniguard')

    // Skip excluded patterns
    const excludes = config.get<string[]>('excludePatterns', [])
    const relPath = vscode.workspace.asRelativePath(document.uri)
    if (excludes.some(p => {
      const pattern = new vscode.RelativePattern(vscode.workspace.workspaceFolders?.[0] || '', p)
      return vscode.languages.match({ pattern: p }, document) > 0 || relPath.includes(p.replace(/\*\*/g, '').replace(/\*/g, ''))
    })) return

    // Skip binary/generated files
    const skipExtensions = new Set(['.png', '.jpg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map', '.lock'])
    const ext = document.uri.fsPath.split('.').pop()
    if (ext && skipExtensions.has(`.${ext}`)) return

    statusBar.text = '$(sync~spin) OmniGuard: scanning...'

    try {
      const findings = await scanDocument(document, config)

      // Filter out suppressed lines
      const text = document.getText()
      const lines = text.split('\n')
      const active = findings.filter(f => {
        const prevLine = lines[(f.line_start || 1) - 2] || ''
        return !prevLine.includes(`omniguard-suppress ${f.rule_id}`)
      })

      findingMap.set(document.uri.fsPath, active)
      treeProvider.update(document.uri, active)

      const failOn = config.get<string>('failOnSeverity', 'high')
      const diags = active.map(f => findingToDiagnostic(f, document, failOn))
      diagCollection.set(document.uri, diags)

      const critCount = active.filter(f => f.severity === 'critical').length
      const highCount = active.filter(f => f.severity === 'high').length
      const total = active.length

      if (total === 0) {
        statusBar.text = '$(shield) OmniGuard ✓'
        statusBar.backgroundColor = undefined
      } else {
        const label = critCount ? `$(error) ${critCount} critical` : `$(warning) ${highCount} high`
        statusBar.text = `$(shield) OmniGuard ${label}${total > critCount + highCount ? ` +${total - critCount - highCount}` : ''}`
        statusBar.backgroundColor = critCount
          ? new vscode.ThemeColor('statusBarItem.errorBackground')
          : new vscode.ThemeColor('statusBarItem.warningBackground')
      }

      if (showProgress && total > 0) {
        vscode.window.showWarningMessage(
          `OmniGuard found ${total} issue${total !== 1 ? 's' : ''} in ${document.fileName.split('/').pop()}`,
          'Show Findings',
        ).then(choice => {
          if (choice === 'Show Findings') vscode.commands.executeCommand('omniguardFindings.focus')
        })
      }
    } catch (err) {
      statusBar.text = '$(shield) OmniGuard'
      console.error('OmniGuard scan error:', err)
    }
  }

  function scheduleScan(document: vscode.TextDocument, delay: number) {
    const key = document.uri.fsPath
    const existing = debounceTimers.get(key)
    if (existing) clearTimeout(existing)
    debounceTimers.set(key, setTimeout(() => { debounceTimers.delete(key); runScan(document) }, delay))
  }

  // ── On-save scanning ─────────────────────────────────────────────────────

  const onSaveDisposable = vscode.workspace.onDidSaveTextDocument(document => {
    const config = vscode.workspace.getConfiguration('omniguard')
    if (config.get<boolean>('enableOnSave', true)) runScan(document)
  })

  // ── On-type scanning ─────────────────────────────────────────────────────

  const onChangeDisposable = vscode.workspace.onDidChangeTextDocument(event => {
    const config = vscode.workspace.getConfiguration('omniguard')
    if (!config.get<boolean>('enableOnType', false)) return
    if (event.contentChanges.length === 0) return
    const delay = config.get<number>('scanDelay', 1000)
    scheduleScan(event.document, delay)
  })

  // ── Commands ─────────────────────────────────────────────────────────────

  const cmdScanFile = vscode.commands.registerCommand('omniguard.scanFile', () => {
    const editor = vscode.window.activeTextEditor
    if (editor) runScan(editor.document, true)
    else vscode.window.showInformationMessage('OmniGuard: Open a file to scan')
  })

  const cmdScanWorkspace = vscode.commands.registerCommand('omniguard.scanWorkspace', async () => {
    const folders = vscode.workspace.workspaceFolders
    if (!folders) { vscode.window.showInformationMessage('OmniGuard: Open a workspace folder first'); return }

    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: 'OmniGuard: Scanning workspace...',
      cancellable: true,
    }, async (progress, token) => {
      const files = await vscode.workspace.findFiles(
        '**/*.{ts,tsx,js,jsx,py,java,go,rb,php,cs,rs,env,yml,yaml,json,tf,sh}',
        '{**/node_modules/**,**/dist/**,**/build/**,**/.git/**}',
        200,
      )
      let done = 0
      for (const uri of files) {
        if (token.isCancellationRequested) break
        try {
          const doc = await vscode.workspace.openTextDocument(uri)
          await runScan(doc)
        } catch { /* skip unreadable */ }
        done++
        progress.report({ increment: (100 / files.length), message: `${done}/${files.length} files` })
      }
    })

    vscode.commands.executeCommand('omniguardFindings.focus')
  })

  const cmdConfigure = vscode.commands.registerCommand('omniguard.configure', async () => {
    const url = await vscode.window.showInputBox({
      prompt: 'OmniGuard Supabase URL (e.g. https://xyz.supabase.co/functions/v1)',
      placeHolder: 'https://xyz.supabase.co/functions/v1',
      value: vscode.workspace.getConfiguration('omniguard').get<string>('supabaseUrl', ''),
    })
    if (url === undefined) return

    const key = await vscode.window.showInputBox({
      prompt: 'OmniGuard API Key (from Dashboard → Settings → API Keys)',
      placeHolder: 'og_live_...',
      password: true,
    })
    if (key === undefined) return

    const config = vscode.workspace.getConfiguration('omniguard')
    await config.update('supabaseUrl', url, vscode.ConfigurationTarget.Global)
    await config.update('apiKey', key, vscode.ConfigurationTarget.Global)

    if (url && key) {
      try {
        const res = await httpRequest(`${url}/api-v1-status`, { headers: { Authorization: `Bearer ${key}` } })
        if (res.ok) vscode.window.showInformationMessage('OmniGuard: Connected successfully!')
        else vscode.window.showWarningMessage(`OmniGuard: Connection check failed (${res.status})`)
      } catch (e) {
        vscode.window.showWarningMessage(`OmniGuard: Could not verify connection — ${e}`)
      }
    } else {
      vscode.window.showInformationMessage('OmniGuard: Configured in offline mode (local scanner only)')
    }
  })

  const cmdClear = vscode.commands.registerCommand('omniguard.clearDiagnostics', () => {
    diagCollection.clear()
    findingMap.clear()
    treeProvider.clearAll()
    statusBar.text = '$(shield) OmniGuard'
    statusBar.backgroundColor = undefined
  })

  const cmdShow = vscode.commands.registerCommand('omniguard.showFindings', () => {
    vscode.commands.executeCommand('omniguardFindings.focus')
  })

  context.subscriptions.push(
    onSaveDisposable, onChangeDisposable,
    cmdScanFile, cmdScanWorkspace, cmdConfigure, cmdClear, cmdShow,
  )

  // Scan active editor on startup
  const editor = vscode.window.activeTextEditor
  if (editor) setTimeout(() => runScan(editor.document), 2000)

  console.log('OmniGuard: Extension activated')
}

export function deactivate() {}
