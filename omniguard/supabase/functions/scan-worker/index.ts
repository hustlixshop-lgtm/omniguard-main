import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";
import { callAI, getAIConfig, getEnvAIConfig, extractJson } from "../_shared/ai.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { autoRefreshToken: false, persistSession: false },
});
const WORKER_ID = `worker-${crypto.randomUUID().slice(0, 8)}`;

// ── Secret patterns ────────────────────────────────────────────
const SECRETS = [
  { id: "SECRET-AWS-001", name: "AWS Access Key ID", re: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, sev: "critical" },
  { id: "SECRET-GITHUB-001", name: "GitHub PAT", re: /gh[pousr]_[A-Za-z0-9_]{36,}/g, sev: "critical" },
  { id: "SECRET-OPENAI-001", name: "OpenAI Key", re: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, sev: "critical" },
  { id: "SECRET-OPENAI-002", name: "OpenAI Project Key", re: /sk-proj-[A-Za-z0-9_-]{40,}/g, sev: "critical" },
  { id: "SECRET-ANTHROPIC-001", name: "Anthropic Key", re: /sk-ant-[A-Za-z0-9\-_]{95,}/g, sev: "critical" },
  { id: "SECRET-STRIPE-001", name: "Stripe Live Key", re: /sk_live_[0-9a-zA-Z]{24,}/g, sev: "critical" },
  { id: "SECRET-STRIPE-002", name: "Stripe Test Key", re: /sk_test_[0-9a-zA-Z]{24,}/g, sev: "medium" },
  { id: "SECRET-SLACK-001", name: "Slack Token", re: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g, sev: "high" },
  { id: "SECRET-SSH-001", name: "SSH Private Key", re: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g, sev: "critical" },
  { id: "SECRET-DB-001", name: "Database Credentials", re: /(postgres|postgresql|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s'"]{5,}/gi, sev: "critical" },
  { id: "SECRET-JWT-001", name: "JWT Secret", re: /jwt[_\-]?secret["']?\s*[:=]\s*["']([A-Za-z0-9\-_!@#$%^&*]{20,})["']/gi, sev: "critical" },
  { id: "SECRET-PASS-001", name: "Hardcoded Password", re: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{8,})["']/gim, sev: "high" },
  { id: "SECRET-GCP-001", name: "GCP Service Account", re: /"private_key":\s*"-----BEGIN (?:RSA )?PRIVATE KEY/g, sev: "critical" },
  { id: "SECRET-NPM-001", name: "NPM Auth Token", re: /\/\/registry\.npmjs\.org\/:_authToken=[A-Za-z0-9\-]{36}/g, sev: "high" },
  { id: "SECRET-DISCORD-001", name: "Discord Bot Token", re: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g, sev: "high" },
  { id: "SECRET-TWILIO-001", name: "Twilio Token", re: /AC[a-zA-Z0-9]{32}/g, sev: "high" },
];

// ── SAST patterns ──────────────────────────────────────────────
const SAST = [
  { id: "SAST-SQL-001", name: "SQL Injection", re: /(?:execute|query)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)[^)]*\+/gi, sev: "critical", cwe: ["CWE-89"], owasp: ["A03:2021"] },
  { id: "SAST-SQL-002", name: "SQL Injection (f-string)", re: /cursor\.execute\s*\(\s*f["'][^"']*\{/g, sev: "critical", cwe: ["CWE-89"], owasp: ["A03:2021"] },
  { id: "SAST-XSS-001", name: "XSS via innerHTML", re: /\.innerHTML\s*[+]?=\s*[^"';\n]{1,80}(?:req\.|request\.|params\.|query\.|\$\{)/gm, sev: "high", cwe: ["CWE-79"], owasp: ["A03:2021"] },
  { id: "SAST-CMD-001", name: "Command Injection (eval)", re: /\beval\s*\([^)]*(?:req\.|request\.|params\.|query\.)/gi, sev: "critical", cwe: ["CWE-78"], owasp: ["A03:2021"] },
  { id: "SAST-CMD-002", name: "Command Injection (exec)", re: /(?:child_process\.exec|execSync|os\.system|subprocess\.call)\s*\([^)]*(?:req\.|request\.|params\.|query\.)/gi, sev: "critical", cwe: ["CWE-78"], owasp: ["A03:2021"] },
  { id: "SAST-SSRF-001", name: "SSRF", re: /(?:fetch|axios\.get|axios\.post|requests\.get)\s*\([^)]*(?:req\.|request\.|params\.|query\.)/gi, sev: "critical", cwe: ["CWE-918"], owasp: ["A10:2021"] },
  { id: "SAST-PATH-001", name: "Path Traversal", re: /(?:path\.join|path\.resolve|open|fs\.readFile)\s*\([^)]*(?:req\.|request\.|params\.|query\.)/gi, sev: "high", cwe: ["CWE-22"], owasp: ["A01:2021"] },
  { id: "SAST-CRYPTO-001", name: "Weak Hash MD5", re: /(?:createHash\s*\(\s*["']md5["']|hashlib\.md5\s*\()/gi, sev: "high", cwe: ["CWE-328"], owasp: ["A02:2021"] },
  { id: "SAST-DESER-001", name: "Unsafe Deserialization", re: /pickle\.loads?\s*\(/g, sev: "critical", cwe: ["CWE-502"], owasp: ["A08:2021"] },
  { id: "SAST-JWT-001", name: "JWT Algorithm None", re: /algorithm[s]?\s*[:=]\s*["']none["']/gi, sev: "critical", cwe: ["CWE-287"], owasp: ["A07:2021"] },
  { id: "SAST-REDIRECT-001", name: "Open Redirect", re: /(?:res\.redirect|response\.redirect)\s*\([^)]*(?:req\.|request\.|params\.|query\.)/gi, sev: "medium", cwe: ["CWE-601"], owasp: ["A01:2021"] },
  { id: "SAST-PROTO-001", name: "Prototype Pollution", re: /__proto__\s*\[|Object\.assign\s*\(\s*req/gi, sev: "high", cwe: ["CWE-1321"], owasp: ["A03:2021"] },
];

// ── IaC patterns ───────────────────────────────────────────────
const IAC = [
  { id: "IAC-S3-001", name: "S3 Public ACL", re: /acl\s*=\s*["']public-read/gi, sev: "critical" },
  { id: "IAC-SG-001", name: "Security Group Open World", re: /ingress\s*\{[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\]/gs, sev: "high" },
  { id: "IAC-RDS-001", name: "RDS Publicly Accessible", re: /publicly_accessible\s*=\s*true/gi, sev: "critical" },
  { id: "IAC-ENC-001", name: "Unencrypted Storage", re: /encrypted\s*=\s*false/gi, sev: "high" },
  { id: "IAC-DOCKER-ROOT", name: "Dockerfile Root User", re: /^USER\s+root\s*$/mi, sev: "high" },
  { id: "IAC-DOCKER-LATEST", name: "Docker :latest Tag", re: /^FROM\s+\S+:latest/mi, sev: "medium" },
  { id: "IAC-DOCKER-SECRET", name: "Secret in Dockerfile ENV", re: /^ENV\s+\w*(?:SECRET|PASSWORD|TOKEN|KEY)\w*\s+\S+/mi, sev: "critical" },
  { id: "IAC-K8S-PRIV", name: "Privileged Container", re: /privileged:\s*true/gi, sev: "critical" },
];

function mask(v: string) { if (v.length <= 8) return "****"; return v.slice(0, 4) + "****" + v.slice(-4) }
function isBinary(c: string) { return (c.match(/[\x00-\x08\x0e-\x1f\x7f]/g) || []).length / Math.max(c.length, 1) > 0.03 }
const SKIP = ["node_modules/", ".git/", "dist/", "build/", "__pycache__/", "vendor/", ".next/"]
const SCANNABLE = new Set(["js","jsx","ts","tsx","py","java","go","rb","php","cs","rs","c","cpp","tf","hcl","yaml","yml","json","toml","ini","env","sh","sql"])

interface RawFinding {
  scanner: string; rule_id: string; rule_name: string; severity: string
  title: string; description: string; evidence: string; file_path: string
  line_start: number; owasp: string[]; cwe: string[]
  risk_score: number; confidence_score: number; remediation?: string
}

interface ScanFile { path: string; content: string }

function runSecrets(files: ScanFile[]): RawFinding[] {
  const out: RawFinding[] = []
  for (const f of files) {
    if (isBinary(f.content)) continue
    for (const r of SECRETS) {
      r.re.lastIndex = 0; let m: RegExpExecArray | null
      const seen = new Set<number>()
      while ((m = r.re.exec(f.content)) !== null) {
        const line = f.content.slice(0, m.index).split("\n").length
        if (seen.has(line)) continue; seen.add(line)
        const lineText = f.content.split("\n")[line - 1]?.trim() || ""
        if (/^\s*(\/\/|#|\*)/.test(lineText)) continue
        if (/(?:test|example|sample|placeholder|changeme|your[-_]|xxx|dummy)/i.test(m[0])) continue
        out.push({ scanner: "secret", rule_id: r.id, rule_name: r.name, severity: r.sev,
          title: `${r.name} detected`, description: `A ${r.name} was found hardcoded. Rotate immediately and use environment variables.`,
          evidence: mask(m[0]), file_path: f.path, line_start: line, owasp: ["A07:2021"], cwe: ["CWE-798"],
          risk_score: r.sev === "critical" ? 95 : r.sev === "high" ? 70 : 45, confidence_score: 0.9,
          remediation: "Remove from source. Add to .gitignore. Use secrets manager or env vars. Rotate the exposed credential immediately." })
      }
    }
  }
  return out
}

function runSAST(files: ScanFile[]): RawFinding[] {
  const out: RawFinding[] = []
  for (const f of files) {
    if (isBinary(f.content)) continue
    for (const r of SAST) {
      r.re.lastIndex = 0; let m: RegExpExecArray | null
      const seen = new Set<number>()
      while ((m = r.re.exec(f.content)) !== null) {
        const line = f.content.slice(0, m.index).split("\n").length
        if (seen.has(line)) continue; seen.add(line)
        if (/^\s*(\/\/|#|\*)/.test(f.content.split("\n")[line - 1]?.trim() || "")) continue
        out.push({ scanner: "sast", rule_id: r.id, rule_name: r.name, severity: r.sev,
          title: `${r.name} detected`, description: `Potential ${r.name} vulnerability found at ${f.path}:${line}.`,
          evidence: m[0].slice(0, 200), file_path: f.path, line_start: line, owasp: r.owasp || [], cwe: r.cwe || [],
          risk_score: r.sev === "critical" ? 90 : r.sev === "high" ? 65 : 40, confidence_score: 0.8 })
      }
    }
  }
  return out
}

function runIaC(files: ScanFile[]): RawFinding[] {
  const out: RawFinding[] = []
  const iacFiles = files.filter(f => {
    const l = f.path.toLowerCase()
    return l.endsWith(".tf") || l.endsWith(".hcl") || /dockerfile$/i.test(l) || l.includes("docker-compose") || l.includes("kubernetes") || l.includes("/k8s/")
  })
  for (const f of iacFiles) {
    for (const r of IAC) {
      r.re.lastIndex = 0; let m: RegExpExecArray | null
      const seen = new Set<number>()
      while ((m = r.re.exec(f.content)) !== null) {
        const line = f.content.slice(0, m.index).split("\n").length
        if (seen.has(line)) continue; seen.add(line)
        out.push({ scanner: "iac", rule_id: r.id, rule_name: r.name, severity: r.sev,
          title: r.name, description: `Infrastructure misconfiguration: ${r.name}`,
          evidence: m[0].slice(0, 150), file_path: f.path, line_start: line, owasp: ["A05:2021"], cwe: ["CWE-16"],
          risk_score: r.sev === "critical" ? 85 : r.sev === "high" ? 60 : 35, confidence_score: 0.92 })
      }
    }
  }
  return out
}

async function runDependencies(files: ScanFile[]): Promise<RawFinding[]> {
  const out: RawFinding[] = []
  for (const f of files) {
    const lower = f.path.toLowerCase()
    if (!lower.endsWith("package.json") && !lower.endsWith("requirements.txt")) continue
    if (lower.includes("node_modules/")) continue
    const deps: Array<{ name: string; version: string; ecosystem: string }> = []
    if (lower.endsWith("package.json")) {
      try {
        const pkg = JSON.parse(f.content)
        for (const [n, v] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
          deps.push({ name: n, version: String(v).replace(/[^0-9.]/g, ""), ecosystem: "npm" })
        }
      } catch { continue }
    } else {
      for (const line of f.content.split("\n")) { const m = /^([A-Za-z0-9_.-]+)/.exec(line.trim()); if (m) deps.push({ name: m[1], version: "*", ecosystem: "pypi" }) }
    }
    for (let i = 0; i < Math.min(deps.length, 60); i += 20) {
      const batch = deps.slice(i, i + 20).filter(d => d.version && d.version !== "*")
      if (!batch.length) continue
      try {
        const res = await fetch("https://api.osv.dev/v1/querybatch", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ queries: batch.map(d => ({ package: { name: d.name, ecosystem: d.ecosystem === "npm" ? "npm" : "PyPI" }, version: d.version })) }),
          signal: AbortSignal.timeout(10_000),
        })
        if (!res.ok) continue
        const data = await res.json()
        for (let j = 0; j < (data.results || []).length; j++) {
          const result = data.results[j]; const dep = batch[j]
          for (const vuln of (result?.vulns || []).slice(0, 2)) {
            const cvss = vuln.severity?.find((s: { score: number }) => s.score)?.score
            const sev = cvss ? (cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low") : "medium"
            out.push({ scanner: "dependency", rule_id: vuln.id || "DEP-CVE", rule_name: vuln.id || "Known Vulnerability",
              severity: sev, title: `${dep.name} — ${vuln.id || "Known CVE"}`, description: vuln.summary || vuln.details?.slice(0, 300) || "Vulnerable dependency",
              evidence: `${dep.name}@${dep.version}`, file_path: f.path, line_start: 1, owasp: ["A06:2021"], cwe: ["CWE-1035"],
              risk_score: cvss ? Math.round(cvss * 10) : 50, confidence_score: 0.95,
              remediation: `Update ${dep.name} to the latest patched version.` })
          }
        }
      } catch { continue }
    }
  }
  return out
}

// ── GitHub file fetcher ────────────────────────────────────────
async function fetchFromGitHub(fullName: string, branch: string, sha: string | null, token: string, changedFiles?: string[]): Promise<ScanFile[]> {
  const hdrs = { Authorization: `token ${token}`, Accept: "application/vnd.github.v3+json", "User-Agent": "OmniGuard/1.0" }
  const ref = sha || branch; const files: ScanFile[] = []
  if (changedFiles?.length) {
    for (const fp of changedFiles.slice(0, 100)) {
      try {
        const ext = fp.split(".").pop() || ""; if (!SCANNABLE.has(ext.toLowerCase()) && !SKIP.every(s => !fp.includes(s))) continue
        const r = await fetch(`https://api.github.com/repos/${fullName}/contents/${fp}?ref=${ref}`, { headers: hdrs, signal: AbortSignal.timeout(8_000) })
        if (!r.ok) continue
        const d = await r.json()
        if (d.encoding === "base64" && d.content) { const c = atob(d.content.replace(/\n/g, "")); files.push({ path: fp, content: c }) }
      } catch { continue }
    }
    return files
  }
  try {
    const treeRes = await fetch(`https://api.github.com/repos/${fullName}/git/trees/${ref}?recursive=1`, { headers: hdrs, signal: AbortSignal.timeout(15_000) })
    if (!treeRes.ok) return files
    const tree = await treeRes.json()
    const candidates = (tree.tree || []).filter((i: { type: string; path: string; size?: number }) => {
      if (i.type !== "blob") return false
      const ext = i.path.split(".").pop()?.toLowerCase() || ""; if (!SCANNABLE.has(ext) && !i.path.toLowerCase().startsWith(".env")) return false
      if (SKIP.some(s => i.path.includes(s))) return false
      return !i.size || i.size < 500_000
    }).slice(0, 200)
    for (let b = 0; b < candidates.length; b += 10) {
      const batch = candidates.slice(b, b + 10)
      const results = await Promise.allSettled(batch.map(async (item: { path: string; sha: string }) => {
        const r = await fetch(`https://api.github.com/repos/${fullName}/git/blobs/${item.sha}`, { headers: hdrs, signal: AbortSignal.timeout(8_000) })
        if (!r.ok) return null
        const d = await r.json()
        return d.encoding === "base64" ? { path: item.path, content: atob(d.content.replace(/\n/g, "")) } : null
      }))
      for (const res of results) if (res.status === "fulfilled" && res.value) files.push(res.value)
    }
  } catch (e) { console.error("GitHub tree fetch:", e) }
  return files
}

// ── Layer 1 AI: Haiku/fast — triage, false positive removal ───
async function layer1Triage(findings: RawFinding[], aiCfg: ReturnType<typeof getAIConfig>): Promise<Set<number>> {
  const fpIndices = new Set<number>()
  const criticalHigh = findings.map((f, i) => ({ f, i })).filter(({ f }) => f.severity === "critical" || f.severity === "high").slice(0, 20)
  if (!criticalHigh.length) return fpIndices
  const prompt = `Security triage. Classify each finding as real (true_positive) or not (false_positive) based on context.
Rules:
- Test files, examples, placeholder values → false_positive
- Real API key patterns in non-test code → true_positive
- SQL concat that never uses user input → false_positive

Findings:
${criticalHigh.map(({ f, i }) => `${i}. [${f.severity}] ${f.rule_name} in ${f.file_path}:${f.line_start}\n   Evidence: ${f.evidence}`).join("\n\n")}

Return JSON: [{"index":0,"verdict":"true_positive|false_positive","confidence":0.9}]`
  const res = await callAI(aiCfg, prompt, "fast", 400)
  if (!res) return fpIndices
  const arr = extractJson<Array<{ index: number; verdict: string; confidence: number }>>(res.text)
  if (arr) { for (const item of arr) { if (item.verdict === "false_positive" && item.confidence > 0.7) fpIndices.add(item.index) } }
  return fpIndices
}

// ── Layer 2 AI: Sonnet/medium — deep analysis of critical/high ─
async function layer2Analyze(f: RawFinding, fileContent: string, aiCfg: ReturnType<typeof getAIConfig>): Promise<{ explanation: string; remediation: string }> {
  const lines = fileContent.split("\n")
  const ctx = lines.slice(Math.max(0, f.line_start - 4), Math.min(lines.length, f.line_start + 8)).join("\n")
  const prompt = `Security engineer. Analyze this ${f.severity} vulnerability and provide a specific fix.

Finding: ${f.title}
Rule: ${f.rule_id}
Location: ${f.file_path}:${f.line_start}
Evidence: ${f.evidence}

Code context:
\`\`\`
${ctx}
\`\`\`

Provide:
1. Why this is dangerous (2 sentences)
2. Exact code fix with before/after example
3. How to verify the fix

Be specific to the actual code shown. Max 300 words.`
  const res = await callAI(aiCfg, prompt, "medium", 700)
  if (!res) return { explanation: f.description, remediation: f.remediation || "" }
  const parts = res.text.split("\n\n")
  return { explanation: parts[0] || f.description, remediation: res.text }
}

// ── Layer 3 AI: Opus/deep — executive summary ─────────────────
async function layer3Summary(findings: RawFinding[], repoName: string, aiCfg: ReturnType<typeof getAIConfig>): Promise<string> {
  if (!findings.length) return ""
  const crit = findings.filter(f => f.severity === "critical").length
  const prompt = `CISO. Write a 3-paragraph executive security summary for ${repoName}.
Total findings: ${findings.length} (${crit} critical, ${findings.filter(f => f.severity === "high").length} high)
Top issues: ${findings.slice(0, 8).map(f => `[${f.severity}] ${f.title} in ${f.file_path}`).join("; ")}
Paragraph 1: Overall risk posture. Paragraph 2: Most critical issues and business impact. Paragraph 3: Top 3 immediate actions.`
  const res = await callAI(aiCfg, prompt, "deep", 500)
  return res?.text || ""
}

// ── RAG: retrieve relevant policy chunks ──────────────────────
async function matchPolicies(finding: RawFinding, orgId: string, embedding: number[]): Promise<string[]> {
  try {
    const { data } = await supabase.rpc("match_policy_chunks", {
      p_org_id: orgId, query_embedding: embedding, match_count: 3
    })
    return (data || []).map((d: { content: string }) => d.content)
  } catch { return [] }
}

// ── Main scan orchestrator ────────────────────────────────────
async function processScan(scanId: string, repoId: string, orgId: string): Promise<void> {
  const t0 = Date.now()
  await supabase.from("scans").update({ status: "running", started_at: new Date().toISOString(), worker_id: WORKER_ID }).eq("id", scanId)
  await supabase.from("worker_heartbeats").upsert({ worker_id: WORKER_ID, worker_type: "scanner", status: "busy", current_scan_id: scanId, last_heartbeat: new Date().toISOString() }, { onConflict: "worker_id" })

  try {
    const [{ data: scan }, { data: repo }, { data: org }] = await Promise.all([
      supabase.from("scans").select("branch, commit_sha, metadata").eq("id", scanId).single(),
      supabase.from("repositories").select("*").eq("id", repoId).single(),
      supabase.from("organizations").select("ai_config").eq("id", orgId).single(),
    ])
    if (!repo) throw new Error("Repository not found")

    // Resolve AI config: org's own key first, fallback to env
    const orgAi = (org?.ai_config as Record<string, unknown>) || {}
    const aiCfg = Object.keys(orgAi).length > 1 ? getAIConfig(orgAi) : getEnvAIConfig()
    console.log(`[scan-worker] ${scanId}: AI provider = ${aiCfg.provider}`)

    // Fetch files
    let files: ScanFile[] = []
    const { data: integration } = await supabase.from("integrations").select("config").eq("organization_id", orgId).eq("provider", "github").eq("status", "active").maybeSingle()
    const token = (integration?.config as Record<string, string>)?.access_token || Deno.env.get("GITHUB_TOKEN")
    if (token) {
      const changedFiles = (scan?.metadata as Record<string, unknown>)?.changed_files as string[] | undefined
      files = await fetchFromGitHub(repo.full_name, scan?.branch || repo.default_branch, scan?.commit_sha || null, token, changedFiles)
    }

    if (!files.length) {
      await supabase.from("scans").update({ status: "completed", completed_at: new Date().toISOString(), duration_seconds: Math.round((Date.now() - t0) / 1000), summary: { files_scanned: 0, total: 0, note: "No files fetched — configure GitHub integration with a PAT" } }).eq("id", scanId)
      await supabase.from("worker_heartbeats").upsert({ worker_id: WORKER_ID, status: "idle", last_heartbeat: new Date().toISOString() }, { onConflict: "worker_id" })
      return
    }

    // Layer 1: Run all regex scanners in parallel
    const [secrets, sast, iac, deps] = await Promise.all([
      Promise.resolve(runSecrets(files)),
      Promise.resolve(runSAST(files)),
      Promise.resolve(runIaC(files)),
      runDependencies(files),
    ])
    const raw = [...secrets, ...sast, ...iac, ...deps]
    console.log(`[scan-worker] ${scanId}: Layer 1 complete — ${raw.length} raw findings`)

    // Layer 1 AI: Fast triage, remove false positives
    const fpIndices = await layer1Triage(raw, aiCfg)
    const verified = raw.filter((_, i) => !fpIndices.has(i))
    console.log(`[scan-worker] ${scanId}: Layer 1 AI triage — removed ${fpIndices.size} FPs, ${verified.length} verified`)

    // Layer 2 AI: Deep analysis for critical/high
    const fileMap = new Map(files.map(f => [f.path, f.content]))
    const l2Map = new Map<string, { explanation: string; remediation: string }>()
    const critHigh = verified.filter(f => f.severity === "critical" || f.severity === "high").slice(0, 10)
    for (const finding of critHigh) {
      const key = `${finding.rule_id}:${finding.file_path}:${finding.line_start}`
      const analysis = await layer2Analyze(finding, fileMap.get(finding.file_path) || "", aiCfg)
      l2Map.set(key, analysis)
    }
    console.log(`[scan-worker] ${scanId}: Layer 2 AI — analyzed ${l2Map.size} findings`)

    // Layer 3 AI: Executive summary
    const execSummary = await layer3Summary(verified, repo.full_name, aiCfg)
    if (execSummary) console.log(`[scan-worker] ${scanId}: Layer 3 AI — summary generated`)

    // Persist findings
    if (verified.length > 0) {
      const rows = verified.map(f => {
        const key = `${f.rule_id}:${f.file_path}:${f.line_start}`
        const l2 = l2Map.get(key)
        return {
          organization_id: orgId, repository_id: repoId, scan_id: scanId,
          scanner: f.scanner, category: f.rule_name, severity: f.severity,
          title: f.title, description: f.description, evidence: f.evidence,
          file_path: f.file_path, line_start: f.line_start, line_end: f.line_start,
          rule_id: f.rule_id, rule_name: f.rule_name,
          owasp: f.owasp, cwe: f.cwe,
          status: "open", risk_score: f.risk_score, confidence_score: f.confidence_score,
          remediation: f.remediation || null,
          ai_summary: l2?.explanation || null, ai_remediation: l2?.remediation || null,
          ai_provider: aiCfg.provider,
        }
      })
      for (let i = 0; i < rows.length; i += 50) {
        await supabase.from("findings").insert(rows.slice(i, i + 50))
      }
    }

    // Update scan record
    const dur = Math.round((Date.now() - t0) / 1000)
    const summary = {
      files_scanned: files.length, total: verified.length,
      critical: verified.filter(f => f.severity === "critical").length,
      high: verified.filter(f => f.severity === "high").length,
      medium: verified.filter(f => f.severity === "medium").length,
      low: verified.filter(f => f.severity === "low").length,
      false_positives_removed: fpIndices.size,
      ai_provider: aiCfg.provider, ai_layers_used: 3,
      executive_summary: execSummary || undefined,
    }
    await supabase.from("scans").update({ status: "completed", completed_at: new Date().toISOString(), duration_seconds: dur, summary }).eq("id", scanId)

    // Update repo risk score
    const avgRisk = verified.length > 0 ? Math.min(100, Math.round(verified.reduce((s, f) => s + f.risk_score, 0) / verified.length)) : 0
    await supabase.from("repositories").update({ risk_score: avgRisk, last_scan_at: new Date().toISOString() }).eq("id", repoId)

    // Notify admins of critical findings
    if (summary.critical > 0) {
      const { data: admins } = await supabase.from("organization_members").select("user_id").eq("organization_id", orgId).in("role", ["owner", "admin"])
      if (admins?.length) {
        await supabase.from("notifications").insert(admins.map(a => ({
          organization_id: orgId, user_id: a.user_id, type: "critical_finding",
          title: `${summary.critical} Critical Finding${summary.critical > 1 ? "s" : ""} in ${repo.full_name}`,
          body: execSummary ? execSummary.split(".")[0] + "." : `${summary.critical} critical vulnerabilities found. Immediate action required.`,
          data: { scan_id: scanId, repository_id: repoId, critical: summary.critical, high: summary.high },
        })))
      }
    }

    await supabase.from("audit_logs").insert({ organization_id: orgId, action: "scan_completed", resource_type: "scan", resource_id: scanId,
      metadata: { findings: verified.length, duration_seconds: dur, files: files.length, ai: aiCfg.provider } })
    await supabase.from("worker_heartbeats").upsert({ worker_id: WORKER_ID, status: "idle", current_scan_id: null, last_heartbeat: new Date().toISOString() }, { onConflict: "worker_id" })

    // Update Prometheus-style metrics
    METRICS.scans_total += 1
    METRICS.findings_total += verified.length
    METRICS.findings_critical += summary.critical
    METRICS.findings_high += summary.high
    METRICS.files_scanned_total += files.length
    METRICS.duration_seconds_sum += dur
    METRICS.last_scan_timestamp = Date.now()

  } catch (err) {
    console.error(`[scan-worker] ${scanId} FAILED:`, err)
    METRICS.scans_failed += 1
    await supabase.from("scans").update({ status: "failed", error_message: err instanceof Error ? err.message : String(err), completed_at: new Date().toISOString(), duration_seconds: Math.round((Date.now() - t0) / 1000) }).eq("id", scanId)
    await supabase.from("worker_heartbeats").upsert({ worker_id: WORKER_ID, status: "error", current_scan_id: null, last_heartbeat: new Date().toISOString() }, { onConflict: "worker_id" })
    throw err
  }
}

// ── Metrics (Prometheus format) ───────────────────────────────────
const METRICS = {
  scans_total: 0,
  scans_failed: 0,
  findings_total: 0,
  findings_critical: 0,
  findings_high: 0,
  ai_calls_total: 0,
  ai_tokens_total: 0,
  files_scanned_total: 0,
  duration_seconds_sum: 0,
  last_scan_timestamp: 0,
}

function prometheusFormat(): string {
  const now = Date.now()
  return `# HELP omniguard_scans_total Total number of scans processed
# TYPE omniguard_scans_total counter
omniguard_scans_total{worker_id="${WORKER_ID}"} ${METRICS.scans_total}

# HELP omniguard_scans_failed_total Total number of failed scans
# TYPE omniguard_scans_failed_total counter
omniguard_scans_failed_total{worker_id="${WORKER_ID}"} ${METRICS.scans_failed}

# HELP omniguard_findings_total Total findings detected
# TYPE omniguard_findings_total counter
omniguard_findings_total{worker_id="${WORKER_ID}"} ${METRICS.findings_total}

# HELP omniguard_findings_by_severity Findings by severity
# TYPE omniguard_findings_by_severity counter
omniguard_findings_by_severity{severity="critical",worker_id="${WORKER_ID}"} ${METRICS.findings_critical}
omniguard_findings_by_severity{severity="high",worker_id="${WORKER_ID}"} ${METRICS.findings_high}

# HELP omniguard_ai_calls_total Total AI API calls
# TYPE omniguard_ai_calls_total counter
omniguard_ai_calls_total{worker_id="${WORKER_ID}"} ${METRICS.ai_calls_total}

# HELP omniguard_ai_tokens_total Total AI tokens consumed
# TYPE omniguard_ai_tokens_total counter
omniguard_ai_tokens_total{worker_id="${WORKER_ID}"} ${METRICS.ai_tokens_total}

# HELP omniguard_files_scanned_total Total files scanned
# TYPE omniguard_files_scanned_total counter
omniguard_files_scanned_total{worker_id="${WORKER_ID}"} ${METRICS.files_scanned_total}

# HELP omniguard_scan_duration_seconds_sum Total scan duration
# TYPE omniguard_scan_duration_seconds_sum counter
omniguard_scan_duration_seconds_sum{worker_id="${WORKER_ID}"} ${METRICS.duration_seconds_sum}

# HELP omniguard_last_scan_timestamp Unix timestamp of last scan
# TYPE omniguard_last_scan_timestamp gauge
omniguard_last_scan_timestamp{worker_id="${WORKER_ID}"} ${METRICS.last_scan_timestamp}

# HELP omniguard_worker_info Worker information
# TYPE omniguard_worker_info gauge
omniguard_worker_info{worker_id="${WORKER_ID}",version="1.0.0"} 1
`
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders })
  const url = new URL(req.url)

  if (req.method === "GET" && url.pathname.endsWith("/health")) {
    return new Response(JSON.stringify({ worker_id: WORKER_ID, status: "healthy", timestamp: new Date().toISOString(), metrics: METRICS }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } })
  }

  if (req.method === "GET" && url.pathname.endsWith("/metrics")) {
    return new Response(prometheusFormat(), { headers: { "Content-Type": "text/plain; version=0.0.4" } })
  }

  if (req.method === "GET" && url.pathname.endsWith("/process")) {
    const { data } = await supabase.rpc("claim_next_scan", { p_worker_id: WORKER_ID })
    const job = Array.isArray(data) ? data[0] : data
    if (!job?.scan_id) return new Response(JSON.stringify({ success: true, message: "No pending scans" }), { headers: { ...corsHeaders, "Content-Type": "application/json" } })
    await processScan(job.scan_id, job.repository_id, job.organization_id)
    return new Response(JSON.stringify({ success: true, scan_id: job.scan_id }), { headers: { ...corsHeaders, "Content-Type": "application/json" } })
  }

  if (req.method === "POST" && url.pathname.endsWith("/process")) {
    const body = await req.json().catch(() => ({}))
    if (!body.scan_id || !body.repository_id || !body.organization_id) {
      return new Response(JSON.stringify({ error: "scan_id, repository_id, organization_id required" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } })
    }
    await processScan(body.scan_id, body.repository_id, body.organization_id)
    return new Response(JSON.stringify({ success: true }), { headers: { ...corsHeaders, "Content-Type": "application/json" } })
  }

  return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } })
})
