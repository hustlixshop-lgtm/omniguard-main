import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";
import { callAI, getEnvAIConfig, extractJson } from "../_shared/ai.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey, X-API-Key",
};

const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { autoRefreshToken: false, persistSession: false },
});

// Local scanner patterns (used when AI is not configured or for fast initial scan)
const SECRETS = [
  { id: "SECRET-AWS-001", name: "AWS Access Key ID", re: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, sev: "critical" },
  { id: "SECRET-GITHUB-001", name: "GitHub PAT", re: /gh[pousr]_[A-Za-z0-9_]{36,}/g, sev: "critical" },
  { id: "SECRET-OPENAI-001", name: "OpenAI Key", re: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, sev: "critical" },
  { id: "SECRET-ANTHROPIC-001", name: "Anthropic Key", re: /sk-ant-[A-Za-z0-9\-_]{95,}/g, sev: "critical" },
  { id: "SECRET-STRIPE-001", name: "Stripe Live Key", re: /sk_live_[0-9a-zA-Z]{24,}/g, sev: "critical" },
  { id: "SECRET-SSH-001", name: "SSH Private Key", re: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g, sev: "critical" },
  { id: "SECRET-DB-001", name: "Database Credentials", re: /(postgres|postgresql|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s'"]{5,}/gi, sev: "critical" },
  { id: "SECRET-JWT-001", name: "JWT Secret", re: /jwt[_\-]?secret["']?\s*[:=]\s*["']([A-Za-z0-9\-_!@#$%^&*]{20,})["']/gi, sev: "critical" },
  { id: "SECRET-PASS-001", name: "Hardcoded Password", re: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{8,})["']/gim, sev: "high" },
];

const SAST = [
  { id: "SAST-SQL-001", name: "SQL Injection", re: /(?:execute|query)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)[^)]*\+/gi, sev: "critical" },
  { id: "SAST-XSS-001", name: "XSS via innerHTML", re: /\.innerHTML\s*[+]?=\s*[^"';\n]{1,80}(?:req\.|request\.|params\.|query\.|\$\{)/gm, sev: "high" },
  { id: "SAST-CMD-001", name: "Command Injection (eval)", re: /\beval\s*\([^)]*(?:req\.|request\.|params\.|query\.)/gi, sev: "critical" },
  { id: "SAST-CMD-002", name: "Command Injection (exec)", re: /(?:child_process\.exec|execSync|os\.system|subprocess\.call)\s*\([^)]*(?:req\.|request\.|params\.|query\.)/gi, sev: "critical" },
  { id: "SAST-SSRF-001", name: "SSRF", re: /(?:fetch|axios\.get|axios\.post|requests\.get)\s*\([^)]*(?:req\.|request\.|params\.|query\.)/gi, sev: "critical" },
  { id: "SAST-PATH-001", name: "Path Traversal", re: /(?:path\.join|path\.resolve|open|fs\.readFile)\s*\([^)]*(?:req\.|request\.|params\.|query\.)/gi, sev: "high" },
];

function mask(v: string) { return v.length <= 8 ? "****" : v.slice(0, 4) + "****" + v.slice(-4); }
function isBinary(c: string) { return (c.match(/[\x00-\x08\x0e-\x1f\x7f]/g) || []).length / Math.max(c.length, 1) > 0.03; }

interface Finding {
  scanner: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  title: string;
  evidence: string;
  file_path: string;
  line_start: number;
  confidence_score: number;
  remediation?: string;
}

function runLocalScan(filePath: string, content: string): Finding[] {
  if (isBinary(content)) return [];
  const out: Finding[] = [];
  const lines = content.split("\n");

  // Secret scanning
  for (const r of SECRETS) {
    r.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    const seen = new Set<number>();
    while ((m = r.re.exec(content)) !== null) {
      const line = content.slice(0, m.index).split("\n").length;
      if (seen.has(line)) continue;
      seen.add(line);
      const lineText = lines[line - 1]?.trim() || "";
      if (/^\s*(\/\/|#|\*)/.test(lineText)) continue;
      if (/(?:test|example|sample|placeholder|changeme|your[-_]|xxx|dummy)/i.test(m[0])) continue;
      out.push({
        scanner: "secret",
        rule_id: r.id,
        rule_name: r.name,
        severity: r.sev,
        title: `${r.name} detected`,
        evidence: mask(m[0]),
        file_path: filePath,
        line_start: line,
        confidence_score: 0.9,
        remediation: "Remove secret from source. Use environment variables or secrets manager.",
      });
    }
  }

  // SAST scanning
  for (const r of SAST) {
    r.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    const seen = new Set<number>();
    while ((m = r.re.exec(content)) !== null) {
      const line = content.slice(0, m.index).split("\n").length;
      if (seen.has(line)) continue;
      seen.add(line);
      if (/^\s*(\/\/|#|\*)/.test(lines[line - 1]?.trim() || "")) continue;
      out.push({
        scanner: "sast",
        rule_id: r.id,
        rule_name: r.name,
        severity: r.sev,
        title: `${r.name} detected`,
        evidence: m[0].slice(0, 150),
        file_path: filePath,
        line_start: line,
        confidence_score: 0.85,
      });
    }
  }

  return out;
}

async function layer1Triage(findings: Finding[], aiCfg: ReturnType<typeof getEnvAIConfig>): Promise<Set<number>> {
  const fpIndices = new Set<number>();
  const criticalHigh = findings.filter(f => f.severity === "critical" || f.severity === "high").slice(0, 15);
  if (!criticalHigh.length || aiCfg.provider === "none") return fpIndices;

  const prompt = `Security triage. Classify each as true_positive or false_positive.
Test files, examples, placeholders = false_positive. Real secrets in non-test = true_positive.

Findings:
${criticalHigh.map((f, i) => `${i}. [${f.severity}] ${f.rule_name} in ${f.file_path}:${f.line_start}\n   Evidence: ${f.evidence}`).join("\n\n")}

Return JSON: [{"index":0,"verdict":"true_positive|false_positive","confidence":0.9}]`;

  const res = await callAI(aiCfg, prompt, "fast", 300);
  if (!res) return fpIndices;
  const arr = extractJson<Array<{ index: number; verdict: string; confidence: number }>>(res.text);
  if (arr) {
    for (const item of arr) {
      if (item.verdict === "false_positive" && item.confidence > 0.7) fpIndices.add(item.index);
    }
  }
  return fpIndices;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const body = await req.json();
    const filePath = body.path || body.file_path || "unknown";
    const content = body.content || "";

    if (!content) {
      return new Response(JSON.stringify({ error: "No content provided" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Run local regex scan
    const rawFindings = runLocalScan(filePath, content);

    // Optional AI triage (Layer 1)
    const aiCfg = getEnvAIConfig();
    const fpIndices = await layer1Triage(rawFindings, aiCfg);
    const verifiedFindings = rawFindings.filter((_, i) => !fpIndices.has(i));

    const summary = {
      total: verifiedFindings.length,
      critical: verifiedFindings.filter(f => f.severity === "critical").length,
      high: verifiedFindings.filter(f => f.severity === "high").length,
      medium: verifiedFindings.filter(f => f.severity === "medium").length,
      low: verifiedFindings.filter(f => f.severity === "low").length,
      false_positives_removed: fpIndices.size,
      ai_provider: aiCfg.provider,
    };

    return new Response(JSON.stringify({
      success: true,
      findings: verifiedFindings,
      summary,
      meta: {
        file_path: filePath,
        lines_scanned: content.split("\n").length,
        scan_type: "quick",
        ai_triage: aiCfg.provider !== "none",
      },
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("scan-quick error:", err);
    return new Response(JSON.stringify({
      error: "Internal server error",
      message: err instanceof Error ? err.message : String(err),
    }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
