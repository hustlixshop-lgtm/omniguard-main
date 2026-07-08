import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";
import { callAI, getAIConfig, getEnvAIConfig, extractJson } from "../_shared/ai.ts";

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey, X-API-Key" };
const supa = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { autoRefreshToken: false, persistSession: false } });

const SECRETS = [
  { id: "SECRET-AWS-001", name: "AWS Access Key", re: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, sev: "critical" },
  { id: "SECRET-GITHUB-001", name: "GitHub PAT", re: /gh[pousr]_[A-Za-z0-9_]{36,}/g, sev: "critical" },
  { id: "SECRET-OPENAI-001", name: "OpenAI Key", re: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, sev: "critical" },
  { id: "SECRET-OPENAI-002", name: "OpenAI Project Key", re: /sk-proj-[A-Za-z0-9_-]{40,}/g, sev: "critical" },
  { id: "SECRET-ANTHROPIC-001", name: "Anthropic Key", re: /sk-ant-[A-Za-z0-9\-_]{95,}/g, sev: "critical" },
  { id: "SECRET-STRIPE-001", name: "Stripe Live Key", re: /sk_live_[0-9a-zA-Z]{24,}/g, sev: "critical" },
  { id: "SECRET-SSH-001", name: "SSH Private Key", re: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g, sev: "critical" },
  { id: "SECRET-DB-001", name: "DB Connection String", re: /(postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s'"]{5,}/gi, sev: "critical" },
];

const SAST = [
  { id: "SAST-SQL-001", name: "SQL Injection", re: /(?:execute|query)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)[^)]*\+/gi, sev: "critical" },
  { id: "SAST-XSS-001", name: "XSS via innerHTML", re: /\.innerHTML\s*[+]?=\s*[^"';\n]{1,80}(?:req\.|request\.|params\.|\$\{)/gm, sev: "high" },
  { id: "SAST-CMD-001", name: "Command Injection", re: /(?:child_process\.exec|execSync|os\.system)\s*\([^)]*(?:req\.|request\.|query\.)/gi, sev: "critical" },
  { id: "SAST-DESER-001", name: "Unsafe Deserialization", re: /pickle\.loads?\s*\(/g, sev: "critical" },
  { id: "SAST-JWT-001", name: "JWT Algorithm None", re: /algorithm[s]?\s*[:=]\s*["']none["']/gi, sev: "critical" },
  { id: "SAST-CRYPTO-001", name: "Weak Hash MD5", re: /createHash\s*\(\s*["']md5["']/gi, sev: "high" },
];

function mask(v: string) { return v.length <= 8 ? "****" : v.slice(0, 4) + "****" + v.slice(-4) }

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: cors });
  if (req.method !== "POST") return new Response(JSON.stringify({ error: "POST required" }), { status: 405, headers: { ...cors, "Content-Type": "application/json" } });

  // Auth
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: { ...cors, "Content-Type": "application/json" } });
  const token = authHeader.slice(7);
  let orgAiConfig: Record<string, unknown> = {};
  if (token.split(".").length === 3) {
    const { data: { user } } = await supa.auth.getUser(token);
    if (user) {
      const { data: m } = await supa.from("organization_members").select("organization_id, organizations(ai_config)").eq("user_id", user.id).eq("status", "active").limit(1).maybeSingle();
      orgAiConfig = (m?.organizations as { ai_config?: Record<string, unknown> } | null)?.ai_config || {};
    }
  } else if (token.startsWith("og_")) {
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)))).map(b => b.toString(16).padStart(2, "0")).join("");
    const { data: k } = await supa.from("api_keys").select("organization_id, organizations(ai_config)").eq("key_hash", hash).eq("is_active", true).maybeSingle();
    if (k) orgAiConfig = (k.organizations as { ai_config?: Record<string, unknown> } | null)?.ai_config || {};
  }

  const aiCfg = Object.keys(orgAiConfig).length > 1 ? getAIConfig(orgAiConfig) : getEnvAIConfig();

  let files: Array<{ path: string; content: string }> = [];
  const body = await req.json().catch(() => ({}));

  // Support single file or batch
  if (body.content && body.path) {
    files = [{ path: body.path, content: body.base64 ? atob(body.content) : body.content }];
  } else if (body.files) {
    files = (body.files as Array<{ path: string; content: string; base64?: boolean }>).map(f => ({ path: f.path, content: f.base64 ? atob(f.content) : f.content })).slice(0, 20);
  }

  if (!files.length) return new Response(JSON.stringify({ error: "path + content required" }), { status: 400, headers: { ...cors, "Content-Type": "application/json" } });

  const findings: unknown[] = [];
  for (const file of files) {
    for (const r of SECRETS) {
      r.re.lastIndex = 0; let m: RegExpExecArray | null
      while ((m = r.re.exec(file.content)) !== null) {
        const line = file.content.slice(0, m.index).split("\n").length;
        const lt = file.content.split("\n")[line - 1]?.trim() || "";
        if (/^\s*(\/\/|#|\*)/.test(lt)) continue;
        if (/(?:test|example|sample|placeholder|changeme)/i.test(m[0])) continue;
        findings.push({ scanner: "secret", rule_id: r.id, severity: r.sev, title: `${r.name} detected`, evidence: mask(m[0]), file_path: file.path, line_start: line, confidence: 0.9 });
      }
    }
    for (const r of SAST) {
      r.re.lastIndex = 0; let m: RegExpExecArray | null
      while ((m = r.re.exec(file.content)) !== null) {
        const line = file.content.slice(0, m.index).split("\n").length;
        if (/^\s*(\/\/|#|\*)/.test(file.content.split("\n")[line - 1]?.trim() || "")) continue;
        findings.push({ scanner: "sast", rule_id: r.id, severity: r.sev, title: `${r.name}`, evidence: m[0].slice(0, 150), file_path: file.path, line_start: line, confidence: 0.8 });
      }
    }
  }

  // AI classification if enabled and findings exist
  let aiUsed = false;
  const critHigh = findings.filter((f) => { const ff = f as { severity: string }; return ff.severity === "critical" || ff.severity === "high" });
  if (aiCfg.provider !== "none" && critHigh.length > 0 && body.ai !== false) {
    const prompt = `Triage these security findings. Return JSON array: [{"index":0,"fp":false,"confidence":0.9}]
${critHigh.slice(0, 10).map((f, i) => { const ff = f as { severity: string; rule_id: string; file_path: string; evidence: string }; return `${i}. [${ff.severity}] ${ff.rule_id} in ${ff.file_path}\n   Evidence: ${ff.evidence}` }).join("\n")}`
    const res = await callAI(aiCfg, prompt, "fast", 300);
    if (res) {
      aiUsed = true;
      const arr = extractJson<Array<{ index: number; fp: boolean; confidence: number }>>(res.text);
      if (arr) {
        const fpIndices = new Set(arr.filter(a => a.fp && a.confidence > 0.7).map(a => a.index));
        for (const idx of fpIndices) {
          const critHighFinding = critHigh[idx];
          const globalIdx = findings.indexOf(critHighFinding);
          if (globalIdx !== -1) (findings[globalIdx] as Record<string, unknown>).status = "false_positive";
        }
      }
    }
  }

  const active = findings.filter((f) => (f as { status?: string }).status !== "false_positive");
  const summary = { total: active.length, critical: active.filter((f) => (f as { severity: string }).severity === "critical").length, high: active.filter((f) => (f as { severity: string }).severity === "high").length, medium: active.filter((f) => (f as { severity: string }).severity === "medium").length, low: active.filter((f) => (f as { severity: string }).severity === "low").length, files_scanned: files.length, ai_used: aiUsed };
  return new Response(JSON.stringify({ success: true, findings: active, summary }), { headers: { ...cors, "Content-Type": "application/json" } });
});
