import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";
import { callAI, resolveAIConfigFromOrg, getEnvAIConfig, extractJson } from "../_shared/ai.ts";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey, X-API-Key",
};

const supa = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

const SECRETS = [
  { id: "SECRET-AWS-001",       name: "AWS Access Key",       re: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,      sev: "critical" },
  { id: "SECRET-GITHUB-001",    name: "GitHub PAT",           re: /gh[pousr]_[A-Za-z0-9_]{36,}/g,                                                 sev: "critical" },
  { id: "SECRET-OPENAI-001",    name: "OpenAI Key",           re: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g,                                  sev: "critical" },
  { id: "SECRET-OPENAI-002",    name: "OpenAI Project Key",   re: /sk-proj-[A-Za-z0-9_-]{40,}/g,                                                  sev: "critical" },
  { id: "SECRET-ANTHROPIC-001", name: "Anthropic Key",        re: /sk-ant-[A-Za-z0-9\-_]{95,}/g,                                                  sev: "critical" },
  { id: "SECRET-STRIPE-001",    name: "Stripe Live Key",      re: /sk_live_[0-9a-zA-Z]{24,}/g,                                                    sev: "critical" },
  { id: "SECRET-SSH-001",       name: "SSH Private Key",      re: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,                      sev: "critical" },
  { id: "SECRET-DB-001",        name: "DB Connection String", re: /(postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s'"]{5,}/gi,              sev: "critical" },
  { id: "SECRET-NPM-001",       name: "npm Token",            re: /npm_[A-Za-z0-9]{36,}/g,                                                        sev: "critical" },
  { id: "SECRET-AZURE-001",     name: "Azure Storage Key",    re: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/g, sev: "critical" },
  { id: "SECRET-PASS-001",      name: "Hardcoded Password",   re: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{8,})["']/gim,                    sev: "high" },
  { id: "SECRET-JWT-001",       name: "JWT Token",            re: /eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}/g,             sev: "high" },
];

const SAST = [
  { id: "SAST-SQL-001",    name: "SQL Injection",           re: /(?:execute|query)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)[^)]*\+/gi,   sev: "critical" },
  { id: "SAST-XSS-001",    name: "XSS via innerHTML",       re: /\.innerHTML\s*[+]?=\s*[^"';\n]{1,80}(?:req\.|request\.|params\.|\$\{)/gm, sev: "high" },
  { id: "SAST-CMD-001",    name: "Command Injection",       re: /(?:child_process\.exec|execSync|os\.system)\s*\([^)]*(?:req\.|request\.|query\.)/gi, sev: "critical" },
  { id: "SAST-DESER-001",  name: "Unsafe Deserialization",  re: /pickle\.loads?\s*\(/g,                                                   sev: "critical" },
  { id: "SAST-JWT-001",    name: "JWT Algorithm None",      re: /algorithm[s]?\s*[:=]\s*["']none["']/gi,                                  sev: "critical" },
  { id: "SAST-CRYPTO-001", name: "Weak Hash MD5",           re: /createHash\s*\(\s*["']md5["']/gi,                                        sev: "high" },
  { id: "SAST-EVAL-001",   name: "eval() Usage",            re: /\beval\s*\(/g,                                                           sev: "high" },
  { id: "SAST-PATH-001",   name: "Path Traversal",          re: /\.\.\/|path\.join\([^)]*req\.|path\.join\([^)]*params\./gi,             sev: "high" },
];

const SKIP_FP = /(?:test|example|sample|placeholder|changeme|your[-_]?api|xxx|<|>|\$\{|\$\(|foobar|00000000)/i;
const SKIP_COMMENT = /^\s*(\/\/|#|\*|<!--)/;

function mask(v: string) {
  return v.length <= 8 ? "****" : v.slice(0, 4) + "...(" + v.length + ")..." + v.slice(-4);
}

function localScan(filePath: string, content: string) {
  const findings: Array<Record<string, unknown>> = [];
  const lines = content.split("\n");

  for (const rule of [...SECRETS, ...SAST]) {
    (rule.re as RegExp).lastIndex = 0;
    let m: RegExpExecArray | null;
    const seen = new Set<number>();
    while ((m = (rule.re as RegExp).exec(content)) !== null) {
      const lineNum = content.slice(0, m.index).split("\n").length;
      if (seen.has(lineNum)) continue;
      seen.add(lineNum);
      const lineText = lines[lineNum - 1] || "";
      if (SKIP_COMMENT.test(lineText)) continue;
      if (SKIP_FP.test(m[0])) continue;
      const isSecret = SECRETS.some(s => s.id === rule.id);
      findings.push({
        scanner: isSecret ? "secret" : "sast",
        rule_id: rule.id, severity: rule.sev,
        title: `${rule.name} detected`,
        evidence: isSecret ? mask(m[0]) : m[0].slice(0, 80),
        file_path: filePath, line_start: lineNum,
      });
    }
  }
  return findings;
}

async function resolveOrgId(authHeader: string): Promise<string | null> {
  const token = authHeader.replace(/^Bearer /, "");
  if (token.split(".").length === 3) {
    const { data: { user } } = await supa.auth.getUser(token);
    if (!user) return null;
    const { data: m } = await supa.from("organization_members").select("organization_id").eq("user_id", user.id).eq("status", "active").limit(1).maybeSingle();
    return m?.organization_id ?? null;
  }
  if (token.startsWith("og_")) {
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)))).map(b => b.toString(16).padStart(2, "0")).join("");
    const { data: k } = await supa.from("api_keys").select("organization_id").eq("key_hash", hash).eq("is_active", true).maybeSingle();
    return k?.organization_id ?? null;
  }
  return null;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: cors });
  if (req.method !== "POST") return new Response(JSON.stringify({ error: "POST required" }), { status: 405, headers: { ...cors, "Content-Type": "application/json" } });

  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: { ...cors, "Content-Type": "application/json" } });

  // Resolve AI config (vault-aware — never returns raw keys to client)
  const orgId = await resolveOrgId(authHeader);
  const aiCfg = orgId ? await resolveAIConfigFromOrg(orgId) : getEnvAIConfig();

  const body = await req.json().catch(() => ({}));

  let files: Array<{ path: string; content: string }> = [];
  if (body.content && body.path) {
    files = [{ path: body.path, content: body.base64 ? atob(body.content) : body.content }];
  } else if (body.files) {
    files = (body.files as Array<{ path: string; content: string; base64?: boolean }>)
      .map(f => ({ path: f.path, content: f.base64 ? atob(f.content) : f.content }))
      .slice(0, 20);
  }

  if (!files.length) return new Response(JSON.stringify({ error: "body must include path+content or files[]" }), { status: 400, headers: { ...cors, "Content-Type": "application/json" } });

  const allFindings: Array<Record<string, unknown>> = [];
  for (const f of files) {
    allFindings.push(...localScan(f.path, f.content));
  }

  // AI enrichment on critical/high findings (fire-and-forget latency guard)
  if (aiCfg.provider !== "none" && allFindings.some(f => ["critical", "high"].includes(f.severity as string))) {
    const topFindings = allFindings.filter(f => ["critical", "high"].includes(f.severity as string)).slice(0, 5);
    const prompt = `You are a security analyst. For each finding below, provide a one-sentence explanation and a one-line code fix. Return JSON array [{rule_id, explanation, fix}].

Findings:
${topFindings.map(f => `- ${f.rule_id}: ${f.title} at ${f.file_path}:${f.line_start}`).join("\n")}`;

    const aiRes = await callAI(aiCfg, prompt, "fast", { maxTokens: 800, orgId: orgId ?? undefined, skipCache: false });
    if (aiRes) {
      const parsed = extractJson<Array<{ rule_id: string; explanation: string; fix: string }>>(aiRes.text);
      if (parsed) {
        const byRule = Object.fromEntries(parsed.map(r => [r.rule_id, r]));
        for (const f of allFindings) {
          const enrich = byRule[f.rule_id as string];
          if (enrich) { f.ai_explanation = enrich.explanation; f.ai_fix = enrich.fix; }
        }
      }
    }
  }

  return new Response(JSON.stringify({ findings: allFindings, total: allFindings.length, ai_enabled: aiCfg.provider !== "none" }), { headers: { ...cors, "Content-Type": "application/json" } });
});
