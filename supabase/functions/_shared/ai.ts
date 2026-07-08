/**
 * OmniGuard AI Provider Abstraction — Production Edition
 *
 * Features:
 * - 7 providers: Anthropic, OpenAI, AWS Bedrock, Azure OpenAI, Google Gemini, OpenRouter, Ollama
 * - BYOK: org-level encrypted keys, platform never pays
 * - 3-tier model routing: fast (triage) → medium (analysis) → deep (summary)
 * - Exponential backoff retry with jitter (3 attempts)
 * - SHA-256 prompt caching (7-day TTL) via ai_cache table
 * - Token counting and cost metering via ai_usage table
 * - Provider fallback chain
 * - Context window management (truncation before sending)
 */

import { createClient } from "npm:@supabase/supabase-js@2.45.0";

// ── Types ─────────────────────────────────────────────────────

export interface AIConfig {
  provider:               "anthropic" | "openai" | "bedrock" | "azure" | "gemini" | "openrouter" | "ollama" | "none";
  anthropic_api_key?:     string;
  openai_api_key?:        string;
  aws_access_key_id?:     string;
  aws_secret_access_key?: string;
  aws_region?:            string;
  azure_openai_endpoint?: string;
  azure_openai_key?:      string;
  azure_deployment_fast?: string;
  azure_deployment_med?:  string;
  gemini_api_key?:        string;
  openrouter_api_key?:    string;
  ollama_url?:            string;
  ollama_model_fast?:     string;
  ollama_model_med?:      string;
  // Fallback provider if primary fails
  fallback_provider?:     string;
  // Cost/latency controls
  max_tokens_per_scan?:   number;  // hard cap total tokens per scan, default 50000
  disable_deep_tier?:     boolean; // skip layer 3 summary (saves cost)
}

export interface AIResponse {
  text:             string;
  model:            string;
  provider:         string;
  prompt_tokens:    number;
  completion_tokens:number;
  total_tokens:     number;
  latency_ms:       number;
  cache_hit:        boolean;
  tier:             Tier;
}

export type Tier = "fast" | "medium" | "deep";

// ── Model registry ────────────────────────────────────────────

export const MODELS: Record<string, Record<Tier, string>> = {
  anthropic:  { fast: "claude-3-5-haiku-20241022",           medium: "claude-3-5-sonnet-20241022",          deep: "claude-opus-4-5"                           },
  openai:     { fast: "gpt-4o-mini",                         medium: "gpt-4o",                              deep: "gpt-4o"                                    },
  bedrock:    { fast: "anthropic.claude-3-5-haiku-20241022-v1:0", medium: "anthropic.claude-3-5-sonnet-20241022-v2:0", deep: "anthropic.claude-3-5-sonnet-20241022-v2:0" },
  azure:      { fast: "gpt-4o-mini",                         medium: "gpt-4o",                              deep: "gpt-4o"                                    },
  gemini:     { fast: "gemini-1.5-flash",                    medium: "gemini-1.5-pro",                      deep: "gemini-1.5-pro"                            },
  openrouter: { fast: "anthropic/claude-3.5-haiku",          medium: "anthropic/claude-3.5-sonnet",         deep: "anthropic/claude-3-opus"                   },
  ollama:     { fast: "llama3.2",                            medium: "llama3.2",                            deep: "llama3.2"                                  },
};

// Approximate cost per 1M tokens (input/output average), USD
const COST_PER_1M: Record<string, Record<Tier, number>> = {
  anthropic:  { fast: 1.0,  medium: 9.0,   deep: 45.0  },
  openai:     { fast: 0.3,  medium: 7.5,   deep: 7.5   },
  bedrock:    { fast: 1.0,  medium: 9.0,   deep: 9.0   },
  azure:      { fast: 0.3,  medium: 7.5,   deep: 7.5   },
  gemini:     { fast: 0.075,medium: 1.25,  deep: 1.25  },
  openrouter: { fast: 1.0,  medium: 9.0,   deep: 9.0   },
  ollama:     { fast: 0.0,  medium: 0.0,   deep: 0.0   },
};

// ── Helpers ───────────────────────────────────────────────────

export function extractJson<T>(text: string): T | null {
  try {
    const clean = text.replace(/^```(?:json)?\n?/, "").replace(/\n?```$/, "").trim();
    const m = clean.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
    return m ? JSON.parse(m[0]) : null;
  } catch { return null; }
}

/** SHA-256 a string, returns hex */
async function sha256(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/** Truncate prompt to fit context window, preserving the end */
function truncatePrompt(prompt: string, maxChars = 30000): string {
  if (prompt.length <= maxChars) return prompt;
  const half = Math.floor(maxChars / 2);
  return prompt.slice(0, half) + "\n\n[...truncated...]\n\n" + prompt.slice(-half);
}

/** Exponential backoff delay with jitter */
function backoffDelay(attempt: number): number {
  return Math.min(1000 * Math.pow(2, attempt) + Math.random() * 500, 10000);
}

// ── Supabase client for caching / metering ────────────────────

let _supa: ReturnType<typeof createClient> | null = null;
function getSupa() {
  if (!_supa) {
    const url = Deno.env.get("SUPABASE_URL");
    const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (url && key) _supa = createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
  }
  return _supa;
}

async function cacheGet(cacheKey: string): Promise<string | null> {
  const supa = getSupa(); if (!supa) return null;
  try {
    const { data } = await supa.from("ai_cache").select("response_text").eq("cache_key", cacheKey).gt("expires_at", new Date().toISOString()).maybeSingle();
    if (data) { await supa.from("ai_cache").update({ hit_count: supa.rpc("increment_hit", {}) }).eq("cache_key", cacheKey).catch(() => {}); return data.response_text; }
  } catch { /* non-fatal */ }
  return null;
}

async function cachePut(cacheKey: string, orgId: string | null, provider: string, model: string, promptHash: string, text: string, tokens: number): Promise<void> {
  const supa = getSupa(); if (!supa) return;
  try {
    await supa.from("ai_cache").upsert({ cache_key: cacheKey, organization_id: orgId, provider, model, prompt_hash: promptHash, response_text: text, tokens_used: tokens, expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() }, { onConflict: "cache_key" });
  } catch { /* non-fatal */ }
}

async function recordUsage(orgId: string | null, scanId: string | null, provider: string, model: string, tier: Tier, promptTokens: number, completionTokens: number, cacheHit: boolean, latencyMs: number): Promise<void> {
  const supa = getSupa(); if (!supa || !orgId) return;
  try {
    await supa.from("ai_usage").insert({ organization_id: orgId, scan_id: scanId, provider, model, tier, prompt_tokens: promptTokens, completion_tokens: completionTokens, total_tokens: promptTokens + completionTokens, cache_hit: cacheHit, latency_ms: latencyMs });
  } catch { /* non-fatal */ }
}

// ── Provider callers ──────────────────────────────────────────

async function callAnthropic(key: string, model: string, prompt: string, maxTokens: number): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model, max_tokens: maxTokens, messages: [{ role: "user", content: prompt }] }),
    signal: AbortSignal.timeout(45_000),
  });
  if (!r.ok) { const e = await r.text(); throw new Error(`Anthropic ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  return { text: d.content?.[0]?.text ?? "", promptTokens: d.usage?.input_tokens ?? 0, completionTokens: d.usage?.output_tokens ?? 0 };
}

async function callOpenAI(key: string, model: string, prompt: string, maxTokens: number): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${key}` },
    body: JSON.stringify({ model, max_tokens: maxTokens, messages: [{ role: "system", content: "You are an expert security engineer." }, { role: "user", content: prompt }] }),
    signal: AbortSignal.timeout(45_000),
  });
  if (!r.ok) { const e = await r.text(); throw new Error(`OpenAI ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  return { text: d.choices?.[0]?.message?.content ?? "", promptTokens: d.usage?.prompt_tokens ?? 0, completionTokens: d.usage?.completion_tokens ?? 0 };
}

async function callGemini(key: string, model: string, prompt: string): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { maxOutputTokens: 1024 } }),
    signal: AbortSignal.timeout(45_000),
  });
  if (!r.ok) { const e = await r.text(); throw new Error(`Gemini ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  return { text: d.candidates?.[0]?.content?.parts?.[0]?.text ?? "", promptTokens: d.usageMetadata?.promptTokenCount ?? 0, completionTokens: d.usageMetadata?.candidatesTokenCount ?? 0 };
}

async function callOpenRouter(key: string, model: string, prompt: string, maxTokens: number): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  const r = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${key}`, "HTTP-Referer": "https://omniguard.io", "X-Title": "OmniGuard" },
    body: JSON.stringify({ model, max_tokens: maxTokens, messages: [{ role: "user", content: prompt }] }),
    signal: AbortSignal.timeout(45_000),
  });
  if (!r.ok) { const e = await r.text(); throw new Error(`OpenRouter ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  return { text: d.choices?.[0]?.message?.content ?? "", promptTokens: d.usage?.prompt_tokens ?? 0, completionTokens: d.usage?.completion_tokens ?? 0 };
}

async function callOllama(baseUrl: string, model: string, prompt: string): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  const r = await fetch(`${baseUrl}/api/generate`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model, prompt, stream: false }),
    signal: AbortSignal.timeout(120_000),
  });
  if (!r.ok) { const e = await r.text(); throw new Error(`Ollama ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  return { text: d.response ?? "", promptTokens: d.prompt_eval_count ?? 0, completionTokens: d.eval_count ?? 0 };
}

async function callBedrock(cfg: AIConfig, modelId: string, prompt: string, maxTokens: number): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  const region = cfg.aws_region ?? "us-east-1";
  const endpoint = `https://bedrock-runtime.${region}.amazonaws.com/model/${encodeURIComponent(modelId)}/invoke`;
  const body = JSON.stringify({ anthropic_version: "bedrock-2023-05-31", max_tokens: maxTokens, messages: [{ role: "user", content: prompt }] });
  const enc = new TextEncoder();
  const now = new Date();
  const dateStr = now.toISOString().replace(/[:-]/g, "").replace(/\.\d{3}Z$/, "Z");
  const shortDate = dateStr.slice(0, 8);
  const payloadHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(body)))).map(b => b.toString(16).padStart(2, "0")).join("");
  const host = `bedrock-runtime.${region}.amazonaws.com`;
  const canonHeaders = `content-type:application/json\nhost:${host}\nx-amz-date:${dateStr}\n`;
  const signedHeaders = "content-type;host;x-amz-date";
  const canonReq = ["POST", `/model/${encodeURIComponent(modelId)}/invoke`, "", canonHeaders, signedHeaders, payloadHash].join("\n");
  const crHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(canonReq)))).map(b => b.toString(16).padStart(2, "0")).join("");
  const credScope = `${shortDate}/${region}/bedrock/aws4_request`;
  const sts = ["AWS4-HMAC-SHA256", dateStr, credScope, crHash].join("\n");
  const hmac = async (k: ArrayBuffer, m: string) => { const key = await crypto.subtle.importKey("raw", k, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); return crypto.subtle.sign("HMAC", key, enc.encode(m)); };
  const kDate = await hmac(enc.encode(`AWS4${cfg.aws_secret_access_key}`), shortDate);
  const kRegion = await hmac(kDate, region); const kSvc = await hmac(kRegion, "bedrock"); const kSign = await hmac(kSvc, "aws4_request");
  const sig = Array.from(new Uint8Array(await hmac(kSign, sts))).map(b => b.toString(16).padStart(2, "0")).join("");
  const auth = `AWS4-HMAC-SHA256 Credential=${cfg.aws_access_key_id}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${sig}`;
  const r = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json", "x-amz-date": dateStr, "Authorization": auth }, body, signal: AbortSignal.timeout(45_000) });
  if (!r.ok) { const e = await r.text(); throw new Error(`Bedrock ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  return { text: d.content?.[0]?.text ?? "", promptTokens: d.usage?.input_tokens ?? 0, completionTokens: d.usage?.output_tokens ?? 0 };
}

async function callAzure(cfg: AIConfig, deployment: string, prompt: string, maxTokens: number): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  const url = `${cfg.azure_openai_endpoint}/openai/deployments/${deployment}/chat/completions?api-version=2024-05-01-preview`;
  const r = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json", "api-key": cfg.azure_openai_key! },
    body: JSON.stringify({ max_tokens: maxTokens, messages: [{ role: "user", content: prompt }] }),
    signal: AbortSignal.timeout(45_000),
  });
  if (!r.ok) { const e = await r.text(); throw new Error(`Azure ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  return { text: d.choices?.[0]?.message?.content ?? "", promptTokens: d.usage?.prompt_tokens ?? 0, completionTokens: d.usage?.completion_tokens ?? 0 };
}

// ── Core dispatch with retry + cache ─────────────────────────

interface CallOptions {
  maxTokens?:     number;
  orgId?:         string;
  scanId?:        string;
  skipCache?:     boolean;
  cacheTtlDays?:  number;
}

async function dispatchWithRetry(
  cfg: AIConfig, model: string, prompt: string, maxTokens: number
): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  let lastErr: Error | null = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) await new Promise(r => setTimeout(r, backoffDelay(attempt - 1)));
    try {
      switch (cfg.provider) {
        case "anthropic":  return await callAnthropic(cfg.anthropic_api_key!,  model, prompt, maxTokens);
        case "openai":     return await callOpenAI(cfg.openai_api_key!,        model, prompt, maxTokens);
        case "bedrock":    return await callBedrock(cfg,                        model, prompt, maxTokens);
        case "azure":      return await callAzure(cfg,                          model, prompt, maxTokens);
        case "gemini":     return await callGemini(cfg.gemini_api_key!,        model, prompt);
        case "openrouter": return await callOpenRouter(cfg.openrouter_api_key!, model, prompt, maxTokens);
        case "ollama":     return await callOllama(cfg.ollama_url ?? "http://localhost:11434", model, prompt);
        default: throw new Error(`Unknown provider: ${cfg.provider}`);
      }
    } catch (err) {
      lastErr = err instanceof Error ? err : new Error(String(err));
      const msg = lastErr.message;
      // Don't retry auth errors
      if (msg.includes("401") || msg.includes("403") || msg.includes("invalid_api_key")) throw lastErr;
      // Don't retry context-length errors
      if (msg.includes("context_length") || msg.includes("maximum context")) throw lastErr;
      console.warn(`[ai] attempt ${attempt + 1} failed for ${cfg.provider}/${model}: ${msg}`);
    }
  }
  throw lastErr ?? new Error("AI call failed after 3 attempts");
}

/**
 * Main entry point — call AI with full caching, retry, metering
 */
export async function callAI(
  cfg: AIConfig,
  prompt: string,
  tier: Tier = "medium",
  opts: CallOptions = {}
): Promise<AIResponse | null> {
  if (cfg.provider === "none") return null;

  const model = (() => {
    if (cfg.provider === "azure") {
      return tier === "fast" ? (cfg.azure_deployment_fast ?? "gpt-4o-mini")
           : tier === "deep" ? (cfg.azure_deployment_med  ?? "gpt-4o")
           : (cfg.azure_deployment_med ?? "gpt-4o");
    }
    if (cfg.provider === "ollama") {
      return tier === "fast" ? (cfg.ollama_model_fast ?? "llama3.2") : (cfg.ollama_model_med ?? "llama3.2");
    }
    return MODELS[cfg.provider]?.[tier];
  })();
  if (!model) return null;

  const maxTokens = opts.maxTokens ?? (tier === "fast" ? 400 : tier === "deep" ? 600 : 800);
  const truncated = truncatePrompt(prompt, tier === "fast" ? 12000 : tier === "deep" ? 20000 : 16000);

  // Cache key = hash(provider + model + truncated prompt)
  const cacheKey = await sha256(`${cfg.provider}:${model}:${truncated}`);
  const t0 = Date.now();

  if (!opts.skipCache) {
    const cached = await cacheGet(cacheKey);
    if (cached) {
      const latency = Date.now() - t0;
      await recordUsage(opts.orgId ?? null, opts.scanId ?? null, cfg.provider, model, tier, 0, 0, true, latency);
      return { text: cached, model, provider: cfg.provider, prompt_tokens: 0, completion_tokens: 0, total_tokens: 0, latency_ms: latency, cache_hit: true, tier };
    }
  }

  let result: { text: string; promptTokens: number; completionTokens: number } | null = null;
  let usedProvider = cfg.provider;
  let usedModel = model;

  try {
    result = await dispatchWithRetry(cfg, model, truncated, maxTokens);
  } catch (primaryErr) {
    // Try fallback provider if configured
    if (cfg.fallback_provider && cfg.fallback_provider !== cfg.provider) {
      const fbCfg = { ...cfg, provider: cfg.fallback_provider as AIConfig["provider"] };
      const fbModel = MODELS[cfg.fallback_provider]?.[tier];
      if (fbModel) {
        try {
          console.warn(`[ai] Primary ${cfg.provider} failed, trying fallback ${cfg.fallback_provider}`);
          result = await dispatchWithRetry(fbCfg, fbModel, truncated, maxTokens);
          usedProvider = cfg.fallback_provider;
          usedModel = fbModel;
        } catch { /* both failed */ }
      }
    }
    if (!result) {
      console.error(`[ai] All providers failed for tier=${tier}: ${primaryErr}`);
      return null;
    }
  }

  const latency = Date.now() - t0;
  const total = result.promptTokens + result.completionTokens;

  // Store in cache
  await cachePut(cacheKey, opts.orgId ?? null, usedProvider, usedModel, cacheKey, result.text, total);

  // Record usage
  await recordUsage(opts.orgId ?? null, opts.scanId ?? null, usedProvider, usedModel, tier, result.promptTokens, result.completionTokens, false, latency);

  console.log(`[ai] ${usedProvider}/${usedModel} tier=${tier} tokens=${total} latency=${latency}ms`);

  return {
    text: result.text, model: usedModel, provider: usedProvider,
    prompt_tokens: result.promptTokens, completion_tokens: result.completionTokens,
    total_tokens: total, latency_ms: latency, cache_hit: false, tier,
  };
}

// ── Config helpers ────────────────────────────────────────────

export function getAIConfig(orgConfig: Record<string, unknown>): AIConfig {
  return {
    provider:               (orgConfig.provider as AIConfig["provider"]) ?? "none",
    anthropic_api_key:      orgConfig.anthropic_api_key   as string | undefined,
    openai_api_key:         orgConfig.openai_api_key      as string | undefined,
    aws_access_key_id:      orgConfig.aws_access_key_id   as string | undefined,
    aws_secret_access_key:  orgConfig.aws_secret_access_key as string | undefined,
    aws_region:             (orgConfig.aws_region         as string | undefined) ?? "us-east-1",
    azure_openai_endpoint:  orgConfig.azure_openai_endpoint as string | undefined,
    azure_openai_key:       orgConfig.azure_openai_key    as string | undefined,
    azure_deployment_fast:  orgConfig.azure_deployment_fast as string | undefined,
    azure_deployment_med:   orgConfig.azure_deployment_med  as string | undefined,
    gemini_api_key:         orgConfig.gemini_api_key      as string | undefined,
    openrouter_api_key:     orgConfig.openrouter_api_key  as string | undefined,
    ollama_url:             orgConfig.ollama_url           as string | undefined,
    ollama_model_fast:      orgConfig.ollama_model_fast    as string | undefined,
    ollama_model_med:       orgConfig.ollama_model_med     as string | undefined,
    fallback_provider:      orgConfig.fallback_provider    as string | undefined,
    max_tokens_per_scan:    orgConfig.max_tokens_per_scan  as number | undefined,
    disable_deep_tier:      orgConfig.disable_deep_tier    as boolean | undefined,
  };
}

export function getEnvAIConfig(): AIConfig {
  return {
    provider:              (Deno.env.get("AI_PROVIDER") ?? "none") as AIConfig["provider"],
    anthropic_api_key:     Deno.env.get("ANTHROPIC_API_KEY"),
    openai_api_key:        Deno.env.get("OPENAI_API_KEY"),
    aws_access_key_id:     Deno.env.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key: Deno.env.get("AWS_SECRET_ACCESS_KEY"),
    aws_region:            Deno.env.get("AWS_REGION") ?? "us-east-1",
    gemini_api_key:        Deno.env.get("GEMINI_API_KEY"),
    openrouter_api_key:    Deno.env.get("OPENROUTER_API_KEY"),
    ollama_url:            Deno.env.get("OLLAMA_URL"),
    fallback_provider:     Deno.env.get("AI_FALLBACK_PROVIDER"),
  };
}

/** Merge org key over platform env — org always wins */
export function resolveAIConfig(orgConfig: Record<string, unknown>): AIConfig {
  const envCfg = getEnvAIConfig();
  const orgCfg = getAIConfig(orgConfig);
  // If org has a provider key configured, use it entirely
  if (orgCfg.provider !== "none") return { ...orgCfg, fallback_provider: orgCfg.fallback_provider ?? envCfg.provider !== "none" ? envCfg.provider : undefined };
  // Fall back to platform env
  return envCfg;
}

/** Estimated cost in USD for a token count */
export function estimateCost(provider: string, tier: Tier, tokens: number): number {
  const rate = COST_PER_1M[provider]?.[tier] ?? 0;
  return (tokens / 1_000_000) * rate;
}
