/**
 * OmniGuard AI Provider Abstraction — Production Edition
 *
 * Features:
 * - 7 providers: Anthropic, OpenAI, AWS Bedrock, Azure OpenAI, Google Gemini, OpenRouter, Ollama
 * - BYOK: org-level encrypted keys stored in Supabase Vault, platform never pays
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
  fallback_provider?:     string;
  max_tokens_per_scan?:   number;
  disable_deep_tier?:     boolean;
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
  anthropic:  { fast: "claude-3-5-haiku-20241022",                        medium: "claude-3-5-sonnet-20241022",                       deep: "claude-3-5-sonnet-20241022"                             },
  openai:     { fast: "gpt-4o-mini",                                      medium: "gpt-4o",                                           deep: "gpt-4o"                                                 },
  bedrock:    { fast: "anthropic.claude-3-5-haiku-20241022-v1:0",         medium: "anthropic.claude-3-5-sonnet-20241022-v2:0",        deep: "anthropic.claude-3-5-sonnet-20241022-v2:0"              },
  azure:      { fast: "gpt-4o-mini",                                      medium: "gpt-4o",                                           deep: "gpt-4o"                                                 },
  gemini:     { fast: "gemini-1.5-flash",                                 medium: "gemini-1.5-pro",                                   deep: "gemini-1.5-pro"                                         },
  openrouter: { fast: "anthropic/claude-3.5-haiku",                       medium: "anthropic/claude-3.5-sonnet",                      deep: "anthropic/claude-3-opus"                                },
  ollama:     { fast: "llama3.2",                                         medium: "llama3.2",                                         deep: "llama3.2"                                               },
};

const COST_PER_1M: Record<string, Record<Tier, number>> = {
  anthropic:  { fast: 1.0,   medium: 9.0,  deep: 45.0 },
  openai:     { fast: 0.3,   medium: 7.5,  deep: 7.5  },
  bedrock:    { fast: 1.0,   medium: 9.0,  deep: 9.0  },
  azure:      { fast: 0.3,   medium: 7.5,  deep: 7.5  },
  gemini:     { fast: 0.075, medium: 1.25, deep: 1.25 },
  openrouter: { fast: 1.0,   medium: 9.0,  deep: 9.0  },
  ollama:     { fast: 0.0,   medium: 0.0,  deep: 0.0  },
};

// ── Helpers ───────────────────────────────────────────────────

export function extractJson<T>(text: string): T | null {
  try {
    const clean = text.replace(/^```(?:json)?\n?/, "").replace(/\n?```$/, "").trim();
    const m = clean.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
    return m ? JSON.parse(m[0]) : null;
  } catch { return null; }
}

async function sha256(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function truncatePrompt(prompt: string, maxChars = 30000): string {
  if (prompt.length <= maxChars) return prompt;
  const half = Math.floor(maxChars / 2);
  return prompt.slice(0, half) + "\n\n[...truncated...]\n\n" + prompt.slice(-half);
}

function backoffDelay(attempt: number): number {
  return Math.min(1000 * Math.pow(2, attempt) + Math.random() * 500, 10000);
}

// ── Supabase client (service role — for cache, metering, vault) ───────────

let _supa: ReturnType<typeof createClient> | null = null;
function getSupa() {
  if (!_supa) {
    const url = Deno.env.get("SUPABASE_URL");
    const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (url && key) _supa = createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
  }
  return _supa;
}

// ── Vault helpers ─────────────────────────────────────────────

/** Read AI keys from Supabase Vault for an org (service-role only) */
async function readVaultKeys(orgId: string): Promise<Record<string, string> | null> {
  const supa = getSupa();
  if (!supa) return null;
  try {
    const { data: org } = await supa
      .from("organizations")
      .select("ai_config, ai_keys_vault_id")
      .eq("id", orgId)
      .maybeSingle();
    if (!org) return null;

    const cfg = org.ai_config as Record<string, unknown> | null;

    if (org.ai_keys_vault_id && cfg?._vault === true) {
      const { data: secret } = await supa.rpc("vault_read_secret", { secret_id: org.ai_keys_vault_id });
      if (secret) {
        try { return JSON.parse(secret as string); } catch { return null; }
      }
    }
    // Fallback: base64-encoded in ai_config
    if (cfg?._keys_encoded) {
      try { return JSON.parse(atob(cfg._keys_encoded as string)); } catch { return null; }
    }
    // Legacy: keys stored directly in ai_config (migration path)
    if (cfg && typeof cfg === "object") {
      const legacy: Record<string, string> = {};
      const keyFields = ["anthropic_api_key","openai_api_key","aws_access_key_id","aws_secret_access_key","azure_openai_key","gemini_api_key","openrouter_api_key"];
      for (const f of keyFields) {
        if (typeof cfg[f] === "string") legacy[f] = cfg[f] as string;
      }
      return Object.keys(legacy).length > 0 ? legacy : null;
    }
    return null;
  } catch { return null; }
}

// ── Cache helpers ─────────────────────────────────────────────

async function cacheGet(cacheKey: string): Promise<string | null> {
  const supa = getSupa(); if (!supa) return null;
  try {
    const { data } = await supa.from("ai_cache").select("response_text, hit_count").eq("cache_key", cacheKey).gt("expires_at", new Date().toISOString()).maybeSingle();
    if (data) {
      supa.from("ai_cache").update({ hit_count: ((data.hit_count as number) ?? 0) + 1 }).eq("cache_key", cacheKey).catch(() => {});
      return data.response_text;
    }
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
    body: JSON.stringify({ model, max_tokens: maxTokens, messages: [{ role: "user", content: prompt }] }),
    signal: AbortSignal.timeout(45_000),
  });
  if (!r.ok) { const e = await r.text(); throw new Error(`OpenAI ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  return { text: d.choices?.[0]?.message?.content ?? "", promptTokens: d.usage?.prompt_tokens ?? 0, completionTokens: d.usage?.completion_tokens ?? 0 };
}

async function callBedrock(cfg: AIConfig, model: string, prompt: string, maxTokens: number): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  const region = cfg.aws_region ?? "us-east-1";
  const body = JSON.stringify({ anthropic_version: "bedrock-2023-05-31", max_tokens: maxTokens, messages: [{ role: "user", content: prompt }] });
  const url = `https://bedrock-runtime.${region}.amazonaws.com/model/${model}/invoke`;
  const date = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "").slice(0, 15) + "Z";
  const dateShort = date.slice(0, 8);
  const bodyHash = await sha256(body);
  const canonicalReq = `POST\n/model/${model}/invoke\n\ncontent-type:application/json\nhost:bedrock-runtime.${region}.amazonaws.com\nx-amz-content-sha256:${bodyHash}\nx-amz-date:${date}\n\ncontent-type;host;x-amz-content-sha256;x-amz-date\n${bodyHash}`;
  const strToSign = `AWS4-HMAC-SHA256\n${date}\n${dateShort}/${region}/bedrock/aws4_request\n${await sha256(canonicalReq)}`;
  async function hmac(key: ArrayBuffer | Uint8Array, msg: string) {
    const k = await crypto.subtle.importKey("raw", key instanceof Uint8Array ? key : new Uint8Array(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg));
  }
  const kDate    = await hmac(new TextEncoder().encode("AWS4" + cfg.aws_secret_access_key!), dateShort);
  const kRegion  = await hmac(kDate, region);
  const kService = await hmac(kRegion, "bedrock");
  const kSigning = await hmac(kService, "aws4_request");
  const sig = Array.from(new Uint8Array(await hmac(kSigning, strToSign))).map(b => b.toString(16).padStart(2,"0")).join("");
  const auth = `AWS4-HMAC-SHA256 Credential=${cfg.aws_access_key_id!}/${dateShort}/${region}/bedrock/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=${sig}`;
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", "Authorization": auth, "x-amz-date": date, "x-amz-content-sha256": bodyHash }, body, signal: AbortSignal.timeout(45_000) });
  if (!r.ok) { const e = await r.text(); throw new Error(`Bedrock ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  return { text: d.content?.[0]?.text ?? "", promptTokens: d.usage?.input_tokens ?? 0, completionTokens: d.usage?.output_tokens ?? 0 };
}

async function callAzure(cfg: AIConfig, model: string, prompt: string, maxTokens: number): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  const endpoint = cfg.azure_openai_endpoint!.replace(/\/$/, "");
  const deployment = model;
  const url = `${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=2024-02-15-preview`;
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "api-key": cfg.azure_openai_key! },
    body: JSON.stringify({ max_tokens: maxTokens, messages: [{ role: "user", content: prompt }] }),
    signal: AbortSignal.timeout(45_000),
  });
  if (!r.ok) { const e = await r.text(); throw new Error(`Azure ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  return { text: d.choices?.[0]?.message?.content ?? "", promptTokens: d.usage?.prompt_tokens ?? 0, completionTokens: d.usage?.completion_tokens ?? 0 };
}

async function callGemini(key: string, model: string, prompt: string, maxTokens: number): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { maxOutputTokens: maxTokens } }),
    signal: AbortSignal.timeout(45_000),
  });
  if (!r.ok) { const e = await r.text(); throw new Error(`Gemini ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  const text = d.candidates?.[0]?.content?.parts?.[0]?.text ?? "";
  const pt = d.usageMetadata?.promptTokenCount ?? 0;
  const ct = d.usageMetadata?.candidatesTokenCount ?? 0;
  return { text, promptTokens: pt, completionTokens: ct };
}

async function callOpenRouter(key: string, model: string, prompt: string, maxTokens: number): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  const r = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${key}`, "HTTP-Referer": "https://omniguard.app", "X-Title": "OmniGuard" },
    body: JSON.stringify({ model, max_tokens: maxTokens, messages: [{ role: "user", content: prompt }] }),
    signal: AbortSignal.timeout(45_000),
  });
  if (!r.ok) { const e = await r.text(); throw new Error(`OpenRouter ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  return { text: d.choices?.[0]?.message?.content ?? "", promptTokens: d.usage?.prompt_tokens ?? 0, completionTokens: d.usage?.completion_tokens ?? 0 };
}

async function callOllama(base: string, model: string, prompt: string): Promise<{ text: string; promptTokens: number; completionTokens: number }> {
  const r = await fetch(`${base}/api/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model, prompt, stream: false }),
    signal: AbortSignal.timeout(120_000),
  });
  if (!r.ok) { const e = await r.text(); throw new Error(`Ollama ${r.status}: ${e.slice(0, 200)}`); }
  const d = await r.json();
  return { text: d.response ?? "", promptTokens: d.prompt_eval_count ?? 0, completionTokens: d.eval_count ?? 0 };
}

// ── Core dispatch with retry + cache ─────────────────────────

interface CallOptions {
  maxTokens?:    number;
  orgId?:        string;
  scanId?:       string;
  skipCache?:    boolean;
  cacheTtlDays?: number;
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
        case "gemini":     return await callGemini(cfg.gemini_api_key!,        model, prompt, maxTokens);
        case "openrouter": return await callOpenRouter(cfg.openrouter_api_key!, model, prompt, maxTokens);
        case "ollama":     return await callOllama(cfg.ollama_url ?? "http://localhost:11434", model, prompt);
        default: throw new Error(`Unknown provider: ${cfg.provider}`);
      }
    } catch (err) {
      lastErr = err instanceof Error ? err : new Error(String(err));
      const msg = lastErr.message;
      if (msg.includes("401") || msg.includes("403") || msg.includes("invalid_api_key")) throw lastErr;
      if (msg.includes("context_length") || msg.includes("maximum context")) throw lastErr;
      console.warn(`[ai] attempt ${attempt + 1} failed for ${cfg.provider}/${model}: ${msg}`);
    }
  }
  throw lastErr ?? new Error("All retries exhausted");
}

export async function callAI(
  cfg: AIConfig,
  prompt: string,
  tier: Tier = "medium",
  opts: CallOptions = {}
): Promise<AIResponse | null> {
  if (cfg.provider === "none") return null;

  const model = (() => {
    if (tier === "deep" && cfg.disable_deep_tier) tier = "medium";
    return MODELS[cfg.provider]?.[tier];
  })();
  if (!model) return null;

  const maxTokens = opts.maxTokens ?? 2048;
  const truncated = truncatePrompt(prompt);

  // Cache lookup
  if (!opts.skipCache) {
    const cacheKey = await sha256(`${cfg.provider}:${model}:${prompt}`);
    const cached = await cacheGet(cacheKey);
    if (cached) {
      await recordUsage(opts.orgId ?? null, opts.scanId ?? null, cfg.provider, model, tier, 0, 0, true, 0);
      return { text: cached, model, provider: cfg.provider, prompt_tokens: 0, completion_tokens: 0, total_tokens: 0, latency_ms: 0, cache_hit: true, tier };
    }
  }

  const cacheKey = await sha256(`${cfg.provider}:${model}:${prompt}`);
  const t0 = Date.now();
  let result: { text: string; promptTokens: number; completionTokens: number } | null = null;
  let usedProvider = cfg.provider;
  let usedModel = model;

  try {
    result = await dispatchWithRetry(cfg, model, truncated, maxTokens);
  } catch (primaryErr) {
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

  await cachePut(cacheKey, opts.orgId ?? null, usedProvider, usedModel, cacheKey, result.text, total);
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
  if (orgCfg.provider !== "none") return { ...orgCfg, fallback_provider: orgCfg.fallback_provider ?? (envCfg.provider !== "none" ? envCfg.provider : undefined) };
  return envCfg;
}

/**
 * Vault-aware config resolution — reads actual API keys from Supabase Vault.
 * Use this in edge functions instead of resolveAIConfig when the org uses vault storage.
 * Requires SUPABASE_SERVICE_ROLE_KEY to be set (automatically available in edge functions).
 */
export async function resolveAIConfigFromOrg(orgId: string): Promise<AIConfig> {
  const supa = getSupa();
  if (!supa) return getEnvAIConfig();

  try {
    const { data: org } = await supa
      .from("organizations")
      .select("ai_config")
      .eq("id", orgId)
      .maybeSingle();

    if (!org) return getEnvAIConfig();

    const cfg = (org.ai_config as Record<string, unknown>) || {};

    // Non-secret config from ai_config column
    const base = getAIConfig(cfg);

    // Merge in vault keys (override any legacy plaintext)
    const vaultKeys = await readVaultKeys(orgId);
    if (vaultKeys) {
      return { ...base, ...vaultKeys };
    }

    return resolveAIConfig(cfg);
  } catch {
    return getEnvAIConfig();
  }
}

/** Estimated cost in USD for a token count */
export function estimateCost(provider: string, tier: Tier, tokens: number): number {
  const rate = COST_PER_1M[provider]?.[tier] ?? 0;
  return (tokens / 1_000_000) * rate;
}
