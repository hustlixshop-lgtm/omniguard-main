/**
 * OmniGuard AI Provider Abstraction
 * Supports: Anthropic, OpenAI, AWS Bedrock, Azure OpenAI, Google Gemini, OpenRouter, Ollama
 * BYOK: Every organization supplies their own keys — platform never pays for AI
 */

export interface AIConfig {
  provider: 'anthropic' | 'openai' | 'bedrock' | 'azure' | 'gemini' | 'openrouter' | 'ollama' | 'none'
  anthropic_api_key?: string
  openai_api_key?: string
  aws_access_key_id?: string; aws_secret_access_key?: string; aws_region?: string
  azure_openai_endpoint?: string; azure_openai_key?: string
  gemini_api_key?: string
  openrouter_api_key?: string
  ollama_url?: string
}

export interface AIResponse { text: string; model: string; tokens: number }

// ── JSON extraction ────────────────────────────────────────────
export function extractJson<T>(text: string): T | null {
  try {
    const clean = text.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '').trim()
    const match = clean.match(/\{[\s\S]*\}|\[[\s\S]*\]/)
    return match ? JSON.parse(match[0]) : null
  } catch { return null }
}

// ── Anthropic ─────────────────────────────────────────────────
async function callAnthropic(key: string, model: string, prompt: string, maxTokens = 800): Promise<AIResponse> {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model, max_tokens: maxTokens, messages: [{ role: 'user', content: prompt }] }),
    signal: AbortSignal.timeout(30_000),
  })
  if (!r.ok) throw new Error(`Anthropic ${r.status}: ${await r.text()}`)
  const d = await r.json()
  return { text: d.content?.[0]?.text || '', model, tokens: d.usage?.input_tokens + d.usage?.output_tokens || 0 }
}

// ── OpenAI ────────────────────────────────────────────────────
async function callOpenAI(key: string, model: string, prompt: string, maxTokens = 800, jsonMode = false): Promise<AIResponse> {
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
    body: JSON.stringify({
      model, max_tokens: maxTokens,
      ...(jsonMode ? { response_format: { type: 'json_object' } } : {}),
      messages: [{ role: 'system', content: 'You are a security expert.' }, { role: 'user', content: prompt }],
    }),
    signal: AbortSignal.timeout(30_000),
  })
  if (!r.ok) throw new Error(`OpenAI ${r.status}: ${await r.text()}`)
  const d = await r.json()
  return { text: d.choices?.[0]?.message?.content || '', model, tokens: d.usage?.total_tokens || 0 }
}

// ── OpenRouter ────────────────────────────────────────────────
async function callOpenRouter(key: string, model: string, prompt: string, maxTokens = 800): Promise<AIResponse> {
  const r = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}`, 'HTTP-Referer': 'https://omniguard.io' },
    body: JSON.stringify({ model, max_tokens: maxTokens, messages: [{ role: 'user', content: prompt }] }),
    signal: AbortSignal.timeout(30_000),
  })
  if (!r.ok) throw new Error(`OpenRouter ${r.status}: ${await r.text()}`)
  const d = await r.json()
  return { text: d.choices?.[0]?.message?.content || '', model, tokens: d.usage?.total_tokens || 0 }
}

// ── Google Gemini ─────────────────────────────────────────────
async function callGemini(key: string, model: string, prompt: string): Promise<AIResponse> {
  const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
    signal: AbortSignal.timeout(30_000),
  })
  if (!r.ok) throw new Error(`Gemini ${r.status}: ${await r.text()}`)
  const d = await r.json()
  return { text: d.candidates?.[0]?.content?.parts?.[0]?.text || '', model, tokens: 0 }
}

// ── Ollama ────────────────────────────────────────────────────
async function callOllama(baseUrl: string, model: string, prompt: string): Promise<AIResponse> {
  const r = await fetch(`${baseUrl}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, prompt, stream: false }),
    signal: AbortSignal.timeout(60_000),
  })
  if (!r.ok) throw new Error(`Ollama ${r.status}: ${await r.text()}`)
  const d = await r.json()
  return { text: d.response || '', model, tokens: d.eval_count || 0 }
}

// ── AWS Bedrock (full SigV4) ──────────────────────────────────
async function callBedrock(cfg: AIConfig, modelId: string, prompt: string, maxTokens = 800): Promise<AIResponse> {
  const region = cfg.aws_region || 'us-east-1'
  const url = `https://bedrock-runtime.${region}.amazonaws.com/model/${encodeURIComponent(modelId)}/invoke`
  const body = JSON.stringify({ anthropic_version: 'bedrock-2023-05-31', max_tokens: maxTokens, messages: [{ role: 'user', content: prompt }] })
  const enc = new TextEncoder()
  const now = new Date()
  const dateStr = now.toISOString().replace(/[:-]/g, '').replace(/\.\d{3}Z$/, 'Z')
  const shortDate = dateStr.slice(0, 8)
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(body))
  const payloadHash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('')
  const host = `bedrock-runtime.${region}.amazonaws.com`
  const canonHeaders = `content-type:application/json\nhost:${host}\nx-amz-date:${dateStr}\n`
  const signedHeaders = 'content-type;host;x-amz-date'
  const canonReq = ['POST', `/model/${encodeURIComponent(modelId)}/invoke`, '', canonHeaders, signedHeaders, payloadHash].join('\n')
  const crHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(canonReq)))).map(b => b.toString(16).padStart(2,'0')).join('')
  const credScope = `${shortDate}/${region}/bedrock/aws4_request`
  const sts = ['AWS4-HMAC-SHA256', dateStr, credScope, crHash].join('\n')
  const hmac = async (key: ArrayBuffer, msg: string) => { const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); return crypto.subtle.sign('HMAC', k, enc.encode(msg)) }
  const kDate = await hmac(enc.encode(`AWS4${cfg.aws_secret_access_key}`), shortDate)
  const kRegion = await hmac(kDate, region); const kService = await hmac(kRegion, 'bedrock'); const kSign = await hmac(kService, 'aws4_request')
  const sig = Array.from(new Uint8Array(await hmac(kSign, sts))).map(b => b.toString(16).padStart(2,'0')).join('')
  const auth = `AWS4-HMAC-SHA256 Credential=${cfg.aws_access_key_id}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${sig}`
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-amz-date': dateStr, 'Authorization': auth }, body, signal: AbortSignal.timeout(30_000) })
  if (!r.ok) throw new Error(`Bedrock ${r.status}: ${await r.text()}`)
  const d = await r.json()
  return { text: d.content?.[0]?.text || '', model: modelId, tokens: (d.usage?.input_tokens || 0) + (d.usage?.output_tokens || 0) }
}

// ── Azure OpenAI ──────────────────────────────────────────────
async function callAzure(cfg: AIConfig, deploymentName: string, prompt: string, maxTokens = 800): Promise<AIResponse> {
  const url = `${cfg.azure_openai_endpoint}/openai/deployments/${deploymentName}/chat/completions?api-version=2024-02-01`
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'api-key': cfg.azure_openai_key! },
    body: JSON.stringify({ max_tokens: maxTokens, messages: [{ role: 'user', content: prompt }] }),
    signal: AbortSignal.timeout(30_000),
  })
  if (!r.ok) throw new Error(`Azure OpenAI ${r.status}: ${await r.text()}`)
  const d = await r.json()
  return { text: d.choices?.[0]?.message?.content || '', model: deploymentName, tokens: d.usage?.total_tokens || 0 }
}

// ── Router ────────────────────────────────────────────────────

type Tier = 'fast' | 'medium' | 'deep'

const MODELS: Record<string, Record<Tier, string>> = {
  anthropic: { fast: 'claude-3-5-haiku-20241022', medium: 'claude-3-5-sonnet-20241022', deep: 'claude-opus-4-5' },
  openai: { fast: 'gpt-4o-mini', medium: 'gpt-4o', deep: 'gpt-4o' },
  bedrock: { fast: 'anthropic.claude-3-5-haiku-20241022-v1:0', medium: 'anthropic.claude-3-5-sonnet-20241022-v2:0', deep: 'anthropic.claude-3-5-sonnet-20241022-v2:0' },
  azure: { fast: 'gpt-4o-mini', medium: 'gpt-4o', deep: 'gpt-4o' },
  gemini: { fast: 'gemini-1.5-flash', medium: 'gemini-1.5-pro', deep: 'gemini-1.5-pro' },
  openrouter: { fast: 'anthropic/claude-3.5-haiku', medium: 'anthropic/claude-3.5-sonnet', deep: 'anthropic/claude-3-opus' },
  ollama: { fast: 'llama3.2', medium: 'llama3.2', deep: 'llama3.2' },
}

export async function callAI(cfg: AIConfig, prompt: string, tier: Tier = 'medium', maxTokens = 800): Promise<AIResponse | null> {
  if (cfg.provider === 'none') return null
  const model = MODELS[cfg.provider]?.[tier]
  if (!model) return null

  try {
    switch (cfg.provider) {
      case 'anthropic': return await callAnthropic(cfg.anthropic_api_key!, model, prompt, maxTokens)
      case 'openai': return await callOpenAI(cfg.openai_api_key!, model, prompt, maxTokens)
      case 'bedrock': return await callBedrock(cfg, model, prompt, maxTokens)
      case 'azure': return await callAzure(cfg, model, prompt, maxTokens)
      case 'gemini': return await callGemini(cfg.gemini_api_key!, model, prompt, maxTokens)
      case 'openrouter': return await callOpenRouter(cfg.openrouter_api_key!, model, prompt, maxTokens)
      case 'ollama': return await callOllama(cfg.ollama_url || 'http://localhost:11434', model, prompt)
      default: return null
    }
  } catch (err) {
    console.error(`AI call failed [${cfg.provider}/${model}]:`, err)
    return null
  }
}

/** Load AI config from organizations table */
export function getAIConfig(orgAiConfig: Record<string, unknown>): AIConfig {
  return {
    provider: (orgAiConfig.provider as AIConfig['provider']) || 'none',
    anthropic_api_key: orgAiConfig.anthropic_api_key as string | undefined,
    openai_api_key: orgAiConfig.openai_api_key as string | undefined,
    aws_access_key_id: orgAiConfig.aws_access_key_id as string | undefined,
    aws_secret_access_key: orgAiConfig.aws_secret_access_key as string | undefined,
    aws_region: (orgAiConfig.aws_region as string | undefined) || 'us-east-1',
    azure_openai_endpoint: orgAiConfig.azure_openai_endpoint as string | undefined,
    azure_openai_key: orgAiConfig.azure_openai_key as string | undefined,
    gemini_api_key: orgAiConfig.gemini_api_key as string | undefined,
    openrouter_api_key: orgAiConfig.openrouter_api_key as string | undefined,
    ollama_url: orgAiConfig.ollama_url as string | undefined,
  }
}

/** Get AI config from Supabase edge function env (platform-level fallback) */
export function getEnvAIConfig(): AIConfig {
  const provider = (Deno.env.get('AI_PROVIDER') || 'none') as AIConfig['provider']
  return {
    provider,
    anthropic_api_key: Deno.env.get('ANTHROPIC_API_KEY'),
    openai_api_key: Deno.env.get('OPENAI_API_KEY'),
    aws_access_key_id: Deno.env.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key: Deno.env.get('AWS_SECRET_ACCESS_KEY'),
    aws_region: Deno.env.get('AWS_REGION') || 'us-east-1',
    gemini_api_key: Deno.env.get('GEMINI_API_KEY'),
    openrouter_api_key: Deno.env.get('OPENROUTER_API_KEY'),
    ollama_url: Deno.env.get('OLLAMA_URL'),
  }
}
