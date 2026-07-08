import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";

/**
 * API Gateway — Rate limiting, key verification, usage tracking
 * for all OmniGuard API keys (og_live_*)
 *
 * Rate limits per plan:
 *   free:       60 req/min, 1000 req/hour
 *   pro:        300 req/min, 10000 req/hour
 *   enterprise: 1000 req/min, unlimited/hour
 *
 * Also provides:
 *   GET  /api-gateway/usage        — key usage stats
 *   GET  /api-gateway/rate-status  — current rate limit window status
 */

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey, X-API-Key",
};

const supa = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

const RATE_LIMITS: Record<string, { per_minute: number; per_hour: number }> = {
  free:       { per_minute: 60,   per_hour: 1_000   },
  pro:        { per_minute: 300,  per_hour: 10_000  },
  enterprise: { per_minute: 1000, per_hour: 100_000 },
};

function j(d: unknown, s = 200, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(d), { status: s, headers: { ...cors, "Content-Type": "application/json", ...extra } });
}

/** Verify an og_live_ API key, return key + org + plan info or null */
export async function verifyApiKey(rawKey: string): Promise<{
  keyId: string; orgId: string; plan: string; scopes: string[];
  rateLimits: { per_minute: number; per_hour: number };
} | null> {
  if (!rawKey.startsWith("og_")) return null;
  const hash = Array.from(new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rawKey))
  )).map(b => b.toString(16).padStart(2, "0")).join("");

  const { data: key } = await supa.from("api_keys")
    .select("id, organization_id, scopes, is_active, expires_at, organizations!inner(plan, rate_limits)")
    .eq("key_hash", hash).eq("is_active", true).maybeSingle();

  if (!key) return null;
  if (key.expires_at && new Date(key.expires_at) < new Date()) return null;

  const org = key.organizations as { plan: string; rate_limits: Record<string, number> } | null;
  const plan = org?.plan ?? "free";
  const defaultLimits = RATE_LIMITS[plan] ?? RATE_LIMITS.free;
  const orgOverrides = org?.rate_limits ?? {};

  // Update last_used_at async
  supa.from("api_keys").update({ last_used_at: new Date().toISOString() }).eq("id", key.id).then(() => {});

  return {
    keyId: key.id,
    orgId: key.organization_id,
    plan,
    scopes: key.scopes ?? ["scans:read", "scans:write", "findings:read", "findings:write"],
    rateLimits: {
      per_minute: (orgOverrides.api_requests_per_minute as number | undefined) ?? defaultLimits.per_minute,
      per_hour:   (orgOverrides.api_requests_per_hour   as number | undefined) ?? defaultLimits.per_hour,
    },
  };
}

/** Check and increment rate limit counter. Returns { allowed, remaining, resetAt } */
export async function enforceRateLimit(keyId: string, orgId: string, windowSec: number, maxCount: number): Promise<{ allowed: boolean; remaining: number; resetAt: string }> {
  const windowStart = Math.floor(Date.now() / (windowSec * 1000)) * windowSec;
  const key = `key:${keyId}:${windowSec}`;
  const windowTs = new Date(windowStart * 1000).toISOString();
  const resetAt   = new Date((windowStart + windowSec) * 1000).toISOString();

  try {
    const { data: allowed } = await supa.rpc("check_rate_limit", {
      p_key: key, p_window_seconds: windowSec, p_max_count: maxCount,
    });
    // Get current count for remaining calculation
    const { data: row } = await supa.from("rate_limit_counters")
      .select("count").eq("key", key).eq("window_start", windowTs).maybeSingle();
    const count = row?.count ?? 1;
    return { allowed: allowed === true, remaining: Math.max(0, maxCount - count), resetAt };
  } catch { return { allowed: true, remaining: maxCount, resetAt }; }
}

/** Record API key usage */
export async function recordApiUsage(keyId: string, orgId: string, endpoint: string, method: string, statusCode: number, responseMs: number, ip: string, ua: string): Promise<void> {
  try {
    await supa.from("api_key_usage").insert({ key_id: keyId, organization_id: orgId, endpoint, method, status_code: statusCode, response_ms: responseMs, ip_address: ip, user_agent: ua });
  } catch { /* non-fatal */ }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: cors });
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/functions\/v1\/api-gateway/, "");

  const authHeader = req.headers.get("Authorization") ?? req.headers.get("X-API-Key") ?? "";
  const rawKey = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;

  if (!rawKey.startsWith("og_")) return j({ error: "API key required (og_live_...)" }, 401);

  const keyInfo = await verifyApiKey(rawKey);
  if (!keyInfo) return j({ error: "Invalid or expired API key" }, 401);

  // Check per-minute rate limit
  const minResult = await enforceRateLimit(keyInfo.keyId, keyInfo.orgId, 60, keyInfo.rateLimits.per_minute);
  if (!minResult.allowed) {
    return j({ error: "Rate limit exceeded", limit: keyInfo.rateLimits.per_minute, window: "1 minute", reset_at: minResult.resetAt }, 429, {
      "X-RateLimit-Limit": String(keyInfo.rateLimits.per_minute),
      "X-RateLimit-Remaining": "0",
      "X-RateLimit-Reset": minResult.resetAt,
      "Retry-After": "60",
    });
  }

  // Check per-hour rate limit
  const hrResult = await enforceRateLimit(keyInfo.keyId, keyInfo.orgId, 3600, keyInfo.rateLimits.per_hour);
  if (!hrResult.allowed) {
    return j({ error: "Hourly rate limit exceeded", limit: keyInfo.rateLimits.per_hour, window: "1 hour", reset_at: hrResult.resetAt }, 429, {
      "X-RateLimit-Limit": String(keyInfo.rateLimits.per_hour),
      "X-RateLimit-Remaining": "0",
      "X-RateLimit-Reset": hrResult.resetAt,
    });
  }

  const rateHeaders = {
    "X-RateLimit-Limit": String(keyInfo.rateLimits.per_minute),
    "X-RateLimit-Remaining": String(minResult.remaining),
    "X-RateLimit-Reset": minResult.resetAt,
    "X-Plan": keyInfo.plan,
  };

  // GET /usage — return usage stats for this key
  if (req.method === "GET" && path === "/usage") {
    const since = url.searchParams.get("since") ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const { data: usage } = await supa.from("api_key_usage")
      .select("endpoint, method, status_code, response_ms, created_at")
      .eq("key_id", keyInfo.keyId).gte("created_at", since)
      .order("created_at", { ascending: false }).limit(500);
    const rows = usage ?? [];
    const byEndpoint = rows.reduce((acc, r) => { acc[r.endpoint] = (acc[r.endpoint] ?? 0) + 1; return acc; }, {} as Record<string, number>);
    const errors = rows.filter(r => r.status_code >= 400).length;
    const avgMs  = rows.length ? Math.round(rows.reduce((s, r) => s + (r.response_ms ?? 0), 0) / rows.length) : 0;
    return j({
      success: true, data: {
        key_id: keyInfo.keyId, org_id: keyInfo.orgId, plan: keyInfo.plan,
        total_requests: rows.length, error_requests: errors, avg_response_ms: avgMs,
        by_endpoint: byEndpoint, rate_limits: keyInfo.rateLimits,
        recent: rows.slice(0, 20),
      },
    }, 200, rateHeaders);
  }

  // GET /rate-status — current window status
  if (req.method === "GET" && path === "/rate-status") {
    return j({
      success: true, data: {
        plan: keyInfo.plan,
        per_minute: { limit: keyInfo.rateLimits.per_minute, remaining: minResult.remaining, reset_at: minResult.resetAt },
        per_hour:   { limit: keyInfo.rateLimits.per_hour,   remaining: hrResult.remaining,  reset_at: hrResult.resetAt },
      },
    }, 200, rateHeaders);
  }

  return j({ error: "Not found" }, 404);
});
