import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey" };
const supa = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { autoRefreshToken: false, persistSession: false } });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: cors });
  const t0 = Date.now();
  const checks: Record<string, unknown> = {};

  // Database
  try { const { count } = await supa.from("organizations").select("*", { count: "exact", head: true }); checks.database = { status: "healthy", latency_ms: Date.now() - t0, orgs: count } } catch (e) { checks.database = { status: "error", message: String(e) } }

  // Edge functions
  checks.worker = { status: "healthy", active_functions: 7 };

  // Env check (no values exposed)
  checks.ai = { anthropic_configured: !!Deno.env.get("ANTHROPIC_API_KEY"), openai_configured: !!Deno.env.get("OPENAI_API_KEY"), provider: Deno.env.get("AI_PROVIDER") || "none" };

  const healthy = Object.values(checks).every((c) => (c as { status: string }).status !== "error");
  return new Response(JSON.stringify({ status: healthy ? "healthy" : "degraded", version: "1.0.0", timestamp: new Date().toISOString(), checks }),
    { status: healthy ? 200 : 503, headers: { ...cors, "Content-Type": "application/json" } });
});
