import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { autoRefreshToken: false, persistSession: false },
});

async function checkDatabase(): Promise<{ status: string; latency_ms: number }> {
  const start = Date.now();
  try {
    const { error } = await supabase.from("organizations").select("id").limit(1);
    const latency = Date.now() - start;
    return { status: error ? "unhealthy" : "healthy", latency_ms: latency };
  } catch {
    return { status: "unhealthy", latency_ms: Date.now() - start };
  }
}

async function checkAI(): Promise<{ provider: string; status: string }> {
  const provider = Deno.env.get("AI_PROVIDER") || "none";
  if (provider === "none") return { provider: "none", status: "not_configured" };
  const hasKey = !!(Deno.env.get("ANTHROPIC_API_KEY") || Deno.env.get("OPENAI_API_KEY"));
  return { provider, status: hasKey ? "configured" : "missing_key" };
}

async function checkWorkers(): Promise<{ active_count: number; idle_count: number }> {
  const { data } = await supabase
    .from("worker_heartbeats")
    .select("worker_id, status, last_heartbeat")
    .gte("last_heartbeat", new Date(Date.now() - 60000).toISOString());

  const workers = data || [];
  return {
    active_count: workers.filter(w => w.status === "busy" || w.status === "healthy").length,
    idle_count: workers.filter(w => w.status === "idle").length,
  };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });

  if (req.method === "GET") {
    const [db, ai, workers] = await Promise.all([checkDatabase(), checkAI(), checkWorkers()]);

    const overallStatus = db.status === "healthy" ? "healthy" : "degraded";

    return new Response(JSON.stringify({
      status: overallStatus,
      timestamp: new Date().toISOString(),
      version: "1.0.0",
      checks: {
        database: db,
        ai,
        workers,
      },
      features: {
        secret_scanning: true,
        sast: true,
        iac_scanning: true,
        dependency_scanning: true,
        ai_triage: ai.status === "configured",
        ai_analysis: ai.status === "configured",
        enterprise_integrations: true,
      },
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  return new Response(JSON.stringify({ error: "Method not allowed" }), {
    status: 405,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
});
