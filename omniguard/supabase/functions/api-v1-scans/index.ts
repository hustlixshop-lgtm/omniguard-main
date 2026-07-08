import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey, X-API-Key" };
const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supa = createClient(supabaseUrl, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { autoRefreshToken: false, persistSession: false } });

function json(d: unknown, s = 200) { return new Response(JSON.stringify(d), { status: s, headers: { ...cors, "Content-Type": "application/json" } }) }

async function auth(h: string | null): Promise<{ valid: boolean; orgId?: string; userId?: string }> {
  if (!h?.startsWith("Bearer ")) return { valid: false };
  const t = h.slice(7);
  if (t.split(".").length === 3) {
    const { data: { user }, error } = await supa.auth.getUser(t);
    if (error || !user) return { valid: false };
    const { data: m } = await supa.from("organization_members").select("organization_id").eq("user_id", user.id).eq("status", "active").limit(1).maybeSingle();
    return { valid: true, orgId: m?.organization_id, userId: user.id };
  }
  if (t.startsWith("og_")) {
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t)))).map(b => b.toString(16).padStart(2,"0")).join("");
    const { data: k } = await supa.from("api_keys").select("organization_id").eq("key_hash", hash).eq("is_active", true).maybeSingle();
    if (!k) return { valid: false };
    return { valid: true, orgId: k.organization_id };
  }
  return { valid: false };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: cors });
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/functions\/v1\/api-v1-scans/, "");
  const a = await auth(req.headers.get("Authorization"));
  if (!a.valid) return json({ success: false, error: "UNAUTHORIZED" }, 401);
  const orgId = a.orgId!;

  try {
    // POST / — trigger scan
    if (req.method === "POST" && (path === "" || path === "/")) {
      const body = await req.json();
      if (!body.repository) return json({ success: false, error: "repository required" }, 400);
      const isUuid = /^[0-9a-f-]{36}$/i.test(body.repository);
      const { data: repo } = await supa.from("repositories").select("id, organization_id, name, full_name, default_branch")
        .eq("organization_id", orgId).is("deleted_at", null)[isUuid ? "eq" : "eq"](isUuid ? "id" : "full_name", body.repository).maybeSingle();
      if (!repo) return json({ success: false, error: "Repository not found" }, 404);
      const { data: scan, error } = await supa.from("scans").insert({ repository_id: repo.id, organization_id: orgId, status: "queued", trigger: body.trigger || "api", branch: body.branch || repo.default_branch, commit_sha: body.commit || null, created_by: a.userId || null }).select().single();
      if (error) throw error;
      // Fire-and-forget scan worker
      fetch(`${supabaseUrl}/functions/v1/scan-worker/process`, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}` },
        body: JSON.stringify({ scan_id: scan.id, repository_id: repo.id, organization_id: orgId }),
      }).catch(() => {});
      await supa.from("audit_logs").insert({ organization_id: orgId, user_id: a.userId || null, action: "scan_triggered", resource_type: "scan", resource_id: scan.id, resource_name: repo.full_name });
      return json({ success: true, data: { id: scan.id, status: scan.status, repository: repo.full_name } }, 201);
    }

    // GET / — list
    if (req.method === "GET" && (path === "" || path === "/")) {
      const limit = Math.min(parseInt(url.searchParams.get("limit") || "50"), 100);
      const offset = parseInt(url.searchParams.get("offset") || "0");
      let q = supa.from("scans").select("*, repositories!inner(full_name)", { count: "exact" }).eq("organization_id", orgId).order("created_at", { ascending: false }).range(offset, offset + limit - 1);
      if (url.searchParams.get("status")) q = q.eq("status", url.searchParams.get("status")!);
      if (url.searchParams.get("repository_id")) q = q.eq("repository_id", url.searchParams.get("repository_id")!);
      const { data, count, error } = await q;
      if (error) throw error;
      return json({ success: true, data, meta: { total: count, limit, offset } });
    }

    // GET /:id — single scan
    const idMatch = path.match(/^\/([a-f0-9-]{36})$/);
    if (req.method === "GET" && idMatch) {
      const { data } = await supa.from("scans").select("*, repositories!inner(full_name), findings(id, severity, status, title, scanner)").eq("id", idMatch[1]).eq("organization_id", orgId).maybeSingle();
      if (!data) return json({ success: false, error: "Not found" }, 404);
      return json({ success: true, data });
    }

    // POST /:id/retry
    const retryMatch = path.match(/^\/([a-f0-9-]{36})\/retry$/);
    if (req.method === "POST" && retryMatch) {
      const { data: existing } = await supa.from("scans").select("*").eq("id", retryMatch[1]).eq("organization_id", orgId).maybeSingle();
      if (!existing) return json({ success: false, error: "Not found" }, 404);
      if (!["failed", "cancelled"].includes(existing.status)) return json({ success: false, error: "Only failed/cancelled scans can be retried" }, 400);
      const { data: newScan } = await supa.from("scans").insert({ repository_id: existing.repository_id, organization_id: orgId, status: "queued", trigger: "retry", branch: existing.branch, commit_sha: existing.commit_sha, created_by: a.userId || null }).select().single();
      fetch(`${supabaseUrl}/functions/v1/scan-worker/process`, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}` },
        body: JSON.stringify({ scan_id: newScan.id, repository_id: existing.repository_id, organization_id: orgId }),
      }).catch(() => {});
      return json({ success: true, data: { id: newScan.id, previous_scan_id: retryMatch[1] } }, 201);
    }

    return json({ success: false, error: "Not found" }, 404);
  } catch (err) {
    return json({ success: false, error: err instanceof Error ? err.message : String(err) }, 500);
  }
});
