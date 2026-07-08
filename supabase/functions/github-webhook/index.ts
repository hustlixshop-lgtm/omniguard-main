import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey, X-GitHub-Event, X-Hub-Signature-256" };
const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supa = createClient(supabaseUrl, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { autoRefreshToken: false, persistSession: false } });

async function verifySig(secret: string, body: string, sig: string): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const hash = Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)))).map(b => b.toString(16).padStart(2, "0")).join("");
  return `sha256=${hash}` === sig;
}

async function getGhToken(orgId: string): Promise<string | null> {
  const { data } = await supa.from("integrations").select("config").eq("organization_id", orgId).eq("provider", "github").eq("status", "active").maybeSingle();
  return (data?.config as Record<string, string>)?.access_token || Deno.env.get("GITHUB_TOKEN") || null;
}

async function createCheckRun(token: string, repo: string, sha: string, scanId: string): Promise<number | null> {
  try {
    const r = await fetch(`https://api.github.com/repos/${repo}/check-runs`, { method: "POST", headers: { Authorization: `token ${token}`, Accept: "application/vnd.github.v3+json", "User-Agent": "OmniGuard/1.0", "Content-Type": "application/json" }, body: JSON.stringify({ name: "OmniGuard Security Scan", head_sha: sha, status: "in_progress", started_at: new Date().toISOString(), output: { title: "Scanning for vulnerabilities…", summary: `OmniGuard is running a 3-layer AI security scan (ID: ${scanId}).` } }), signal: AbortSignal.timeout(10_000) });
    if (!r.ok) return null;
    const d = await r.json(); return d.id;
  } catch { return null; }
}

async function updateCheckRun(token: string, repo: string, checkId: number, findings: Record<string, number>, failOn: string): Promise<void> {
  const blocking = failOn === "critical" ? findings.critical > 0 : failOn === "high" ? (findings.critical + findings.high) > 0 : findings.total > 0;
  const title = blocking ? `${findings.critical} critical · ${findings.high} high · merge blocked` : findings.total > 0 ? `${findings.total} findings (none blocking)` : "✓ No security issues";
  const summary = `| Severity | Count |\n|---|---|\n| Critical | ${findings.critical} |\n| High | ${findings.high} |\n| Medium | ${findings.medium} |\n| Low | ${findings.low} |\n\n${blocking ? "⛔ Merge blocked — resolve critical/high findings first." : "✅ Safe to merge."}`;
  try {
    await fetch(`https://api.github.com/repos/${repo}/check-runs/${checkId}`, { method: "PATCH", headers: { Authorization: `token ${token}`, Accept: "application/vnd.github.v3+json", "User-Agent": "OmniGuard/1.0", "Content-Type": "application/json" }, body: JSON.stringify({ status: "completed", completed_at: new Date().toISOString(), conclusion: blocking ? "action_required" : "success", output: { title, summary } }), signal: AbortSignal.timeout(10_000) });
  } catch { /* non-fatal */ }
}

async function pollAndUpdate(token: string, repo: string, checkId: number, scanId: string, failOn: string): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < 180_000) {
    await new Promise(r => setTimeout(r, 5_000));
    const { data: scan } = await supa.from("scans").select("status, summary").eq("id", scanId).single();
    if (scan?.status === "completed" || scan?.status === "failed") {
      const s = (scan.summary as Record<string, number>) || {};
      await updateCheckRun(token, repo, checkId, { total: s.total || 0, critical: s.critical || 0, high: s.high || 0, medium: s.medium || 0, low: s.low || 0 }, failOn);
      return;
    }
  }
  await fetch(`https://api.github.com/repos/${repo}/check-runs/${checkId}`, { method: "PATCH", headers: { Authorization: `token ${token}`, Accept: "application/vnd.github.v3+json", "User-Agent": "OmniGuard/1.0", "Content-Type": "application/json" }, body: JSON.stringify({ status: "completed", completed_at: new Date().toISOString(), conclusion: "timed_out", output: { title: "Scan timed out", summary: "OmniGuard scan did not complete within 3 minutes." } }), signal: AbortSignal.timeout(10_000) }).catch(() => {});
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: cors });
  if (req.method !== "POST") return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers: { ...cors, "Content-Type": "application/json" } });
  const event = req.headers.get("X-GitHub-Event");
  if (!event) return new Response(JSON.stringify({ error: "Missing X-GitHub-Event" }), { status: 400, headers: { ...cors, "Content-Type": "application/json" } });
  const payload = await req.text();
  if (event === "ping") return new Response(JSON.stringify({ ok: true }), { headers: { ...cors, "Content-Type": "application/json" } });

  try {
    const body = JSON.parse(payload);
    const repoId = String(body.repository?.id);
    const { data: repo } = await supa.from("repositories").select("id, organization_id, full_name, default_branch, webhook_secret, created_by").eq("provider", "github").eq("provider_id", repoId).is("deleted_at", null).maybeSingle();
    if (!repo) return new Response(JSON.stringify({ ok: true, message: "Repository not registered" }), { headers: { ...cors, "Content-Type": "application/json" } });

    const sig = req.headers.get("X-Hub-Signature-256");
    if (repo.webhook_secret && sig && !(await verifySig(repo.webhook_secret, payload, sig))) {
      return new Response(JSON.stringify({ error: "Invalid signature" }), { status: 401, headers: { ...cors, "Content-Type": "application/json" } });
    }

    let scanData: { id: string } | null = null;

    if (event === "push") {
      const branch = body.ref?.replace("refs/heads/", "");
      if (body.after === "0".repeat(40)) return new Response(JSON.stringify({ ok: true }), { headers: { ...cors, "Content-Type": "application/json" } });
      const changedFiles = (body.commits || []).flatMap((c: { added: string[]; modified: string[] }) => [...c.added, ...c.modified]);
      const { data: scan } = await supa.from("scans").insert({ repository_id: repo.id, organization_id: repo.organization_id, status: "queued", trigger: "webhook", branch, commit_sha: body.after, commit_message: body.commits?.[0]?.message, commit_author: body.sender?.login, created_by: repo.created_by, metadata: { changed_files: changedFiles.slice(0, 500) } }).select().single();
      scanData = scan;
    } else if (event === "pull_request" && ["opened", "synchronize", "reopened"].includes(body.action)) {
      const { data: scan } = await supa.from("scans").insert({ repository_id: repo.id, organization_id: repo.organization_id, status: "queued", trigger: "pull_request", branch: body.pull_request.head.ref, commit_sha: body.pull_request.head.sha, commit_message: `PR #${body.pull_request.number}: ${body.pull_request.title}`, commit_author: body.sender?.login, created_by: repo.created_by, metadata: { pr_number: body.pull_request.number, base_branch: body.pull_request.base.ref } }).select().single();
      scanData = scan;
      // Create GitHub Check Run to block merge
      const token = await getGhToken(repo.organization_id);
      if (token && scan) {
        const checkId = await createCheckRun(token, repo.full_name, body.pull_request.head.sha, scan.id);
        if (checkId) {
          const { data: org } = await supa.from("organizations").select("settings").eq("id", repo.organization_id).single();
          const failOn = (org?.settings as Record<string, string>)?.pr_fail_on || "high";
          pollAndUpdate(token, repo.full_name, checkId, scan.id, failOn).catch(() => {});
        }
      }
    }

    if (scanData) {
      fetch(`${supabaseUrl}/functions/v1/scan-worker/process`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}` }, body: JSON.stringify({ scan_id: scanData.id, repository_id: repo.id, organization_id: repo.organization_id }) }).catch(() => {});
      await supa.from("audit_logs").insert({ organization_id: repo.organization_id, action: `webhook_received`, resource_type: "scan", resource_id: scanData.id, resource_name: repo.full_name, metadata: { event } });
    }

    return new Response(JSON.stringify({ ok: true, scan_id: scanData?.id }), { headers: { ...cors, "Content-Type": "application/json" } });
  } catch (err) {
    return new Response(JSON.stringify({ error: String(err) }), { status: 500, headers: { ...cors, "Content-Type": "application/json" } });
  }
});
