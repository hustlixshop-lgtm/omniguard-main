import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey" };
const supa = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { autoRefreshToken: false, persistSession: false } });

async function sendSlack(url: string, blocks: unknown[], fallback: string): Promise<boolean> {
  try { const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: fallback, blocks }), signal: AbortSignal.timeout(10_000) }); return r.ok } catch { return false }
}

async function sendEmail(apiKey: string, to: string, subject: string, html: string): Promise<boolean> {
  try {
    const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ from: `OmniGuard <${Deno.env.get("NOTIFICATION_FROM_EMAIL") || "noreply@omniguard.io"}>`, to: [to], subject, html }), signal: AbortSignal.timeout(10_000) });
    return r.ok;
  } catch { return false }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: cors });
  if (req.method !== "POST") return new Response(JSON.stringify({ error: "POST required" }), { status: 405, headers: { ...cors, "Content-Type": "application/json" } });

  const body = await req.json().catch(() => ({}));
  const { type, organization_id, scan_id } = body;
  if (!organization_id) return new Response(JSON.stringify({ error: "organization_id required" }), { status: 400, headers: { ...cors, "Content-Type": "application/json" } });

  const { data: org } = await supa.from("organizations").select("name, settings").eq("id", organization_id).single();
  const settings = (org?.settings as Record<string, unknown>) || {};
  const notifSettings = (settings.notifications as Record<string, unknown>) || {};
  const slackWebhook = notifSettings.slack_webhook as string | undefined;
  const resendKey = Deno.env.get("RESEND_API_KEY");
  const results: Record<string, boolean> = {};

  if (type === "scan_completed" && scan_id) {
    const { data: scan } = await supa.from("scans").select("*, repositories(full_name)").eq("id", scan_id).single();
    if (!scan) return new Response(JSON.stringify({ error: "Scan not found" }), { status: 404, headers: { ...cors, "Content-Type": "application/json" } });
    const s = (scan.summary as Record<string, number>) || {};
    const repoName = (scan.repositories as { full_name: string } | null)?.full_name || "unknown";
    if (slackWebhook && s.total > 0) {
      results.slack = await sendSlack(slackWebhook, [{
        type: "header", text: { type: "plain_text", text: `${s.critical > 0 ? "🔴" : s.high > 0 ? "🟠" : "✅"} OmniGuard Scan: ${repoName}` }
      }, { type: "section", fields: [{ type: "mrkdwn", text: `*Critical:* ${s.critical || 0}` }, { type: "mrkdwn", text: `*High:* ${s.high || 0}` }, { type: "mrkdwn", text: `*Total:* ${s.total || 0}` }, { type: "mrkdwn", text: `*Files:* ${s.files_scanned || 0}` }] }, { type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: "View Findings" }, style: s.critical > 0 ? "danger" : "primary", url: `${Deno.env.get("SUPABASE_URL")?.replace(".supabase.co", ".vercel.app") || "#"}/findings` }] }],
        `OmniGuard scan complete: ${repoName} — ${s.total} findings (${s.critical} critical)`);
    }
  }

  if (type === "critical_finding") {
    const { finding_id, finding_ids } = body;
    const ids = finding_ids || (finding_id ? [finding_id] : []);
    if (!ids.length) return new Response(JSON.stringify({ error: "finding_id required" }), { status: 400, headers: { ...cors, "Content-Type": "application/json" } });
    const { data: findings } = await supa.from("findings").select("*, repositories(full_name)").in("id", ids).eq("organization_id", organization_id);
    for (const f of findings || []) {
      const repo = (f.repositories as { full_name: string } | null)?.full_name || "unknown";
      if (slackWebhook) {
        await sendSlack(slackWebhook, [{ type: "header", text: { type: "plain_text", text: `🔴 Critical: ${f.title}` } }, { type: "section", fields: [{ type: "mrkdwn", text: `*Repo:* ${repo}` }, { type: "mrkdwn", text: `*File:* \`${f.file_path}:${f.line_start}\`` }, { type: "mrkdwn", text: `*Scanner:* ${f.scanner}` }, { type: "mrkdwn", text: `*Rule:* ${f.rule_id}` }] }],
          `🔴 Critical security finding in ${repo}: ${f.title}`);
      }
    }
  }

  if (type === "weekly_digest") {
    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const { data: findings } = await supa.from("findings").select("severity, status").eq("organization_id", organization_id).gte("created_at", weekAgo);
    const total = findings?.length || 0; const critical = findings?.filter(f => f.severity === "critical").length || 0; const resolved = findings?.filter(f => f.status === "resolved").length || 0;
    if (slackWebhook && total > 0) {
      results.slack = await sendSlack(slackWebhook, [], `📊 OmniGuard Weekly: ${total} new findings (${critical} critical, ${resolved} resolved) in ${org?.name || "your org"}`);
    }
  }

  return new Response(JSON.stringify({ success: true, results }), { headers: { ...cors, "Content-Type": "application/json" } });
});
