import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { autoRefreshToken: false, persistSession: false },
});

// Integration test functions
async function testGithub(token: string): Promise<{ ok: boolean; message: string }> {
  const r = await fetch("https://api.github.com/user", {
    headers: { Authorization: `token ${token}`, Accept: "application/vnd.github.v3+json" },
  });
  if (!r.ok) return { ok: false, message: `GitHub API error: ${r.status}` };
  const d = await r.json();
  return { ok: true, message: `Connected as ${d.login}` };
}

async function testGitlab(url: string, token: string): Promise<{ ok: boolean; message: string }> {
  const baseUrl = url || "https://gitlab.com";
  const r = await fetch(`${baseUrl}/api/v4/user`, {
    headers: { "Private-Token": token },
  });
  if (!r.ok) return { ok: false, message: `GitLab API error: ${r.status}` };
  const d = await r.json();
  return { ok: true, message: `Connected as ${d.username}` };
}

async function testJira(domain: string, email: string, token: string): Promise<{ ok: boolean; message: string }> {
  const r = await fetch(`https://${domain}/rest/api/3/myself`, {
    headers: { Authorization: `Basic ${btoa(`${email}:${token}`)}` },
  });
  if (!r.ok) return { ok: false, message: `Jira API error: ${r.status}` };
  const d = await r.json();
  return { ok: true, message: `Connected as ${d.displayName}` };
}

async function testLinear(key: string): Promise<{ ok: boolean; message: string }> {
  const r = await fetch("https://api.linear.app/graphql", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
    body: JSON.stringify({ query: "{ viewer { name } }" }),
  });
  if (!r.ok) return { ok: false, message: `Linear API error: ${r.status}` };
  const d = await r.json();
  return { ok: true, message: `Connected as ${d.data?.viewer?.name || "user"}` };
}

async function testSlack(webhook: string): Promise<{ ok: boolean; message: string }> {
  const r = await fetch(webhook, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: "OmniGuard connection test successful!" }),
  });
  return { ok: r.ok, message: r.ok ? "Webhook verified" : `Slack error: ${r.status}` };
}

async function testTeams(webhook: string): Promise<{ ok: boolean; message: string }> {
  const r = await fetch(webhook, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: "OmniGuard connection test successful!" }),
  });
  return { ok: r.ok, message: r.ok ? "Webhook verified" : `Teams error: ${r.status}` };
}

async function testConfluence(domain: string, email: string, token: string): Promise<{ ok: boolean; message: string }> {
  const r = await fetch(`https://${domain}/wiki/rest/api/user/current`, {
    headers: { Authorization: `Basic ${btoa(`${email}:${token}`)}` },
  });
  if (!r.ok) return { ok: false, message: `Confluence API error: ${r.status}` };
  const d = await r.json();
  return { ok: true, message: `Connected as ${d.displayName}` };
}

async function testOkta(domain: string, token: string): Promise<{ ok: boolean; message: string }> {
  const r = await fetch(`https://${domain}/api/v1/users/me`, {
    headers: { Authorization: `SSWS ${token}` },
  });
  if (!r.ok) return { ok: false, message: `Okta API error: ${r.status}` };
  const d = await r.json();
  return { ok: true, message: `Okta connected (${d.profile?.login || "verified"})` };
}

// Integration action functions
async function createJiraTicket(config: Record<string, string>, finding: { title: string; severity: string; file_path: string; line_start: number; rule_id: string }): Promise<{ ok: boolean; key?: string; error?: string }> {
  const { domain, email, api_token, project_key } = config;
  const body = {
    fields: {
      project: { key: project_key || "SEC" },
      summary: `[OmniGuard] ${finding.severity.toUpperCase()}: ${finding.title}`,
      description: `*Severity:* ${finding.severity}\n*File:* ${finding.file_path}:${finding.line_start}\n*Rule:* ${finding.rule_id}\n\n_Tracked by OmniGuard Security Platform_`,
      issuetype: { name: "Bug" },
      labels: ["security", "omniguard", finding.severity],
    },
  };
  const r = await fetch(`https://${domain}/rest/api/3/issue`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${btoa(`${email}:${api_token}`)}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!r.ok) return { ok: false, error: await r.text() };
  const d = await r.json();
  return { ok: true, key: d.key };
}

async function createLinearIssue(config: Record<string, string>, finding: { title: string; severity: string; file_path: string; line_start: number; rule_id: string }): Promise<{ ok: boolean; id?: string; error?: string }> {
  const { api_key, team_id } = config;
  const mutation = `mutation CreateIssue($teamId: String!, $title: String!, $description: String) {
    issueCreate(input: { teamId: $teamId, title: $title, description: $description }) { success issue { id identifier } }
  }`;
  const r = await fetch("https://api.linear.app/graphql", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${api_key}` },
    body: JSON.stringify({
      query: mutation,
      variables: {
        teamId: team_id,
        title: `[${finding.severity.toUpperCase()}] ${finding.title}`,
        description: `**File:** ${finding.file_path}:${finding.line_start}\n**Rule:** ${finding.rule_id}`,
      },
    }),
  });
  if (!r.ok) return { ok: false, error: await r.text() };
  const d = await r.json();
  return { ok: d.data?.issueCreate?.success, id: d.data?.issueCreate?.issue?.identifier };
}

// Verify auth
async function verifyAuth(authHeader: string | null): Promise<{ valid: boolean; orgId?: string; userId?: string }> {
  if (!authHeader?.startsWith("Bearer ")) return { valid: false };
  const token = authHeader.slice(7);
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return { valid: false };
  const { data: m } = await supabase.from("organization_members").select("organization_id").eq("user_id", user.id).eq("status", "active").limit(1).maybeSingle();
  return { valid: true, orgId: m?.organization_id, userId: user.id };
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 200, headers: corsHeaders });
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/functions\/v1\/enterprise-integrations/, "");
  const auth = await verifyAuth(req.headers.get("Authorization"));
  if (!auth.valid) return json({ success: false, error: "UNAUTHORIZED" }, 401);
  const orgId = auth.orgId!;

  try {
    // GET / — list integrations
    if (req.method === "GET" && (path === "" || path === "/")) {
      const { data } = await supabase.from("integrations").select("*").eq("organization_id", orgId);
      return json({ success: true, data: data || [] });
    }

    // POST /test — test integration
    if (req.method === "POST" && path === "/test") {
      const { provider, config } = await req.json();
      let result: { ok: boolean; message: string };

      switch (provider) {
        case "github":
          result = await testGithub(config.access_token);
          break;
        case "gitlab":
          result = await testGitlab(config.gitlab_url, config.access_token);
          break;
        case "jira":
          result = await testJira(config.domain, config.email, config.api_token);
          break;
        case "linear":
          result = await testLinear(config.api_key);
          break;
        case "slack":
          result = await testSlack(config.webhook_url);
          break;
        case "teams":
          result = await testTeams(config.webhook_url);
          break;
        case "confluence":
          result = await testConfluence(config.domain, config.email, config.api_token);
          break;
        case "okta":
          result = await testOkta(config.domain, config.api_token);
          break;
        default:
          return json({ success: false, message: `Unknown provider: ${provider}` }, 400);
      }

      return json({ success: result.ok, message: result.message });
    }

    // POST /connect — create/update integration
    if (req.method === "POST" && path === "/connect") {
      const { provider, config, test_connection = true } = await req.json();

      // Optionally test before saving
      if (test_connection) {
        // Test would be done above, just validate required fields
        const requiredFields: Record<string, string[]> = {
          github: ["access_token"],
          gitlab: ["access_token"],
          jira: ["domain", "email", "api_token"],
          linear: ["api_key"],
          slack: ["webhook_url"],
          teams: ["webhook_url"],
          confluence: ["domain", "email", "api_token"],
          okta: ["domain", "api_token"],
        };
        const required = requiredFields[provider] || [];
        const missing = required.filter(f => !config[f]);
        if (missing.length > 0) {
          return json({ success: false, message: `Missing required fields: ${missing.join(", ")}` }, 400);
        }
      }

      // Upsert integration
      const { data: existing } = await supabase.from("integrations").select("id").eq("organization_id", orgId).eq("provider", provider).maybeSingle();

      let data;
      if (existing) {
        const { data: updated } = await supabase.from("integrations").update({
          config,
          status: "active",
          updated_at: new Date().toISOString(),
        }).eq("id", existing.id).select().single();
        data = updated;
      } else {
        const { data: created } = await supabase.from("integrations").insert({
          organization_id: orgId,
          provider,
          config,
          status: "active",
          created_by: auth.userId,
        }).select().single();
        data = created;
      }

      await supabase.from("audit_logs").insert({
        organization_id: orgId,
        user_id: auth.userId,
        action: existing ? "integration_updated" : "integration_created",
        resource_type: "integration",
        resource_id: data.id,
        metadata: { provider },
      });

      return json({ success: true, data, message: `${provider} connected` });
    }

    // DELETE /:provider — disconnect
    const deleteMatch = path.match(/^\/([a-z-]+)$/);
    if (req.method === "DELETE" && deleteMatch) {
      const provider = deleteMatch[1];
      const { error } = await supabase.from("integrations").update({ status: "inactive" }).eq("organization_id", orgId).eq("provider", provider);
      if (error) throw error;
      await supabase.from("audit_logs").insert({
        organization_id: orgId,
        user_id: auth.userId,
        action: "integration_disconnected",
        resource_type: "integration",
        metadata: { provider },
      });
      return json({ success: true, message: `${provider} disconnected` });
    }

    return json({ success: false, error: "Not found" }, 404);
  } catch (err) {
    console.error("enterprise-integrations error:", err);
    return json({ success: false, error: err instanceof Error ? err.message : String(err) }, 500);
  }
});
