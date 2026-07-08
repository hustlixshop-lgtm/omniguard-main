import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.45.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey, X-GitHub-Event, X-GitHub-Delivery, X-Hub-Signature-256",
};

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const supabase = createClient(supabaseUrl, supabaseServiceKey, {
  auth: { autoRefreshToken: false, persistSession: false }
});

interface GitHubPushEvent {
  ref: string;
  repository: {
    id: number;
    name: string;
    full_name: string;
    owner: { login: string };
    default_branch: string;
    private: boolean;
    description?: string;
    language?: string;
  };
  after: string;
  before: string;
  commits: Array<{
    id: string;
    message: string;
    author: { name: string; email: string };
    added: string[];
    removed: string[];
    modified: string[];
  }>;
  sender: { login: string };
}

interface GitHubPREvent {
  action: string;
  number: number;
  pull_request: {
    id: number;
    number: number;
    title: string;
    head: { ref: string; sha: string };
    base: { ref: string; sha: string };
    state: string;
  };
  repository: GitHubPushEvent["repository"];
  sender: { login: string };
}

async function verifySignature(secret: string, payload: string, signature: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  const expected = Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
  return signature === `sha256=${expected}`;
}

async function createCheckRun(repoId: string, orgId: string, headSha: string, prNumber: number): Promise<string | null> {
  // Get GitHub token from integration
  const { data: integration } = await supabase
    .from("integrations")
    .select("config")
    .eq("organization_id", orgId)
    .eq("provider", "github")
    .eq("status", "active")
    .maybeSingle();

  const token = (integration?.config as Record<string, string>)?.access_token || Deno.env.get("GITHUB_TOKEN");
  if (!token) return null;

  // Get repo info
  const { data: repo } = await supabase.from("repositories").select("full_name").eq("id", repoId).single();
  if (!repo) return null;

  const res = await fetch(`https://api.github.com/repos/${repo.full_name}/check-runs`, {
    method: "POST",
    headers: {
      "Authorization": `token ${token}`,
      "Accept": "application/vnd.github.v3+json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name: "OmniGuard Security Scan",
      head_sha: headSha,
      status: "queued",
      output: {
        title: "Security scan in progress",
        summary: "OmniGuard is analyzing this pull request for security issues.",
      },
    }),
  });

  if (!res.ok) return null;
  const data = await res.json();
  return data.id;
}

async function updateCheckRun(repoId: string, orgId: string, checkRunId: string, conclusion: string, summary: { critical: number; high: number; total: number }) {
  const { data: integration } = await supabase
    .from("integrations")
    .select("config")
    .eq("organization_id", orgId)
    .eq("provider", "github")
    .eq("status", "active")
    .maybeSingle();

  const token = (integration?.config as Record<string, string>)?.access_token || Deno.env.get("GITHUB_TOKEN");
  if (!token) return;

  const { data: repo } = await supabase.from("repositories").select("full_name").eq("id", repoId).single();
  if (!repo) return;

  const status = summary.critical > 0 || summary.high > 0 ? "failure" : "success";
  const outputTitle = status === "success"
    ? "No security issues found"
    : `Found ${summary.critical} critical, ${summary.high} high issues`;

  await fetch(`https://api.github.com/repos/${repo.full_name}/check-runs/${checkRunId}`, {
    method: "PATCH",
    headers: {
      "Authorization": `token ${token}`,
      "Accept": "application/vnd.github.v3+json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      status: "completed",
      conclusion,
      output: {
        title: outputTitle,
        summary: `OmniGuard scan complete. ${summary.total} findings total (${summary.critical} critical, ${summary.high} high).`,
      },
    }),
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }

  try {
    const githubEvent = req.headers.get("X-GitHub-Event");
    const signature = req.headers.get("X-Hub-Signature-256");

    if (!githubEvent) {
      return new Response(JSON.stringify({ error: "Missing X-GitHub-Event header" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const payload = await req.text();

    // Handle push events
    if (githubEvent === "push") {
      const event: GitHubPushEvent = JSON.parse(payload);

      const { data: repo, error: repoError } = await supabase
        .from("repositories")
        .select("*, organizations!inner(id)")
        .eq("provider", "github")
        .eq("provider_id", String(event.repository.id))
        .is("deleted_at", null)
        .maybeSingle();

      if (repoError || !repo) {
        return new Response(JSON.stringify({
          received: true,
          message: "Repository not registered with OmniGuard"
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // Verify webhook secret
      if (repo.webhook_secret && signature) {
        const valid = await verifySignature(repo.webhook_secret, payload, signature);
        if (!valid) {
          return new Response(JSON.stringify({ error: "Invalid signature" }), {
            status: 401,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      const branch = event.ref.replace("refs/heads/", "");
      const changedFiles = [...event.commits.flatMap(c => [...c.added, ...c.modified])];

      const { data: scan, error: scanError } = await supabase
        .from("scans")
        .insert({
          repository_id: repo.id,
          organization_id: repo.organization_id,
          status: "queued",
          trigger: "webhook",
          branch,
          commit_sha: event.after,
          commit_message: event.commits[0]?.message || "Push event",
          commit_author: event.sender.login,
          created_by: repo.created_by,
          metadata: { changed_files: [...new Set(changedFiles)].slice(0, 100) }
        })
        .select()
        .single();

      if (scanError) throw scanError;

      // Trigger scan worker
      fetch(`${supabaseUrl}/functions/v1/scan-worker/process`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${supabaseServiceKey}`,
        },
        body: JSON.stringify({
          scan_id: scan.id,
          repository_id: repo.id,
          organization_id: repo.organization_id,
        }),
      }).catch(e => console.error("Failed to trigger scan worker:", e));

      await supabase.from("repositories").update({ last_sync_at: new Date().toISOString() }).eq("id", repo.id);
      await supabase.from("audit_logs").insert({
        organization_id: repo.organization_id,
        action: "webhook_received",
        resource_type: "scan",
        resource_id: scan.id,
        resource_name: `${repo.full_name}:${branch}`,
        metadata: { commits: event.commits.length, pusher: event.sender.login }
      });

      return new Response(JSON.stringify({
        received: true,
        scan_id: scan.id,
        repository: repo.full_name,
        branch
      }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Handle PR events
    if (githubEvent === "pull_request") {
      const event: GitHubPREvent = JSON.parse(payload);

      if (!["opened", "synchronize", "reopened"].includes(event.action)) {
        return new Response(JSON.stringify({ received: true, message: `Action ${event.action} ignored` }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      const { data: repo } = await supabase
        .from("repositories")
        .select("*, organizations!inner(id)")
        .eq("provider", "github")
        .eq("provider_id", String(event.repository.id))
        .is("deleted_at", null)
        .maybeSingle();

      if (!repo) {
        return new Response(JSON.stringify({ received: true, message: "Repository not registered" }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // Create check run
      const checkRunId = await createCheckRun(repo.id, repo.organization_id, event.pull_request.head.sha, event.pull_request.number);

      // Create scan
      const { data: scan } = await supabase.from("scans").insert({
        repository_id: repo.id,
        organization_id: repo.organization_id,
        status: "queued",
        trigger: "pull_request",
        branch: event.pull_request.head.ref,
        commit_sha: event.pull_request.head.sha,
        commit_message: `PR #${event.pull_request.number}: ${event.pull_request.title}`,
        commit_author: event.sender.login,
        metadata: { pr_number: event.pull_request.number, check_run_id: checkRunId },
      }).select().single();

      // Trigger scan
      if (scan) {
        fetch(`${supabaseUrl}/functions/v1/scan-worker/process`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${supabaseServiceKey}`,
          },
          body: JSON.stringify({
            scan_id: scan.id,
            repository_id: repo.id,
            organization_id: repo.organization_id,
          }),
        }).catch(() => {});
      }

      return new Response(JSON.stringify({ received: true, scan_id: scan?.id }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (githubEvent === "ping") {
      return new Response(JSON.stringify({ received: true, message: "OmniGuard webhook endpoint active" }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    return new Response(JSON.stringify({ received: true, message: `Event ${githubEvent} acknowledged` }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });

  } catch (error) {
    console.error("Webhook error:", error);
    return new Response(JSON.stringify({
      error: "Internal server error",
      details: error instanceof Error ? error.message : String(error)
    }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
