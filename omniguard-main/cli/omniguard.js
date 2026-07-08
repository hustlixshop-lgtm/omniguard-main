#!/usr/bin/env node
/**
 * OmniGuard CLI
 *
 * Usage:
 *   npx omniguard install-hooks        Install pre-commit and pre-push hooks
 *   npx omniguard scan [files...]       Run security scan on files or current directory
 *   npx omniguard status               Show organization security status
 *   npx omniguard suppress <id> [reason]  Suppress a finding
 *   npx omniguard help                 Show help
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');

const BASE_URL = process.env.OMNIGUARD_URL || 'https://api.omniguard.io';
const API_KEY = process.env.OMNIGUARD_API_KEY;

const colors = {
  red: '\x1b[0;31m',
  green: '\x1b[0;32m',
  yellow: '\x1b[1;33m',
  blue: '\x1b[0;34m',
  cyan: '\x1b[0;36m',
  reset: '\x1b[0m',
};

function log(msg, color = 'reset') {
  process.stdout.write(`${colors[color]}${msg}${colors.reset}\n`);
}

function getGitRoot() {
  try {
    return execSync('git rev-parse --show-toplevel', { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return null;
  }
}

// ─── install-hooks ────────────────────────────────────────────────────────────

function installHooks() {
  const gitRoot = getGitRoot();
  if (!gitRoot) {
    log('Error: Not inside a git repository.', 'red');
    process.exit(1);
  }

  const hooksDir = path.join(gitRoot, '.git', 'hooks');
  if (!fs.existsSync(hooksDir)) fs.mkdirSync(hooksDir, { recursive: true });

  const preCommitSrc = path.join(__dirname, '..', 'hooks', 'pre-commit');
  const preCommitDest = path.join(hooksDir, 'pre-commit');

  if (fs.existsSync(preCommitSrc)) {
    fs.copyFileSync(preCommitSrc, preCommitDest);
  } else {
    fs.writeFileSync(preCommitDest, generatePreCommitHook(), { mode: 0o755 });
  }
  fs.chmodSync(preCommitDest, '755');
  log('✓ Installed pre-commit hook', 'green');

  const prePushSrc = path.join(__dirname, '..', 'hooks', 'pre-push');
  const prePushDest = path.join(hooksDir, 'pre-push');

  if (fs.existsSync(prePushSrc)) {
    fs.copyFileSync(prePushSrc, prePushDest);
  } else {
    fs.writeFileSync(prePushDest, generatePrePushHook(), { mode: 0o755 });
  }
  fs.chmodSync(prePushDest, '755');
  log('✓ Installed pre-push hook', 'green');

  log('\nOmniGuard Git hooks installed.', 'green');
  log('\nRequired environment variables:', 'blue');
  log('  OMNIGUARD_URL      - Your Supabase functions URL');
  log('  OMNIGUARD_API_KEY  - API key from dashboard → Settings → API Keys');
  log('  OMNIGUARD_FAIL_ON  - Minimum severity to block (default: critical)');
}

function generatePreCommitHook() {
  return `#!/usr/bin/env bash
# OmniGuard Pre-Commit Hook
OMNIGUARD_URL="\${OMNIGUARD_URL:-https://api.omniguard.io}"
OMNIGUARD_API_KEY="\${OMNIGUARD_API_KEY:-}"
FAIL_ON="\${OMNIGUARD_FAIL_ON:-critical}"

STAGED=$(git diff --cached --name-only --diff-filter=ACM)
[ -z "$STAGED" ] && exit 0

echo "🔒 OmniGuard: Scanning staged files..."

if [ -z "$OMNIGUARD_API_KEY" ]; then
  # Local mode: grep for common secret patterns
  FOUND=0
  for FILE in $STAGED; do
    [ -f "$FILE" ] || continue
    grep -qE '(AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|sk-ant-[A-Za-z0-9_-]{95}|-----BEGIN .* PRIVATE KEY)' "$FILE" && FOUND=1 && echo "  ❌ Potential secret in: $FILE"
  done
  [ $FOUND -eq 1 ] && echo "\\n⚠ Secrets detected. Set OMNIGUARD_API_KEY for full scanning." && exit 1
  echo "✓ No obvious secrets found (local mode)"
  exit 0
fi

# API mode: send files to scan-quick endpoint
TMPFILE=$(mktemp)
echo '{"files":[' > "$TMPFILE"
FIRST=true
for FILE in $STAGED; do
  [ -f "$FILE" ] || continue
  SIZE=$(wc -c < "$FILE")
  [ "$SIZE" -gt 1048576 ] && continue
  "$FIRST" && FIRST=false || echo ',' >> "$TMPFILE"
  CONTENT=$(base64 < "$FILE" | tr -d '\\n')
  echo "{\\"path\\":\\"$FILE\\",\\"content\\":\\"$CONTENT\\",\\"base64\\":true}" >> "$TMPFILE"
done
echo '],"ai":false}' >> "$TMPFILE"

RESPONSE=$(curl -s -X POST \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $OMNIGUARD_API_KEY" \\
  --max-time 30 \\
  -d @"$TMPFILE" \\
  "$OMNIGUARD_URL/scan-quick")
rm -f "$TMPFILE"

CRITICAL=$(echo "$RESPONSE" | grep -o '"critical":[0-9]*' | grep -o '[0-9]*' || echo 0)
HIGH=$(echo "$RESPONSE" | grep -o '"high":[0-9]*' | grep -o '[0-9]*' || echo 0)
CLASS=$(echo "$RESPONSE" | grep -o '"classification":"[^"]*"' | cut -d'"' -f4 || echo "UNKNOWN")

echo "  Classification: $CLASS | Critical: $CRITICAL | High: $HIGH"

BLOCK=0
case "$FAIL_ON" in
  critical) [ "$CRITICAL" -gt 0 ] && BLOCK=1 ;;
  high) ( [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] ) && BLOCK=1 ;;
  *) [ "$CRITICAL" -gt 0 ] && BLOCK=1 ;;
esac

if [ $BLOCK -eq 1 ]; then
  echo "❌ OmniGuard: Commit blocked — security issues detected."
  echo "   View details in the OmniGuard dashboard or run: omniguard scan"
  exit 1
fi

echo "✓ OmniGuard: No blocking issues found."
exit 0
`;
}

function generatePrePushHook() {
  return `#!/usr/bin/env bash
# OmniGuard Pre-Push Hook
OMNIGUARD_URL="\${OMNIGUARD_URL:-https://api.omniguard.io}"
OMNIGUARD_API_KEY="\${OMNIGUARD_API_KEY:-}"
FAIL_ON="\${OMNIGUARD_FAIL_ON:-high}"

echo "🔒 OmniGuard: Pre-push security check..."

if [ -z "$OMNIGUARD_API_KEY" ]; then
  echo "⚠ OMNIGUARD_API_KEY not set — skipping pre-push scan."
  exit 0
fi

REMOTE="$1"
REMOTE_URL="$2"
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
REPOSITORY=$(git remote get-url "$REMOTE" 2>/dev/null | sed 's/.*github.com[\\/:]//' | sed 's/\\.git$//')

echo "  Repository: $REPOSITORY | Branch: $CURRENT_BRANCH"

# Trigger full scan via API
RESPONSE=$(curl -s -X POST \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $OMNIGUARD_API_KEY" \\
  --max-time 10 \\
  -d "{\\"repository\\":\\"$REPOSITORY\\",\\"branch\\":\\"$CURRENT_BRANCH\\",\\"trigger\\":\\"pre-push\\"}" \\
  "$OMNIGUARD_URL/api-v1-scans")

SCAN_ID=$(echo "$RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$SCAN_ID" ]; then
  echo "⚠ Could not trigger scan — proceeding with push."
  exit 0
fi

echo "  Scan queued: $SCAN_ID"
echo "  Monitor progress in OmniGuard dashboard."
echo "✓ Pre-push check complete."
exit 0
`;
}

// ─── scan ─────────────────────────────────────────────────────────────────────

async function runScan(files) {
  if (!API_KEY) {
    log('Error: OMNIGUARD_API_KEY not set.', 'red');
    log('Get your API key from: dashboard → Settings → API Keys', 'yellow');
    process.exit(1);
  }

  log('\n🔒 OmniGuard Security Scanner\n', 'blue');

  const filesToScan = [];

  if (files.length > 0) {
    for (const f of files) {
      const absPath = path.resolve(f);
      if (!fs.existsSync(absPath)) continue;
      const stat = fs.statSync(absPath);
      if (stat.isDirectory()) {
        // Recursively add files from directory
        addDirFiles(absPath, absPath, filesToScan);
      } else if (stat.isFile() && stat.size <= 1_000_000) {
        filesToScan.push({ path: f, content: fs.readFileSync(absPath, 'utf-8') });
      }
    }
  } else {
    // Scan git tracked files in current directory
    const gitRoot = getGitRoot();
    if (gitRoot) {
      try {
        const tracked = execSync('git ls-files', { encoding: 'utf-8', cwd: gitRoot }).trim().split('\n');
        for (const f of tracked.slice(0, 200)) {
          const absPath = path.join(gitRoot, f);
          if (!fs.existsSync(absPath)) continue;
          const stat = fs.statSync(absPath);
          if (stat.size > 500_000) continue;
          filesToScan.push({ path: f, content: fs.readFileSync(absPath, 'utf-8') });
        }
      } catch {
        log('Warning: Could not list git files.', 'yellow');
      }
    }
  }

  if (filesToScan.length === 0) {
    log('No files to scan.', 'yellow');
    process.exit(0);
  }

  log(`Scanning ${filesToScan.length} file(s)...`);

  try {
    const response = await makeRequest('POST', '/scan-quick', { files: filesToScan });
    displayResults(response);
    const blocked = response.summary?.critical > 0 || response.summary?.high > 0;
    process.exit(blocked ? 1 : 0);
  } catch (err) {
    log(`Scan failed: ${err.message}`, 'red');
    process.exit(2);
  }
}

function addDirFiles(dir, baseDir, results) {
  const SKIP = new Set(['node_modules', '.git', 'dist', 'build', '.next', '__pycache__']);
  const entries = fs.readdirSync(dir);
  for (const entry of entries) {
    if (SKIP.has(entry)) continue;
    const full = path.join(dir, entry);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      addDirFiles(full, baseDir, results);
    } else if (stat.isFile() && stat.size <= 500_000) {
      results.push({ path: path.relative(baseDir, full), content: fs.readFileSync(full, 'utf-8') });
    }
  }
}

// ─── status ──────────────────────────────────────────────────────────────────

async function showStatus() {
  if (!API_KEY) {
    log('Error: OMNIGUARD_API_KEY not set.', 'red');
    process.exit(1);
  }

  try {
    const health = await makeRequest('GET', '/api-v1-status');
    const scans = await makeRequest('GET', '/api-v1-scans?limit=5');
    const findings = await makeRequest('GET', '/api-v1-findings?status=open&limit=1');

    log('\n🔍 OmniGuard Status\n', 'blue');
    log(`API: ${health.data?.status === 'healthy' ? '✓ Healthy' : '⚠ ' + health.data?.status}`, health.data?.status === 'healthy' ? 'green' : 'yellow');

    if (scans.data) {
      log(`\nRecent Scans (${scans.meta?.total || 0} total):`);
      for (const scan of (scans.data || []).slice(0, 5)) {
        const icon = scan.status === 'completed' ? '✓' : scan.status === 'failed' ? '✗' : '⟳';
        log(`  ${icon} ${scan.repository?.full_name || scan.id} — ${scan.status} (${scan.branch || 'main'})`);
      }
    }

    if (findings.meta) {
      log(`\nOpen Findings: ${findings.meta.total || 0}`);
    }
  } catch (err) {
    log(`Failed: ${err.message}`, 'red');
    process.exit(1);
  }
}

// ─── suppress ────────────────────────────────────────────────────────────────

async function suppressFinding(id, reason) {
  if (!API_KEY) {
    log('Error: OMNIGUARD_API_KEY not set.', 'red');
    process.exit(1);
  }
  if (!id) {
    log('Error: Finding ID required.', 'red');
    process.exit(1);
  }
  try {
    await makeRequest('POST', `/api-v1-findings/${id}/suppress`, { reason: reason || 'Suppressed via CLI' });
    log(`Finding ${id} suppressed.`, 'green');
  } catch (err) {
    log(`Failed: ${err.message}`, 'red');
    process.exit(1);
  }
}

// ─── HTTP client ──────────────────────────────────────────────────────────────

function makeRequest(method, endpoint, data) {
  return new Promise((resolve, reject) => {
    const urlStr = endpoint.startsWith('http') ? endpoint : `${BASE_URL}${endpoint}`;
    let parsedUrl;
    try { parsedUrl = new URL(urlStr); } catch (e) { reject(new Error(`Invalid URL: ${urlStr}`)); return; }

    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_KEY}`,
      },
    };

    const module = parsedUrl.protocol === 'https:' ? require('https') : require('http');
    const req = module.request(options, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          if (res.statusCode >= 400) reject(new Error(parsed.error?.message || `HTTP ${res.statusCode}`));
          else resolve(parsed);
        } catch {
          reject(new Error('Invalid JSON response'));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(60_000, () => { req.destroy(); reject(new Error('Request timed out')); });

    if (data) req.write(JSON.stringify(data));
    req.end();
  });
}

// ─── display ─────────────────────────────────────────────────────────────────

function displayResults(r) {
  const s = r.summary || {};
  log(`\n📊 Scan Results (${r.duration_ms}ms)\n`);
  log(`Classification: ${r.classification}`, r.classification === 'CRITICAL' || r.classification === 'HIGH' ? 'red' : r.classification === 'MEDIUM' ? 'yellow' : 'green');
  log(`\nFindings:`);
  log(`  🔴 Critical: ${s.critical || 0}`, s.critical > 0 ? 'red' : 'reset');
  log(`  🟠 High:     ${s.high || 0}`, s.high > 0 ? 'yellow' : 'reset');
  log(`  🟡 Medium:   ${s.medium || 0}`);
  log(`  🔵 Low:      ${s.low || 0}`);

  const findings = r.findings || [];
  if (findings.length > 0) {
    log(`\n📋 Findings:\n`, 'yellow');
    for (const f of findings.slice(0, 25)) {
      const icon = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'medium' ? '🟡' : '🔵';
      log(`${icon} [${f.severity.toUpperCase()}] ${f.title}`);
      log(`   ${f.file_path}:${f.line_start}  (${f.rule_id})`);
      if (f.evidence) log(`   Evidence: ${f.evidence}`, 'cyan');
      log('');
    }
    if (findings.length > 25) log(`... and ${findings.length - 25} more findings.`, 'yellow');
  }
}

// ─── CLI ──────────────────────────────────────────────────────────────────────

const [, , command, ...args] = process.argv;

(async () => {
  switch (command) {
    case 'install-hooks':
    case 'install':
      installHooks();
      break;
    case 'scan':
      await runScan(args);
      break;
    case 'status':
      await showStatus();
      break;
    case 'suppress':
      await suppressFinding(args[0], args.slice(1).join(' '));
      break;
    case 'help':
    case '--help':
    case '-h':
      log('\nOmniGuard - AI-Powered Security Scanner\n', 'blue');
      log('Usage: omniguard <command> [options]\n');
      log('Commands:');
      log('  install-hooks               Install Git pre-commit and pre-push hooks');
      log('  scan [files/dirs...]        Scan files (default: git tracked files)');
      log('  status                      Show organization security status');
      log('  suppress <id> [reason]      Suppress a finding by ID');
      log('  help                        Show this help\n');
      log('Environment Variables:');
      log('  OMNIGUARD_URL              Supabase functions URL (e.g., https://xyz.supabase.co/functions/v1)');
      log('  OMNIGUARD_API_KEY          API key from dashboard → Settings → API Keys');
      log('  OMNIGUARD_FAIL_ON          Minimum severity to block commit (critical/high/medium/low)');
      log('  ANTHROPIC_API_KEY          Enable AI classification in scan results\n');
      break;
    default:
      if (command) {
        log(`Unknown command: ${command}`, 'red');
        log('Run "omniguard help" for usage.', 'yellow');
        process.exit(1);
      } else {
        log('\nOmniGuard - AI-Powered Security Scanner', 'blue');
        log('Run "omniguard help" for usage.\n');
      }
  }
})();
