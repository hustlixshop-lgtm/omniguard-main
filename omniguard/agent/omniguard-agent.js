#!/usr/bin/env node
/**
 * OmniGuard Local Agent
 * Runs as a background service (Windows Service / Linux systemd / macOS launchd)
 * Continuously monitors repositories, sends heartbeats, syncs with server
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');
const os = require('os');

// Configuration from environment or .env
const CONFIG = {
  API_URL: process.env.OMNIGUARD_URL || '',
  API_KEY: process.env.OMNIGUARD_API_KEY || '',
  WORKER_ID: process.env.OMNIGUARD_WORKER_ID || `agent-${os.hostname()}-${Date.now().toString(36)}`,
  HEARTBEAT_INTERVAL: parseInt(process.env.OMNIGUARD_HEARTBEAT_INTERVAL || '60000'),
  SCAN_INTERVAL: parseInt(process.env.OMNIGUARD_SCAN_INTERVAL || '300000'),
  MONITORED_PATHS: (process.env.OMNIGUARD_PATHS || process.cwd()).split(':'),
  LOG_LEVEL: process.env.OMNIGUARD_LOG_LEVEL || 'info',
  PID_FILE: process.env.OMNIGUARD_PID_FILE || '/var/run/omniguard-agent.pid',
  LOG_FILE: process.env.OMNIGUARD_LOG_FILE || '/var/log/omniguard-agent.log',
};

const REPO_CACHE = new Map();
let isRunning = true;
let lastScanTime = 0;

// Logging
function log(level, msg, ...args) {
  const levels = { debug: 0, info: 1, warn: 2, error: 3 };
  if (levels[level] < levels[CONFIG.LOG_LEVEL]) return;
  const ts = new Date().toISOString();
  const line = `[${ts}] [${level.toUpperCase()}] [${CONFIG.WORKER_ID}] ${msg}`;
  console.error(line, ...args); // stderr for service logs
  try {
    fs.appendFileSync(CONFIG.LOG_FILE, line + '\n');
  } catch {}
}

// HTTP request helper
function request(url, options = {}, body = null) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${CONFIG.API_KEY}`,
        'X-Worker-ID': CONFIG.WORKER_ID,
        ...options.headers
      }
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          resolve({ ok: res.statusCode < 300, status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ ok: false, status: res.statusCode, body: data });
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.setTimeout(30000);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// Heartbeat
async function sendHeartbeat(status = 'healthy', metadata = {}) {
  if (!CONFIG.API_URL) return;
  try {
    const res = await request(`${CONFIG.API_URL}/agent/heartbeat`, { method: 'POST' }, {
      worker_id: CONFIG.WORKER_ID,
      worker_type: 'local-agent',
      status,
      hostname: os.hostname(),
      platform: process.platform,
      arch: os.arch(),
      uptime: Math.floor(process.uptime()),
      memory_used_mb: Math.round(process.memoryUsage().rss / 1024 / 1024),
      monitored_repos: REPO_CACHE.size,
      ...metadata
    });
    log('debug', 'Heartbeat sent:', res.ok ? 'OK' : `FAILED ${res.status}`);
    return res.ok;
  } catch (e) {
    log('warn', 'Heartbeat failed:', e.message);
    return false;
  }
}

// Discover git repositories in monitored paths
function discoverRepos() {
  const repos = [];
  for (const basePath of CONFIG.MONITORED_PATHS) {
    if (!fs.existsSync(basePath)) continue;
    try {
      const items = fs.readdirSync(basePath, { withFileTypes: true });
      for (const item of items) {
        if (!item.isDirectory()) continue;
        const gitDir = path.join(basePath, item.name, '.git');
        if (fs.existsSync(gitDir)) {
          const repoPath = path.join(basePath, item.name);
          repos.push({
            path: repoPath,
            name: item.name,
            last_modified: fs.statSync(repoPath).mtimeMs
          });
        }
      }
    } catch (e) {
      log('warn', `Failed to scan ${basePath}:`, e.message);
    }
  }
  return repos;
}

// Get git status for a repo
function getGitStatus(repoPath) {
  try {
    const branch = execSync('git rev-parse --abbrev-ref HEAD', { cwd: repoPath, encoding: 'utf8' }).trim();
    const head = execSync('git rev-parse HEAD', { cwd: repoPath, encoding: 'utf8' }).trim();
    const status = execSync('git status --porcelain', { cwd: repoPath, encoding: 'utf8' }).trim();
    const remote = execSync('git remote get-url origin 2>/dev/null || echo ""', { cwd: repoPath, encoding: 'utf8' }).trim();
    return {
      branch,
      commit_sha: head,
      dirty: status.length > 0,
      remote_url: remote,
      dirty_files: status.split('\n').filter(l => l.trim())
    };
  } catch (e) {
    return { error: e.message };
  }
}

// Sync repos with server
async function syncRepos() {
  if (!CONFIG.API_URL) return;
  const repos = discoverRepos();
  for (const repo of repos) {
    const status = getGitStatus(repo.path);
    const key = status.remote_url || repo.path;
    const cached = REPO_CACHE.get(key);
    REPO_CACHE.set(key, { ...repo, ...status, last_sync: Date.now() });
    if (cached?.commit_sha !== status.commit_sha || !cached) {
      log('info', `Repo changed: ${repo.name} (${status.branch}@${status.commit_sha?.slice(0, 7)})`);
      // Notify server of repo change
      try {
        await request(`${CONFIG.API_URL}/agent/repo-sync`, { method: 'POST' }, {
          worker_id: CONFIG.WORKER_ID,
          repo_path: repo.path,
          repo_name: repo.name,
          remote_url: status.remote_url,
          branch: status.branch,
          commit_sha: status.commit_sha,
          is_dirty: status.dirty
        });
      } catch (e) {
        log('warn', `Failed to sync ${repo.name}:`, e.message);
      }
    }
  }
  log('debug', `Discovered ${repos.length} repos`);
}

// Run local scan
async function runLocalScan(repoPath) {
  if (!CONFIG.API_URL) return null;
  try {
    const res = await request(`${CONFIG.API_URL}/scan-quick`, { method: 'POST' }, {
      path: repoPath,
      content: '',
      mode: 'repo-monitor'
    });
    return res.body;
  } catch (e) {
    log('warn', `Scan failed for ${repoPath}:`, e.message);
    return null;
  }
}

// Main loop
async function main() {
  log('info', `OmniGuard Local Agent starting...`);
  log('info', `Worker ID: ${CONFIG.WORKER_ID}`);
  log('info', `Monitored paths: ${CONFIG.MONITORED_PATHS.join(', ')}`);
  log('info', `API URL: ${CONFIG.API_URL || '(offline mode)'}`);

  // Write PID file
  try {
    fs.writeFileSync(CONFIG.PID_FILE, process.pid.toString());
  } catch {}

  // Initial heartbeat
  await sendHeartbeat('starting');

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    log('info', 'Received SIGTERM, shutting down...');
    isRunning = false;
    await sendHeartbeat('stopping');
    try { fs.unlinkSync(CONFIG.PID_FILE); } catch {}
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    log('info', 'Received SIGINT, shutting down...');
    isRunning = false;
    await sendHeartbeat('stopping');
    try { fs.unlinkSync(CONFIG.PID_FILE); } catch {}
    process.exit(0);
  });

  // Main loop
  let heartbeatCount = 0;
  while (isRunning) {
    try {
      // Heartbeat every minute
      if (heartbeatCount % (CONFIG.HEARTBEAT_INTERVAL / 1000) === 0) {
        await sendHeartbeat('healthy', { scan_interval: CONFIG.SCAN_INTERVAL });
      }

      // Sync repos every scan interval
      if (Date.now() - lastScanTime > CONFIG.SCAN_INTERVAL) {
        await syncRepos();
        lastScanTime = Date.now();
      }

      heartbeatCount++;
      await new Promise(r => setTimeout(r, 1000));
    } catch (e) {
      log('error', 'Main loop error:', e.message);
      await new Promise(r => setTimeout(r, 5000));
    }
  }
}

// Health check endpoint (when run with --health flag)
if (process.argv.includes('--health')) {
  try {
    const pid = parseInt(fs.readFileSync(CONFIG.PID_FILE, 'utf8'));
    process.kill(pid, 0);
    console.log('Healthy');
    process.exit(0);
  } catch {
    console.log('Not running');
    process.exit(1);
  }
}

// Run as daemon foreground
if (process.argv.includes('--foreground') || process.argv.includes('-f')) {
  main();
} else if (require.main === module) {
  main();
}

module.exports = { sendHeartbeat, syncRepos, discoverRepos };
