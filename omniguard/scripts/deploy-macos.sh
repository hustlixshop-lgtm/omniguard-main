#!/usr/bin/env bash
# OmniGuard One-Command Deploy — macOS
# Usage: VITE_SUPABASE_URL=https://xyz.supabase.co VITE_SUPABASE_ANON_KEY=eyJ... bash deploy-macos.sh

set -euo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${GREEN}[OmniGuard]${NC} $*"; }
warn() { echo -e "${YELLOW}[OmniGuard]${NC} $*"; }
err()  { echo -e "${RED}[OmniGuard]${NC} $*" >&2; exit 1; }

[[ -z "${VITE_SUPABASE_URL:-}"      ]] && err "VITE_SUPABASE_URL not set"
[[ -z "${VITE_SUPABASE_ANON_KEY:-}" ]] && err "VITE_SUPABASE_ANON_KEY not set"

PORT="${PORT:-8080}"

# Check Docker Desktop
if ! command -v docker >/dev/null 2>&1; then
  warn "Docker not found. Installing via Homebrew..."
  command -v brew >/dev/null 2>&1 || err "Homebrew not found. Install from https://brew.sh"
  brew install --cask docker
  open /Applications/Docker.app
  info "Waiting for Docker to start (60s)..."
  sleep 60
fi

info "Building OmniGuard..."
docker build \
  --build-arg VITE_SUPABASE_URL="${VITE_SUPABASE_URL}" \
  --build-arg VITE_SUPABASE_ANON_KEY="${VITE_SUPABASE_ANON_KEY}" \
  -t omniguard:latest .

info "Starting container..."
docker rm -f omniguard 2>/dev/null || true
docker run -d --name omniguard --restart unless-stopped -p "${PORT}:80" omniguard:latest

# Wait for health
for i in $(seq 1 30); do curl -sf "http://localhost:${PORT}/health" >/dev/null 2>&1 && break || sleep 2; done
curl -sf "http://localhost:${PORT}/health" >/dev/null 2>&1 || err "Health check failed"

# Optional: register launchd service so it starts on boot
PLIST="$HOME/Library/LaunchAgents/io.omniguard.dashboard.plist"
cat > "$PLIST" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.omniguard.dashboard</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/docker</string>
    <string>start</string>
    <string>omniguard</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/omniguard.log</string>
  <key>StandardErrorPath</key><string>/tmp/omniguard.err</string>
</dict>
</plist>
PLIST_EOF
launchctl load "$PLIST" 2>/dev/null || true

info ""
info "✓ OmniGuard running at http://localhost:${PORT}"
info "  Auto-start on login: enabled (launchd)"
info "  Logs: docker logs omniguard"
info "  Stop: docker stop omniguard"
