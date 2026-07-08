#!/usr/bin/env bash
# OmniGuard One-Command Deploy Script (Linux/macOS)
# Usage: VITE_SUPABASE_URL=https://xyz.supabase.co VITE_SUPABASE_ANON_KEY=eyJ... bash deploy.sh [--port 80] [--domain security.yourco.com]

set -euo pipefail

# ── Config ─────────────────────────────────────────────────────
PORT="${PORT:-80}"
DOMAIN="${DOMAIN:-}"
COMPOSE_FILE="docker-compose.prod.yml"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[OmniGuard]${NC} $*"; }
warn()  { echo -e "${YELLOW}[OmniGuard]${NC} $*"; }
error() { echo -e "${RED}[OmniGuard]${NC} $*" >&2; exit 1; }

# ── Checks ─────────────────────────────────────────────────────
[[ -z "${VITE_SUPABASE_URL:-}" ]] && error "VITE_SUPABASE_URL not set"
[[ -z "${VITE_SUPABASE_ANON_KEY:-}" ]] && error "VITE_SUPABASE_ANON_KEY not set"
command -v docker >/dev/null 2>&1 || error "Docker not found. Install: https://docs.docker.com/engine/install/"

info "Starting OmniGuard deployment..."
info "Supabase URL: $VITE_SUPABASE_URL"

# ── Build & deploy ──────────────────────────────────────────────
cat > docker-compose.prod.yml << EOF
version: '3.9'
services:
  omniguard:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        VITE_SUPABASE_URL: ${VITE_SUPABASE_URL}
        VITE_SUPABASE_ANON_KEY: ${VITE_SUPABASE_ANON_KEY}
    ports:
      - "${PORT}:80"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost/health"]
      interval: 30s
      timeout: 5s
      retries: 3
EOF

info "Building Docker image..."
docker compose -f $COMPOSE_FILE build --no-cache

info "Starting container..."
docker compose -f $COMPOSE_FILE up -d

info "Waiting for health check..."
MAX_RETRIES=30; RETRY=0
until docker compose -f $COMPOSE_FILE exec -T omniguard wget -qO- http://localhost/health >/dev/null 2>&1 || [ $RETRY -ge $MAX_RETRIES ]; do
  sleep 2; RETRY=$((RETRY+1))
done
[ $RETRY -ge $MAX_RETRIES ] && error "Health check failed after ${MAX_RETRIES} attempts"

# ── SSL with Caddy (optional) ───────────────────────────────────
if [[ -n "$DOMAIN" ]]; then
  if command -v caddy >/dev/null 2>&1; then
    info "Configuring Caddy for $DOMAIN..."
    cat > /etc/caddy/Caddyfile << CADDYEOF
$DOMAIN {
    reverse_proxy localhost:$PORT
}
CADDYEOF
    systemctl reload caddy || caddy reload 2>/dev/null || warn "Manual Caddy reload may be needed"
  else
    warn "Caddy not found. To enable SSL: sudo apt install caddy && configure /etc/caddy/Caddyfile"
  fi
fi

info ""
info "✓ OmniGuard deployed successfully!"
info "  Dashboard: http://localhost:$PORT${DOMAIN:+ or https://$DOMAIN}"
info "  Health:    http://localhost:$PORT/health"
info ""
info "  Next steps:"
info "  1. Open the dashboard URL and create an account"
info "  2. Go to Settings → AI Provider and enter your Anthropic key"
info "  3. Go to Settings → Integrations and enter your GitHub PAT"
info "  4. Connect a repository and run your first scan"
info ""
