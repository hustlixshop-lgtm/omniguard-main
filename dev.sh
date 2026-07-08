#!/usr/bin/env bash
# =============================================================================
#  OmniGuard — Local Dev Setup & Run Script
#  Usage:  bash dev.sh            # install + start everything
#          bash dev.sh --install  # install only, don't start servers
#          bash dev.sh --start    # start servers (assumes install done)
#          bash dev.sh --cli      # also install CLI globally via npm link
#          bash dev.sh --ext      # also build & install VS Code extension
# =============================================================================

set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}  ✓${RESET}  $*"; }
info() { echo -e "${BLUE}  →${RESET}  $*"; }
warn() { echo -e "${YELLOW}  ⚠${RESET}  $*"; }
fail() { echo -e "${RED}  ✗  $*${RESET}"; exit 1; }
hdr()  { echo -e "\n${BOLD}${CYAN}$*${RESET}"; }

# ── Flags ─────────────────────────────────────────────────────────────────────
DO_INSTALL=true
DO_START=true
DO_CLI=false
DO_EXT=false

for arg in "$@"; do
  case "$arg" in
    --install) DO_START=false ;;
    --start)   DO_INSTALL=false ;;
    --cli)     DO_CLI=true ;;
    --ext)     DO_EXT=true ;;
    --help|-h)
      echo "Usage: bash dev.sh [--install] [--start] [--cli] [--ext]"
      echo ""
      echo "  (no flags)   Install everything, then start the dashboard"
      echo "  --install    Install dependencies only (don't start)"
      echo "  --start      Start servers only (skip reinstall)"
      echo "  --cli        Also install the CLI globally (npm link)"
      echo "  --ext        Also build + install the VS Code extension"
      exit 0 ;;
  esac
done

# ── Locate project root ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR"

# Support running from a sub-directory
for candidate in "$ROOT" "$ROOT/.." "$ROOT/../.."; do
  if [[ -f "$candidate/omniguard/package.json" ]]; then
    ROOT="$(cd "$candidate" && pwd)"
    break
  fi
done

DASHBOARD="$ROOT/omniguard"
CLI_DIR="$ROOT/cli"
SCANNER_DIR="$ROOT/omniguard-main/scanner"
VSCODE_DIR="$ROOT/vscode-extension"
ENV_FILE="$DASHBOARD/.env"

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║          OmniGuard — Local Dev Environment           ║${RESET}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${RESET}"

# ── Preflight checks ───────────────────────────────────────────────────────────
hdr "Preflight checks"

command -v node >/dev/null 2>&1 || fail "Node.js not found. Install from https://nodejs.org (v18+)"
NODE_VER=$(node --version | sed 's/v//')
NODE_MAJ=$(echo "$NODE_VER" | cut -d. -f1)
[[ "$NODE_MAJ" -ge 18 ]] || fail "Node.js v18+ required (found v$NODE_VER)"
ok "Node.js v$NODE_VER"

command -v npm >/dev/null 2>&1 || fail "npm not found"
ok "npm $(npm --version)"

[[ -d "$DASHBOARD" ]] || fail "Dashboard directory not found at $DASHBOARD"
ok "Project root: $ROOT"

# ── .env setup ────────────────────────────────────────────────────────────────
hdr "Environment (.env)"

if [[ ! -f "$ENV_FILE" ]]; then
  # Check if there's a root .env with the Supabase vars
  if [[ -f "$ROOT/.env" ]]; then
    info "Copying root .env → $ENV_FILE"
    cp "$ROOT/.env" "$ENV_FILE"
    ok ".env created from root"
  else
    warn ".env not found — creating template"
    cat > "$ENV_FILE" << 'ENVEOF'
# OmniGuard — Dashboard Environment
# Fill in your Supabase project credentials from:
# https://supabase.com/dashboard → Project Settings → API

VITE_SUPABASE_URL=https://YOUR_PROJECT_ID.supabase.co
VITE_SUPABASE_ANON_KEY=YOUR_ANON_KEY_HERE
ENVEOF
    echo ""
    echo -e "${YELLOW}  ┌─────────────────────────────────────────────────────┐${RESET}"
    echo -e "${YELLOW}  │  ACTION REQUIRED: edit omniguard/.env               │${RESET}"
    echo -e "${YELLOW}  │  Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY   │${RESET}"
    echo -e "${YELLOW}  │  Get credentials from: supabase.com/dashboard       │${RESET}"
    echo -e "${YELLOW}  └─────────────────────────────────────────────────────┘${RESET}"
    echo ""
  fi
else
  ok ".env exists"
  # Validate it has the required keys
  if grep -q "YOUR_PROJECT_ID" "$ENV_FILE" 2>/dev/null; then
    warn ".env still has placeholder values — update VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY"
  else
    SUPA_URL=$(grep "^VITE_SUPABASE_URL=" "$ENV_FILE" | cut -d= -f2- | tr -d '"' | tr -d "'")
    [[ -n "$SUPA_URL" ]] && ok "Supabase URL: $SUPA_URL" || warn "VITE_SUPABASE_URL not set"
  fi
fi

# ── Install dependencies ───────────────────────────────────────────────────────
if [[ "$DO_INSTALL" == true ]]; then
  hdr "Installing dependencies"

  # Dashboard
  info "Dashboard (omniguard/)"
  cd "$DASHBOARD"
  npm install --silent
  ok "Dashboard dependencies installed"

  # Scanner (optional — only if directory exists with package.json)
  if [[ -f "$SCANNER_DIR/package.json" ]]; then
    info "Scanner (omniguard-main/scanner/)"
    cd "$SCANNER_DIR"
    npm install --silent
    ok "Scanner dependencies installed"
  fi

  # CLI (optional --cli flag)
  if [[ "$DO_CLI" == true ]]; then
    hdr "CLI — global install (npm link)"
    if [[ -f "$CLI_DIR/package.json" ]]; then
      cd "$CLI_DIR"
      chmod +x src/index.js 2>/dev/null || true
      npm link --silent 2>/dev/null || sudo npm link --silent
      ok "CLI installed globally → 'omniguard' command available"
      omniguard version 2>/dev/null && ok "CLI works" || warn "CLI linked but 'omniguard' not in PATH yet — restart your shell"
    else
      warn "CLI directory not found at $CLI_DIR — skipping"
    fi
  fi

  # VS Code extension (optional --ext flag)
  if [[ "$DO_EXT" == true ]]; then
    hdr "VS Code extension — build + install"
    if [[ -f "$VSCODE_DIR/package.json" ]]; then
      cd "$VSCODE_DIR"
      npm install --silent
      npm run compile
      ok "Extension compiled"

      VSIX=$(ls "$VSCODE_DIR"/omniguard-*.vsix 2>/dev/null | head -1)
      if [[ -z "$VSIX" ]]; then
        info "Packaging extension..."
        npx vsce package --no-yarn --allow-missing-repository 2>/dev/null
        VSIX=$(ls "$VSCODE_DIR"/omniguard-*.vsix 2>/dev/null | head -1)
      fi

      if [[ -n "$VSIX" ]]; then
        ok "Extension packaged: $(basename "$VSIX")"
        if command -v code >/dev/null 2>&1; then
          code --install-extension "$VSIX" --force
          ok "Extension installed in VS Code"
        else
          warn "'code' CLI not found — install manually:"
          warn "  VS Code → Extensions → ··· → Install from VSIX → $VSIX"
        fi
      else
        warn "VSIX not found after packaging — check for errors above"
      fi
    else
      warn "VS Code extension directory not found at $VSCODE_DIR — skipping"
    fi
  fi
fi

# ── Connectivity check ─────────────────────────────────────────────────────────
hdr "Supabase connectivity"

SUPA_URL=$(grep "^VITE_SUPABASE_URL=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'" || true)

if [[ -n "$SUPA_URL" && "$SUPA_URL" != *"YOUR_PROJECT_ID"* ]]; then
  STATUS_URL="${SUPA_URL}/functions/v1/api-v1-status"
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$STATUS_URL" 2>/dev/null || echo "000")
  if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]]; then
    ok "Supabase edge functions reachable (HTTP $HTTP_CODE)"
  elif [[ "$HTTP_CODE" == "000" ]]; then
    warn "Could not reach Supabase — check your internet connection"
  else
    warn "Supabase returned HTTP $HTTP_CODE — functions may not be deployed yet"
  fi
else
  warn "Supabase URL not configured — skipping connectivity check"
fi

# ── Summary + start ────────────────────────────────────────────────────────────
if [[ "$DO_START" == true ]]; then
  hdr "Starting development server"

  cd "$DASHBOARD"

  echo ""
  echo -e "${BOLD}  Services:${RESET}"
  echo -e "  ${GREEN}◉${RESET}  Dashboard   →  ${BOLD}http://localhost:5173${RESET}"
  echo -e "  ${CYAN}◉${RESET}  Backend     →  Supabase (${SUPA_URL:-not configured})"
  [[ "$DO_CLI" == true ]] && echo -e "  ${CYAN}◉${RESET}  CLI         →  omniguard (global)"
  [[ "$DO_EXT" == true ]] && echo -e "  ${CYAN}◉${RESET}  VS Code ext →  installed"
  echo ""
  echo -e "  Press ${BOLD}Ctrl+C${RESET} to stop"
  echo ""

  # Use npx vite directly so it works even without tsc in PATH
  exec ./node_modules/.bin/vite

else
  hdr "Done"
  echo ""
  echo -e "  All dependencies installed. To start the dashboard:"
  echo -e "  ${BOLD}  cd omniguard && npm run dev${RESET}"
  echo ""
  [[ "$DO_CLI" == false  ]] && echo -e "  To also install the CLI:          ${BOLD}bash dev.sh --cli${RESET}"
  [[ "$DO_EXT" == false  ]] && echo -e "  To also build the VS Code ext:    ${BOLD}bash dev.sh --ext${RESET}"
  echo ""
fi
