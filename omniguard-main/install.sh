#!/bin/bash
# OmniGuard Installation Script
# Builds the CLI from source and installs it locally.
# No fake npm packages. No fake URLs. No fake Marketplace extensions.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLI_DIR="$REPO_ROOT/cli"

banner() {
  echo -e "${BLUE}"
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║              OmniGuard Security Platform v1                ║"
  echo "║                    Installation Script                     ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

step() { echo -e "${BLUE}▶ $*${NC}"; }
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }

banner

# ─── Check dependencies ───────────────────────────────────────────────────────

step "Checking dependencies..."

command -v node >/dev/null 2>&1 || fail "Node.js is required. Install from https://nodejs.org/"
NODE_MAJOR=$(node -e 'process.stdout.write(String(process.versions.node.split(".")[0]))')
[ "$NODE_MAJOR" -ge 18 ] || fail "Node.js >=18 required. Found: $(node --version)"
ok "Node.js $(node --version)"

command -v npm >/dev/null 2>&1 || fail "npm is required. Install from https://nodejs.org/"
ok "npm $(npm --version)"

command -v git >/dev/null 2>&1 && ok "git $(git --version | head -1)" || warn "git not found — hook installation will be skipped"

# ─── Build & install CLI ─────────────────────────────────────────────────────

step "Installing OmniGuard CLI..."

if [ ! -d "$CLI_DIR" ]; then
  fail "CLI directory not found at $CLI_DIR"
fi

if [ ! -f "$CLI_DIR/src/index.js" ]; then
  fail "CLI source not found at $CLI_DIR/src/index.js"
fi

# Ensure the CLI is executable
chmod +x "$CLI_DIR/src/index.js"

# Use npm link to install CLI globally from local source (no npm publish required)
cd "$CLI_DIR"
npm link 2>&1 | grep -v "^npm warn" || true
cd - >/dev/null

# Verify installation
if command -v omniguard >/dev/null 2>&1; then
  ok "omniguard CLI installed ($(omniguard version))"
else
  # Fallback: add to PATH manually using a wrapper
  warn "npm link didn't put omniguard in PATH. Adding wrapper..."
  if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    cat > /usr/local/bin/omniguard << WRAPPER
#!/bin/sh
node "$CLI_DIR/src/index.js" "\$@"
WRAPPER
    chmod +x /usr/local/bin/omniguard
    ok "omniguard CLI wrapper installed at /usr/local/bin/omniguard"
  elif [ -d "$HOME/.local/bin" ] || mkdir -p "$HOME/.local/bin"; then
    cat > "$HOME/.local/bin/omniguard" << WRAPPER
#!/bin/sh
node "$CLI_DIR/src/index.js" "\$@"
WRAPPER
    chmod +x "$HOME/.local/bin/omniguard"
    ok "omniguard CLI wrapper installed at $HOME/.local/bin/omniguard"
    echo ""
    warn "Add $HOME/.local/bin to your PATH:"
    echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
  fi
fi

# ─── Install git hooks (if in a git repo) ────────────────────────────────────

if [ -d ".git" ]; then
  step "Installing git hooks in current repository..."
  mkdir -p .git/hooks
  omniguard install-hooks && ok "Git hooks installed" || warn "Hook installation failed (non-fatal)"
else
  warn "Not in a git repository. Skipping hook installation."
  echo "  Run 'omniguard install-hooks' inside any git repository."
fi

# ─── VS Code Extension (build from source if present) ────────────────────────

VSCE_DIR=""
for candidate in "$REPO_ROOT/vscode-extension" "$REPO_ROOT/omniguard-main/vscode-extension"; do
  [ -d "$candidate" ] && VSCE_DIR="$candidate" && break
done

if [ -n "$VSCE_DIR" ] && [ -f "$VSCE_DIR/package.json" ]; then
  step "Building VS Code extension..."
  cd "$VSCE_DIR"
  npm install --silent
  if command -v vsce >/dev/null 2>&1 || npx vsce --version >/dev/null 2>&1; then
    npm run compile 2>&1 | tail -5 || true
    npx vsce package --no-yarn 2>&1 | tail -5 || true
    VSIX=$(ls *.vsix 2>/dev/null | head -1)
    if [ -n "$VSIX" ] && command -v code >/dev/null 2>&1; then
      code --install-extension "$VSIX" --force 2>&1 | tail -3 || true
      ok "VS Code extension installed from $VSIX"
    elif [ -n "$VSIX" ]; then
      ok "VS Code extension built: $VSIX"
      warn "Install manually: code --install-extension $VSCE_DIR/$VSIX"
    fi
  else
    warn "vsce not available. Install with: npm install -g @vscode/vsce"
  fi
  cd - >/dev/null
else
  warn "VS Code extension not found — skipping"
fi

# ─── Configuration guidance ──────────────────────────────────────────────────

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Configuration${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Connect OmniGuard to your Supabase project:"
echo ""
echo "    omniguard login"
echo ""
echo "  Or set environment variables:"
echo ""
echo "    export OMNIGUARD_URL=\"https://<project>.supabase.co/functions/v1\""
echo "    export OMNIGUARD_API_KEY=\"og_live_...\"  # from Dashboard → Settings → API Keys"
echo ""
echo "  Get your Supabase project URL from: https://supabase.com/dashboard"
echo ""

# ─── Quick start ─────────────────────────────────────────────────────────────

echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            OmniGuard installation complete!                ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo ""
echo "  omniguard version          # Verify installation"
echo "  omniguard doctor           # Check your setup"
echo "  omniguard login            # Authenticate with dashboard"
echo "  omniguard scan .           # Scan current directory"
echo "  omniguard install-hooks    # Install git hooks in current repo"
echo "  omniguard help             # Show all commands"
echo ""
echo -e "${BLUE}Documentation:${NC} ./docs/ directory in this repository"
echo ""
