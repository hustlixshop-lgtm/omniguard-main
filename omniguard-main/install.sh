#!/bin/bash
# OmniGuard Installation Script
# This script installs OmniGuard, sets up hooks, and configures your environment

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              OmniGuard Security Platform                   ║"
echo "║                    Installation Script                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check dependencies
echo -e "${BLUE}Checking dependencies...${NC}"

has_node=$(command -v node || echo "")
if [ -z "$has_node" ]; then
    echo -e "${RED}Error: Node.js is required but not installed.${NC}"
    echo "Please install Node.js from https://nodejs.org/"
    exit 1
fi

has_git=$(command -v git || echo "")
if [ -z "$has_git" ]; then
    echo -e "${RED}Error: Git is required but not installed.${NC}"
    echo "Please install Git from https://git-scm.com/"
    exit 1
fi

has_curl=$(command -v curl || echo "")
if [ -z "$has_curl" ]; then
    echo -e "${YELLOW}Warning: curl not found. Some features may be limited.${NC}"
fi

echo -e "${GREEN}✓ Dependencies OK${NC}"

# Detect package manager
PKG_MANAGER=""
if command -v pnpm &> /dev/null; then
    PKG_MANAGER="pnpm"
elif command -v yarn &> /dev/null; then
    PKG_MANAGER="yarn"
elif command -v npm &> /dev/null; then
    PKG_MANAGER="npm"
fi

echo -e "${BLUE}Package manager: $PKG_MANAGER${NC}"

# Install OmniGuard CLI
echo -e "${BLUE}Installing OmniGuard CLI...${NC}"

if [ "$PKG_MANAGER" = "pnpm" ]; then
    pnpm add -g @omniguard/cli
elif [ "$PKG_MANAGER" = "yarn" ]; then
    yarn global add @omniguard/cli
elif [ "$PKG_MANAGER" = "npm" ]; then
    npm install -g @omniguard/cli
fi

echo -e "${GREEN}✓ OmniGuard CLI installed${NC}"

# Check if in a git repository
if [ -d ".git" ]; then
    echo -e "${BLUE}Git repository detected. Installing hooks...${NC}"

    # Create hooks directory
    mkdir -p .git/hooks

    # Download and install pre-commit hook
    curl -fsSL https://raw.githubusercontent.com/omniguard/omniguard/main/hooks/pre-commit -o .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit

    # Download and install pre-push hook
    curl -fsSL https://raw.githubusercontent.com/omniguard/omniguard/main/hooks/pre-push -o .git/hooks/pre-push
    chmod +x .git/hooks/pre-push

    echo -e "${GREEN}✓ Git hooks installed${NC}"
else
    echo -e "${YELLOW}Not in a git repository. Skipping hook installation.${NC}"
    echo -e "Run 'omniguard install-hooks' inside a git repository to set up hooks."
fi

# Configuration
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Configuration${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"

# API Key
if [ -z "$OMNIGUARD_API_KEY" ]; then
    echo ""
    echo -e "${YELLOW}To enable full functionality, set your environment variables:${NC}"
    echo ""
    echo "  export OMNIGUARD_URL=\"https://api.omniguard.io\""
    echo "  export OMNIGUARD_API_KEY=\"your-api-key-here\""
    echo ""
    echo -e "${YELLOW}Get your API key at:${NC} https://app.omniguard.io/settings/api-keys"
    echo ""
fi

# VS Code Extension
echo -e "${BLUE}Installing VS Code extension...${NC}"
if command -v code &> /dev/null; then
    code --install-extension omniguard.omniguard --force 2>/dev/null || echo -e "${YELLOW}VS Code extension available at: https://marketplace.visualstudio.com/items?itemName=omniguard.omniguard${NC}"
else
    echo -e "${YELLOW}VS Code not found. Install extension manually from:${NC}"
    echo "https://marketplace.visualstudio.com/items?itemName=omniguard.omniguard"
fi

# Final message
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            OmniGuard installation complete!                ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo ""
echo "  omniguard scan                  # Scan current directory"
echo "  omniguard status                # Check security status"
echo "  omniguard install-hooks         # Install Git hooks"
echo "  omniguard help                  # Show all commands"
echo ""
echo -e "${BLUE}VS Code:${NC}"
echo "  Open a file and press Cmd+Shift+P → OmniGuard: Scan Current File"
echo ""
echo -e "${BLUE}Documentation:${NC} https://docs.omniguard.io"
echo -e "${BLUE}Support:${NC} https://github.com/omniguard/omniguard/issues"
echo ""
