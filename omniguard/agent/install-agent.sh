#!/usr/bin/env bash
# OmniGuard Agent Installer — Linux (systemd) and macOS (launchd)
# Usage: OMNIGUARD_URL=... OMNIGUARD_API_KEY=... sudo bash install-agent.sh

set -euo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${GREEN}[OmniGuard]${NC} $*"; }
warn() { echo -e "${YELLOW}[OmniGuard]${NC} $*"; }
err()  { echo -e "${RED}[OmniGuard]${NC} $*" >&2; exit 1; }

[[ -z "${OMNIGUARD_URL:-}"     ]] && err "OMNIGUARD_URL required"
[[ -z "${OMNIGUARD_API_KEY:-}" ]] && err "OMNIGUARD_API_KEY required"

command -v node >/dev/null 2>&1 || err "Node.js not found. Install from https://nodejs.org"

INSTALL_DIR="/opt/omniguard"
AGENT_SCRIPT="${INSTALL_DIR}/agent/omniguard-agent.js"
MONITORED_PATHS="${OMNIGUARD_PATHS:-${HOME}/repos:${HOME}/projects}"
LOG_DIR="/var/log/omniguard"
RUN_DIR="/var/run"

mkdir -p "${INSTALL_DIR}/agent" "${LOG_DIR}" 2>/dev/null || {
  LOG_DIR="${HOME}/.omniguard/logs"
  mkdir -p "${INSTALL_DIR}/agent" "${LOG_DIR}"
}

info "Installing OmniGuard Agent to ${INSTALL_DIR}..."

# Copy agent
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [[ -f "${SCRIPT_DIR}/omniguard-agent.js" ]]; then
  cp "${SCRIPT_DIR}/omniguard-agent.js" "${INSTALL_DIR}/agent/"
else
  err "omniguard-agent.js not found in ${SCRIPT_DIR}"
fi

# Write env file
HOSTNAME_PART=$(hostname | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')
cat > "${INSTALL_DIR}/agent.env" << EOF
OMNIGUARD_URL=${OMNIGUARD_URL}
OMNIGUARD_API_KEY=${OMNIGUARD_API_KEY}
OMNIGUARD_WORKER_ID=agent-${HOSTNAME_PART}
OMNIGUARD_HEARTBEAT_INTERVAL=60000
OMNIGUARD_SCAN_INTERVAL=300000
OMNIGUARD_PATHS=${MONITORED_PATHS}
OMNIGUARD_LOG_LEVEL=${OMNIGUARD_LOG_LEVEL:-info}
OMNIGUARD_LOG_FILE=${LOG_DIR}/agent.log
OMNIGUARD_PID_FILE=${RUN_DIR}/omniguard-agent.pid
EOF
chmod 600 "${INSTALL_DIR}/agent.env"

# Detect OS
if [[ "$(uname)" == "Darwin" ]]; then
  # macOS launchd
  PLIST_DIR="${HOME}/Library/LaunchAgents"
  PLIST_FILE="${PLIST_DIR}/io.omniguard.agent.plist"
  mkdir -p "${PLIST_DIR}"

  # Unload if already running
  launchctl unload "${PLIST_FILE}" 2>/dev/null || true

  # Source env file as shell vars for launchd env dict
  source "${INSTALL_DIR}/agent.env"

  cat > "${PLIST_FILE}" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.omniguard.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(command -v node)</string>
    <string>${AGENT_SCRIPT}</string>
    <string>--foreground</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>OMNIGUARD_URL</key><string>${OMNIGUARD_URL}</string>
    <key>OMNIGUARD_API_KEY</key><string>${OMNIGUARD_API_KEY}</string>
    <key>OMNIGUARD_WORKER_ID</key><string>agent-${HOSTNAME_PART}</string>
    <key>OMNIGUARD_HEARTBEAT_INTERVAL</key><string>60000</string>
    <key>OMNIGUARD_SCAN_INTERVAL</key><string>300000</string>
    <key>OMNIGUARD_PATHS</key><string>${MONITORED_PATHS}</string>
    <key>OMNIGUARD_LOG_FILE</key><string>${LOG_DIR}/agent.log</string>
    <key>OMNIGUARD_PID_FILE</key><string>${HOME}/.omniguard/agent.pid</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict><key>Crashed</key><true/></dict>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key><string>${LOG_DIR}/agent.log</string>
  <key>StandardErrorPath</key><string>${LOG_DIR}/agent.err</string>
</dict>
</plist>
PLIST_EOF

  # Create symlink
  mkdir -p "${HOME}/.omniguard"
  ln -sfn "${INSTALL_DIR}/agent.env" "${HOME}/.omniguard/agent.env"

  # Load plist
  launchctl load -w "${PLIST_FILE}"
  sleep 2

  info ""
  info "✓ OmniGuard Agent installed (macOS launchd)"
  info "  Start:  launchctl start io.omniguard.agent"
  info "  Stop:   launchctl stop io.omniguard.agent"
  info "  Status: launchctl print system/io.omniguard.agent"
  info "  Logs:   tail -f ${LOG_DIR}/agent.log"

elif command -v systemctl >/dev/null 2>&1; then
  # Linux systemd
  SCRIPT_DIR_ABS="$(realpath "${SCRIPT_DIR}")"
  NODE_BIN="$(command -v node)"

  cat > /etc/systemd/system/omniguard-agent.service << UNIT_EOF
[Unit]
Description=OmniGuard Local Security Agent
Documentation=https://docs.omniguard.io/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${INSTALL_DIR}/agent.env
ExecStart=${NODE_BIN} ${AGENT_SCRIPT} --foreground
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=30
LimitNOFILE=65535
StandardOutput=append:${LOG_DIR}/agent.log
StandardError=append:${LOG_DIR}/agent.err
SyslogIdentifier=omniguard-agent

[Install]
WantedBy=multi-user.target
UNIT_EOF

  systemctl daemon-reload
  systemctl enable omniguard-agent
  systemctl restart omniguard-agent
  sleep 2

  info ""
  info "✓ OmniGuard Agent installed (systemd)"
  info "  Start:  sudo systemctl start omniguard-agent"
  info "  Stop:   sudo systemctl stop omniguard-agent"
  info "  Status: sudo systemctl status omniguard-agent"
  info "  Logs:   sudo journalctl -u omniguard-agent -f"
else
  err "Unsupported OS or no systemd/launchd found"
fi
