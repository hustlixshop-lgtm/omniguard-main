# OmniGuard One-Command Deploy (Windows PowerShell)
# Usage: $env:VITE_SUPABASE_URL="https://xyz.supabase.co"; $env:VITE_SUPABASE_ANON_KEY="eyJ..."; .\deploy-windows.ps1

param(
    [string]$Port = "80",
    [string]$Domain = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Status($msg) { Write-Host "[OmniGuard] $msg" -ForegroundColor Green }
function Write-Warn($msg)   { Write-Host "[OmniGuard] $msg" -ForegroundColor Yellow }
function Write-Err($msg)    { Write-Host "[OmniGuard] ERROR: $msg" -ForegroundColor Red; exit 1 }

if (-not $env:VITE_SUPABASE_URL) { Write-Err "VITE_SUPABASE_URL not set" }
if (-not $env:VITE_SUPABASE_ANON_KEY) { Write-Err "VITE_SUPABASE_ANON_KEY not set" }

# Check Docker
try { docker --version | Out-Null } catch { Write-Err "Docker Desktop not found. Install from https://docker.com/desktop" }

Write-Status "Starting OmniGuard deployment..."

# Write compose file
$compose = @"
version: '3.9'
services:
  omniguard:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        VITE_SUPABASE_URL: $env:VITE_SUPABASE_URL
        VITE_SUPABASE_ANON_KEY: $env:VITE_SUPABASE_ANON_KEY
    ports:
      - "${Port}:80"
    restart: unless-stopped
"@
$compose | Set-Content docker-compose.prod.yml

Write-Status "Building Docker image..."
docker compose -f docker-compose.prod.yml build --no-cache

Write-Status "Starting container..."
docker compose -f docker-compose.prod.yml up -d

Write-Status "Waiting for health check..."
$retries = 0
do {
    Start-Sleep 2; $retries++
    try { $r = Invoke-WebRequest -Uri "http://localhost:$Port/health" -UseBasicParsing -TimeoutSec 3; break } catch { }
} while ($retries -lt 30)
if ($retries -ge 30) { Write-Err "Health check failed" }

Write-Status ""
Write-Status "✓ OmniGuard deployed!"
Write-Status "  Dashboard: http://localhost:$Port"
Write-Status "  Health:    http://localhost:$Port/health"
Write-Status ""
Write-Status "Next: open the dashboard, create an account, add your Anthropic key in Settings."
