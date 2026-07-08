# OmniGuard Agent Windows Service Installer
# Run as Administrator: Set-ExecutionPolicy Bypass -Scope Process; .\install-service.ps1

param(
    [string]$Action = "install",
    [string]$InstallPath = "E:\\OmniGuard-Install",
    [string]$NodePath = "node.exe",
    [string]$SupabaseUrl = $env:OMNIGUARD_URL,
    [string]$SupabaseKey = $env:OMNIGUARD_API_KEY
)

$ErrorActionPreference = "Stop"
$ServiceName = "OmniGuardAgent"
$ServiceDisplayName = "OmniGuard Security Agent"

function Write-Status($msg) { Write-Host "[OmniGuard] $msg" -ForegroundColor Green }
function Write-Err($msg)    { Write-Host "[OmniGuard] ERROR: $msg" -ForegroundColor Red; exit 1 }

# Check Administrator
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$prin = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "This script must be run as Administrator"
}

# Main install
if ($Action -eq "install") {
    if (-not $SupabaseUrl -or -not $SupabaseKey) {
        Write-Err "Set OMNIGUARD_URL and OMNIGUARD_API_KEY environment variables or pass as parameters"
    }

    Write-Status "Installing OmniGuard Agent..."

    # Create install directory
    if (-not (Test-Path $InstallPath)) {
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path "$InstallPath\agent")) {
        New-Item -Path "$InstallPath\agent" -ItemType Directory -Force | Out-Null
    }

    # Copy agent script
    $agentPath = "$InstallPath\agent\omniguard-agent.js"
    Copy-Item -Path "$PSScriptRoot\omniguard-agent.js" -Destination $agentPath -Force

    # Create config
    $configContent = @"
OMNIGUARD_URL=$SupabaseUrl
OMNIGUARD_API_KEY=$SupabaseKey
OMNIGUARD_WORKER_ID=agent-$($env:COMPUTERNAME.ToLower())
OMNIGUARD_HEARTBEAT_INTERVAL=60000
OMNIGUARD_SCAN_INTERVAL=300000
OMNIGUARD_PATHS=C:\Repos;C:\Projects
OMNIGUARD_LOG_LEVEL=info
OMNIGUARD_PID_FILE=$InstallPath\agent.pid
OMNIGUARD_LOG_FILE=$InstallPath\agent.log
"@
    $configContent | Out-File -FilePath "$InstallPath\agent.env" -Encoding ascii

    # Create NSSM service (NSSM is recommended for Node.js services)
    $nssmPath = "$InstallPath\nssm.exe"
    if (-not (Get-Command nssm -ErrorAction SilentlyContinue) -and -not (Test-Path $nssmPath)) {
        Write-Status "Downloading NSSM (Non-Sucking Service Manager)..."
        $nssmUrl = "https://nssm.cc/ci/nssm-2.25-103-gdee932d.zip"
        Invoke-WebRequest -Uri $nssmUrl -OutFile "$InstallPath\nssm.zip" -UseBasicParsing
        Expand-Archive -Path "$InstallPath\nssm.zip" -DestinationPath "$InstallPath\nssm-temp" -Force
        Copy-Item -Path "$InstallPath\nssm-temp\nssm-2.25-103-gdee932d\win64\nssm.exe" -Destination $nssmPath -Force
        Remove-Item -Path "$InstallPath\nssm-temp" -Recurse -Force
        Remove-Item -Path "$InstallPath\nssm.zip" -Force
    }

    # Remove existing service if present
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Status "Removing existing service..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & $nssmPath remove $ServiceName confirm
    }

    # Install service with NSSM
    Write-Status "Creating Windows Service..."
    & $nssmPath install $ServiceName $NodePath "`"$agentPath`""
    & $nssmPath set $ServiceName AppDirectory "$InstallPath"
    & $nssmPath set $ServiceName DisplayName $ServiceDisplayName
    & $nssmPath set $ServiceName Description "OmniGuard Security Agent - Monitors repositories for security issues"
    & $nssmPath set $ServiceName Start SERVICE_AUTO_START
    & $nssmPath set $ServiceName AppStdout "$InstallPath\service.log"
    & $nssmPath set $ServiceName AppStderr "$InstallPath\error.log"
    & $nssmPath set $ServiceName AppRotateFiles 1
    & $nssmPath set $ServiceName AppRotateBytes 1048576

    # Start service
    Write-Status "Starting service..."
    Start-Service -Name $ServiceName

    Write-Status ""
    Write-Status "OmniGuard Agent installed successfully!"
    Write-Status "  Service: $ServiceName"
    Write-Status "  Logs: $InstallPath\agent.log"
    Write-Status ""
    Write-Status "Commands:"
    Write-Status "  Start:   Start-Service $ServiceName"
    Write-Status "  Stop:    Stop-Service $ServiceName"
    Write-Status "  Status:  Get-Service $ServiceName"
    Write-Status "  Logs:    Get-Content -Tail 100 '$InstallPath\agent.log'"
}

elseif ($Action -eq "uninstall") {
    Write-Status "Uninstalling OmniGuard Agent..."

    $nssmPath = "$InstallPath\nssm.exe"
    if (Test-Path $nssmPath) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & $nssmPath remove $ServiceName confirm
    }

    Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction SilentlyContinue

    Write-Status "OmniGuard Agent uninstalled."
}

else {
    Write-Err "Unknown action: $Action. Use 'install' or 'uninstall'"
}
