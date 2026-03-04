<#
.SYNOPSIS
    Enterprise Ignition Sequence for Cloudscape Nexus v5.0 (Aether).

.DESCRIPTION
    Orchestrates the complete multi-tier startup process:
    1. Validates the .env configuration and Docker daemon state.
    2. Initializes the Docker Compose infrastructure mesh.
    3. Executes asynchronous TCP health polling on core databases.
    4. Validates and activates the Python 64-bit Virtual Environment.
    5. Spawns the Aether Visualization Dashboard (Streamlit) as a background job.
    6. Triggers the Global Master Orchestrator (main.py).

.EXAMPLE
    .\launch_cloudscape.ps1
#>

[CmdletBinding()]
param ()

$ErrorActionPreference = 'Stop'

# ==============================================================================
# 1. DYNAMIC PATH RESOLUTION & ENVIRONMENT SETUP
# ==============================================================================
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location -Path $ProjectRoot

# Ensure Python knows where the root module is for imports
$env:PYTHONPATH = $ProjectRoot

Clear-Host
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "               CLOUDSCAPE NEXUS 5.0 AETHER - IGNITION SEQUENCE                  " -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# ==============================================================================
# 2. PRE-FLIGHT DIAGNOSTICS
# ==============================================================================
Write-Host "[*] Executing Pre-Flight Diagnostics..." -ForegroundColor Yellow

if (-not (Test-Path "$ProjectRoot\.env")) {
        Write-Host "[!] CRITICAL: .env file is missing." -ForegroundColor Red
        exit 1
    }

# Optimized Check: Only fail if the command actually returns a non-zero exit code
docker version > $null 2>&1
if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] CRITICAL: Docker Daemon is not responding to CLI requests." -ForegroundColor Red
        Write-Host "    Check Docker Desktop UI for 'Engine Stopped' status." -ForegroundColor Yellow
        exit 1
    } else {
        Write-Host "  [OK] Docker Daemon is responsive." -ForegroundColor Green
}

# ==============================================================================
# 3. INFRASTRUCTURE MESH IGNITION
# ==============================================================================
Write-Host "`n[*] Igniting Multi-Cloud Infrastructure Mesh..." -ForegroundColor Yellow

try {
    # Check if user has docker-compose plugin or standalone binary
    if (Get-Command "docker-compose" -ErrorAction SilentlyContinue) {
        docker-compose up -d
    } else {
        docker compose up -d
    }
    Write-Host "  [OK] Docker Compose sequence executed successfully." -ForegroundColor Green
} catch {
    Write-Host "[!] CRITICAL: Failed to launch Docker containers: $_" -ForegroundColor Red
    exit 1
}

# ==============================================================================
# 4. ASYNCHRONOUS TCP HEALTH POLLING
# ==============================================================================
Write-Host "`n[*] Commencing TCP Health Polling on Core Subsystems..." -ForegroundColor Yellow

$Services = @(
    [pscustomobject]@{Name="Neo4j Enterprise GDS"; Port=7687},
    [pscustomobject]@{Name="Redis State Cache"; Port=6379},
    [pscustomobject]@{Name="LocalStack Gateway"; Port=4566}
)

$MaxWaitSeconds = 60
$WaitInterval = 3

foreach ($Service in $Services) {
    $IsReady = $false
    $Elapsed = 0

    Write-Host "  -> Polling $($Service.Name) on port $($Service.Port)..." -NoNewline
    
    while ($Elapsed -lt $MaxWaitSeconds) {
        # Test TCP connection silently
        $Test = Test-NetConnection -ComputerName "localhost" -Port $Service.Port -WarningAction SilentlyContinue -InformationAction SilentlyContinue
        
        if ($Test.TcpTestSucceeded) {
            $IsReady = $true
            Write-Host " [ONLINE]" -ForegroundColor Green
            break
        }
        
        Start-Sleep -Seconds $WaitInterval
        $Elapsed += $WaitInterval
        Write-Host "." -NoNewline
    }

    if (-not $IsReady) {
        Write-Host "`n[!] CRITICAL: $($Service.Name) failed to bind to port $($Service.Port) within $MaxWaitSeconds seconds." -ForegroundColor Red
        Write-Host "    Check Docker logs for crash details. Aborting ignition." -ForegroundColor Red
        exit 1
    }
}

# ==============================================================================
# 5. VIRTUAL ENVIRONMENT ACTIVATION
# ==============================================================================
Write-Host "`n[*] Validating Python Virtual Environment..." -ForegroundColor Yellow
$VenvPython = "$ProjectRoot\.venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "  [!] Virtual environment not found. Initiating first-time build..." -ForegroundColor DarkYellow
    try {
        python -m venv "$ProjectRoot\.venv"
        & $VenvPython -m pip install --upgrade pip
        & $VenvPython -m pip install -r "$ProjectRoot\requirements.txt"
        Write-Host "  [OK] Virtual environment built and dependencies installed." -ForegroundColor Green
    } catch {
        Write-Host "[!] CRITICAL: Failed to build Python virtual environment: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  [OK] Virtual environment verified." -ForegroundColor Green
}

# ==============================================================================
# 6. AETHER DASHBOARD SPAWN (BACKGROUND PROCESS)
# ==============================================================================
Write-Host "`n[*] Spawning Aether Visualization Dashboard..." -ForegroundColor Yellow
try {
    # We launch Streamlit via the venv's python executable in a background/minimized process 
    # so it does not block the terminal from running the master orchestrator.
    $DashboardArgs = "-m streamlit run dashboard/app.py --server.port=8501 --server.headless=true"
    Start-Process -FilePath $VenvPython -ArgumentList $DashboardArgs -WindowStyle Minimized
    
    Write-Host "  [OK] Dashboard process dispatched to port 8501." -ForegroundColor Green
    Write-Host "  [i] You can view the UI at: http://localhost:8501 (Once scan completes)" -ForegroundColor Cyan
} catch {
    Write-Host "  [!] WARNING: Failed to spawn Dashboard background process. You may need to run it manually. Error: $_" -ForegroundColor DarkYellow
}

# ==============================================================================
# 7. MASTER ORCHESTRATOR IGNITION
# ==============================================================================
Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host " IGNITING GLOBAL ORCHESTRATOR SCAN SEQUENCE..." -ForegroundColor White
Write-Host "================================================================================`n" -ForegroundColor Cyan

try {
    # Execute the main Python engine directly using the venv executable
    & $VenvPython main.py --scan
} catch {
    Write-Host "`n[!] CRITICAL: Orchestrator execution failed: $_" -ForegroundColor Red
}

Write-Host "`n Cloudscape Nexus Sequence Concluded." -ForegroundColor Green