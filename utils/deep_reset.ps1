<#
.SYNOPSIS
    The "Nuclear" Deep Reset Utility for Cloudscape Nexus v5.0 (Aether).

.DESCRIPTION
    Executes a catastrophic teardown of the entire Cloudscape environment.
    Upgraded for v5.0 to handle background Streamlit processes, massive 
    synthetic data caches, and GZipped forensic matrices.
    
    Phases:
    1. Terminate zombie Python/Java/Streamlit processes holding file locks.
    2. Destroy the .venv (Virtual Environment) completely.
    3. Force removal of all local Docker images built for this project.
    4. Execute a Docker system prune to wipe orphaned networks/volumes.
    5. Obliterate all persistent local data directories and forensic evidence.

.PARAMETER Force
    Bypasses the multi-stage safety confirmation prompts.

.EXAMPLE
    .\deep_reset.ps1
    .\deep_reset.ps1 -Force
#>

[CmdletBinding()]
param (
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# ==============================================================================
# 1. DYNAMIC PATH RESOLUTION
# ==============================================================================
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location -Path $ProjectRoot

# Directories slated for total physical destruction (Expanded for v5.0)
$DestructivePaths = @(
    "$ProjectRoot\volume",
    "$ProjectRoot\logs",
    "$ProjectRoot\forensics",
    "$ProjectRoot\.venv",
    "$ProjectRoot\.pytest_cache"
)

# ==============================================================================
# 2. UI & BANNER
# ==============================================================================
Clear-Host
Write-Host "================================================================================" -ForegroundColor DarkRed
Write-Host "             CLOUDSCAPE NEXUS v5.0 AETHER - NUCLEAR DEEP RESET                  " -ForegroundColor White -BackgroundColor DarkRed
Write-Host "================================================================================" -ForegroundColor DarkRed
Write-Host " WARNING: THIS IS THE LEVEL-0 WIPE PROTOCOL." -ForegroundColor Red
Write-Host " This script will permanently obliterate:" -ForegroundColor Yellow
Write-Host "  [X] The entire Python Virtual Environment (.venv)" -ForegroundColor Gray
Write-Host "  [X] All downloaded Docker images and custom networks" -ForegroundColor Gray
Write-Host "  [X] All LocalStack, Neo4j, Redis, and Azurite databases" -ForegroundColor Gray
Write-Host "  [X] All Forensic Evidence, GZipped Matrices, and Graph Snapshots" -ForegroundColor Gray
Write-Host "  [X] Any zombie processes (including Streamlit UIs) lingering in memory" -ForegroundColor Gray
Write-Host "================================================================================" -ForegroundColor DarkRed
Write-Host ""

# ==============================================================================
# 3. SAFETY GUARDRAILS (DOUBLE CONFIRMATION)
# ==============================================================================
if (-not $Force) {
    $Confirm1 = Read-Host "Are you absolutely sure you want to trigger a nuclear reset? (Y/N)"
    if ($Confirm1 -notmatch "^[Yy]$") { Write-Host "Aborted." -ForegroundColor Green; Exit 0 }
    
    $Confirm2 = Read-Host "Type 'DESTROY' to confirm total obliteration of the environment"
    if ($Confirm2 -cne "DESTROY") { Write-Host "Aborted. Authorization string mismatch." -ForegroundColor Green; Exit 0 }
} else {
    Write-Host "[!] -Force flag authorized. Safety protocols bypassed." -ForegroundColor DarkYellow
}

$StartTime = Get-Date
Write-Host "`n[START] Commencing Deep Teardown Sequence at $($StartTime.ToString('HH:mm:ss'))`n" -ForegroundColor Cyan

# ==============================================================================
# 4. PHASE 1: ZOMBIE PROCESS TERMINATION
# ==============================================================================
Write-Host ">>> PHASE 1: Hunting zombie processes holding file locks..." -ForegroundColor Yellow
try {
    # Find python, java (Neo4j JVM), or streamlit processes running from our project folder
    $Zombies = Get-Process -Name "python", "java", "redis-server", "streamlit" -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and $_.Path -match [regex]::Escape($ProjectRoot)
    }
    
    if ($Zombies) {
        foreach ($Process in $Zombies) {
            Write-Host "  [KILL] Terminating orphaned process: $($Process.Name) (PID: $($Process.Id))" -ForegroundColor DarkYellow
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "  [OK] No orphaned host processes detected." -ForegroundColor Green
    }
} catch {
    Write-Host "  [WARN] Process hunting encountered an error, continuing: $_" -ForegroundColor DarkGray
}

# ==============================================================================
# 5. PHASE 2: DOCKER NUCLEAR TEARDOWN
# ==============================================================================
Write-Host "`n>>> PHASE 2: Executing Docker Image & Network Purge..." -ForegroundColor Yellow
try {
    # Spin down and remove volumes AND local images created by this compose file
    if (Get-Command "docker-compose" -ErrorAction SilentlyContinue) {
        docker-compose down -v --rmi local --remove-orphans 2>&1 | Out-Null
    } else {
        docker compose down -v --rmi local --remove-orphans 2>&1 | Out-Null
    }
    Write-Host "  [OK] Project containers, networks, and images destroyed." -ForegroundColor Green

    # Force prune dangling volumes to ensure no orphaned database disks remain
    Write-Host "  [*] Executing deep system volume prune..." -ForegroundColor DarkGray
    docker volume prune -f 2>&1 | Out-Null
    Write-Host "  [OK] Docker daemon completely sanitized." -ForegroundColor Green
} catch {
    Write-Host "  [FATAL] Docker teardown failed. Is Docker running? Error: $_" -ForegroundColor Red
}

# ==============================================================================
# 6. PHASE 3: SCORCHED EARTH FILE WIPE
# ==============================================================================
Write-Host "`n>>> PHASE 3: Obliterating Physical Data Directories & .venv..." -ForegroundColor Yellow

foreach ($Path in $DestructivePaths) {
    if (Test-Path $Path) {
        try {
            # Total removal of the directory itself
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            Write-Host "  [DESTROYED] $Path" -ForegroundColor DarkGray
        } catch {
            Write-Host "  [FAILED] Could not delete $Path. A hidden process may still be holding a lock." -ForegroundColor Red
        }
    } else {
        Write-Host "  [SKIPPED] Already absent: $Path" -ForegroundColor DarkGray
    }
}

# Scrub all Python __pycache__ folders recursively
$PyCacheDirs = Get-ChildItem -Path $ProjectRoot -Filter "__pycache__" -Recurse -Directory -ErrorAction SilentlyContinue
foreach ($Cache in $PyCacheDirs) {
    Remove-Item -Path $Cache.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "  [OK] Python Bytecode cache eradicated." -ForegroundColor Green

# ==============================================================================
# 7. PHASE 4: DIRECTORY BASELINE RECONSTRUCTION
# ==============================================================================
Write-Host "`n>>> PHASE 4: Reconstructing empty environment baseline..." -ForegroundColor Yellow

# Rebuild directories including the new Aether structures
$BaselineDirs = @(
    "$ProjectRoot\volume\neo4j_data",
    "$ProjectRoot\volume\neo4j_logs",
    "$ProjectRoot\volume\neo4j_import",
    "$ProjectRoot\volume\neo4j_plugins",
    "$ProjectRoot\volume\redis_data",
    "$ProjectRoot\volume\localstack",
    "$ProjectRoot\volume\azure_data",
    "$ProjectRoot\logs",
    "$ProjectRoot\forensics\reports",
    "$ProjectRoot\forensics\graph_snapshots"
)

foreach ($Dir in $BaselineDirs) {
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
}
Write-Host "  [OK] Clean directory structure successfully rebuilt." -ForegroundColor Green

# ==============================================================================
# 8. COMPLETION
# ==============================================================================
$EndTime = Get-Date
$Duration = New-TimeSpan -Start $StartTime -End $EndTime

Write-Host "`n================================================================================" -ForegroundColor DarkRed
Write-Host " NUCLEAR RESET COMPLETE." -ForegroundColor Green
Write-Host " The system has been restored to a Level-0 state in $($Duration.TotalSeconds) seconds." -ForegroundColor Cyan
Write-Host " You must now use 'utils\launch_cloudscape.ps1' to perform a complete cold boot." -ForegroundColor White
Write-Host "================================================================================`n" -ForegroundColor DarkRed