<#
.SYNOPSIS
    The "Soft Reset" Utility for Cloudscape Nexus v5.0 (Aether).

.DESCRIPTION
    Executes a rapid, Level-1 state purge. This resets the simulation environment 
    for a fresh run without destroying the core infrastructure.
    
    Actions:
    1. Terminates zombie Python/Streamlit processes safely.
    2. Executes standard Docker teardown (removes containers & volumes, KEEPS images).
    3. Purges Neo4j data, Redis state, and LocalStack mock APIs.
    4. Clears all Forensic Evidence and log files.
    5. Recursively obliterates Python bytecode caches (__pycache__).
    6. PRESERVES the .venv and .env files to ensure immediate fast-boot capability.

.PARAMETER Force
    Bypasses the safety confirmation prompt.

.EXAMPLE
    .\reset_environment.ps1
    .\reset_environment.ps1 -Force
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

# Target directories where contents (files/subfolders) will be purged
$TargetDataDirs = @(
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

# ==============================================================================
# 2. UI & BANNER
# ==============================================================================
Clear-Host
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "            CLOUDSCAPE NEXUS v5.0 AETHER - LEVEL-1 SOFT RESET                   " -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " STATUS: FAST RECOVERY MODE." -ForegroundColor Yellow
Write-Host " This script will rapidly purge state data while preserving infrastructure:" -ForegroundColor White
Write-Host "  [X] Wiping Neo4j Graph, Redis Cache, and LocalStack Data" -ForegroundColor Gray
Write-Host "  [X] Clearing Forensic Reports and System Logs" -ForegroundColor Gray
Write-Host "  [X] Scrubbing Python Bytecode (__pycache__)" -ForegroundColor Gray
Write-Host "  [!] PRESERVING: Python Virtual Environment (.venv)" -ForegroundColor Green
Write-Host "  [!] PRESERVING: Downloaded Docker Images" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# ==============================================================================
# 3. SAFETY GUARDRAILS
# ==============================================================================
if (-not $Force) {
    $Confirm = Read-Host "Proceed with Level-1 Soft Reset? (Y/N)"
    if ($Confirm -notmatch "^[Yy]$") { Write-Host "Aborted." -ForegroundColor Green; Exit 0 }
}

$StartTime = Get-Date
Write-Host "`n[START] Commencing Soft Teardown Sequence at $($StartTime.ToString('HH:mm:ss'))`n" -ForegroundColor Cyan

# ==============================================================================
# 4. PHASE 1: PROCESS MANAGEMENT
# ==============================================================================
Write-Host ">>> PHASE 1: Releasing File Locks & Zombie UI Threads..." -ForegroundColor Yellow
try {
    # Specifically target streamlit or python instances running from our directory
    $Zombies = Get-Process -Name "python", "streamlit" -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and $_.Path -match [regex]::Escape($ProjectRoot)
    }
    
    if ($Zombies) {
        foreach ($Process in $Zombies) {
            Write-Host "  [KILL] Terminating UI/Engine process: $($Process.Name) (PID: $($Process.Id))" -ForegroundColor DarkYellow
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "  [OK] No locked processes detected." -ForegroundColor Green
    }
} catch {
    Write-Host "  [WARN] Process hunting encountered an error, continuing: $_" -ForegroundColor DarkGray
}

# ==============================================================================
# 5. PHASE 2: DOCKER STATE PURGE (NON-DESTRUCTIVE TO IMAGES)
# ==============================================================================
Write-Host "`n>>> PHASE 2: Spinning Down Mesh & Purging Container Volumes..." -ForegroundColor Yellow
try {
    # -v destroys the volumes so Neo4j/Redis start blank. 
    # Notice we OMIT '--rmi local' so we don't have to re-download the 2GB Neo4j image.
    if (Get-Command "docker-compose" -ErrorAction SilentlyContinue) {
        docker-compose down -v --remove-orphans 2>&1 | Out-Null
    } else {
        docker compose down -v --remove-orphans 2>&1 | Out-Null
    }
    Write-Host "  [OK] Containers stopped and mounted data volumes destroyed." -ForegroundColor Green
} catch {
    Write-Host "  [FATAL] Docker teardown failed. Is Docker running? Error: $_" -ForegroundColor Red
}

# ==============================================================================
# 6. PHASE 3: TARGETED CACHE & DATA SCRUBBING
# ==============================================================================
Write-Host "`n>>> PHASE 3: Scrubbing Local Directories & Bytecode..." -ForegroundColor Yellow

foreach ($Dir in $TargetDataDirs) {
    if (Test-Path $Dir) {
        try {
            # Delete the CONTENTS of the folder, but leave the folder itself intact
            Remove-Item -Path "$Dir\*" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  [CLEARED] $Dir" -ForegroundColor DarkGray
        } catch {
            Write-Host "  [FAILED] Could not clear $Dir. A file may still be in use." -ForegroundColor Red
        }
    } else {
        # If the directory doesn't exist, create it so the next run doesn't crash
        New-Item -ItemType Directory -Force -Path $Dir | Out-Null
        Write-Host "  [CREATED] $Dir (Was missing)" -ForegroundColor DarkGray
    }
}

# Scrub all Python __pycache__ folders recursively
$PyCacheDirs = Get-ChildItem -Path $ProjectRoot -Filter "__pycache__" -Recurse -Directory -ErrorAction SilentlyContinue
foreach ($Cache in $PyCacheDirs) {
    Remove-Item -Path $Cache.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "  [OK] Python Bytecode cache eradicated." -ForegroundColor Green

# ==============================================================================
# 7. COMPLETION
# ==============================================================================
$EndTime = Get-Date
$Duration = New-TimeSpan -Start $StartTime -End $EndTime

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host " LEVEL-1 RESET COMPLETE." -ForegroundColor Green
Write-Host " The simulation state has been zeroed out in $($Duration.TotalSeconds) seconds." -ForegroundColor Cyan
Write-Host " Your virtual environment (.venv) and Docker images remain intact." -ForegroundColor White
Write-Host " Run 'utils\launch_cloudscape.ps1' to ignite a fresh simulation." -ForegroundColor Yellow
Write-Host "================================================================================`n" -ForegroundColor Cyan