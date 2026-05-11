# VANT-Agent Builder
# Builds VANT-Agent-Setup.exe (GUI installer wizard with embedded agent)

$RootDir = Split-Path $PSScriptRoot -Parent
$DistDir = Join-Path $RootDir "dist"
$VenvPython = "C:\Users\SysAdmin\Documents\develop\venv-schrodinger\Scripts\python.exe"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  VANT-Agent Builder v1.1.0" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# --- Step 1: Check Python ---
Write-Host "[1/5] Checking Python..." -ForegroundColor Yellow
if (Test-Path $VenvPython) {
    $PythonExe = $VenvPython
    Write-Host "  Venv Python: $PythonExe" -ForegroundColor Green
} else {
    $PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $PythonExe) { $PythonExe = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
    if (-not $PythonExe) {
        Write-Host "  ERROR: Python not found" -ForegroundColor Red
        exit 1
    }
    Write-Host "  System Python: $PythonExe" -ForegroundColor Yellow
}
$PyVer = & $PythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "  Version: $PyVer" -ForegroundColor Green

# --- Step 2: Install dependencies ---
Write-Host "`n[2/5] Installing dependencies..." -ForegroundColor Yellow
& $PythonExe -m pip install -q pyinstaller pyyaml requests PyQt6
Write-Host "  Done" -ForegroundColor Green

# --- Step 3: Clean ---
Write-Host "`n[3/5] Cleaning previous builds..." -ForegroundColor Yellow
foreach ($d in @("build", "build-setup")) {
    $p = Join-Path $RootDir $d
    if (Test-Path $p) {
        Remove-Item $p -Recurse -Force
        Write-Host "  Removed: $d/" -ForegroundColor Gray
    }
}
Get-ChildItem $RootDir -Filter "*.spec" | Remove-Item -Force
Get-ChildItem $RootDir -Filter "*.spec" -Recurse | Remove-Item -Force
Remove-Item -Path "$DistDir\VANT-Agent-Setup.exe" -Force -ErrorAction SilentlyContinue
Write-Host "  Done" -ForegroundColor Green

# --- Step 4: Build VANT-Agent.exe (intermediate) ---
Write-Host "`n[4/5] Building VANT-Agent component..." -ForegroundColor Yellow

$AgentBuildDir = Join-Path $RootDir "build-agent"
$AgentDistDir = Join-Path $RootDir "dist-agent"

Set-Location $RootDir

& $PythonExe -m PyInstaller `
    --name VANT-Agent `
    --onefile `
    --windowed `
    --icon vant.ico `
    --clean `
    --distpath $AgentDistDir `
    --workpath $AgentBuildDir `
    --add-data "config.example.yaml;." `
    --hidden-import yaml `
    --hidden-import requests `
    --hidden-import vant `
    --hidden-import vant.main `
    --hidden-import vant.modules.inventory.collector `
    --hidden-import vant.modules.inventory.service `
    --hidden-import vant.modules.heartbeat.service `
    --hidden-import vant.modules.collectors.file_log `
    --hidden-import vant.modules.collectors.windows_eventlog `
    --hidden-import vant.modules.collectors.postgres_log `
    --hidden-import vant.modules.collectors.suricata `
    --hidden-import vant.modules.collectors.snort `
    --hidden-import vant.modules.dlp.aegis `
    --hidden-import jaraco.text `
    --hidden-import jaraco.functools `
    --hidden-import jaraco.context `
    --exclude-module pytest `
    run.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Agent component build failed" -ForegroundColor Red
    exit 1
}

$AgentExe = Join-Path $AgentDistDir "VANT-Agent.exe"
if (-not (Test-Path $AgentExe)) {
    Write-Host "  ERROR: VANT-Agent.exe not found" -ForegroundColor Red
    exit 1
}

$AgentSizeMB = [math]::Round((Get-Item $AgentExe).Length / 1MB, 1)
Write-Host "  Agent component built ($AgentSizeMB MB)" -ForegroundColor Green

# --- Step 5: Build VANT-Agent-Setup.exe (final installer) ---
Write-Host "`n[5/5] Building VANT-Agent-Setup.exe..." -ForegroundColor Yellow

$InstallerScript = Join-Path (Join-Path $RootDir "installer") "agent_installer.py"
$Logo = Join-Path $RootDir "windows\package\staticfiles\img\logo.png"

& $PythonExe -m PyInstaller `
    --name VANT-Agent-Setup `
    --onefile `
    --windowed `
    --icon vant.ico `
    --clean `
    --distpath $DistDir `
    --workpath build-setup `
    --add-data "$AgentExe;." `
    --add-data "$Logo;." `
    --hidden-import yaml `
    --hidden-import requests `
    --exclude-module pytest `
    --exclude-module setuptools `
    $InstallerScript

if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Installer build failed" -ForegroundColor Red
    exit 1
}

$SetupExe = Join-Path $DistDir "VANT-Agent-Setup.exe"
if (-not (Test-Path $SetupExe)) {
    Write-Host "  ERROR: VANT-Agent-Setup.exe not found" -ForegroundColor Red
    exit 1
}

# Clean up intermediate agent build artifacts
Remove-Item $AgentBuildDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $AgentDistDir -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem $RootDir -Filter "*.spec" | Remove-Item -Force

$SetupSizeMB = [math]::Round((Get-Item $SetupExe).Length / 1MB, 1)

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Build Complete!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  VANT-Agent-Setup.exe ($SetupSizeMB MB)" -ForegroundColor White
Write-Host "  Location: $SetupExe" -ForegroundColor White
