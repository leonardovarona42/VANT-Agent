# VANT-Agent Windows Installer Builder
# Requires: PyInstaller, Inno Setup 6.x

$ErrorActionPreference = "Stop"

$RootDir = Split-Path $PSScriptRoot -Parent
$DistDir = Join-Path $RootDir "dist"
$InstallerDir = Join-Path $DistDir "installer"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  VANT-Agent Installer Builder" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Python
Write-Host "[1/4] Checking Python..." -ForegroundColor Yellow
$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    $PythonExe = (Get-Command python3 -ErrorAction SilentlyContinue).Source
}
if (-not $PythonExe) {
    Write-Host "ERROR: Python not found" -ForegroundColor Red
    exit 1
}
Write-Host "  Python: $PythonExe" -ForegroundColor Green

# Step 2: Install dependencies
Write-Host "`n[2/4] Installing dependencies..." -ForegroundColor Yellow
& $PythonExe -m pip install -q pyinstaller pyyaml requests

# Step 3: Build executable
Write-Host "`n[3/4] Building VANT-Agent executable..." -ForegroundColor Yellow
if (Test-Path (Join-Path $DistDir "VANT-Agent.exe")) {
    Remove-Item (Join-Path $DistDir "VANT-Agent.exe") -Force
}

$BuildCmd = @(
    $PythonExe, "-m", "PyInstaller",
    "--name", "VANT-Agent",
    "--onefile",
    "--console",
    "--clean",
    "--add-data", "config.example.yaml;.",
    "--hidden-import", "yaml",
    "--hidden-import", "requests",
    "--exclude-module", "pytest",
    "--exclude-module", "setuptools",
    "-m", "vant.main"
)

$BuildResult = & $PythonExe @BuildCmd 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  VANT-Agent.exe built successfully" -ForegroundColor Green
} else {
    Write-Host "  ERROR: Build failed" -ForegroundColor Red
    Write-Host $BuildResult
    exit 1
}

# Step 4: Build Inno Setup installer
Write-Host "`n[4/4] Building installer..." -ForegroundColor Yellow

$InnoPath = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $InnoPath)) {
    $InnoPath = "C:\Program Files\Inno Setup 6\ISCC.exe"
}

if (Test-Path $InnoPath) {
    $IssFile = Join-Path $RootDir "installer\vant_agent.iss"
    Write-Host "  Inno Setup: $InnoPath" -ForegroundColor Green
    Write-Host "  Compiling installer..."

    $CompileResult = & $InnoPath $IssFile 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Installer built successfully!" -ForegroundColor Green

        # Find the output
        $SetupExe = Get-ChildItem $InstallerDir -Filter "VANT-Agent-Setup-*.exe" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($SetupExe) {
            Write-Host "  Output: $($SetupExe.FullName)" -ForegroundColor Cyan
        }
    } else {
        Write-Host "  ERROR: Inno Setup compilation failed" -ForegroundColor Red
        Write-Host $CompileResult
    }
} else {
    Write-Host "  WARNING: Inno Setup 6 not found at $InnoPath" -ForegroundColor Yellow
    Write-Host "  Install from https://jrsoftware.org/isdl.php" -ForegroundColor Yellow
    Write-Host "  Executable is ready at: $(Join-Path $DistDir 'VANT-Agent.exe')" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Build Complete!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Files:" -ForegroundColor White
Write-Host "  Executable: $(Join-Path $DistDir 'VANT-Agent.exe')" -ForegroundColor Gray
if (Test-Path (Join-Path $DistDir "VANT-Agent.exe")) {
    $Size = (Get-Item (Join-Path $DistDir "VANT-Agent.exe")).Length / 1MB
    Write-Host "  Size: $([math]::Round($Size, 1)) MB" -ForegroundColor Gray
}
Write-Host ""
