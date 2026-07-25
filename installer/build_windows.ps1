# VANT-Agent Windows Installer Builder
# Produces: dist/installer/VANT-Agent-Setup-<version>.exe  (Inno Setup)
#           dist/installer/VANT-Agent-<version>.zip        (ZIP distribution)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path $PSScriptRoot -Parent
$DistDir = Join-Path $RootDir "dist"
$InstallerOutDir = Join-Path $DistDir "installer"
$Version = "1.1.0"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  VANT-Agent Windows Installer Builder v$Version" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# --- Step 1: Find Python ---
Write-Host "[1/4] Checking Python..." -ForegroundColor Yellow
$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) { $PythonExe = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
if (-not $PythonExe) {
    Write-Host "  ERROR: Python not found" -ForegroundColor Red
    exit 1
}
$PyVer = & $PythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "  Python $PyVer : $PythonExe" -ForegroundColor Green

# --- Step 2: Download wheels for offline install ---
Write-Host "`n[2/4] Downloading Python wheels..." -ForegroundColor Yellow
$WheelDir = Join-Path $RootDir "installer\wheels"
if (-not (Test-Path $WheelDir)) {
    New-Item -ItemType Directory -Path $WheelDir -Force | Out-Null
}
$Wheels = @("PyYAML", "requests", "urllib3", "certifi", "charset-normalizer", "idna")
& $PythonExe -m pip download --only-binary=:all: --dest $WheelDir $Wheels 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    $WheelCount = (Get-ChildItem "$WheelDir\*.whl").Count
    Write-Host "  $WheelCount wheels downloaded to: $WheelDir" -ForegroundColor Green
} else {
    Write-Host "  Warning: pip download failed (wheels will be fetched at install time)" -ForegroundColor Yellow
}

# --- Step 3: Create ZIP distribution ---
Write-Host "`n[3/4] Creating ZIP distribution..." -ForegroundColor Yellow

$ZipDir = Join-Path $RootDir "build\windows-zip"
if (Test-Path $ZipDir) { Remove-Item $ZipDir -Recurse -Force }
New-Item -ItemType Directory -Path $ZipDir -Force | Out-Null

# Copy core files
Copy-Item (Join-Path $RootDir "agent.py")           $ZipDir
Copy-Item (Join-Path $RootDir "output.py")          $ZipDir
Copy-Item (Join-Path $RootDir "agent_tray.py")      $ZipDir

# Collectors
$CollectorsDir = Join-Path $ZipDir "collectors"
New-Item -ItemType Directory -Path $CollectorsDir -Force | Out-Null
Get-ChildItem (Join-Path $RootDir "collectors\*.py") | Copy-Item -Destination $CollectorsDir

# Services
$ServicesDir = Join-Path $ZipDir "services"
New-Item -ItemType Directory -Path $ServicesDir -Force | Out-Null
Get-ChildItem (Join-Path $RootDir "services\*.py") | Copy-Item -Destination $ServicesDir

# Scripts
Copy-Item (Join-Path $RootDir "linux\common\agent_installer_cli.py") $ZipDir
Copy-Item (Join-Path $RootDir "linux\common\agent_tools.py")         $ZipDir

# Config templates
$ConfigSrc = Join-Path $RootDir "config.template.yaml"
if (-not (Test-Path $ConfigSrc)) { $ConfigSrc = Join-Path $RootDir "config.example.yaml" }
if (Test-Path $ConfigSrc) { Copy-Item $ConfigSrc (Join-Path $ZipDir "config.template.yaml") }

# Requirements and setup
Copy-Item (Join-Path $RootDir "requirements.txt")   $ZipDir
Copy-Item (Join-Path $RootDir "installer\setup.bat") $ZipDir

# Wheels
if ((Get-ChildItem $WheelDir\*.whl -ErrorAction SilentlyContinue).Count -gt 0) {
    $WheelsZipDir = Join-Path $ZipDir "wheels"
    New-Item -ItemType Directory -Path $WheelsZipDir -Force | Out-Null
    Copy-Item "$WheelDir\*.whl" $WheelsZipDir
}

# Create ZIP
if (-not (Test-Path $InstallerOutDir)) {
    New-Item -ItemType Directory -Path $InstallerOutDir -Force | Out-Null
}
$ZipPath = Join-Path $InstallerOutDir "VANT-Agent-$Version.zip"
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($ZipDir, $ZipPath)

$ZipSizeMB = [math]::Round((Get-Item $ZipPath).Length / 1MB, 1)
Write-Host "  ZIP created: $ZipPath ($ZipSizeMB MB)" -ForegroundColor Green

# Clean build dir
Remove-Item $ZipDir -Recurse -Force

# --- Step 4: Check for Inno Setup ---
Write-Host "`n[4/4] Inno Setup..." -ForegroundColor Yellow
$ISCC = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
if (-not $ISCC) {
    $ISCCPaths = @(
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 5\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 5\ISCC.exe"
    )
    foreach ($p in $ISCCPaths) {
        if (Test-Path $p) { $ISCC = $p; break }
    }
}
if ($ISCC) {
    Write-Host "  Inno Setup found: $ISCC" -ForegroundColor Green
    $IssPath = Join-Path $RootDir "installer\vant_agent.iss"
    $SetupExe = Join-Path $InstallerOutDir "VANT-Agent-Setup-$Version.exe"
    Write-Host "  Compiling installer..." -ForegroundColor Yellow
    & $ISCC $IssPath
    if (Test-Path $SetupExe) {
        $SetupSizeMB = [math]::Round((Get-Item $SetupExe).Length / 1MB, 1)
        Write-Host "  Installer EXE created: $SetupExe ($SetupSizeMB MB)" -ForegroundColor Green
    } else {
        Write-Host "  Warning: Inno Setup compilation may have failed" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Inno Setup not installed." -ForegroundColor Yellow
    Write-Host "  Install Inno Setup 6 from https://jrsoftware.org/isinfo.php" -ForegroundColor Yellow
    Write-Host "  Then run: ISCC.exe installer\vant_agent.iss" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Build complete!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Outputs:"
Write-Host "    ZIP:     $ZipPath" -ForegroundColor White
Write-Host "    Size:    $ZipSizeMB MB" -ForegroundColor White
Write-Host ""
Write-Host "  To distribute:"
Write-Host "    1. Extract VANT-Agent-$Version.zip"
Write-Host "    2. Run setup.bat as Administrator"
Write-Host ""
Write-Host "  OR compile Inno Setup installer:"
Write-Host "    ISCC.exe installer\vant_agent.iss"
Write-Host ""
