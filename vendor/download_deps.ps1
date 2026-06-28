# Descarga todas las dependencias para compilacion offline
# Ejecutar en una maquina con internet

$VendorDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== Descargando dependencias offline ===" -ForegroundColor Cyan

# Windows
Write-Host "`n--- Dependencias Windows ---" -ForegroundColor Yellow
pip download -r "$VendorDir\..\windows\requirements.txt" -d "$VendorDir" --platform win_amd64 --python-version 3.12 --only-binary=:all:
if ($LASTEXITCODE -ne 0) {
    pip download -r "$VendorDir\..\windows\requirements.txt" -d "$VendorDir"
}

# PyInstaller
Write-Host "`n--- PyInstaller ---" -ForegroundColor Yellow
pip download pyinstaller -d "$VendorDir"

Write-Host "`n=== Descarga completada ===" -ForegroundColor Green
Write-Host "Wheels guardados en: $VendorDir"
$count = (Get-ChildItem "$VendorDir\*.whl").Count
Write-Host "Total: $count paquetes"
