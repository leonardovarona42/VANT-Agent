param(
    [string]$PythonExe
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$buildScript = Join-Path $repoRoot "opensearch_agents\windows\build_setup.ps1"

if ($PythonExe) {
    powershell -ExecutionPolicy Bypass -File $buildScript -PythonExe $PythonExe
} else {
    powershell -ExecutionPolicy Bypass -File $buildScript
}
