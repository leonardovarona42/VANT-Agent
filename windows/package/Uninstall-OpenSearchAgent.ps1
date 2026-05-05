param(
    [string]$InstallDir = "$env:ProgramFiles\VANT\OpenSearchAgent",
    [string]$TaskName = "VANT-OpenSearch-Agent",
    [switch]$KeepFiles,
    [switch]$UserMode
)

$ErrorActionPreference = "Stop"

function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Stop-AgentProcesses {
    $processNames = @(
        "vant-opensearch-agent",
        "vant-opensearch-agent-tray",
        "sendheartbeat",
        "opena_checker",
        "opena_cheker",
        "opena_mover"
    )

    foreach ($name in $processNames) {
        try {
            Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        } catch {}
    }
}

if ($UserMode) {
    if ($InstallDir -eq "$env:ProgramFiles\VANT\OpenSearchAgent") {
        $InstallDir = "$env:LOCALAPPDATA\VANT\OpenSearchAgent"
    }
}

if (-not $UserMode -and -not (Test-Admin)) {
    throw "Run PowerShell as Administrator."
}

try {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
} catch {}
Stop-AgentProcesses
Start-Sleep -Seconds 2

try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
} catch {}

$startupDir = if ($UserMode) {
    [Environment]::GetFolderPath("Startup")
} else {
    [Environment]::GetFolderPath("CommonStartup")
}
$runKeyPath = if ($UserMode) {
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
} else {
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
}
$runValueName = "VANTOpenSearchAgentTray"
$shortcutPath = Join-Path $startupDir "VANT-OpenSearch-Agent Tray.lnk"
if ($UserMode) {
    $uninstallKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\VANTOpenSearchAgent"
} else {
    $uninstallKeyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\VANTOpenSearchAgent"
}
if (Test-Path $shortcutPath) {
    Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
}
if (Test-Path $runKeyPath) {
    Remove-ItemProperty -Path $runKeyPath -Name $runValueName -ErrorAction SilentlyContinue
}
if (Test-Path $uninstallKeyPath) {
    Remove-Item -Path $uninstallKeyPath -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $KeepFiles -and (Test-Path $InstallDir)) {
    Remove-Item -Path $InstallDir -Recurse -Force
}

Write-Host "OpenSearch agent uninstalled."
Write-Host "Task removed: $TaskName"
if ($KeepFiles) {
    Write-Host "Files kept in: $InstallDir"
}
