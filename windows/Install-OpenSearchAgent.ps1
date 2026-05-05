param(
    [string]$InstallDir = "$env:ProgramFiles\VANT\OpenSearchAgent",
    [string]$TaskName = "VANT-OpenSearch-Agent",
    [switch]$RunNow,
    [switch]$UserMode
)

$ErrorActionPreference = "Stop"

function Invoke-IcaclsSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    try {
        $output = cmd.exe /c ('icacls ' + (($Arguments | ForEach-Object {
            if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
        }) -join ' ') + ' 2>&1')
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            Write-Warning ("icacls returned exit code {0}: {1}" -f $exitCode, (($output | Out-String).Trim()))
        }
    } catch {
        Write-Warning ("icacls invocation failed: {0}" -f $_.Exception.Message)
    }
}

function Invoke-NativeCommandSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$Arguments = @()
    )

    try {
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            Write-Warning ("{0} exited with code {1}: {2}" -f $FilePath, $exitCode, (($output | Out-String).Trim()))
            return $false
        }
        return $true
    } catch {
        Write-Warning ("Unable to execute {0}: {1}" -f $FilePath, $_.Exception.Message)
        return $false
    }
}

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

function Reset-InstallPermissions {
    param(
        [string]$TargetPath
    )

    if (-not (Test-Path $TargetPath)) {
        return
    }

    Write-Host "Resetting ownership and ACLs for $TargetPath"
    Invoke-NativeCommandSafe -FilePath "takeown.exe" -Arguments @("/F", $TargetPath, "/R", "/A") | Out-Null
    Invoke-IcaclsSafe -Arguments @($TargetPath, "/inheritance:e", "/T", "/C")
    Invoke-IcaclsSafe -Arguments @($TargetPath, "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX", "/T", "/C")
}

function Invoke-UninstallCommandSafe {
    param(
        [string]$FilePath,
        [string[]]$Arguments = @()
    )

    if (-not (Test-Path $FilePath)) {
        return $false
    }

    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
        if ($null -ne $process -and $process.ExitCode -eq 0) {
            return $true
        }

        Write-Warning ("Uninstall command exited with code {0}: {1}" -f $process.ExitCode, $FilePath)
    } catch {
        Write-Warning ("Unable to execute uninstall command {0}: {1}" -f $FilePath, $_.Exception.Message)
    }

    return $false
}

function Uninstall-ExistingInstall {
    param(
        [string]$TargetInstallDir,
        [string]$TargetTaskName,
        [bool]$IsUserMode
    )

    if (-not (Test-Path $TargetInstallDir)) {
        return
    }

    $existingConfig = Join-Path $TargetInstallDir "config.yaml"
    $existingUninstallExe = Join-Path $TargetInstallDir "Uninstall-VANT-OpenSearch-Agent.exe"
    $existingUninstallScript = Join-Path $TargetInstallDir "Uninstall-OpenSearchAgent.ps1"
    $existingUserMode = $IsUserMode

    if ((-not $existingUserMode) -and $TargetInstallDir -like "$env:LOCALAPPDATA*") {
        $existingUserMode = $true
    }

    Write-Host "Existing installation detected in $TargetInstallDir. Removing it before reinstalling."
    Write-Host ("Installer admin token: {0}" -f (Test-Admin))
    Write-Host ("Installer identity: {0}" -f [Security.Principal.WindowsIdentity]::GetCurrent().Name)

    try {
        Stop-ScheduledTask -TaskName $TargetTaskName -ErrorAction SilentlyContinue
    } catch {}
    Stop-AgentProcesses
    Start-Sleep -Seconds 2
    Reset-InstallPermissions -TargetPath $TargetInstallDir

    $uninstallSucceeded = $false

    if (Test-Path $existingUninstallExe) {
        $arguments = @("--noprompt")
        if ($existingUserMode) {
            $arguments += "--user-mode"
        }
        if (Test-Path $existingConfig) {
            $arguments += @("--install-dir", $TargetInstallDir)
        }

        $uninstallSucceeded = Invoke-UninstallCommandSafe -FilePath $existingUninstallExe -Arguments $arguments
        if (-not $uninstallSucceeded) {
            Write-Warning "Falling back to the PowerShell uninstall script."
        }
    }

    if ((-not $uninstallSucceeded) -and (Test-Path $existingUninstallScript)) {
        $scriptArgs = @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", $existingUninstallScript,
            "-TaskName", $TargetTaskName
        )
        if ($existingUserMode) {
            $scriptArgs += "-UserMode"
        }

        if (Test-Path $existingConfig) {
            $scriptArgs += @("-InstallDir", $TargetInstallDir)
        }

        $uninstallSucceeded = Invoke-UninstallCommandSafe -FilePath "powershell.exe" -Arguments $scriptArgs
    }

    if (Test-Path $TargetInstallDir) {
        Start-Sleep -Seconds 2
        Stop-AgentProcesses
        Reset-InstallPermissions -TargetPath $TargetInstallDir
        Remove-Item -Path $TargetInstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path $TargetInstallDir) {
        throw "Could not remove the previous installation in $TargetInstallDir. Close any running agent processes and try again."
    }
}

function Get-OwnerAccountFromConfig {
    param(
        [string]$ConfigPath
    )

    $fallback = if ($env:USERDOMAIN -and $env:USERNAME) {
        "$($env:USERDOMAIN)\$($env:USERNAME)"
    } else {
        $env:USERNAME
    }

    if (-not (Test-Path $ConfigPath)) {
        return $fallback
    }

    try {
        $match = Select-String -Path $ConfigPath -Pattern '^\s*owner_account:\s*"?(.*?)"?\s*$' | Select-Object -First 1
        if ($match -and $match.Matches.Count -gt 0) {
            $candidate = $match.Matches[0].Groups[1].Value.Trim()
            if ($candidate) {
                return $candidate
            }
        }
    } catch {}

    return $fallback
}

function Set-SecureInstallAcl {
    param(
        [string]$TargetPath,
        [string]$OwnerAccount
    )

    if (-not (Test-Path $TargetPath)) {
        return
    }

    if (-not $OwnerAccount) {
        $OwnerAccount = if ($env:USERDOMAIN -and $env:USERNAME) {
            "$($env:USERDOMAIN)\$($env:USERNAME)"
        } else {
            $env:USERNAME
        }
    }

    Write-Host "Applying install ACL to $TargetPath for owner $OwnerAccount"
    $systemSid = "*S-1-5-18"
    $adminsSid = "*S-1-5-32-544"
    $usersSid = "*S-1-5-32-545"
    $ownerGrant = "${OwnerAccount}:(OI)(CI)M"

    # Preserve inherited Program Files permissions and add explicit grants needed by the installer/owner.
    Invoke-IcaclsSafe -Arguments @($TargetPath, "/grant:r", "${systemSid}:(OI)(CI)F", "${adminsSid}:(OI)(CI)F", $ownerGrant, "${usersSid}:(OI)(CI)RX", "/T", "/C")
    Invoke-IcaclsSafe -Arguments @($TargetPath, "/inheritance:e", "/T", "/C")
}

function Register-UninstallEntry {
    param(
        [string]$InstallDir,
        [string]$DisplayVersion,
        [bool]$IsUserMode
    )

    $uninstallScript = Join-Path $InstallDir "Uninstall-OpenSearchAgent.ps1"
    $uninstallExe = Join-Path $InstallDir "Uninstall-VANT-OpenSearch-Agent.exe"
    if ((-not (Test-Path $uninstallScript)) -and (-not (Test-Path $uninstallExe))) {
        return
    }

    $iconPath = Join-Path $InstallDir "vant-opensearch-agent-tray.exe"
    if (-not (Test-Path $iconPath)) {
        $iconPath = Join-Path $InstallDir "vant-opensearch-agent.exe"
    }

    $regPath = if ($IsUserMode) {
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\VANTOpenSearchAgent"
    } else {
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\VANTOpenSearchAgent"
    }
    if (Test-Path $uninstallExe) {
        $uninstallCommand = "`"$uninstallExe`" --noprompt"
        if ($IsUserMode) {
            $uninstallCommand += " --user-mode"
        }
        $quietUninstallCommand = $uninstallCommand
    } else {
        $uninstallCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$uninstallScript`""
        $quietUninstallCommand = $uninstallCommand
    }

    New-Item -Path $regPath -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "DisplayName" -Value "VANT OpenSearch Agent" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "DisplayVersion" -Value $DisplayVersion -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "Publisher" -Value "Leonardo L. Varona Tabares" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "InstallLocation" -Value $InstallDir -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "DisplayIcon" -Value $iconPath -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "UninstallString" -Value $uninstallCommand -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "QuietUninstallString" -Value $quietUninstallCommand -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "NoModify" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "NoRepair" -Value 1 -PropertyType DWord -Force | Out-Null
}

$defaultSystemInstallDir = "$env:ProgramFiles\VANT\OpenSearchAgent"
$defaultUserInstallDir = "$env:LOCALAPPDATA\VANT\OpenSearchAgent"
$isAdmin = Test-Admin

if ($UserMode -and $InstallDir -eq $defaultSystemInstallDir) {
    $InstallDir = $defaultUserInstallDir
}

if ((-not $UserMode) -and (-not $isAdmin)) {
    if ($InstallDir -eq $defaultSystemInstallDir) {
        Write-Warning "No admin privileges detected. Switching install to user mode under $defaultUserInstallDir."
        $UserMode = $true
        $InstallDir = $defaultUserInstallDir
    } else {
        throw "Run PowerShell as Administrator or use -UserMode for custom non-admin installs."
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$exeSource = Join-Path $scriptDir "vant-opensearch-agent.exe"
$traySource = Join-Path $scriptDir "vant-opensearch-agent-tray.exe"
$dirSource = Join-Path $scriptDir "vant-opensearch-agent"
$cfgSource = Join-Path $scriptDir "config.yaml"
$heartbeatSource = Join-Path $scriptDir "sendheartbeat.exe"
$heartbeatLegacySource = Join-Path $scriptDir "sendhearbet.exe"
$checkerSource = Join-Path $scriptDir "opena_checker.exe"
$checkerLegacySource = Join-Path $scriptDir "opena_cheker.exe"
$moverSource = Join-Path $scriptDir "opena_mover.exe"
$uninstallSource = Join-Path $scriptDir "Uninstall-OpenSearchAgent.ps1"
$uninstallExeSource = Join-Path $scriptDir "Uninstall-VANT-OpenSearch-Agent.exe"

if (-not (Test-Path $exeSource) -and -not (Test-Path (Join-Path $dirSource "vant-opensearch-agent.exe"))) {
    throw "Agent binary not found in package."
}

# Stop existing task before replacing binaries to avoid locked files.
try {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
} catch {}
Stop-AgentProcesses

Uninstall-ExistingInstall -TargetInstallDir $InstallDir -TargetTaskName $TaskName -IsUserMode ([bool]$UserMode)

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $InstallDir "logs") -Force | Out-Null

if (Test-Path (Join-Path $dirSource "vant-opensearch-agent.exe")) {
    $agentInstallDir = Join-Path $InstallDir "agent"
    if (Test-Path $agentInstallDir) {
        Remove-Item $agentInstallDir -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $agentInstallDir) {
            Start-Sleep -Seconds 2
            Remove-Item $agentInstallDir -Recurse -Force
        }
    }
    Copy-Item $dirSource $agentInstallDir -Recurse -Force
    $exePath = Join-Path $agentInstallDir "vant-opensearch-agent.exe"
} else {
    Copy-Item $exeSource (Join-Path $InstallDir "vant-opensearch-agent.exe") -Force
    $exePath = Join-Path $InstallDir "vant-opensearch-agent.exe"
}
if (Test-Path $traySource) {
    Copy-Item $traySource (Join-Path $InstallDir "vant-opensearch-agent-tray.exe") -Force
}
if (Test-Path $cfgSource) {
    Copy-Item $cfgSource (Join-Path $InstallDir "config.yaml") -Force
}
if (Test-Path $uninstallSource) {
    Copy-Item $uninstallSource (Join-Path $InstallDir "Uninstall-OpenSearchAgent.ps1") -Force
    Set-Content -Path (Join-Path $InstallDir "Uninstall-VANT-OpenSearch-Agent.cmd") -Value "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"%~dp0Uninstall-OpenSearchAgent.ps1`" %*" -Encoding ASCII
}
if (Test-Path $uninstallExeSource) {
    Copy-Item $uninstallExeSource (Join-Path $InstallDir "Uninstall-VANT-OpenSearch-Agent.exe") -Force
}
if (Test-Path $heartbeatSource) {
    Copy-Item $heartbeatSource (Join-Path $InstallDir "sendheartbeat.exe") -Force
    Copy-Item $heartbeatSource (Join-Path $InstallDir "sendhearbet.exe") -Force
} elseif (Test-Path $heartbeatLegacySource) {
    Copy-Item $heartbeatLegacySource (Join-Path $InstallDir "sendheartbeat.exe") -Force
    Copy-Item $heartbeatLegacySource (Join-Path $InstallDir "sendhearbet.exe") -Force
}
if (Test-Path $checkerSource) {
    Copy-Item $checkerSource (Join-Path $InstallDir "opena_checker.exe") -Force
    Copy-Item $checkerSource (Join-Path $InstallDir "opena_cheker.exe") -Force
} elseif (Test-Path $checkerLegacySource) {
    Copy-Item $checkerLegacySource (Join-Path $InstallDir "opena_checker.exe") -Force
    Copy-Item $checkerLegacySource (Join-Path $InstallDir "opena_cheker.exe") -Force
}
if (Test-Path $moverSource) {
    Copy-Item $moverSource (Join-Path $InstallDir "opena_mover.exe") -Force
}
if (Test-Path (Join-Path $scriptDir "staticfiles")) {
    Copy-Item (Join-Path $scriptDir "staticfiles") (Join-Path $InstallDir "staticfiles") -Recurse -Force
}

$cfgPath = Join-Path $InstallDir "config.yaml"
$ownerAccount = Get-OwnerAccountFromConfig -ConfigPath $cfgPath
$ownerInfoPath = Join-Path $InstallDir "install_owner.txt"
Set-Content -Path $ownerInfoPath -Value @(
    "owner_account=$ownerAccount"
    "installed_at=$(Get-Date -Format s)"
    "install_dir=$InstallDir"
) -Encoding ASCII
Set-SecureInstallAcl -TargetPath $InstallDir -OwnerAccount $ownerAccount
Register-UninstallEntry -InstallDir $InstallDir -DisplayVersion "1.0.4" -IsUserMode $UserMode

$arg = "--config `"$cfgPath`""
$trayExe = Join-Path $InstallDir "vant-opensearch-agent-tray.exe"
$trayArg = "--config `"$cfgPath`" --monitor-only"
$runKeyPath = if ($UserMode) {
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
} else {
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
}
$runValueName = "VANTOpenSearchAgentTray"

$action = New-ScheduledTaskAction -Execute $exePath -Argument $arg -WorkingDirectory $InstallDir
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
if ($UserMode) {
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
} else {
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

$startupDir = if ($UserMode) {
    [Environment]::GetFolderPath("Startup")
} else {
    [Environment]::GetFolderPath("CommonStartup")
}

if (Test-Path $trayExe) {
    $shortcutPath = Join-Path $startupDir "VANT-OpenSearch-Agent Tray.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $trayExe
    $shortcut.Arguments = $trayArg
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.IconLocation = "$trayExe,0"
    $shortcut.Description = "VANT-SIEM Agent tray"
    $shortcut.Save()
    New-Item -Path $runKeyPath -Force | Out-Null
    Set-ItemProperty -Path $runKeyPath -Name $runValueName -Value "`"$trayExe`" $trayArg" -Force
}

if ($RunNow) {
    Start-ScheduledTask -TaskName $TaskName
    if ((Test-Path $trayExe) -and [Environment]::UserInteractive) {
        try {
            Start-Process -FilePath $trayExe -ArgumentList $trayArg -WorkingDirectory $InstallDir -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning ("Tray launch skipped: {0}" -f $_.Exception.Message)
        }
    }
}

Write-Host "Installed OpenSearch agent."
Write-Host "InstallDir: $InstallDir"
Write-Host "TaskName: $TaskName"
Write-Host "Mode: $(if ($UserMode) { 'UserMode' } else { 'SystemMode' })"
Write-Host "OwnerAccount: $ownerAccount"
Write-Host "Edit config: $cfgPath"
