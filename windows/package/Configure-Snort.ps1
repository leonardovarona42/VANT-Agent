param(
    [string]$SnortRoot = "C:\Snort",
    [string]$InterfaceAlias = "Ethernet",
    [string]$HomeNet = "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]",
    [string]$ServiceNameHint = "Snort"
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

function Write-Step {
    param([string]$Message)
    Write-Host "[Snort] $Message"
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Convert-ToSnortPath {
    param([string]$PathValue)
    return ($PathValue -replace '\\', '/')
}

function Get-SnortInterfaceIndex {
    param(
        [string]$SnortExe,
        [string]$Alias
    )

    $adapter = Get-NetAdapter -Name $Alias -ErrorAction Stop
    $stdout = [System.IO.Path]::GetTempFileName()
    $stderr = [System.IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process -FilePath $SnortExe -ArgumentList "-W" -WorkingDirectory $snortBinDir -Wait -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $lines = @()
        if (Test-Path $stdout) {
            $lines += Get-Content $stdout
        }
        if (Test-Path $stderr) {
            $lines += Get-Content $stderr
        }
    } finally {
        Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
    foreach ($line in $lines) {
        if ($line -match '^\s*(\d+)\s+' -and $line -like "*$($adapter.InterfaceDescription)*") {
            return [int]$Matches[1]
        }
    }
    throw "No se encontro el indice de Snort para la interfaz '$Alias'."
}

function Set-ConfigLine {
    param(
        [string]$Content,
        [string]$Pattern,
        [string]$Replacement
    )
    $regex = [regex]::new($Pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
    if ($regex.IsMatch($Content)) {
        return $regex.Replace($Content, $Replacement, 1)
    }
    return ($Content.TrimEnd() + "`r`n" + $Replacement + "`r`n")
}

$snortRootPath = (Resolve-Path $SnortRoot).Path
$snortExe = Join-Path $snortRootPath "bin\snort.exe"
$snortBinDir = Join-Path $snortRootPath "bin"
$snortConf = Join-Path $snortRootPath "etc\snort.conf"
$logDir = Join-Path $snortRootPath "log"
$rulesDir = Join-Path $snortRootPath "rules"
$preprocRulesDir = Join-Path $snortRootPath "preproc_rules"
$dynamicPreprocDir = Join-Path $snortRootPath "lib\snort_dynamicpreprocessor"
$dynamicEngine = Join-Path $snortRootPath "lib\snort_dynamicengine\sf_engine.dll"
$dynamicRulesDir = Join-Path $snortRootPath "lib\snort_dynamicrules"
$rulesDirCfg = "../rules"
$preprocRulesDirCfg = "../preproc_rules"
$dynamicPreprocDirCfg = "../lib/snort_dynamicpreprocessor"
$dynamicEngineCfg = "../lib/snort_dynamicengine/sf_engine.dll"
$dynamicRulesDirCfg = "../lib/snort_dynamicrules"
$logDirCfg = "../log"
$alertsFast = Join-Path $logDir "alerts.fast"

if (-not (Test-Path $snortExe)) {
    throw "No se encontro snort.exe en $snortExe"
}
if (-not (Test-Path $snortConf)) {
    throw "No se encontro snort.conf en $snortConf"
}

New-Item -ItemType Directory -Path $logDir, $rulesDir, $preprocRulesDir, $dynamicRulesDir -Force | Out-Null
if (-not (Test-Path $alertsFast)) {
    New-Item -ItemType File -Path $alertsFast -Force | Out-Null
}
foreach ($ruleFile in @("local.rules", "white_list.rules", "black_list.rules")) {
    $path = Join-Path $rulesDir $ruleFile
    if (-not (Test-Path $path)) {
        New-Item -ItemType File -Path $path -Force | Out-Null
    }
}

$minimalLocalRules = @'
alert icmp any any -> $HOME_NET any (msg:"VANT Backbone ICMP observed"; sid:1000001; rev:1;)
alert tcp any any -> $HOME_NET [21,22,23,25,53,80,110,135,139,143,389,443,445,3389,5985,8080,8443] (msg:"VANT Backbone TCP service observed"; flow:stateless; sid:1000002; rev:1;)
alert udp any any -> $HOME_NET [53,67,68,69,123,137,138,161,500,514] (msg:"VANT Backbone UDP service observed"; sid:1000003; rev:1;)
'@
$localRulesPath = Join-Path $rulesDir "local.rules"
Set-Content -Path $localRulesPath -Value $minimalLocalRules -Encoding ASCII

$backup = "$snortConf.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
Copy-Item $snortConf $backup -Force
Write-Step "Backup creado en $backup"

$config = Get-Content $snortConf -Raw
$config = Set-ConfigLine $config '^\s*ipvar HOME_NET .*$' "ipvar HOME_NET $HomeNet"
$config = Set-ConfigLine $config '^\s*var RULE_PATH .*$' "var RULE_PATH $rulesDirCfg"
$config = Set-ConfigLine $config '^\s*var SO_RULE_PATH .*$' "var SO_RULE_PATH $dynamicRulesDirCfg"
$config = Set-ConfigLine $config '^\s*var PREPROC_RULE_PATH .*$' "var PREPROC_RULE_PATH $preprocRulesDirCfg"
$config = Set-ConfigLine $config '^\s*var WHITE_LIST_PATH .*$' "var WHITE_LIST_PATH $rulesDirCfg"
$config = Set-ConfigLine $config '^\s*var BLACK_LIST_PATH .*$' "var BLACK_LIST_PATH $rulesDirCfg"
$config = Set-ConfigLine $config '^\s*#?\s*config logdir:.*$' "config logdir: $logDirCfg"
$config = Set-ConfigLine $config '^\s*dynamicpreprocessor directory .*$' "dynamicpreprocessor directory $dynamicPreprocDirCfg"
$config = Set-ConfigLine $config '^\s*dynamicengine .*$' "dynamicengine $dynamicEngineCfg"
$config = Set-ConfigLine $config '^\s*dynamicdetection directory .*$' "dynamicdetection directory $dynamicRulesDirCfg"

if ($config -match '^\s*#\s*output alert_fast:.*$') {
    $config = [regex]::Replace(
        $config,
        '^\s*#\s*output alert_fast:.*$',
        'output alert_fast: alerts.fast',
        [System.Text.RegularExpressions.RegexOptions]::Multiline
    )
} elseif ($config -notmatch '^\s*output alert_fast:.*$') {
    $config += "`r`noutput alert_fast: alerts.fast`r`n"
}

$hasRuleCorpus = Test-Path (Join-Path $rulesDir "app-detect.rules")
if (-not $hasRuleCorpus) {
    $config = [regex]::Replace(
        $config,
        'include \$RULE_PATH/app-detect\.rules[\s\S]*?(?=###################################################\r?\n# Step #8)',
        "# Managed by VANT: minimal local rules profile`r`n`r`n",
        [System.Text.RegularExpressions.RegexOptions]::Singleline
    )
    $config = [regex]::Replace(
        $config,
        '^\s*#\s*include \$PREPROC_RULE_PATH/preprocessor\.rules\s*$',
        'include $PREPROC_RULE_PATH/preprocessor.rules',
        [System.Text.RegularExpressions.RegexOptions]::Multiline
    )
    $config = [regex]::Replace(
        $config,
        '^\s*#\s*include \$PREPROC_RULE_PATH/decoder\.rules\s*$',
        'include $PREPROC_RULE_PATH/decoder.rules',
        [System.Text.RegularExpressions.RegexOptions]::Multiline
    )
    $config = [regex]::Replace(
        $config,
        '^\s*#\s*include \$PREPROC_RULE_PATH/sensitive-data\.rules\s*$',
        'include $PREPROC_RULE_PATH/sensitive-data.rules',
        [System.Text.RegularExpressions.RegexOptions]::Multiline
    )
    Write-Step "No se detecto el ruleset VRT completo; se aplico perfil minimo con local.rules y preproc_rules."
}

Set-Content -Path $snortConf -Value $config -Encoding ASCII
Write-Step "snort.conf actualizado para Windows backbone."

$interfaceIndex = Get-SnortInterfaceIndex -SnortExe $snortExe -Alias $InterfaceAlias
Write-Step "Interfaz backbone '$InterfaceAlias' mapeada al indice Snort $interfaceIndex."

Write-Step "Probando configuracion de Snort..."
$testStdout = [System.IO.Path]::GetTempFileName()
$testStderr = [System.IO.Path]::GetTempFileName()
$testProc = Start-Process -FilePath $snortExe -ArgumentList @("-T", "-q", "-i", $interfaceIndex, "-A", "fast", "-c", $snortConf, "-l", $logDir) -WorkingDirectory $snortBinDir -Wait -NoNewWindow -PassThru -RedirectStandardOutput $testStdout -RedirectStandardError $testStderr
if ($testProc.ExitCode -ne 0) {
    Get-Content $testStdout, $testStderr -ErrorAction SilentlyContinue
    throw "La validacion de Snort fallo."
}
Remove-Item $testStdout, $testStderr -Force -ErrorAction SilentlyContinue

$serviceInstallHelper = Join-Path $snortRootPath "install_snort_service_as_admin.cmd"
$serviceInstallCommand = "cd /d `"$snortBinDir`" && snort.exe /SERVICE /INSTALL -i $interfaceIndex -A fast -c `"$snortConf`" -l `"$logDir`" -I -y"
@"
@echo off
echo Installing Snort service for VANT-SIEM...
$serviceInstallCommand
if errorlevel 1 (
  echo Snort service install failed.
  exit /b 1
)
sc start Snort
"@ | Set-Content -Path $serviceInstallHelper -Encoding ASCII

if (-not (Test-IsAdmin)) {
    Write-Step "Configuracion validada, pero la sesion actual no tiene privilegios de administrador para registrar servicios."
    Write-Host ""
    Write-Host "Snort configurado y validado."
    Write-Host "Root: $snortRootPath"
    Write-Host "InterfaceAlias: $InterfaceAlias"
    Write-Host "SnortInterfaceIndex: $interfaceIndex"
    Write-Host "Config: $snortConf"
    Write-Host "Alerts: $alertsFast"
    Write-Host "Helper: $serviceInstallHelper"
    Write-Warning "Snort quedo listo para servicio, pero debes ejecutar el helper como Administrador para registrarlo en Windows."
    return
}

$existingService = Get-Service | Where-Object { $_.Name -like "*$ServiceNameHint*" -or $_.DisplayName -like "*$ServiceNameHint*" }
if ($existingService) {
    foreach ($service in $existingService) {
        try {
            if ($service.Status -ne "Stopped") {
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    $uninstallProc = Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", "snort.exe /SERVICE /UNINSTALL") -WorkingDirectory $snortBinDir -Wait -NoNewWindow -PassThru
    Start-Sleep -Seconds 2
}

Write-Step "Instalando Snort como servicio de Windows..."
$svcProc = Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", "snort.exe /SERVICE /INSTALL -i $interfaceIndex -A fast -c `"$snortConf`" -l `"$logDir`" -I -y") -WorkingDirectory $snortBinDir -Wait -NoNewWindow -PassThru
if ($svcProc.ExitCode -ne 0) {
    throw "No se pudo instalar el servicio de Snort."
}

Start-Sleep -Seconds 2
$service = Get-Service | Where-Object { $_.Name -like "*$ServiceNameHint*" -or $_.DisplayName -like "*$ServiceNameHint*" } | Select-Object -First 1
if (-not $service) {
    throw "Se instalo Snort, pero no se pudo localizar el servicio."
}

Set-Service -Name $service.Name -StartupType Automatic
Start-Service -Name $service.Name
Start-Sleep -Seconds 3
$service.Refresh()
Write-Step "Servicio $($service.Name) en estado $($service.Status)."

Write-Host ""
Write-Host "Snort listo."
Write-Host "Root: $snortRootPath"
Write-Host "InterfaceAlias: $InterfaceAlias"
Write-Host "SnortInterfaceIndex: $interfaceIndex"
Write-Host "Config: $snortConf"
Write-Host "Alerts: $alertsFast"
Write-Host "ServiceName: $($service.Name)"
