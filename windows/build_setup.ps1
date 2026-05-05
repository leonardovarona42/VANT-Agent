param(
    [string]$PythonExe
)

$ErrorActionPreference = "Stop"

function Resolve-PythonExe {
    param(
        [string]$RequestedPython
    )

    if ($RequestedPython) {
        if (-not (Test-Path $RequestedPython)) {
            throw "Python executable not found: $RequestedPython"
        }
        return (Resolve-Path $RequestedPython).Path
    }

    $activeVenv = $env:VIRTUAL_ENV
    if ($activeVenv) {
        $activeVenvPython = Join-Path $activeVenv "Scripts\python.exe"
        if (Test-Path $activeVenvPython) {
            return (Resolve-Path $activeVenvPython).Path
        }
    }

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $repoPython = Join-Path $repoRoot "venv\Scripts\python.exe"
    if (Test-Path $repoPython) {
        return (Resolve-Path $repoPython).Path
    }

    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        return $pythonCommand.Source
    }

    throw "Python not found. Activate a virtualenv, provide -PythonExe, or create venv\\Scripts\\python.exe."
}

function Assert-BuildDependency {
    param(
        [string]$ModuleName,
        [string]$PipName = $ModuleName
    )

    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $PythonExe -c "import $ModuleName" *> $null
    $ErrorActionPreference = $previousPreference
    if ($LASTEXITCODE -eq 0) {
        return
    }

    Write-Host "Instalando dependencia de build faltante: $PipName"
    & $PythonExe -m pip install $PipName
    if ($LASTEXITCODE -ne 0) {
        throw "No se pudo instalar la dependencia requerida: $PipName"
    }
}

$PythonExe = Resolve-PythonExe -RequestedPython $PythonExe

Assert-BuildDependency -ModuleName "PyInstaller"
Assert-BuildDependency -ModuleName "requests"
Assert-BuildDependency -ModuleName "yaml" -PipName "pyyaml"
Assert-BuildDependency -ModuleName "PyQt6"

function New-LogoIcon {
    param(
        [string]$PngPath,
        [string]$IcoPath
    )

    Add-Type -AssemblyName System.Drawing
    $bitmap = [System.Drawing.Bitmap]::FromFile($PngPath)
    try {
        $icon = [System.Drawing.Icon]::FromHandle($bitmap.GetHicon())
        $stream = [System.IO.File]::Open($IcoPath, [System.IO.FileMode]::Create)
        try {
            $icon.Save($stream)
        } finally {
            $stream.Dispose()
            $icon.Dispose()
        }
    } finally {
        $bitmap.Dispose()
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$windowsDir = Join-Path $repoRoot "opensearch_agents\windows"
$buildRoot = Join-Path $env:TEMP ("vant-opensearch-build-" + (Get-Date -Format "yyyyMMddHHmmss"))
$agentWork = Join-Path $buildRoot "agent-work"
$agentSpec = Join-Path $buildRoot "agent-spec"
$agentDist = Join-Path $buildRoot "agent-dist"
$toolsWork = Join-Path $buildRoot "tools-work"
$toolsSpec = Join-Path $buildRoot "tools-spec"
$toolsDist = Join-Path $buildRoot "tools-dist"
$setupWork = Join-Path $buildRoot "setup-work"
$setupSpec = Join-Path $buildRoot "setup-spec"
$trayWork = Join-Path $buildRoot "tray-work"
$traySpec = Join-Path $buildRoot "tray-spec"
$uninstallWork = Join-Path $buildRoot "uninstall-work"
$uninstallSpec = Join-Path $buildRoot "uninstall-spec"
$packageDir = Join-Path $windowsDir "package"
$setupPayloadRoot = Join-Path $buildRoot "setup-payload"
$setupPayloadPackage = Join-Path $setupPayloadRoot "package"
$setupDist = Join-Path $buildRoot "setup-dist"
$configsDir = Join-Path $windowsDir "configs"
$outputExe = Join-Path $windowsDir "opensearch_agent_setup.exe"
$finalOutputExe = $outputExe
$logoAbs = (Resolve-Path (Join-Path $repoRoot "staticfiles\img\logo.png")).Path
$iconPath = Join-Path $buildRoot "vant_logo.ico"
$versionFile = Join-Path $buildRoot "version_info.txt"

if (Test-Path $buildRoot) {
    Remove-Item $buildRoot -Recurse -Force
}

if (Test-Path $packageDir) {
    Remove-Item $packageDir -Recurse -Force
}

foreach ($path in @($agentWork, $agentSpec, $agentDist, $toolsWork, $toolsSpec, $toolsDist, $trayWork, $traySpec, $uninstallWork, $uninstallSpec, $setupWork, $setupSpec, $setupDist, $packageDir, $setupPayloadRoot, $setupPayloadPackage)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

New-LogoIcon -PngPath $logoAbs -IcoPath $iconPath
@"
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 2, 0),
    prodvers=(1, 0, 2, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          '040904B0',
          [
            StringStruct('CompanyName', 'Leonardo L. Varona Tabares'),
            StringStruct('FileDescription', 'VANT-SIEM OpenSearch Agent'),
            StringStruct('FileVersion', '1.0.2'),
            StringStruct('InternalName', 'vant-opensearch-agent'),
            StringStruct('OriginalFilename', 'vant-opensearch-agent.exe'),
            StringStruct('ProductName', 'VANT-SIEM OpenSearch Agent'),
            StringStruct('ProductVersion', '1.0.2'),
            StringStruct('Comments', 'Contacto: leonardovarona42@gmail.com')
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"@ | Set-Content -Path $versionFile -Encoding ASCII

if (Test-Path $outputExe) {
    try {
        Remove-Item $outputExe -Force
    } catch {
        $finalOutputExe = Join-Path $windowsDir ("opensearch_agent_setup_{0}.exe" -f (Get-Date -Format "yyyyMMddHHmmss"))
        Write-Warning "No se pudo reemplazar opensearch_agent_setup.exe porque esta en uso. Se generara: $finalOutputExe"
    }
}

& $PythonExe -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --name "vant-opensearch-agent" `
  --icon $iconPath `
  --version-file $versionFile `
  --paths "opensearch_agents" `
  --hidden-import "yaml" `
  --hidden-import "requests" `
  --distpath $agentDist `
  --workpath $agentWork `
  --specpath $agentSpec `
  "opensearch_agents\agent.py"

$agentExe = Join-Path $agentDist "vant-opensearch-agent.exe"
if (-not (Test-Path $agentExe)) {
    throw "No se pudo generar vant-opensearch-agent.exe"
}

& $PythonExe -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --windowed `
  --name "vant-opensearch-agent-tray" `
  --icon $iconPath `
  --version-file $versionFile `
  --paths "opensearch_agents" `
  --hidden-import "agent" `
  --hidden-import "PyQt6.sip" `
  --hidden-import "PyQt6.QtCore" `
  --hidden-import "PyQt6.QtGui" `
  --hidden-import "PyQt6.QtWidgets" `
  --hidden-import "requests" `
  --hidden-import "yaml" `
  --distpath $agentDist `
  --workpath $trayWork `
  --specpath $traySpec `
  "opensearch_agents\agent_tray.py"

if ($LASTEXITCODE -ne 0) {
    throw "Fallo PyInstaller al compilar vant-opensearch-agent-tray.exe"
}

$trayExe = Join-Path $agentDist "vant-opensearch-agent-tray.exe"
if (-not (Test-Path $trayExe)) {
    throw "No se pudo generar vant-opensearch-agent-tray.exe"
}

& $PythonExe -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --name "Uninstall-VANT-OpenSearch-Agent" `
  --icon $iconPath `
  --version-file $versionFile `
  --hidden-import "ctypes" `
  --distpath $toolsDist `
  --workpath $uninstallWork `
  --specpath $uninstallSpec `
  "opensearch_agents\windows\uninstall_wrapper.py"

$uninstallExe = Join-Path $toolsDist "Uninstall-VANT-OpenSearch-Agent.exe"
if (-not (Test-Path $uninstallExe)) {
    throw "No se pudo generar Uninstall-VANT-OpenSearch-Agent.exe"
}

$toolDefinitions = @(
  @{ Name = "sendheartbeat"; Script = "opensearch_agents\sendheartbeat.py"; VersionName = "sendheartbeat.exe" },
  @{ Name = "opena_mover"; Script = "opensearch_agents\opensearchmover.py"; VersionName = "opena_mover.exe" },
  @{ Name = "opena_checker"; Script = "opensearch_agents\opensearchcheck.py"; VersionName = "opena_checker.exe" }
)

foreach ($tool in $toolDefinitions) {
  & $PythonExe -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --name $tool.Name `
    --icon $iconPath `
    --version-file $versionFile `
    --hidden-import "yaml" `
    --hidden-import "requests" `
    --distpath $toolsDist `
    --workpath (Join-Path $toolsWork $tool.Name) `
    --specpath $toolsSpec `
    $tool.Script

  if ($LASTEXITCODE -ne 0) {
    throw "Fallo PyInstaller al compilar $($tool.VersionName)"
  }

  $builtTool = Join-Path $toolsDist $tool.VersionName
  if (-not (Test-Path $builtTool)) {
    throw "No se pudo generar $($tool.VersionName)"
  }

  Copy-Item $builtTool (Join-Path $packageDir $tool.VersionName) -Force
}

Copy-Item (Join-Path $packageDir "sendheartbeat.exe") (Join-Path $packageDir "sendhearbet.exe") -Force
Copy-Item (Join-Path $packageDir "opena_checker.exe") (Join-Path $packageDir "opena_cheker.exe") -Force

Copy-Item $agentExe (Join-Path $packageDir "vant-opensearch-agent.exe") -Force
Copy-Item $trayExe (Join-Path $packageDir "vant-opensearch-agent-tray.exe") -Force
Copy-Item $uninstallExe (Join-Path $packageDir "Uninstall-VANT-OpenSearch-Agent.exe") -Force
Copy-Item (Join-Path $windowsDir "Install-OpenSearchAgent.ps1") (Join-Path $packageDir "Install-OpenSearchAgent.ps1") -Force
Copy-Item (Join-Path $windowsDir "Uninstall-OpenSearchAgent.ps1") (Join-Path $packageDir "Uninstall-OpenSearchAgent.ps1") -Force
Copy-Item (Join-Path $windowsDir "Configure-Snort.ps1") (Join-Path $packageDir "Configure-Snort.ps1") -Force
Copy-Item (Join-Path $configsDir "config.yaml") (Join-Path $packageDir "config.yaml") -Force
Copy-Item (Join-Path $configsDir "config.windows-server-ad.yaml") (Join-Path $packageDir "config.windows-server-ad.yaml") -Force
Copy-Item (Join-Path $configsDir "config.windows11-ids.yaml") (Join-Path $packageDir "config.windows11-ids.yaml") -Force

$bootstrapKey = Join-Path $windowsDir "bootstrap.key"
if (Test-Path $bootstrapKey) {
    Copy-Item $bootstrapKey (Join-Path $packageDir "bootstrap.key") -Force
}

$requiredPackageFiles = @(
    @{ Source = (Join-Path $windowsDir "Install-OpenSearchAgent.ps1"); Destination = (Join-Path $packageDir "Install-OpenSearchAgent.ps1") },
    @{ Source = (Join-Path $windowsDir "Uninstall-OpenSearchAgent.ps1"); Destination = (Join-Path $packageDir "Uninstall-OpenSearchAgent.ps1") },
    @{ Source = (Join-Path $windowsDir "Configure-Snort.ps1"); Destination = (Join-Path $packageDir "Configure-Snort.ps1") },
    @{ Source = (Join-Path $configsDir "config.yaml"); Destination = (Join-Path $packageDir "config.yaml") },
    @{ Source = (Join-Path $configsDir "config.windows-server-ad.yaml"); Destination = (Join-Path $packageDir "config.windows-server-ad.yaml") },
    @{ Source = (Join-Path $configsDir "config.windows11-ids.yaml"); Destination = (Join-Path $packageDir "config.windows11-ids.yaml") }
)

foreach ($item in $requiredPackageFiles) {
    Copy-Item $item.Source $item.Destination -Force
    if (-not (Test-Path $item.Destination)) {
        throw "No se pudo preparar el archivo requerido para el paquete: $($item.Destination)"
    }
}

$packageAbs = (Resolve-Path $packageDir).Path
$packageStaticDir = Join-Path $packageDir "staticfiles\img"
New-Item -ItemType Directory -Path $packageStaticDir -Force | Out-Null
Copy-Item $logoAbs (Join-Path $packageStaticDir "logo.png") -Force
Get-ChildItem $packageDir -File | Copy-Item -Destination $setupPayloadPackage -Force
New-Item -ItemType Directory -Path (Join-Path $setupPayloadPackage "staticfiles\img") -Force | Out-Null
Get-ChildItem $packageStaticDir -File | Copy-Item -Destination (Join-Path $setupPayloadPackage "staticfiles\img") -Force

$packagePayloadAbs = (Resolve-Path $setupPayloadPackage).Path

& $PythonExe -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --windowed `
  --name "opensearch_agent_setup" `
  --icon $iconPath `
  --version-file $versionFile `
  --hidden-import "PyQt6.sip" `
  --hidden-import "PyQt6.QtCore" `
  --hidden-import "PyQt6.QtGui" `
  --hidden-import "PyQt6.QtWidgets" `
  --hidden-import "requests" `
  --hidden-import "yaml" `
  --distpath $setupDist `
  --workpath $setupWork `
  --specpath $setupSpec `
  --add-data "${packagePayloadAbs};package" `
  --add-data "${logoAbs};staticfiles\img" `
  "opensearch_agents\windows\agent_setup_ui.py"

if (-not (Test-Path (Join-Path $setupDist "opensearch_agent_setup.exe"))) {
    throw "No se pudo generar opensearch_agent_setup.exe"
}

Copy-Item (Join-Path $setupDist "opensearch_agent_setup.exe") $finalOutputExe -Force

Write-Host "Windows GUI setup listo en: $finalOutputExe"
