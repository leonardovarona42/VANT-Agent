; VANT-Agent Windows Installer - Inno Setup Script v6.x
; Bundles agent source files + Python + deps, runs setup.bat post-install

#define MyAppName "VANT-Agent"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "VANT-SIEM"
#define MyAppURL "https://github.com/leonardovarona42/VANT-SIEM"
#define MyAppExeName "agent.py"

[Setup]
AppId={{A7B3F2E1-9C4D-4E8F-B6A2-1D5C8E3F7A9B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=..\dist\installer
OutputBaseFilename=VANT-Agent-Setup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
DisableProgramGroupPage=yes
DisableFinishedPage=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "runwizard"; Description: "Run configuration wizard after installation"; GroupDescription: "Setup:"; Flags: checkedonce

[Files]
; Compiled agent executable (includes vant/ module)
Source: "..\dist\VANT-Agent.exe"; DestDir: "{app}"; Flags: ignoreversion

; Core agent files (fallback / tray)
Source: "..\agent.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\windows\agent.py"; DestDir: "{app}"; DestName: "agent_src.py"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\agent_tray.py"; DestDir: "{app}"; Flags: ignoreversion

; VANT module (for source-based execution)
Source: "..\vant\*.py"; DestDir: "{app}\vant"; Flags: ignoreversion
Source: "..\vant\modules\*.py"; DestDir: "{app}\vant\modules"; Flags: ignoreversion
Source: "..\vant\modules\inventory\*.py"; DestDir: "{app}\vant\modules\inventory"; Flags: ignoreversion
Source: "..\vant\modules\heartbeat\*.py"; DestDir: "{app}\vant\modules\heartbeat"; Flags: ignoreversion
Source: "..\vant\modules\collectors\*.py"; DestDir: "{app}\vant\modules\collectors"; Flags: ignoreversion
Source: "..\vant\modules\screen\*.py"; DestDir: "{app}\vant\modules\screen"; Flags: ignoreversion
Source: "..\vant\modules\dlp\*.py"; DestDir: "{app}\vant\modules\dlp"; Flags: ignoreversion

; Setup scripts
Source: "setup.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\linux\common\agent_installer_cli.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\linux\common\agent_tools.py"; DestDir: "{app}"; Flags: ignoreversion

; Config templates
Source: "..\config.template.yaml"; DestDir: "{app}"; DestName: "config.template.yaml"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\config.example.yaml"; DestDir: "{app}"; DestName: "config.template.yaml"; Flags: ignoreversion skipifsourcedoesntexist

; Dependencies
Source: "..\requirements.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{sys}\python.exe"; Parameters: """{app}\agent_tray.py"" --config ""{app}\config.yaml"""; WorkingDir: "{app}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{sys}\python.exe"; Parameters: """{app}\agent_tray.py"" --config ""{app}\config.yaml"""; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\setup.bat"; Description: "Complete installation (admin)"; Flags: runhidden runascurrentuser postinstall skipifsilent; Tasks: runwizard
Filename: "{sys}\python.exe"; Parameters: """{app}\agent.py"" --config ""{app}\config.yaml"""; Description: "Launch agent now"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\.vant_state"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\collectors\__pycache__"
Type: filesandordirs; Name: "{app}\services\__pycache__"

[UninstallRun]
Filename: "{sys}\schtasks"; Parameters: "/Delete /TN VANT-SIEM-Agent /F"; Flags: runhidden runascurrentuser
