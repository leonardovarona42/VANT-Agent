; ┌──────────────────────────────────────────────────────────────────────────┐
; │                   VANT-Agent Windows Installer                          │
; │                   Inno Setup Script v6.x                                │
; │                                                                         │
; │ Build: build_installer.ps1                                              │
; └──────────────────────────────────────────────────────────────────────────┘

#define MyAppName "VANT-Agent"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "VANT-SIEM"
#define MyAppURL "https://github.com/leonardovarona42/VANT-SIEM"
#define MyAppExeName "VANT-Agent.exe"

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
LicenseFile=
OutputDir=..\dist\installer
OutputBaseFilename=VANT-Agent-Setup-{#MyAppVersion}
SetupIconFile=
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
WizardImageFile=
WizardSmallImageFile=
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "startservice"; Description: "Start agent after installation"; GroupDescription: "Service Options:"; Flags: checkedonce

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\config.example.yaml"; DestDir: "{app}"; DestName: "config.yaml"; Flags: onlyifdoesntexist
Source: "..\requirements.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{#MyAppName} Configuration"; Filename: "{app}\config.yaml"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch VANT-Agent"; Flags: nowait postinstall skipifsilent; Tasks: startservice

[UninstallDelete]
Type: filesandordirs; Name: "{app}\.vant_state"
Type: filesandordirs; Name: "{app}\logs"

[Code]
var
  ServerPage: TInputQueryWizardPage;
  LogsServerPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  ServerPage := CreateInputQueryPage(wpInfoBefore,
    'Server Configuration', 'VANT-SIEM Server Address',
    'Enter the address of your VANT-SIEM server. The agent will connect to this server to register and send data.');
  ServerPage.Add('Server URL (port 8000):', False);
  ServerPage.Values[0] := 'http://localhost:8000';

  LogsServerPage := CreateInputQueryPage(ServerPage.ID,
    'Logs Service Address', 'Logs Service URL',
    'Enter the address of the Logs Service (usually port 9201).');
  LogsServerPage.Add('Logs Service URL (port 9201):', False);
  LogsServerPage.Values[0] := 'http://localhost:9201';
end;

function UpdateConfigFile(const FileName, ServerUrl, LogsUrl: String): Boolean;
var
  Lines: TArrayOfString;
  I: Integer;
  NewLines: TStringList;
  Line: String;
begin
  Result := False;
  NewLines := TStringList.Create;
  try
    if LoadStringsFromFile(FileName, Lines) then
    begin
      for I := 0 to GetArrayLength(Lines) - 1 do
      begin
        Line := Lines[I];
        if (Pos('url:', Line) > 0) and (Pos('logs_url', Line) = 0) and (Pos('#', Trim(Line)) = 0) then
        begin
          Line := Format('  url: "%s"', [ServerUrl]);
        end
        else if Pos('logs_url:', Line) > 0 then
        begin
          Line := Format('  logs_url: "%s"', [LogsUrl]);
        end;
        NewLines.Add(Line);
      end;
      NewLines.SaveToFile(FileName);
      Result := True;
    end;
  finally
    NewLines.Free;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigPath: String;
begin
  if CurStep = ssPostInstall then
  begin
    ConfigPath := ExpandConstant('{app}\config.yaml');
    if FileExists(ConfigPath) then
    begin
      UpdateConfigFile(ConfigPath,
        ServerPage.Values[0],
        LogsServerPage.Values[0]);
    end;
  end;
end;
