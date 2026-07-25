# Run this script AS ADMINISTRATOR to update the deployed agent
# Right-click -> "Run with PowerShell" -> "Yes" to UAC

$agentDir = "C:\Program Files\VANT-Agent"
$sourceExe = "C:\Users\leona\3D Objects\VANT-Agent\dist\VANT-Agent.exe"
$token = "92a6f7b6-6a54-4c3b-b357-3af798e8b7e9"

Write-Host "Stopping agent..." -ForegroundColor Yellow
$proc = Get-Process -Name "VANT-Agent" -ErrorAction SilentlyContinue
if ($proc) { $proc | Stop-Process -Force; Start-Sleep -Seconds 2 }

Write-Host "Copying new VANT-Agent.exe..." -ForegroundColor Yellow
Copy-Item -Path $sourceExe -Destination "$agentDir\VANT-Agent.exe" -Force

Write-Host "Updating config.yaml with enrollment token..." -ForegroundColor Yellow
python -c "
import yaml
p = r'$agentDir\config.yaml'
with open(p) as f:
    c = yaml.safe_load(f)
c['output']['auth']['mode'] = 'token'
c['output']['auth']['token'] = '$token'
c['control']['token'] = '$token'
with open(p, 'w') as f:
    yaml.dump(c, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
print('Config updated OK')
"

Write-Host "Clearing old state for fresh start..." -ForegroundColor Yellow
Remove-Item "$agentDir\.agent_state\*" -Force -ErrorAction SilentlyContinue
Remove-Item "$agentDir\.vant_state\*" -Force -ErrorAction SilentlyContinue

Write-Host "Starting agent..." -ForegroundColor Yellow
Start-Process -FilePath "$agentDir\VANT-Agent.exe" -WorkingDirectory $agentDir

Write-Host "`nDone! Agent updated and restarted with:" -ForegroundColor Green
Write-Host "  - Fixed EventLog collector (no more 0 events)" -ForegroundColor Cyan
Write-Host "  - Token $token" -ForegroundColor Cyan
