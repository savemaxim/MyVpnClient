param(
  [string] $AppPath = (Join-Path $PSScriptRoot 'artifacts\MyVpnClient-1.0.44-win-x64\MyVpnClient.exe'),
  [int] $ApiPort = 17873,
  [int] $ConnectTimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'

function Read-Api($Path) {
  Invoke-RestMethod -Uri "http://127.0.0.1:$ApiPort$Path"
}

function Post-Api($Path) {
  Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$ApiPort$Path"
}

Write-Host "Starting MyVpnClient: $AppPath"
$proc = Start-Process -FilePath $AppPath -PassThru
Start-Sleep -Seconds 6

Write-Host 'Initial status:'
Read-Api '/status' | ConvertTo-Json -Depth 5

Write-Host 'Requesting connect. Approve FortiToken if prompted.'
Post-Api '/connect' | ConvertTo-Json -Depth 5

$deadline = (Get-Date).AddSeconds($ConnectTimeoutSeconds)
while ((Get-Date) -lt $deadline) {
  $status = Read-Api '/status'
  $status | ConvertTo-Json -Depth 5
  if ($status.State -eq 'Connected' -or $status.State -eq 'Disconnected') {
    break
  }
  Start-Sleep -Seconds 5
}

Write-Host 'Health before UI kill:'
Read-Api '/health' | ConvertTo-Json -Depth 5

Write-Host "Killing MyVpnClient PID $($proc.Id) to verify owner shutdown behavior."
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 8

$bridge = Join-Path $env:ProgramData 'MyVpnClient\myvpnclient_bridge.py'
Write-Host 'Bridge status after UI kill:'
py -B $bridge status
py -B $bridge health













