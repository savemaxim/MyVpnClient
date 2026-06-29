$ErrorActionPreference = 'Stop'

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$bridgePath = Join-Path $projectDir 'myvpnclient_bridge.py'
$configPath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'MyVpnClient\config.json'

if (-not (Test-Path -LiteralPath $bridgePath)) {
  throw "Missing bridge script: $bridgePath"
}

foreach ($oldTaskName in @(
  'MyVpnClient Connect',
  'MyVpnClient Disconnect',
  'MyVpnClient Repair Network',
  'MyVpnClient Reset Network',
  'MyVpnClient Full Diagnostic'
)) {
  Unregister-ScheduledTask -TaskName $oldTaskName -Confirm:$false -ErrorAction SilentlyContinue
}

function Register-MyVpnTask {
  param(
    [Parameter(Mandatory=$true)] [string] $Name,
    [Parameter(Mandatory=$true)] [string] $Command,
    [Parameter(Mandatory=$true)] [TimeSpan] $ExecutionTimeLimit
  )

  $argument = "-B `"$bridgePath`" --config `"$configPath`" $Command"
  $action = New-ScheduledTaskAction `
    -Execute 'py.exe' `
    -Argument $argument `
    -WorkingDirectory $projectDir
  $principal = New-ScheduledTaskPrincipal `
    -UserId $user `
    -LogonType Interactive `
    -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -Hidden `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit $ExecutionTimeLimit

  Register-ScheduledTask `
    -TaskName $Name `
    -Action $action `
    -Principal $principal `
    -Settings $settings `
    -Description "MyVpnClient elevated Python task installed from $projectDir" `
    -Force | Out-Null
}

Register-MyVpnTask -Name 'MyVpnClient-Connect' -Command 'connect-watch' -ExecutionTimeLimit (New-TimeSpan -Hours 12)
Register-MyVpnTask -Name 'MyVpnClient-Disconnect' -Command 'disconnect' -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-MyVpnTask -Name 'MyVpnClient-RepairNetwork' -Command 'fix-network' -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-MyVpnTask -Name 'MyVpnClient-ResetNetwork' -Command 'reset-network' -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-MyVpnTask -Name 'MyVpnClient-FullDiagnostic' -Command 'full-diagnostic' -ExecutionTimeLimit (New-TimeSpan -Minutes 8)

Write-Host 'Installed MyVpnClient Python helper tasks:'
Write-Host '  MyVpnClient-Connect'
Write-Host '  MyVpnClient-Disconnect'
Write-Host '  MyVpnClient-RepairNetwork'
Write-Host '  MyVpnClient-ResetNetwork'
Write-Host '  MyVpnClient-FullDiagnostic'
