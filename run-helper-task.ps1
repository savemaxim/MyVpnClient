param(
  [Parameter(Mandatory=$true)]
  [ValidateSet('connect', 'disconnect', 'repair', 'reset', 'full-diagnostic')]
  [string] $Action
)

$taskName = switch ($Action) {
  'connect' { 'MyVpnClient-Connect' }
  'disconnect' { 'MyVpnClient-Disconnect' }
  'repair' { 'MyVpnClient-RepairNetwork' }
  'reset' { 'MyVpnClient-ResetNetwork' }
  'full-diagnostic' { 'MyVpnClient-FullDiagnostic' }
}

Write-Host "Starting scheduled task: $taskName"
schtasks.exe /Run /TN $taskName
if ($LASTEXITCODE -ne 0) {
  throw "Failed to start scheduled task '$taskName' (schtasks exit code $LASTEXITCODE)."
}

schtasks.exe /Query /TN $taskName /FO LIST | Select-String -Pattern 'TaskName:', 'Status:', 'Last Run Time:', 'Last Result:' | ForEach-Object {
  Write-Host $_.Line
}
