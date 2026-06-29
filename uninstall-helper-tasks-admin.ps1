$ErrorActionPreference = 'SilentlyContinue'

Unregister-ScheduledTask -TaskName 'MyVpnClient-Connect' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'MyVpnClient-Disconnect' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'MyVpnClient-RepairNetwork' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'MyVpnClient-ResetNetwork' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'MyVpnClient-FullDiagnostic' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'MyVpnClient Connect' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'MyVpnClient Disconnect' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'MyVpnClient Repair Network' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'MyVpnClient Reset Network' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'MyVpnClient Full Diagnostic' -Confirm:$false -ErrorAction SilentlyContinue

Write-Host 'Removed MyVpnClient helper tasks.'
