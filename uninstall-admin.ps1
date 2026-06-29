param(
  [switch] $RemoveData,
  [switch] $KeepData
)

$ErrorActionPreference = 'Continue'

if ($RemoveData -and $KeepData) {
  throw 'Use either -RemoveData or -KeepData, not both.'
}

function Get-NativeProgramFiles {
  $programFiles = [Environment]::GetEnvironmentVariable('ProgramW6432')
  if ([string]::IsNullOrWhiteSpace($programFiles)) {
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
  }
  if ([string]::IsNullOrWhiteSpace($programFiles)) {
    $programFiles = $env:ProgramFiles
  }
  return $programFiles
}

$installDir = Join-Path (Get-NativeProgramFiles) 'MyVpnClient'
$dataDir = Join-Path $env:ProgramData 'MyVpnClient'
$startMenuDir = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\MyVpnClient'
$uninstallKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyVpnClient'

function Confirm-RemoveData {
  if ($RemoveData) {
    return $true
  }

  if ($KeepData -or -not [Environment]::UserInteractive) {
    return $false
  }

  try {
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    $message = @"
Uninstall will remove MyVpnClient application files from:
$installDir

Do you also want to remove saved profiles, configuration, logs and diagnostics from:
$dataDir
"@
    $result = [System.Windows.Forms.MessageBox]::Show(
      $message,
      'Uninstall MyVpnClient',
      [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
      [System.Windows.Forms.MessageBoxIcon]::Question
    )
    if ($result -eq [System.Windows.Forms.DialogResult]::Cancel) {
      throw 'Uninstall cancelled.'
    }
    return $result -eq [System.Windows.Forms.DialogResult]::Yes
  } catch {
    if ($_.Exception.Message -eq 'Uninstall cancelled.') {
      throw
    }

    Write-Host "Could not show data-removal prompt, keeping MyVpnClient data by default: $dataDir"
    return $false
  }
}

function Remove-DirectoryIfExpected {
  param(
    [Parameter(Mandatory=$true)] [string] $Path,
    [Parameter(Mandatory=$true)] [string] $ExpectedPath,
    [string] $Description = 'directory',
    [switch] $IgnoreMissing
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    if (-not $IgnoreMissing) {
      Write-Host "Skipping missing $Description`: $Path"
    }
    return
  }

  $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
  $resolvedExpected = $ExpectedPath
  if (Test-Path -LiteralPath $ExpectedPath) {
    $resolvedExpected = (Resolve-Path -LiteralPath $ExpectedPath).Path
  }

  if ($resolvedPath -ne $resolvedExpected) {
    throw "Refusing to remove unexpected $Description path: $resolvedPath"
  }

  Remove-Item -LiteralPath $resolvedPath -Recurse -Force -ErrorAction SilentlyContinue
}

if (Test-Path -LiteralPath (Join-Path $dataDir 'uninstall-helper-tasks-admin.ps1')) {
  & (Join-Path $dataDir 'uninstall-helper-tasks-admin.ps1')
} else {
  Unregister-ScheduledTask -TaskName 'MyVpnClient-Connect' -Confirm:$false -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName 'MyVpnClient-Disconnect' -Confirm:$false -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName 'MyVpnClient-RepairNetwork' -Confirm:$false -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName 'MyVpnClient Connect' -Confirm:$false -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName 'MyVpnClient Disconnect' -Confirm:$false -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName 'MyVpnClient Repair Network' -Confirm:$false -ErrorAction SilentlyContinue
}

Get-Process -Name MyVpnClient -ErrorAction SilentlyContinue | Stop-Process -Force

Remove-DirectoryIfExpected -Path $startMenuDir -ExpectedPath (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\MyVpnClient') -Description 'Start Menu folder' -IgnoreMissing
Remove-Item -Path $uninstallKey -Recurse -Force -ErrorAction SilentlyContinue
Remove-DirectoryIfExpected -Path $installDir -ExpectedPath (Join-Path (Get-NativeProgramFiles) 'MyVpnClient') -Description 'install folder' -IgnoreMissing

if (Confirm-RemoveData) {
  Remove-DirectoryIfExpected -Path $dataDir -ExpectedPath (Join-Path $env:ProgramData 'MyVpnClient') -Description 'data folder' -IgnoreMissing
  Write-Host 'Removed MyVpnClient data.'
} else {
  Write-Host "Kept MyVpnClient data: $dataDir"
}

Write-Host 'MyVpnClient uninstalled.'



