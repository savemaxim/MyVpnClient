param(
  [switch] $ForceCloseRunning,
  [switch] $ForceDisconnectVpn
)

$ErrorActionPreference = 'Stop'

$sourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectPath = Join-Path $sourceDir 'src\MyVpnClient\MyVpnClient.csproj'
$publishDir = Join-Path $sourceDir 'artifacts\publish\MyVpnClient'

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
$shortcutPath = Join-Path $startMenuDir 'MyVpnClient.lnk'
$uninstallKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MyVpnClient'
$installUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

function Copy-RequiredFile {
  param(
    [Parameter(Mandatory=$true)] [string] $Name
  )

  $source = Join-Path $sourceDir $Name
  $target = Join-Path $dataDir $Name
  if (-not (Test-Path -LiteralPath $source)) {
    throw "Missing required source file: $source"
  }
  Copy-Item -LiteralPath $source -Destination $target -Force
}

function Copy-RequiredDirectory {
  param(
    [Parameter(Mandatory=$true)] [string] $Name
  )

  $source = Join-Path $sourceDir $Name
  $target = Join-Path $dataDir $Name
  if (-not (Test-Path -LiteralPath $source)) {
    throw "Missing required source directory: $source"
  }
  if (Test-Path -LiteralPath $target) {
    Remove-Item -LiteralPath $target -Recurse -Force
  }
  Copy-Item -LiteralPath $source -Destination $target -Recurse -Force
}

function Stop-RunningMyVpnClient {
  $processes = @(Get-Process -Name MyVpnClient -ErrorAction SilentlyContinue)
  if ($processes.Count -eq 0) {
    return
  }

  $ids = ($processes | Select-Object -ExpandProperty Id) -join ', '
  if (-not $ForceCloseRunning) {
    if (-not [Environment]::UserInteractive) {
      throw "MyVpnClient is running (PID: $ids). Re-run with -ForceCloseRunning to close it during install."
    }

    $answer = Read-Host "MyVpnClient is running (PID: $ids). Close it and continue install? [y/N]"
    if ($answer -notin @('y', 'Y', 'yes', 'YES')) {
      throw 'Install cancelled because MyVpnClient is still running.'
    }
  }

  $processes | Stop-Process -Force
}

function Test-ProcessRunningById {
  param([Parameter(Mandatory=$true)] [int] $ProcessId)

  return $null -ne (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
}

function Disconnect-ActiveVpnForInstall {
  $pidPath = Join-Path $dataDir 'state\openconnect.pid'
  $myvpnStatePath = Join-Path $dataDir 'state\myvpn_tunnel.json'
  if (-not (Test-Path -LiteralPath $pidPath)) {
    return
  }

  $vpnPidText = (Get-Content -LiteralPath $pidPath -ErrorAction SilentlyContinue | Select-Object -First 1)
  $vpnPid = 0
  if (-not [int]::TryParse($vpnPidText, [ref]$vpnPid) -or -not (Test-ProcessRunningById -ProcessId $vpnPid)) {
    Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $myvpnStatePath -Force -ErrorAction SilentlyContinue
    return
  }

  $backendName = 'myvpn_tunnel VPN'

  if (-not $ForceDisconnectVpn) {
    if (-not [Environment]::UserInteractive) {
      throw "$backendName is running (PID: $vpnPid). Re-run with -ForceDisconnectVpn to disconnect it during install."
    }

    $answer = Read-Host "$backendName is running (PID: $vpnPid). Disconnect it and continue install? [y/N]"
    if ($answer -notin @('y', 'Y', 'yes', 'YES')) {
      throw 'Install cancelled because the VPN is still connected.'
    }
  }

  Write-Host "Disconnecting $backendName PID $vpnPid..."
  taskkill.exe /PID $vpnPid /T /F | Out-Null
  Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $myvpnStatePath -Force -ErrorAction SilentlyContinue
}

function Remove-LegacyX86Install {
  $programFilesX86 = ${env:ProgramFiles(x86)}
  if ([string]::IsNullOrWhiteSpace($programFilesX86)) {
    return
  }

  $legacyDir = Join-Path $programFilesX86 'MyVpnClient'
  if (-not (Test-Path -LiteralPath $legacyDir)) {
    return
  }

  $resolvedLegacy = (Resolve-Path -LiteralPath $legacyDir).Path
  $expectedLegacy = Join-Path $programFilesX86 'MyVpnClient'
  if ($resolvedLegacy -ne $expectedLegacy) {
    throw "Refusing to remove unexpected legacy install path: $resolvedLegacy"
  }

  Write-Host "Removing legacy x86 install: $resolvedLegacy"
  Remove-Item -LiteralPath $resolvedLegacy -Recurse -Force
}

Write-Host 'Publishing self-contained MyVpnClient...'
dotnet publish $projectPath `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -o $publishDir


Write-Host "Installing app to $installDir"
Stop-RunningMyVpnClient
Disconnect-ActiveVpnForInstall
Remove-LegacyX86Install
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item -Path (Join-Path $publishDir '*') -Destination $installDir -Recurse -Force

Write-Host "Installing runtime source to $installDir"
foreach ($name in @(
  'myvpnclient_bridge.py',
  'connect-admin.ps1',
  'task-connect.ps1',
  'task-disconnect.ps1',
  'task-repair-network.ps1',
  'task-reset-network.ps1',
  'run-helper-task.ps1',
  'install-helper-tasks-admin.ps1',
  'uninstall-helper-tasks-admin.ps1',
  'config.example.json',
  'profiles.example.json'
)) {
  $source = Join-Path $sourceDir $name
  if (-not (Test-Path -LiteralPath $source)) {
    throw "Missing required source file: $source"
  }
  Copy-Item -LiteralPath $source -Destination (Join-Path $installDir $name) -Force
}
$installTunnelSource = Join-Path $sourceDir 'backend\myvpn_tunnel'
$installTunnelTarget = Join-Path $installDir 'backend\myvpn_tunnel'
$installTunnelParent = Split-Path -Parent $installTunnelTarget
New-Item -ItemType Directory -Force -Path $installTunnelParent | Out-Null
if (Test-Path -LiteralPath $installTunnelTarget) {
  Remove-Item -LiteralPath $installTunnelTarget -Recurse -Force
}
if (Test-Path -LiteralPath (Join-Path $installDir 'myvpn_tunnel')) {
  Remove-Item -LiteralPath (Join-Path $installDir 'myvpn_tunnel') -Recurse -Force
}
Copy-Item -LiteralPath $installTunnelSource -Destination $installTunnelTarget -Recurse -Force

Write-Host "Installing runtime data to $dataDir"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
Copy-RequiredFile 'myvpnclient_bridge.py'
Copy-RequiredFile 'connect-admin.ps1'
Copy-RequiredFile 'task-connect.ps1'
Copy-RequiredFile 'task-disconnect.ps1'
Copy-RequiredFile 'task-repair-network.ps1'
Copy-RequiredFile 'task-reset-network.ps1'
Copy-RequiredFile 'run-helper-task.ps1'
Copy-RequiredFile 'install-helper-tasks-admin.ps1'
Copy-RequiredFile 'uninstall-helper-tasks-admin.ps1'
Copy-RequiredDirectory 'backend'
if (Test-Path -LiteralPath (Join-Path $dataDir 'myvpn_tunnel')) {
  Remove-Item -LiteralPath (Join-Path $dataDir 'myvpn_tunnel') -Recurse -Force
}

if (-not (Test-Path -LiteralPath (Join-Path $dataDir 'config.json'))) {
  if (Test-Path -LiteralPath (Join-Path $sourceDir 'config.json')) {
    Copy-Item -LiteralPath (Join-Path $sourceDir 'config.json') -Destination (Join-Path $dataDir 'config.json') -Force
  } else {
    Copy-Item -LiteralPath (Join-Path $sourceDir 'config.example.json') -Destination (Join-Path $dataDir 'config.json') -Force
  }
}
if (-not (Test-Path -LiteralPath (Join-Path $dataDir 'profiles.json')) -and (Test-Path -LiteralPath (Join-Path $sourceDir 'profiles.json'))) {
  Copy-Item -LiteralPath (Join-Path $sourceDir 'profiles.json') -Destination (Join-Path $dataDir 'profiles.json') -Force
}

New-Item -ItemType Directory -Force -Path (Join-Path $dataDir 'state') | Out-Null
Write-Host "Granting data folder access to $installUser"
icacls.exe $dataDir /grant "${installUser}:(OI)(CI)M" | Out-Null

Write-Host 'Installing elevated helper scheduled tasks...'
& (Join-Path $dataDir 'install-helper-tasks-admin.ps1')

Write-Host 'Creating Start Menu shortcut...'
New-Item -ItemType Directory -Force -Path $startMenuDir | Out-Null
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = Join-Path $installDir 'MyVpnClient.exe'
$shortcut.WorkingDirectory = $installDir
$shortcut.IconLocation = Join-Path $installDir 'MyVpnClient.exe'
$shortcut.Save()

Write-Host 'Installing uninstaller...'
Copy-Item -LiteralPath (Join-Path $sourceDir 'uninstall-admin.ps1') -Destination (Join-Path $installDir 'uninstall-admin.ps1') -Force

Write-Host 'Creating Windows uninstall entry...'
New-Item -Path $uninstallKey -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name 'DisplayName' -Value 'MyVpnClient' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name 'DisplayVersion' -Value '1.0.137' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name 'Publisher' -Value 'MyVpnClient' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name 'InstallLocation' -Value $installDir -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name 'UninstallString' -Value "powershell.exe -ExecutionPolicy Bypass -File `"$installDir\uninstall-admin.ps1`"" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name 'DisplayIcon' -Value (Join-Path $installDir 'MyVpnClient.exe') -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name 'NoModify' -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name 'NoRepair' -Value 1 -PropertyType DWord -Force | Out-Null

$installedVersion = (Get-Item -LiteralPath (Join-Path $installDir 'MyVpnClient.exe')).VersionInfo.ProductVersion
if ($installedVersion -ne '1.0.137') {
  throw "Installed MyVpnClient.exe version verification failed: expected 1.0.137, got $installedVersion"
}

Write-Host ''
Write-Host "MyVpnClient $installedVersion installed."
Write-Host "App: $installDir\MyVpnClient.exe"
Write-Host "Data: $dataDir"














