param(
  [Parameter(Position = 0)]
  [string] $Command = 'preflight',
  [int] $DurationSeconds = 90,
  [string] $Config = 'C:\ProgramData\MyVpnClient\config.json',
  [string] $OpenConnectSource = (Join-Path (Split-Path -Parent $PSScriptRoot) '..\openconnect'),
  [switch] $PreferDtls,
  [switch] $ForceOnlinkJira,
  [switch] $WindowsResolver,
  [switch] $DisablePostConnectNetworkFix,
  [switch] $KeepAlive,
  [switch] $TracePackets,
  [switch] $NoFastDataPath,
  [switch] $SkipLiveAdapterCheck,
  [switch] $SkipLiveRouteCheck,
  [switch] $SkipLiveTcpCheck,
  [switch] $SkipLiveHttpsCheck,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]] $ExtraArgs
)

$ErrorActionPreference = 'Stop'
$pythonCommand = Get-Command py -ErrorAction SilentlyContinue
if (-not $pythonCommand) {
  throw 'Python launcher `py` was not found on PATH.'
}
$python = $pythonCommand.Source
$labArgs = @($Command, '--config', $Config, '--openconnect-source', $OpenConnectSource, '--duration-seconds', $DurationSeconds)
if ($PreferDtls) { $labArgs += '--prefer-dtls' }
if ($ForceOnlinkJira) { $labArgs += '--force-onlink-jira' }
if ($WindowsResolver) { $labArgs += '--windows-resolver' }
if ($DisablePostConnectNetworkFix) { $labArgs += '--disable-post-connect-network-fix' }
if ($KeepAlive) { $labArgs += '--keepalive' }
if ($TracePackets) { $labArgs += '--trace-packets' }
if ($NoFastDataPath) { $labArgs += '--no-fast-data-path' }
if ($SkipLiveAdapterCheck) { $labArgs += '--skip-live-adapter-check' }
if ($SkipLiveRouteCheck) { $labArgs += '--skip-live-route-check' }
if ($SkipLiveTcpCheck) { $labArgs += '--skip-live-tcp-check' }
if ($SkipLiveHttpsCheck) { $labArgs += '--skip-live-https-check' }
if ($ExtraArgs) { $labArgs += $ExtraArgs }
& $python -3 -u -B (Join-Path $PSScriptRoot 'vpn_lab.py') @labArgs
exit $LASTEXITCODE
