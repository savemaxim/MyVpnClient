$ErrorActionPreference = 'Stop'

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$command = "Set-Location -LiteralPath '$projectDir'; py -B .\myvpnclient_bridge.py connect-watch"

Start-Process `
  -FilePath 'powershell.exe' `
  -ArgumentList '-NoProfile', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-Command', $command `
  -WindowStyle Hidden `
  -Verb RunAs
