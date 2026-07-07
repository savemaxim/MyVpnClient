param([switch]$NoPause)

$ErrorActionPreference = "Stop"

function Convert-PackageScriptToLf {
    param([Parameter(Mandatory=$true)] [string] $Path)
    $text = [System.IO.File]::ReadAllText($Path).Replace("`r`n", "`n").Replace("`r", "`n")
    [System.IO.File]::WriteAllText($Path, $text, [System.Text.UTF8Encoding]::new($false))
}


$root = $PSScriptRoot
$csproj = Join-Path $root "src\MyVpnClient\MyVpnClient.csproj"
[xml]$_xml = Get-Content $csproj
$version = $_xml.Project.PropertyGroup.Version
if (-not $version) { throw "Could not read Version from MyVpnClient.csproj" }
$publishDir = Join-Path $root "artifacts\publish\MyVpnClient-linux-x64"
$distDir = Join-Path $root "artifacts"
$zipPath = Join-Path $distDir "MyVpnClient-$version-linux-x64.zip"

Write-Host "=== MyVpnClient $version Linux x64 package ===" -ForegroundColor Cyan

if (Test-Path $publishDir) {
    Remove-Item -LiteralPath $publishDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $publishDir | Out-Null
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

Write-Host "`n[1/2] Staging Linux CLI package..." -ForegroundColor Yellow
Copy-Item "$root\backend" -Destination $publishDir -Recurse -Force
Copy-Item "$root\myvpnclient_bridge.py", "$root\config.example.json", "$root\config.linux.example.json", "$root\myvpnclient-linux", "$root\install-linux.sh", "$root\update-linux.sh" -Destination $publishDir -Force
Convert-PackageScriptToLf (Join-Path $publishDir "myvpnclient-linux")
Convert-PackageScriptToLf (Join-Path $publishDir "install-linux.sh")
Convert-PackageScriptToLf (Join-Path $publishDir "update-linux.sh")
Copy-Item "$root\README.md", "$root\LICENSE", "$root\THIRD_PARTY_NOTICES.md" -Destination $publishDir -Force

Write-Host "`n[2/2] Creating zip and checksum..." -ForegroundColor Yellow
if (Test-Path $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
Compress-Archive -Path (Join-Path $publishDir "*") -DestinationPath $zipPath -Force
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash
"$hash  MyVpnClient-$version-linux-x64.zip" | Set-Content -Encoding ascii (Join-Path $distDir "MyVpnClient-$version-linux-x64.zip.sha256")

Write-Host "`n=== Done! ===" -ForegroundColor Green
Write-Host "Zip: $zipPath"
if (-not $NoPause) {
    Write-Host "Press any key to close..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
