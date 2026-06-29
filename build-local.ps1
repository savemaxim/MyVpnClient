param([switch]$NoPause)

$ErrorActionPreference = "Stop"

# Read version from csproj so we never need to hand-edit this script.
$csproj = Join-Path $PSScriptRoot "src\MyVpnClient\MyVpnClient.csproj"
[xml]$_xml = Get-Content $csproj
$version = $_xml.Project.PropertyGroup.Version
if (-not $version) { throw "Could not read Version from MyVpnClient.csproj" }
$fileVersion = "$version.0"
$root = $PSScriptRoot
$publishDir = Join-Path $root "artifacts\publish\MyVpnClient"
$packageDir = Join-Path $root "artifacts\package"
$distDir = Join-Path $root "artifacts"

Write-Host "=== MyVpnClient $version local build ===" -ForegroundColor Cyan

# Publish
if (Test-Path $publishDir) {
    Remove-Item -LiteralPath $publishDir -Recurse -Force
}
Write-Host "`n[1/3] Publishing MyVpnClient..." -ForegroundColor Yellow
dotnet publish "$root\src\MyVpnClient\MyVpnClient.csproj" `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:Version=$version -p:FileVersion=$fileVersion `
  -p:AssemblyVersion=$fileVersion -p:InformationalVersion=$version `
  -o $publishDir

Write-Host "`n[2/3] Staging MSI payload..." -ForegroundColor Yellow
$artifactsRoot = [System.IO.Path]::GetFullPath((Join-Path $root "artifacts"))
$packageRoot = [System.IO.Path]::GetFullPath($packageDir)
if (-not $packageRoot.StartsWith($artifactsRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean unexpected package directory: $packageRoot"
}
if (Test-Path $packageRoot) {
    Remove-Item -LiteralPath $packageRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $packageDir | Out-Null
Copy-Item -Path (Join-Path $publishDir "*") -Destination $packageDir -Recurse -Force
Copy-Item "$root\README.md", "$root\LICENSE", "$root\THIRD_PARTY_NOTICES.md", "$root\OPENCONNECT-LGPL-2.1.txt", "$root\GITHUB_PUBLISH_CHECKLIST.md" -Destination $packageDir -Force
Copy-Item "$root\myvpnclient_bridge.py", "$root\connect-admin.ps1" -Destination $packageDir -Force
Copy-Item "$root\install-helper-tasks-admin.ps1", "$root\uninstall-helper-tasks-admin.ps1" -Destination $packageDir -Force
Copy-Item "$root\run-helper-task.ps1", "$root\task-connect.ps1", "$root\task-disconnect.ps1" -Destination $packageDir -Force
Copy-Item "$root\task-repair-network.ps1", "$root\task-reset-network.ps1" -Destination $packageDir -Force
Copy-Item "$root\config.example.json", "$root\profiles.example.json" -Destination $packageDir -Force
Copy-Item "$root\backend" -Destination $packageDir -Recurse -Force
Copy-Item "$root\installer\MyVpnClient.wxs", "$root\installer\License.rtf" -Destination $packageDir -Force
New-Item -ItemType Directory -Force -Path (Join-Path $packageDir "MyVpnClient") | Out-Null
Copy-Item "$root\src\MyVpnClient\AppIcon.ico" -Destination (Join-Path $packageDir "MyVpnClient\AppIcon.ico") -Force

# Bundle OpenConnect for Windows runtime used by the default tunnel backend.
$openConnectSourceCandidates = @(
    "C:\Program Files\OpenConnect",
    "C:\Program Files\MyVpnClient\OpenConnect"
)
$openConnectSource = $openConnectSourceCandidates |
    Where-Object { Test-Path (Join-Path $_ "openconnect.exe") } |
    Select-Object -First 1
$openConnectPackageDir = Join-Path $packageDir "OpenConnect"
if (-not $openConnectSource) {
    throw "OpenConnect runtime not found. Install OpenConnect for Windows or install a bundled MyVpnClient first."
}
New-Item -ItemType Directory -Force -Path $openConnectPackageDir | Out-Null
$openConnectFiles = @(
    "openconnect.exe",
    "vpnc-script-win.js",
    "list-system-keys.exe",
    "wintun.dll",
    "iconv.dll",
    "libffi-8.dll",
    "libgcc_s_seh-1.dll",
    "libgmp-10.dll",
    "libgnutls-30.dll",
    "libhogweed-6.dll",
    "libintl-8.dll",
    "liblz4.dll",
    "libnettle-8.dll",
    "libopenconnect-5.dll",
    "libp11-kit-0.dll",
    "libstoken-1.dll",
    "libtasn1-6.dll",
    "libwinpthread-1.dll",
    "libxml2-2.dll",
    "zlib1.dll",
    "Online Documentation.url"
)
foreach ($file in $openConnectFiles) {
    Copy-Item -LiteralPath (Join-Path $openConnectSource $file) -Destination $openConnectPackageDir -Force
}

Write-Host "`n[3/3] Building MSI..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $distDir | Out-Null
$msiPath = Join-Path $distDir "MyVpnClient-$version-win-x64.msi"

# Locate wix: prefer project-local tool, fall back to PATH.
$wixExe = Join-Path $root ".tools\wix.exe"
if (-not (Test-Path $wixExe)) {
    $wixExe = "wix"
}
Write-Host "Using wix: $wixExe"

function Resolve-WixExtension {
    param(
        [Parameter(Mandatory=$true)] [string] $Name,
        [Parameter(Mandatory=$true)] [string] $DllName
    )

    $projectExt = Join-Path $root ".wix\extensions\$Name\7.0.0\wixext7\$DllName"
    if (Test-Path $projectExt) { return $projectExt }

    $userExt = Join-Path $env:USERPROFILE ".wix\extensions\$Name\7.0.0\wixext7\$DllName"
    if (Test-Path $userExt) { return $userExt }

    return $Name
}

$uiExtDll = Resolve-WixExtension -Name "WixToolset.UI.wixext" -DllName "WixToolset.UI.wixext.dll"
$utilExtDll = Resolve-WixExtension -Name "WixToolset.Util.wixext" -DllName "WixToolset.Util.wixext.dll"
Write-Host "Using UI extension: $uiExtDll"
Write-Host "Using Util extension: $utilExtDll"

Push-Location $packageDir
& $wixExe build .\MyVpnClient.wxs `
  -arch x64 `
  -ext $uiExtDll `
  -ext $utilExtDll `
  -d ProductVersion=$version `
  -o $msiPath
if ($LASTEXITCODE -ne 0) { throw "wix build failed with exit code $LASTEXITCODE" }
Pop-Location

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $msiPath).Hash
"$hash  MyVpnClient-$version-win-x64.msi" | Set-Content -Encoding ascii (Join-Path $distDir "MyVpnClient-$version-win-x64.msi.sha256")

Write-Host "`n=== Done! ===" -ForegroundColor Green
Write-Host "MSI: $msiPath"
if (-not $NoPause) {
    Write-Host "Press any key to close..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
