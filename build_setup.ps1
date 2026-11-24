$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$appVersion = (Get-Content -LiteralPath (Join-Path $root "VERSION") -Raw).Trim()

# Optional Authenticode signing. Unsigned builds are the default; signing turns on when one of these is set:
#   WAP_SIGN_THUMBPRINT  SHA1 thumbprint of a code-signing certificate in the Windows certificate store
#   WAP_SIGN_COMMAND     any signing command; {file} is replaced with the quoted path (CA cloud-signing tools)
# WAP_SIGN_TIMESTAMP overrides the RFC 3161 timestamp server.
function Get-SigningTool {
    $kits = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    $found = Get-ChildItem -Path $kits -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like "*\x64\signtool.exe" } | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $found) { throw "signtool.exe not found under $kits" }
    return $found.FullName
}

function Invoke-CodeSigning([string[]]$files) {
    $thumbprint = $env:WAP_SIGN_THUMBPRINT
    $command = $env:WAP_SIGN_COMMAND
    if ([string]::IsNullOrWhiteSpace($thumbprint) -and [string]::IsNullOrWhiteSpace($command)) { return }
    $timestamp = if ($env:WAP_SIGN_TIMESTAMP) { $env:WAP_SIGN_TIMESTAMP } else { "http://timestamp.digicert.com" }
    foreach ($file in $files) {
        if ($command) {
            Invoke-Expression ($command.Replace("{file}", '"' + $file + '"'))
        }
        else {
            & (Get-SigningTool) sign /sha1 $thumbprint /fd sha256 /tr $timestamp /td sha256 /d "App PIN Guard" $file
        }
        if ($LASTEXITCODE -ne 0) { throw "Signing failed: $file" }
        Write-Host "Signed $file"
    }
}

$candidateRoots = @(
    (Join-Path $root "src\Avalonia\bin"),
    (Join-Path $root "build")
)

Get-Process WindowsAppProtector.WinUI -ErrorAction SilentlyContinue | Where-Object {
    try {
        $processPath = $_.Path
        $candidateRoots | Where-Object {
            $processPath.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase)
        }
    }
    catch {
        $false
    }
} | Stop-Process -Force -ErrorAction SilentlyContinue

$payloadSource = Join-Path $root "build\publish-win-x64"
# Publish, rather than build output, includes the self-contained .NET and Avalonia runtimes.
if (Test-Path -LiteralPath $payloadSource) {
    $resolved = (Resolve-Path -LiteralPath $payloadSource).Path
    if ($resolved -ne (Join-Path $root "build\publish-win-x64")) { throw "Unexpected publish directory: $resolved" }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
& dotnet publish "$root\src\Avalonia\WindowsAppProtector.App.csproj" -c Release -p:Platform=x64 -r win-x64 --self-contained true -o $payloadSource
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

foreach ($required in @("hostfxr.dll", "coreclr.dll", "Avalonia.Base.dll", "libSkiaSharp.dll")) {
    if (!(Test-Path -LiteralPath (Join-Path $payloadSource $required))) { throw "Missing app-local runtime: $required" }
}
# Shared C# 5 sources (one schema/serializer for every component); each csc build gets only what it needs.
function Get-SharedSources([string[]]$names) { $names | ForEach-Object { Join-Path $root ("src\Shared\" + $_ + ".cs") } }
$productBrandSource = Join-Path $root "src\Shared\ProductBrand.cs"
$serviceSources = @(Get-ChildItem -LiteralPath (Join-Path $root "src\Service") -Filter *.cs | ForEach-Object { $_.FullName }) +
    (Get-SharedSources @("ProductBrand", "WapPaths", "WapLog", "PolicyModel", "PolicyStore", "PolicyRules", "PinHash", "GateSpool", "StatusModel", "EnforcementFile", "LegacyMigration", "WapSecurity"))
$gateShared = Get-SharedSources @("ProductBrand", "WapPaths", "WapLog", "GateSpool", "WapSecurity", "EnforcementFile", "WindowResolver")
$agentShared = Get-SharedSources @("WapPaths", "WapLog", "WapSecurity", "EnforcementFile", "WindowResolver")
$setupShared = Get-SharedSources @("ProductBrand", "WapPaths")
$agentSource = Join-Path $root "src\WindowAgent\Program.cs"
$gateSource = Join-Path $root "src\LaunchGate\Program.cs"
$gateThemeSource = Join-Path $root "src\LaunchGate\GateTheme.cs"
$gateFormSource = Join-Path $root "src\LaunchGate\GateForm.cs"
$gateManifest = Join-Path $root "src\LaunchGate\app.manifest"
$gateFontDir = Join-Path $root "src\Avalonia\Assets\Fonts"
$serviceBuildDir = Join-Path $root "build\service"
$serviceExe = Join-Path $serviceBuildDir "WindowsAppProtector.Service.exe"
$buildDir = Join-Path $root "build\installer"
$payloadDir = Join-Path $buildDir "payload"
$distDir = Join-Path $root "dist\installer"
$setupSource = Join-Path $root "src\Installer\Setup.cs"
$manifest = Join-Path $root "src\Installer\app.manifest"
$icon = Join-Path $root "src\Avalonia\Assets\AppIcon.ico"
$setupExe = Join-Path $distDir "Setup.exe"
$versionedDistDir = Join-Path $root ("dist\releases\" + $appVersion)
$zipPath = Join-Path $buildDir "payload.zip"

foreach ($cleanupDir in @($buildDir, $distDir, $serviceBuildDir)) {
    if (Test-Path -LiteralPath $cleanupDir) {
        $resolved = (Resolve-Path -LiteralPath $cleanupDir).Path
        if (!$resolved.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected cleanup directory: $resolved" }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
New-Item -ItemType Directory -Path $serviceBuildDir | Out-Null
New-Item -ItemType Directory -Path $payloadDir | Out-Null
New-Item -ItemType Directory -Path $distDir | Out-Null

$csc = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (!(Test-Path $csc)) {
    throw "csc.exe not found: $csc"
}

& $csc /nologo /codepage:65001 /target:exe /optimize+ /warnaserror+ /reference:System.ServiceProcess.dll /reference:System.Runtime.Serialization.dll /reference:System.Management.dll /out:$serviceExe $serviceSources
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Copy-Item -Path (Join-Path $payloadSource "*") -Destination $payloadDir -Recurse -Force
Copy-Item -LiteralPath $serviceExe -Destination $payloadDir -Force
$gateExe = Join-Path $payloadDir "WindowsAppProtector.Gate.exe"
& $csc /nologo /codepage:65001 /target:winexe /platform:x64 /optimize+ /win32manifest:$gateManifest /win32icon:$icon /warnaserror+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Runtime.Serialization.dll /out:$gateExe $gateSource $gateThemeSource $gateFormSource $gateShared
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
foreach ($fontName in @("Pretendard-Regular.otf", "Pretendard-SemiBold.otf")) {
    $fontSource = Join-Path $gateFontDir $fontName
    if (!(Test-Path -LiteralPath $fontSource)) {
        throw "Gate font not found: $fontSource"
    }
    Copy-Item -LiteralPath $fontSource -Destination (Join-Path $payloadDir $fontName) -Force
}
$agentExe = Join-Path $payloadDir "WindowsAppProtector.WindowAgent.exe"
& $csc /nologo /codepage:65001 /target:winexe /platform:x64 /optimize+ /warnaserror+ /win32manifest:$gateManifest /win32icon:$icon /reference:System.Runtime.Serialization.dll /out:$agentExe $agentSource $agentShared
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
$payloadAssetsDir = Join-Path $payloadDir "Assets"
New-Item -ItemType Directory -Path $payloadAssetsDir -Force | Out-Null
Copy-Item -LiteralPath $icon -Destination (Join-Path $payloadAssetsDir "AppIcon.ico") -Force

& $csc /nologo /codepage:65001 /target:winexe /optimize+ /warnaserror+ /win32manifest:$manifest /win32icon:$icon /reference:System.IO.Compression.FileSystem.dll /out:$setupExe $setupSource $setupShared
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Invoke-CodeSigning @((Join-Path $payloadDir "WindowsAppProtector.Service.exe"), $gateExe, $agentExe, (Join-Path $payloadDir "WindowsAppProtector.WinUI.exe"))

Add-Type -AssemblyName System.IO.Compression.FileSystem
if (Test-Path $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
[System.IO.Compression.ZipFile]::CreateFromDirectory($payloadDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

$zipBytes = [System.IO.File]::ReadAllBytes($zipPath)
$lengthBytes = [BitConverter]::GetBytes([Int64]$zipBytes.Length)
$markerBytes = [System.Text.Encoding]::ASCII.GetBytes("WAPZIP01")
$stream = [System.IO.File]::Open($setupExe, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
try {
    $stream.Write($zipBytes, 0, $zipBytes.Length)
    $stream.Write($lengthBytes, 0, $lengthBytes.Length)
    $stream.Write($markerBytes, 0, $markerBytes.Length)
}
finally {
    $stream.Dispose()
}

# The signature goes last: it sits after the appended payload, which Setup finds through the PE certificate table.
Invoke-CodeSigning @($setupExe)

Write-Host "Created $setupExe"
New-Item -ItemType Directory -Path $versionedDistDir -Force | Out-Null
Copy-Item -LiteralPath $setupExe -Destination (Join-Path $versionedDistDir "Setup.exe") -Force
Write-Host "Preserved versioned installer at $(Join-Path $versionedDistDir 'Setup.exe')"
