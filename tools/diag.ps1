<#
.SYNOPSIS
  Collects protection diagnostics into one file. Works without administrator rights; items that need them
  are attempted and reported as failed.
.PARAMETER OutputPath
  Where to write the report. Defaults to diag-output.txt next to this script.
#>
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot "diag-output.txt")
)

$ErrorActionPreference = "Continue"
$dataRoot = Join-Path $env:ProgramData "Windows App Protector"
$lines = New-Object System.Collections.Generic.List[string]
function Add-Line([string]$text) { $script:lines.Add($text) }

function Add-Section([string]$title) {
    Add-Line ""
    Add-Line ("===== " + $title)
}

function Add-Attempt([string]$title, [scriptblock]$action) {
    try { & $action }
    catch { Add-Line ("[failed] " + $title + ": " + $_.Exception.Message) }
}

Add-Line ("time: " + (Get-Date -Format "o"))
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
Add-Line ("user: " + $env:USERNAME + "  admin: " + $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

Add-Section "service"
Add-Attempt "service" {
    $service = Get-CimInstance Win32_Service -Filter "Name='WindowsAppProtectorService'"
    if ($null -eq $service) { Add-Line "service: not installed" }
    else { Add-Line ("service: state=" + $service.State + " start=" + $service.StartMode + " account=" + $service.StartName + " path=" + $service.PathName) }
}
Add-Attempt "processes" {
    foreach ($name in @("WindowsAppProtector.Service", "WindowsAppProtector.WindowAgent", "WindowsAppProtector.WinUI", "WindowsAppProtector.Gate")) {
        $found = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
        Add-Line ("process " + $name + ": " + $found.Count + " running" + $(if ($found.Count -gt 0) { " (session " + (($found | ForEach-Object { $_.SessionId }) -join ",") + ")" } else { "" }))
    }
}

Add-Section "Runtime\status.json"
Add-Attempt "status.json" {
    $statusFile = Join-Path $dataRoot "Runtime\status.json"
    if (Test-Path -LiteralPath $statusFile) { Add-Line ([System.IO.File]::ReadAllText($statusFile)) }
    else { Add-Line "missing" }
}

Add-Section "Runtime\enforcement.txt (paths shown as base64 decoded names only)"
Add-Attempt "enforcement.txt" {
    $enforcementFile = Join-Path $dataRoot "Runtime\enforcement.txt"
    if (Test-Path -LiteralPath $enforcementFile) {
        foreach ($line in [System.IO.File]::ReadAllLines($enforcementFile)) {
            if ($line -match '^([WFLC]):([^|]+)(\|.*)?$') {
                $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[2]))
                Add-Line ($Matches[1] + ": " + (Split-Path -Leaf $decoded) + $Matches[3])
            }
            else { Add-Line $line }
        }
    }
    else { Add-Line "missing" }
}

Add-Section "managed IFEO keys (HKLM read works without admin)"
Add-Attempt "ifeo" {
    $ifeoRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $managed = 0
    foreach ($key in Get-ChildItem $ifeoRoot -ErrorAction Stop) {
        $properties = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
        if ($properties.WindowsAppProtectorManaged -eq "1") {
            $managed++
            $filters = @(Get-ChildItem $key.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like "WAP.Launch.*" })
            Add-Line ("  " + $key.PSChildName + " UseFilter=" + $properties.UseFilter + " Debugger=" + $properties.Debugger + " filters=" + $filters.Count)
        }
        elseif ($properties.Debugger -like "*WindowsAppProtector*") {
            Add-Line ("  " + $key.PSChildName + " (not marked managed) Debugger=" + $properties.Debugger)
        }
    }
    Add-Line ("managed keys: " + $managed)
}

Add-Section "data folder (names, sizes, owner)"
Add-Attempt "data folder" {
    foreach ($item in Get-ChildItem -LiteralPath $dataRoot -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 60) {
        $owner = try { (Get-Acl -LiteralPath $item.FullName).Owner } catch { "?" }
        Add-Line ("  " + $item.FullName.Substring($dataRoot.Length) + "  " + $item.Length + " bytes  " + $item.LastWriteTime.ToString("s") + "  owner=" + $owner)
    }
}

function Add-LogTail([string]$title, [string]$path) {
    Add-Section ($title + " (last 200 lines)")
    if (Test-Path -LiteralPath $path) {
        Get-Content -LiteralPath $path -Tail 200 -Encoding UTF8 | ForEach-Object { Add-Line $_ }
    }
    else { Add-Line "missing: $path" }
}

foreach ($logName in @("service.log", "ui.log")) {
    Add-Attempt $logName { Add-LogTail ("Logs\" + $logName) (Join-Path $dataRoot ("Logs\" + $logName)) }
}
$userLogs = Join-Path $env:LOCALAPPDATA "WindowsAppProtector.WinUI\Logs"
foreach ($logName in @("gate.log", "agent.log")) {
    Add-Attempt $logName { Add-LogTail ("user " + $logName) (Join-Path $userLogs $logName) }
}

$lines | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "done: $OutputPath"
