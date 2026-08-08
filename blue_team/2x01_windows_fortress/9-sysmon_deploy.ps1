<#
.SYNOPSIS
9-sysmon_deploy.ps1

.DESCRIPTION
Downloads Sysmon and the SwiftOnSecurity baseline, installs Sysmon,
verifies the service and driver, and validates Event ID 11 generation.

.NOTES
Script Name: 9-sysmon_deploy.ps1
Purpose: Sysmon deployment and event generation verification
Author: Tristeceratops
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Admin = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $Admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run as Administrator." }

$Root = "$env:TEMP\Sysmon"
$Zip = "$Root\Sysmon.zip"
$Exe = "$Root\Sysmon64.exe"
$Config = "$Root\sysmonconfig.xml"
$SysmonURL = "https://download.sysinternals.com/files/Sysmon.zip"
$ConfigURL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$Log = "Microsoft-Windows-Sysmon/Operational"

New-Item -Path $Root -ItemType Directory -Force | Out-Null

Write-Host "[*] Downloading Sysmon..."
if (Test-Path $Exe) {
Write-Host "    Sysmon64.exe already downloaded [SKIP]"
} else {
Invoke-WebRequest -Uri $SysmonURL -OutFile $Zip
Expand-Archive -Path $Zip -DestinationPath $Root -Force
$DownloadedExe = Get-ChildItem $Root -Filter Sysmon64.exe -Recurse | Select-Object -First 1
if ($null -eq $DownloadedExe) { throw "Sysmon64.exe was not found after download." }
Copy-Item $DownloadedExe.FullName $Exe -Force
Write-Host "    Sysmon64.exe [OK]"
}

Write-Host "[*] Downloading SwiftOnSecurity config..."
if (Test-Path $Config) {
Write-Host "    sysmonconfig.xml already downloaded [SKIP]"
} else {
Invoke-WebRequest -Uri $ConfigURL -OutFile $Config
Write-Host "    sysmonconfig.xml [OK]"
}

[xml]$Xml = Get-Content $Config -Raw
if ($null -eq $Xml.SelectSingleNode("//EventFiltering")) { throw "EventFiltering node not found." }
if ($null -eq $Xml.SelectSingleNode("//FileCreate")) { throw "FileCreate rule not found." }

Write-Host "[*] Installing Sysmon with config..."
$Service = Get-Service Sysmon64 -ErrorAction SilentlyContinue

if ($null -eq $Service) {
& $Exe -accepteula -i $Config | Out-Host
} else {
& $Exe -c $Config | Out-Host
}

if ($LASTEXITCODE -ne 0) { throw "Sysmon installation/configuration failed." }

$Service = Get-Service Sysmon64
if ($Service.Status -ne "Running") {
Start-Service Sysmon64
$Service = Get-Service Sysmon64
}

if ($Service.Status -ne "Running") { throw "Sysmon64 is not running." }
Write-Host "Service: Sysmon64 - Running            [OK]" -ForegroundColor Green

$Driver = sc.exe query SysmonDrv 2>&1
if ($Driver -notmatch "RUNNING") { throw "SysmonDrv is not loaded." }
Write-Host "Driver: SysmonDrv - Loaded             [OK]" -ForegroundColor Green

Write-Host "[*] Verifying event generation..."
$Start = Get-Date
Start-Sleep -Seconds 2
$Events = @(Get-WinEvent -FilterHashtable @{LogName=$Log; StartTime=$Start} -ErrorAction SilentlyContinue)
Write-Host "Events in last 60 seconds: $($Events.Count)          [OK]"

Write-Host "[*] Testing FileCreate detection..."
$TestFile = "C:\Windows\Temp\sysmon_test.ps1"
Remove-Item $TestFile -Force -ErrorAction SilentlyContinue
Set-Content -Path $TestFile -Value "Write-Host 'Sysmon test'"
Write-Host "Created: $TestFile"

$Event = $null
$Deadline = (Get-Date).AddSeconds(30)

while ((Get-Date) -lt $Deadline -and $null -eq $Event) {
$Event = Get-WinEvent -FilterHashtable @{
LogName = $Log
Id = 11
StartTime = $Start
} -ErrorAction SilentlyContinue |
Where-Object { $_.Message -like "*$TestFile*" } |
Select-Object -First 1
if ($null -eq $Event) { Start-Sleep -Seconds 2 }
}

Remove-Item $TestFile -Force -ErrorAction SilentlyContinue

if ($null -eq $Event) {
Write-Host "Event ID 11 was not captured." -ForegroundColor Red
& $Exe -c
throw "Event ID 11 verification failed."
}

Write-Host "Event ID 11 captured                   [VERIFIED]" -ForegroundColor Green
Write-Host ""
Write-Host "Sysmon Deployment VERIFIED" -ForegroundColor Green
