<#
.SYNOPSIS
6-powershell_security.ps1

.DESCRIPTION
Creates and links the MedDefense PowerShell Security GPO, enables Script
Block Logging, Module Logging, Transcription, verifies AMSI, and tests
Event ID 4104 using an encoded PowerShell command.

.NOTES
Script Name: 6-powershell_security.ps1
Purpose: PowerShell security logging and AMSI configuration
Author: Tristeceratops
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

$GPOName = "MedDefense - PowerShell Security"
$Target = (Get-ADDomain).DistinguishedName
$ScriptKey = "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$ModuleKey = "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$TransKey = "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
$TranscriptPath = "C:\PSTranscripts"
$LogName = "Microsoft-Windows-PowerShell/Operational"

Write-Host "[*] Creating GPO: `"$GPOName`"..." -ForegroundColor Cyan
$GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
if ($null -eq $GPO) {
$GPO = New-GPO -Name $GPOName
Write-Host "    CREATED" -ForegroundColor Green
} else {
Write-Host "    EXISTS" -ForegroundColor Yellow
}

Write-Host "[*] Configuring Script Block Logging..." -ForegroundColor Cyan
Set-GPRegistryValue -Name $GPOName -Key $ScriptKey -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1
Write-Host "    EnableScriptBlockLogging = 1           [SET]"
Write-Host "    -> Event ID 4104 captures decoded scripts"

Write-Host "[*] Configuring Module Logging..." -ForegroundColor Cyan
Set-GPRegistryValue -Name $GPOName -Key $ModuleKey `    -ValueName "EnableModuleLogging" -Type DWord -Value 1
Set-GPRegistryValue -Name $GPOName -Key "$ModuleKey\ModuleNames" -ValueName "*" -Type String -Value "*"
Write-Host "    EnableModuleLogging = 1, ModuleNames = *  [SET]"
Write-Host "    -> Event ID 4103 captures module invocations"

Write-Host "[*] Configuring Transcription..." -ForegroundColor Cyan
if (-not (Test-Path $TranscriptPath)) {
New-Item $TranscriptPath -ItemType Directory -Force | Out-Null
}
Set-GPRegistryValue -Name $GPOName -Key $TransKey -ValueName "EnableTranscripting" -Type DWord -Value 1
Set-GPRegistryValue -Name $GPOName -Key $TransKey -ValueName "EnableInvocationHeader" -Type DWord -Value 1
Set-GPRegistryValue -Name $GPOName -Key $TransKey -ValueName "OutputDirectory" -Type String -Value $TranscriptPath
Write-Host "    OutputDirectory = $TranscriptPath     [SET]"

Write-Host "[*] Verifying AMSI..." -ForegroundColor Cyan
$Amsi = (Get-Process -Id $PID).Modules | Where-Object ModuleName -eq "amsi.dll"
if ($null -ne $Amsi) {
Write-Host "    AMSI DLL loaded     [OK]" -ForegroundColor Green
} else {
Write-Warning "AMSI DLL not loaded in current PowerShell process."
}

$Links = Get-GPInheritance -Target $Target
if (-not ($Links.GpoLinks | Where-Object DisplayName -eq $GPOName)) {
New-GPLink -Name $GPOName -Target $Target -LinkEnabled Yes | Out-Null
}

Write-Host "[*] Linking GPO and forcing update..." -ForegroundColor Cyan
gpupdate /force | Out-Null
Write-Host "    COMPLETE" -ForegroundColor Green

Write-Host "[*] Testing encoded command..." -ForegroundColor Cyan
$Command = 'Write-Host "Test"'
$Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
$Before = Get-Date
Write-Host "    Input: powershell -enc $Encoded"

$PS = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
Start-Process $PS -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $Encoded" -Wait -WindowStyle Hidden

$Found = $false
for ($i = 1; $i -le 10 -and -not $Found; $i++) {
Start-Sleep -Milliseconds 500
$Events = Get-WinEvent -FilterHashtable @{
LogName = $LogName
Id = 4104
StartTime = $Before
} -ErrorAction SilentlyContinue
if ($Events | Where-Object Message -match "Write-Host") {
$Found = $true
}
}

if ($Found) {
Write-Host "    Event ID 4104 found: `"Write-Host 'Test'`"  [VERIFIED]" -ForegroundColor Green
} else {
Write-Warning "Event ID 4104 was not found."
}

Write-Host ""
Write-Host "PowerShell Security $(if ($Found) {'VERIFIED'} else {'CONFIGURED - VERIFICATION FAILED'})" `
-ForegroundColor $(if ($Found) {'Green'} else {'Yellow'})