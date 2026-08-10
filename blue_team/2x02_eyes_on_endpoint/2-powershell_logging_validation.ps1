<#
.SYNOPSIS
2-powershell_logging_validation.ps1

.DESCRIPTION
Validates PowerShell ScriptBlock logging, encoded commands, module logging,
multi-line ScriptBlock capture, and Transcript output.

.NOTES
Script name: 2-powershell_logging_validation.ps1
purpose: Validate PowerShell logging coverage
author: Tristeceratops
date: 10/08/2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

Write-Host '[*] Testing PowerShell logging coverage...'

$StartTime = Get-Date
$Marker = "PSLOG_$([guid]::NewGuid().ToString('N'))"
$TranscriptDirectory = 'C:\PSTranscripts'
$Captured = 0
$Missed = 0

function Get-LoggedEvent {
param (
[int]$EventId,
[string]$SearchText
)

Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = $EventId
    StartTime = $StartTime
} -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Message -match [regex]::Escape($SearchText)
    } |
    Select-Object -First 1

}

Write-Host '    [1/5] Simple command (Get-Process)...'

powershell.exe -NoProfile -Command "Get-Process | Out-Null; Write-Host '$Marker'" |
Out-Null

$Event4104 = Get-LoggedEvent -EventId 4104 -SearchText 'Get-Process'

if ($null -ne $Event4104) {
Write-Host '          EID 4104 ScriptBlock: "Get-Process" CAPTURED [PASS]'
Write-Host '          Detail: full'
$Captured++
}
else {
Write-Host '          EID 4104 ScriptBlock: "Get-Process" MISSED [FAIL]'
Write-Host '          Detail: partial'
$Missed++
}

Write-Host '    [2/5] Encoded command...'

$EncodedText = 'Write-Host "Test"'
$EncodedCommand = [Convert]::ToBase64String(
[Text.Encoding]::Unicode.GetBytes($EncodedText)
)

Write-Host "          Input: -enc $EncodedCommand"
Write-Host "          EncodedCommand: $EncodedCommand"

powershell.exe -NoProfile -EncodedCommand $EncodedCommand |
Out-Null

$Event4104 = Get-LoggedEvent -EventId 4104 -SearchText 'Write-Host'

if ($null -ne $Event4104) {
Write-Host '          EID 4104: decoded Write-Host captured [PASS]'
Write-Host '          Detail: full'
$Captured++
}
else {
Write-Host '          EID 4104: decoded command MISSED [FAIL]'
Write-Host '          Detail: partial'
$Missed++
}

Write-Host '    [3/5] Module import...'

powershell.exe -NoProfile -Command @"
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Write-Host '$Marker'
"@ | Out-Null

$Event4103 = Get-LoggedEvent -EventId 4103 -SearchText 'ActiveDirectory'

if ($null -ne $Event4103) {
Write-Host '          EID 4103: Import-Module ActiveDirectory CAPTURED [PASS]'
Write-Host '          Detail: full'
$Captured++
}
else {
Write-Host '          EID 4103: Import-Module ActiveDirectory MISSED [FAIL]'
Write-Host '          Detail: partial'
$Missed++
}

Write-Host '    [4/5] multi-line script block...'

$MultiLineScript = @'
$A = "PSLOG"
$B = "Validation"
$C = "Test"
Write-Host "$A $B $C"
'@

powershell.exe -NoProfile -Command $MultiLineScript |
Out-Null

$MultiLineEvent = Get-WinEvent -FilterHashtable @{
LogName   = 'Microsoft-Windows-PowerShell/Operational'
Id        = 4104
StartTime = $StartTime
} -ErrorAction SilentlyContinue |
Where-Object {
$*.Message -match '$A\s*=\s*"PSLOG"' -and
$*.Message -match '$B\s*=\s*"Validation"' -and
$*.Message -match '$C\s*=\s*"Test"' -and
$*.Message -match 'Write-Host'
} |
Select-Object -First 1

if ($null -ne $MultiLineEvent) {
Write-Host '          EID 4104: Full multi-line block CAPTURED [PASS]'
Write-Host '          Detail: full'
$Captured++
}
else {
Write-Host '          EID 4104: multi-line block MISSED [FAIL]'
Write-Host '          Detail: partial'
$Missed++
}

Write-Host '    [5/5] Transcript file...'

$TranscriptFile = Join-Path $TranscriptDirectory "PowerShell_$Marker.txt"

powershell.exe -NoProfile -Command @"
Start-Transcript -Path '$TranscriptFile' -Force
Write-Host '$Marker'
Get-Date
Stop-Transcript
"@ | Out-Null

$Transcript = Get-ChildItem -Path $TranscriptDirectory `
-Filter '*.txt' -ErrorAction SilentlyContinue |
Where-Object {
$_.Name -like "*$Marker*.txt"
} |
Select-Object -First 1

if ($null -ne $Transcript) {
$TranscriptContent = Get-Content -LiteralPath $Transcript.FullName -Raw

if ($TranscriptContent -match $Marker) {
    Write-Host "          C:\PSTranscripts\*.txt Transcript CAPTURED [PASS]"
    Write-Host '          Detail: full'
    $Captured++
}
else {
    Write-Host '          C:\PSTranscripts\*.txt Transcript MISSED [FAIL]'
    Write-Host '          Detail: partial'
    $Missed++
}

}
else {
Write-Host '          C:\PSTranscripts*.txt Transcript MISSED [FAIL]'
Write-Host '          Detail: partial'
$Missed++
}

Write-Host "Tests: 5 | CAPTURED: $Captured | MISSED: $Missed"
