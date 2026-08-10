<#
.SYNOPSIS
0-sysmon_validation.ps1

.DESCRIPTION
Validates that Sysmon captures five common telemetry actions:

* Process creation
* Network connection
* File creation
* Registry modification
* DNS query

The script triggers each action, searches the Sysmon event log, and verifies
that the expected Event ID and relevant event details are present.

.NOTES
Script Name: 0-sysmon_validation.ps1
Purpose: Validate Sysmon telemetry collection and event detail levels
Author: Tristeceratops
Date: 10/08/2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SysmonLog = 'Microsoft-Windows-Sysmon/Operational'
$TempFile = 'C:\Windows\Temp\SysmonTest.txt'
$RegistryPath = 'HKCU:\Software\SysmonTest'

$Results = [System.Collections.Generic.List[object]]::new()

function Get-SysmonEvent {
param (
[int]$EventId,
[datetime]$StartTime,
[scriptblock]$Validation
)

for ($Attempt = 1; $Attempt -le 10; $Attempt++) {

    $Events = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = $SysmonLog
            Id        = $EventId
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue
    )

    foreach ($Event in $Events) {
        [xml]$Xml = $Event.ToXml()
        $Data = @{}

        foreach ($Item in $Xml.Event.EventData.Data) {
            $Data[$Item.Name] = [string]$Item.'#text'
        }

        if (& $Validation $Data) {
            return $Data
        }
    }

    Start-Sleep -Milliseconds 500
}

return $null

}

function Add-TestResult {
param (
[string]$Name,
[string]$Description,
[bool]$Captured
)

$Status = if ($Captured) { 'PASS' } else { 'MISS' }

$Results.Add([pscustomobject]@{
    Name     = $Name
    Captured = $Captured
})

if ($Captured) {
    Write-Host "          $Description   [$Status]"
}
else {
    Write-Host "          $Description   [$Status]"
}

}

Write-Host '[*] Running Sysmon telemetry validation...'

try {

Write-Host '    [1/5] Process creation (Event ID 1)...'

$Timestamp = Get-Date
$SearchStart = $Timestamp.AddSeconds(-1)

cmd.exe /c whoami | Out-Null

$Event = Get-SysmonEvent `
    -EventId 1 `
    -StartTime $SearchStart `
    -Validation {
        param($Data)

        $Data.CommandLine -match 'cmd\.exe\s+/c\s+whoami'
    }

$Captured = $null -ne $Event

Add-TestResult `
    -Name 'Process creation' `
    -Description 'cmd.exe /c whoami -> Sysmon EID 1 captured, CommandLine present' `
    -Captured $Captured

Write-Host '    [2/5] Network connection (Event ID 3)...'

$Timestamp = Get-Date
$SearchStart = $Timestamp.AddSeconds(-1)

$DestinationIp = '1.1.1.1'
$DestinationPort = 443

Test-NetConnection `
    -ComputerName $DestinationIp `
    -Port $DestinationPort `
    -InformationLevel Quiet | Out-Null

$Event = Get-SysmonEvent `
    -EventId 3 `
    -StartTime $SearchStart `
    -Validation {
        param($Data)

        $Data.DestinationIp -eq $DestinationIp -and
        $Data.DestinationPort -eq "$DestinationPort" -and
        -not [string]::IsNullOrWhiteSpace($Data.Image)
    }

$Captured = $null -ne $Event

Add-TestResult `
    -Name 'Network connection' `
    -Description 'Outbound TCP -> Sysmon EID 3 captured, DestinationIp/DestinationPort/process present' `
    -Captured $Captured

Write-Host '    [3/5] File creation (Event ID 11)...'

$Timestamp = Get-Date
$SearchStart = $Timestamp.AddSeconds(-1)

Set-Content `
    -LiteralPath $TempFile `
    -Value 'Sysmon validation test' `
    -Force

$Event = Get-SysmonEvent `
    -EventId 11 `
    -StartTime $SearchStart `
    -Validation {
        param($Data)

        $Data.TargetFilename -ieq $TempFile -and
        -not [string]::IsNullOrWhiteSpace($Data.Image)
    }

$Captured = $null -ne $Event

Add-TestResult `
    -Name 'File creation' `
    -Description "$TempFile -> Sysmon EID 11 captured, TargetFilename/process present" `
    -Captured $Captured

Write-Host '    [4/5] Registry modification (Event ID 13)...'

$Timestamp = Get-Date
$SearchStart = $Timestamp.AddSeconds(-1)

New-Item `
    -Path $RegistryPath `
    -Force | Out-Null

New-ItemProperty `
    -Path $RegistryPath `
    -Name 'SysmonTest' `
    -Value 'Validation' `
    -PropertyType String `
    -Force | Out-Null

$Event = Get-SysmonEvent `
    -EventId 13 `
    -StartTime $SearchStart `
    -Validation {
        param($Data)

        $Data.TargetObject -match 'SysmonTest' -and
        $Data.EventType -match 'SetValue'
    }

$Captured = $null -ne $Event

Add-TestResult `
    -Name 'Registry modification' `
    -Description 'HKCU\...\SysmonTest -> Sysmon EID 13 captured, key/value/operation present' `
    -Captured $Captured


Write-Host '    [5/5] DNS query (Event ID 22)...'

$Timestamp = Get-Date
$SearchStart = $Timestamp.AddSeconds(-1)

$Domain = 'example.com'

Resolve-DnsName $Domain -ErrorAction SilentlyContinue | Out-Null
cmd.exe /c "nslookup $Domain 2>nul" | Out-Null

$Event = Get-SysmonEvent `
    -EventId 22 `
    -StartTime $SearchStart `
    -Validation {
        param($Data)

        $Data.QueryName -match '^example\.com\.?$' -and
        -not [string]::IsNullOrWhiteSpace($Data.QueryResults)
    }

$Captured = $null -ne $Event

Add-TestResult `
    -Name 'DNS query' `
    -Description 'nslookup example.com -> Sysmon EID 22 captured, query/result present' `
    -Captured $Captured

}
finally {

Write-Host '[*] Cleanup: removing test artifacts...'

Remove-Item `
    -LiteralPath $TempFile `
    -Force `
    -ErrorAction SilentlyContinue

Remove-ItemProperty `
    -Path $RegistryPath `
    -Name 'SysmonTest' `
    -Force `
    -ErrorAction SilentlyContinue

Remove-Item `
    -Path $RegistryPath `
    -Force `
    -ErrorAction SilentlyContinue
}

$CapturedCount = @(
$Results | Where-Object { $_.Captured }
).Count

$MissedCount = $Results.Count - $CapturedCount

Write-Host ''
Write-Host "Actions tested: $($Results.Count) | Captured: $CapturedCount | Missed: $MissedCount"