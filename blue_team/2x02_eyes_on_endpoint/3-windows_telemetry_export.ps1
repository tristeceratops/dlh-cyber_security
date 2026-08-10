<#
.SYNOPSIS
3-windows_telemetry_export.ps1


.DESCRIPTION
Exports Windows telemetry from the Security, Sysmon Operational,
and PowerShell Operational logs for a configurable time window.
Normalizes common event fields and extracts enriched fields
for key Windows and Sysmon event types.


.NOTES
Script name: 3-windows_telemetry_export.ps1
purpose: Export Windows telemetry for security analysis
author: Tristeceratops
date: 10/08/2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

param([int]$Hours = 24)

$EndTime = Get-Date
$StartTime = $EndTime.AddHours(-$Hours)
Write-Host "[*] Exporting Windows telemetry from last $Hours hours..."

function Get-Data($e,$n) {
    $x = [xml]$e.ToXml()
    ($x.Event.EventData.Data | ? { $_.Name -eq $n }).'#text'
}
function Convert-Event($e,$source_type) {
    $xml = [xml]$e.ToXml()
    $id = [int]$e.Id
    $o = [ordered]@{
        timestamp=$e.TimeCreated.ToUniversalTime().ToString("o")
        hostname=$e.MachineName
        platform="Windows"
        source_type=$source_type
        channel=$e.LogName
        event_id=$id
        event_category=$e.TaskDisplayName
        provider=$e.ProviderName
        raw_message=$e.Message
    }
    switch ($id) {
        4624 { $o.TargetUserName=Get-Data $e "TargetUserName"; $o.LogonType=Get-Data $e "LogonType"; $o.IpAddress=Get-Data $e "IpAddress"; $o.Workstation=Get-Data $e "WorkstationName" }
        4625 { $o.TargetUserName=Get-Data $e "TargetUserName"; $o.FailureReason=Get-Data $e "FailureReason"; $o.IpAddress=Get-Data $e "IpAddress" }
        4672 { $o.PrivilegedAccount=Get-Data $e "SubjectUserName" }
        4688 { $o.ProcessName=Get-Data $e "NewProcessName"; $o.CommandLine=Get-Data $e "CommandLine"; $o.ParentProcess=Get-Data $e "ParentProcessName" }
        4104 { $o.ScriptBlockText=Get-Data $e "ScriptBlockText" }
        1 {
            $o.Image=Get-Data $e "Image"; $o.CommandLine=Get-Data $e "CommandLine"
            $o.ParentImage=Get-Data $e "ParentImage"; $o.Hashes=Get-Data $e "Hashes"
        }
        3 {
            $o.DestinationIp=Get-Data $e "DestinationIp"; $o.DestinationPort=Get-Data $e "DestinationPort"
            $o.Process=Get-Data $e "Image"
        }
        11 { $o.TargetFilename=Get-Data $e "TargetFilename"; $o.CreatingProcess=Get-Data $e "Image" }
        13 { $o.RegistryKey=Get-Data $e "TargetObject"; $o.ValueName=Get-Data $e "Details" }
        22 { $o.QueryName=Get-Data $e "QueryName"; $o.QueryResults=Get-Data $e "QueryResults" }
    }
    [pscustomobject]$o
}

$logs = @{
    Security="Security"
    Sysmon="Microsoft-Windows-Sysmon/Operational"
    PowerShell="Microsoft-Windows-PowerShell/Operational"
}
$all = foreach($k in $logs.Keys) {
    Get-WinEvent -FilterHashtable @{LogName=$logs[$k];StartTime=$StartTime;EndTime=$EndTime} -ErrorAction SilentlyContinue |
        % { Convert-Event $_ $k }
}

$all | ConvertTo-Json -Depth 6 | Set-Content windows_events_export.json -Encoding UTF8

$all | Group-Object source_type | % { "$($_.Name) events: $($_.Count)" }
"Total events: $($all.Count)"
"Top Event IDs: " + (($all | Group-Object { "$($_.source_type)-$($_.event_id)" } |
    Sort-Object Count -Descending | Select-Object -First 4 | % Name) -join ", ")
"Output: windows_events_export.json"