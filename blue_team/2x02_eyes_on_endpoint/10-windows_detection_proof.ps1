<#
.SYNOPSIS
10-windows_detection_proof.ps1

.DESCRIPTION
Compares Task 9 ground truth actions against Windows Security,
Sysmon, and PowerShell telemetry.

.NOTES
Script name: 10-windows_detection_proof.ps1
purpose: Validate Windows telemetry detection coverage
author: Tristeceratops
date: 10/08/2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$ground = Get-Content "windows_attack_log.json" | ConvertFrom-Json
Write-Host "[*] Loading ground truth ($($ground.Count) actions)..."
Write-Host "[*] Searching telemetry for each action..."

# Required reference:
# Get-WinEvent -LogName "Security", "Sysmon", "PowerShell"
# source event_id detail key_fields status
# 4720 4732 4104 1 3 11

$logs = @{
    Security   = "Security"
    Sysmon     = "Microsoft-Windows-Sysmon/Operational"
    PowerShell = "Microsoft-Windows-PowerShell/Operational"
}

$events = @{}
foreach ($source in $logs.Keys) {
    $events[$source] = @(Get-WinEvent -LogName $logs[$source] -ErrorAction SilentlyContinue)
}

$report = @()
$multi = 0

foreach ($action in $ground) {
    $timestamp = [datetime]$action.timestamp
    $start = $timestamp.AddSeconds(-30)
    $end = $timestamp.AddSeconds(30)

    $ids = switch -Regex ($action.expected) {
        "4720" { @(4720) }
        "4732" { @(4732) }
        "4104" { @(4104) }
        "Sysmon Event ID 1" { @(1) }
        "Event ID 3" { @(3) }
        "Event ID 11" { @(11) }
        default { @() }
    }

    foreach ($source in $logs.Keys) {
        $hits = @($events[$source] | Where-Object {
            $_.Id -in $ids -and
            $_.TimeCreated -ge $start -and
            $_.TimeCreated -le $end
        })

        foreach ($e in $hits) {
            $key_fields = @()
            $xml = [xml]$e.ToXml()

            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name -and "$($d.'#text')".Trim()) {
                    $key_fields += $d.Name
                }
            }

            $detail = if ($key_fields.Count -ge 2) { "Full" } elseif ($key_fields.Count) { "Partial" } else { "Partial" }

            $report += [pscustomobject]@{
                action     = $action.action
                source     = $source
                event_id   = $e.Id
                detail     = $detail
                key_fields = $key_fields -join ", "
                status     = "[CAPTURED]"
            }
        }
    }

    $sources = @($report | Where-Object action -eq $action.action | Select-Object -ExpandProperty source -Unique)
    if ($sources.Count -gt 1) { $multi++ }

    if (!$sources) {
        $report += [pscustomobject]@{
            action     = $action.action
            source     = "-"
            event_id   = "-"
            detail     = "Missed"
            key_fields = ""
            status     = "[MISSED]"
        }
    }
}

$report | Format-Table action,source,event_id,detail,status -AutoSize

$captured = @($report | Where-Object status -eq "[CAPTURED]" |
    Select-Object -ExpandProperty action -Unique).Count

$final = [ordered]@{
    actions = $ground.Count
    captured = $captured
    coverage = if ($ground.Count) { [math]::Round($captured / $ground.Count * 100,2) } else { 0 }
    multi_source = $multi
    detections = $report
}

$final | ConvertTo-Json -Depth 8 |
    Set-Content windows_detection_matrix.json -Encoding UTF8

Write-Host "Actions: $($ground.Count) | Captured: $captured/$($ground.Count) ($($final.coverage)%) | Multi-source: $multi"
Write-Host "Report saved to: windows_detection_matrix.json"