<#
.SYNOPSIS
4-windows_telemetry_quality.ps1

.DESCRIPTION
Analyzes windows_events_export.json for event distribution,
channel coverage, time gaps, field completeness, and quality score.

.NOTES
Script name: 4-windows_telemetry_quality.ps1
purpose: Validate Windows telemetry quality
author: Tristeceratops
date: 10/08/2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "[*] Analyzing windows_events_export.json..."

$events = Get-Content windows_events_export.json -Raw | ConvertFrom-Json
$total = $events.Count

# Event Distribution
$eventDistribution = $events | Group-Object event_id | ForEach-Object {
    [pscustomobject]@{
        EventID   = $_.Name
        count     = $_.Count
        percentage = [math]::Round(($_.Count / $total) * 100, 2)
    }
}

# Channel Distribution
$channelDistribution = $events | Group-Object source_type | ForEach-Object {
    [pscustomobject]@{
        Channel = $_.Name
        count = $_.Count
        percentage = [math]::Round(($_.Count / $total) * 100, 2)
    }
}

# Time Coverage
$times = $events | ForEach-Object { [datetime]$_.timestamp } | Sort-Object
$first = $times[0]
$last = $times[-1]
$hours = [math]::Ceiling(($last - $first).TotalHours)
$hourGroups = $events | Group-Object { ([datetime]$_.timestamp).ToString("yyyy-MM-dd HH") }
$hoursWithEvents = $hourGroups.Count
$hoursWithoutEvents = [math]::Max(0, $hours - $hoursWithEvents)

# Gap detection - 30 minutes
$gaps = @()
for ($i = 1; $i -lt $times.Count; $i++) {
    $gap = ($times[$i] - $times[$i-1]).TotalMinutes
    if ($gap -gt 30) {
        $gaps += [pscustomobject]@{
            Start = $times[$i-1]
            End = $times[$i]
            Minutes = [math]::Round($gap, 2)
        }
    }
}
$largestGap = if ($gaps) { ($gaps | Measure-Object Minutes -Maximum).Maximum } else { 0 }

# Field Completeness
function Completeness($items, $field) {
    if (!$items) { return 100 }
    $good = @($items | Where-Object { $null -ne $_.$field -and "$($_.$field)".Trim() -ne "" }).Count
    [math]::Round(($good / $items.Count) * 100, 2)
}

$processEvents = @($events | Where-Object { $_.event_id -in @(1,4688) })
$logonEvents = @($events | Where-Object { $_.event_id -in @(4624,4625) })
$scriptEvents = @($events | Where-Object { $_.event_id -eq 4104 })

$CommandLine = Completeness $processEvents "CommandLine"
$SourceIP = Completeness $logonEvents "IpAddress"
$ScriptBlockText = Completeness $scriptEvents "ScriptBlockText"

$FieldCompleteness = [pscustomobject]@{
    CommandLine = "$CommandLine%"
    SourceIP = "$SourceIP%"
    ScriptBlockText = "$ScriptBlockText%"
}

# Quality score
$QualityScore = [math]::Round(
    ($CommandLine * .35) +
    ($SourceIP * .30) +
    ($ScriptBlockText * .25) +
    ([math]::Min(100, ($hoursWithEvents / [math]::Max(1,$hours)) * 100) * .10), 2)

$assessment = if ($QualityScore -ge 90) {
    "good"
} elseif ($QualityScore -ge 70) {
    "acceptable"
} else {
    "poor"
}

$report = [ordered]@{
    "Event Distribution" = $eventDistribution
    "Channel Distribution" = $channelDistribution
    "Time Coverage" = [pscustomobject]@{
        "events per hour" = [math]::Round($total / [math]::Max(1,$hours), 2)
        "Hours with events" = $hoursWithEvents
        "Hours without events" = $hoursWithoutEvents
        "gap 30 minutes" = $gaps
        "Largest gap minutes" = $largestGap
    }
    "Field Completeness" = $FieldCompleteness
    "Quality score" = [pscustomobject]@{
        Score = $QualityScore
        Assessment = $assessment
    }
}

$report | ConvertTo-Json -Depth 8 | Set-Content windows_telemetry_quality.json -Encoding UTF8

Write-Host "Total events: $total"
Write-Host "Hours with events: $hoursWithEvents/$hours"
Write-Host "Largest gap: $([math]::Round($largestGap)) minutes"
Write-Host "Command-line completeness: $CommandLine%"
Write-Host "Source IP completeness: $SourceIP%"
Write-Host "Script block completeness: $ScriptBlockText%"
Write-Host "Quality score: $QualityScore% ($assessment)"
Write-Host "Report saved to: windows_telemetry_quality.json"