<#
.SYNOPSIS
1-sysmon_coverage_matrix.ps1

.DESCRIPTION
Parses a Sysmon configuration and generates an ATT&CK coverage matrix
based on the configured Sysmon Event IDs and filtering rules.

.NOTES
Script name: 1-sysmon_coverage_matrix.ps1
purpose: Generate Sysmon ATT&CK coverage matrix
author: Tristeceratops
date: 10/08/2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ConfigPath = Join-Path $PSScriptRoot 'sysmonconfig.xml'
$ReportPath = Join-Path $PSScriptRoot 'sysmon_coverage_matrix.json'

Write-Host '[*] Parsing Sysmon config: sysmonconfig.xml'

if (-not (Test-Path -LiteralPath $ConfigPath)) {
Write-Host '[ERROR] sysmonconfig.xml not found.'
exit 1
}

[xml]$ConfigXml = Get-Content -LiteralPath $ConfigPath -Raw

$FilterSection = $ConfigXml.SelectSingleNode(
'//*[local-name()="EventFiltering"]'
)

if ($null -eq $FilterSection) {
Write-Host '[ERROR] EventFiltering section not found.'
exit 1
}

$EventTypes = @{
ProcessCreate = 1
FileCreateTime = 2
NetworkConnect = 3
SysmonServiceStateChanged = 4
ProcessTerminate = 5
DriverLoad = 6
ImageLoad = 7
CreateRemoteThread = 8
RawAccessRead = 9
ProcessAccess = 10
FileCreate = 11
RegistryEvent = 12
RegistryEventSetValue = 13
RegistryEventRenameKey = 14
FileCreateStreamHash = 15
ServiceConfiguration = 16
PipeEvent = 17
WmiEventFilter = 19
WmiEventConsumer = 20
WmiEventConsumerToFilter = 21
DnsQuery = 22
}

$EnabledIds = [System.Collections.Generic.List[int]]::new()
$ExcludedEvents = [System.Collections.Generic.List[string]]::new()

foreach ($EventNode in $FilterSection.ChildNodes) {


if ($EventNode.NodeType -ne 'Element') {
    continue
}

$EventName = $EventNode.LocalName

if ($EventTypes.ContainsKey($EventName)) {

    $EventId = $EventTypes[$EventName]

    if (-not $EnabledIds.Contains($EventId)) {
        $EnabledIds.Add($EventId)
    }

    $MatchMode = ''

    if ($EventNode.Attributes['onmatch']) {
        $MatchMode = $EventNode.Attributes['onmatch'].Value
    }

    if ($MatchMode -eq 'exclude') {
        $ExcludedEvents.Add($EventName)
    }
}


}

$AttackMappings = @(
@{
Id = 'T1059'
Name = 'Command and Scripting Interpreter'
Events = @(1)
Fields = @('Image', 'CommandLine', 'User', 'ParentImage')
}
@{
Id = 'T1053'
Name = 'Scheduled Task/Job'
Events = @(1)
Fields = @('Image', 'CommandLine', 'ParentImage')
}
@{
Id = 'T1547'
Name = 'Boot or Logon Autostart Execution'
Events = @(13)
Fields = @('TargetObject', 'Details', 'Image')
}
@{
Id = 'T1055'
Name = 'Process Injection'
Events = @(8, 10)
Fields = @('SourceImage', 'TargetImage', 'GrantedAccess')
}
@{
Id = 'T1071'
Name = 'Application Layer Protocol'
Events = @(3, 22)
Fields = @(
'Image',
'DestinationIp',
'DestinationPort',
'QueryName'
)
}
@{
Id = 'T1574.002'
Name = 'DLL Side-Loading'
Events = @(7)
Fields = @('Image', 'ImageLoaded', 'Hashes')
}
@{
Id = 'T1027'
Name = 'Obfuscated or Compressed Files'
Events = @(11, 15)
Fields = @('Image', 'TargetFilename', 'Hashes')
}
)

$CoverageRows = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($Mapping in $AttackMappings) {


$Available = @(
    $Mapping.Events | Where-Object {
        $EnabledIds.Contains($_)
    }
)

$Unavailable = @(
    $Mapping.Events | Where-Object {
        -not $EnabledIds.Contains($_)
    }
)

$Conflicts = @()

foreach ($ExcludedName in $ExcludedEvents) {

    $ExcludedId = $EventTypes[$ExcludedName]

    if ($Mapping.Events -contains $ExcludedId) {
        $Conflicts += "$ExcludedName uses onmatch=exclude"
    }
}

if ($Available.Count -eq 0) {
    $Coverage = 'blind'
    $Explanation = "None of the required Event IDs are enabled."
    $Action = "Enable Event ID(s): $($Mapping.Events -join ', ')."
}
elseif ($Unavailable.Count -gt 0) {
    $Coverage = 'partial'
    $Explanation = "Required Event ID(s) missing: $($Unavailable -join ', ')."
    $Action = "Enable missing Event ID(s): $($Unavailable -join ', ')."
}
elseif ($Conflicts.Count -gt 0) {
    $Coverage = 'partial'
    $Explanation = "Relevant Event ID(s) have exclude filtering."
    $Action = 'Review and narrow the relevant exclude rules.'
}
else {
    $Coverage = 'covered'
    $Explanation = 'All required Event IDs are enabled with no detected exclude conflict.'
    $Action = 'No tuning required.'
}

$CoverageRows.Add(
    [PSCustomObject]@{
        technique_id = $Mapping.Id
        technique_name = $Mapping.Name
        required_event_ids = @($Mapping.Events)
        enabled_event_ids = @($Available)
        filter_conflicts = @($Conflicts)
        coverage_status = $Coverage
        reason = $Explanation
        evidence_fields_expected = $Mapping.Fields
        recommendation = $Action
    }
)


}

$CoveredTotal = @(
$CoverageRows | Where-Object {
$_.coverage_status -eq 'covered'
}
).Count

$PartialTotal = @(
$CoverageRows | Where-Object {
$_.coverage_status -eq 'partial'
}
).Count

$BlindTotal = @(
$CoverageRows | Where-Object {
$_.coverage_status -eq 'blind'
}
).Count

$OutputData = [ordered]@{
generated_at = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'
config_file = $ConfigPath
enabled_event_ids = @($EnabledIds | Sort-Object)
summary = [ordered]@{
techniques_assessed = $CoverageRows.Count
covered = $CoveredTotal
partial = $PartialTotal
blind = $BlindTotal
}
matrix = $CoverageRows
}

$OutputData |
ConvertTo-Json -Depth 6 |
Set-Content -LiteralPath $ReportPath -Encoding UTF8

Write-Host "Enabled Event IDs: $((@($EnabledIds | Sort-Object -Unique)) -join ', ')"
Write-Host "Techniques assessed: $($CoverageRows.Count)"
Write-Host "Covered: $CoveredTotal"
Write-Host "Partial: $PartialTotal"
Write-Host "Blind: $BlindTotal"
Write-Host "Report saved to: $ReportPath"
