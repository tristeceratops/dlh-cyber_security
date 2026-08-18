#!/usr/bin/env pwsh
<#
.SYNOPSIS
6-windows_firewall.ps1

.DESCRIPTION
Aligns Windows Firewall with the MedDefense network segmentation design
defined in segmentation_rules.json.

The script determines the local zone from the host IPv4 addresses and
creates inbound Windows Firewall rules for authorized flows terminating
on this host.

The script performs the following actions:
- Reads segmentation_rules.json from the project directory
- Determines the local zone from the host IPv4 addresses
- Captures the existing Windows Firewall configuration before modification
- Saves the pre-change state as a structured JSON artifact
- Sets Domain, Private, and Public profiles to:
    - DefaultInboundAction = Block
    - DefaultOutboundAction = Allow
    - LogBlocked = True
    - LogFileName = %systemroot%\system32\LogFiles\Firewall\meddefense.log
- Removes all existing MedDefense-* rules
- Recreates authorized inbound rules from the segmentation flow matrix
- Uses the source zone CIDR as the RemoteAddress
- Verifies that the expected number of MedDefense rules were created
- Captures the resulting Windows Firewall configuration as JSON

The script is idempotent. Existing MedDefense-* rules are removed before
the ruleset is recreated.

Each firewall rule uses:
- DisplayName: MedDefense-<src_zone>-<proto>-<dport>
- Direction: Inbound
- Action: Allow
- Protocol: TCP or UDP
- LocalPort: destination port from the flow
- RemoteAddress: source zone CIDR
- Profile: Any

The script has no Internet dependency and uses only local system state
and the project-provided segmentation_rules.json file.

.OUTPUTS
windows_firewall_prechange.json
windows_firewall_postchange.json

.NOTES
Script Name : 6-windows_firewall.ps1
Purpose     : Windows Firewall segmentation enforcement
Target      : Windows host aligned with the MedDefense segmentation design
Author      : Tristeceratops
Date        : 18/08/2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SegmentationFile = Join-Path $PSScriptRoot 'segmentation_rules.json'
$PreChangeJson = Join-Path $PSScriptRoot 'windows_firewall_prechange.json'
$PostChangeJson = Join-Path $PSScriptRoot 'windows_firewall_postchange.json'
$LogFileName = '%systemroot%\system32\LogFiles\Firewall\meddefense.log'
$RulePrefix = 'MedDefense-'

if (-not (Test-Path -LiteralPath $SegmentationFile -PathType Leaf)) {
    Write-Error "segmentation_rules.json not found: $SegmentationFile"
    exit 1
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    Write-Error 'This script must be run as Administrator.'
    exit 1
}

if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
    Write-Error 'NetSecurity module is not available.'
    exit 1
}

Write-Host '[*] Reading segmentation_rules.json...'

$Segmentation = Get-Content -LiteralPath $SegmentationFile -Raw | ConvertFrom-Json

if ($null -eq $Segmentation.zones -or $Segmentation.zones.Count -eq 0) {
    Write-Error 'segmentation_rules.json contains no zones.'
    exit 1
}

if ($null -eq $Segmentation.flows) {
    Write-Error 'segmentation_rules.json contains no flows.'
    exit 1
}

$ZoneNetworks = @{}

foreach ($Zone in $Segmentation.zones) {
    $ZoneNetworks[$Zone.name] = $Zone.cidr
}

$LocalIPv4 = @(
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            $_.IPAddress -ne '127.0.0.1' -and
            $_.IPAddress -notlike '169.254.*'
        } |
        Select-Object -ExpandProperty IPAddress
)

if ($LocalIPv4.Count -eq 0) {
    Write-Error 'Could not determine any local IPv4 address.'
    exit 1
}

function Test-IPv4InCidr {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,

        [Parameter(Mandatory = $true)]
        [string]$Cidr
    )

    $Parts = $Cidr.Split('/')

    if ($Parts.Count -ne 2) {
        throw "Invalid CIDR: $Cidr"
    }

    $NetworkAddress = [System.Net.IPAddress]::Parse($Parts[0])
    $PrefixLength = [int]$Parts[1]
    $Address = [System.Net.IPAddress]::Parse($IPAddress)

    if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) {
        throw "Invalid CIDR prefix: $Cidr"
    }

    $NetworkBytes = $NetworkAddress.GetAddressBytes()
    $AddressBytes = $Address.GetAddressBytes()

    if ($NetworkBytes.Count -ne 4 -or $AddressBytes.Count -ne 4) {
        return $false
    }

    $FullBytes = [math]::Floor($PrefixLength / 8)
    $RemainingBits = $PrefixLength % 8

    for ($Index = 0; $Index -lt $FullBytes; $Index++) {
        if ($NetworkBytes[$Index] -ne $AddressBytes[$Index]) {
            return $false
        }
    }

    if ($RemainingBits -gt 0) {
        $Mask = [byte](256 - [math]::Pow(2, 8 - $RemainingBits))

        if (($NetworkBytes[$FullBytes] -band $Mask) -ne
            ($AddressBytes[$FullBytes] -band $Mask)) {
            return $false
        }
    }

    return $true
}

$LocalZones = New-Object System.Collections.Generic.List[string]

foreach ($Zone in $Segmentation.zones) {
    foreach ($IPAddress in $LocalIPv4) {
        if (Test-IPv4InCidr -IPAddress $IPAddress -Cidr $Zone.cidr) {
            if (-not $LocalZones.Contains($Zone.name)) {
                $LocalZones.Add($Zone.name)
            }
        }
    }
}

if ($LocalZones.Count -eq 0) {
    Write-Error 'Could not determine the local zone from the host IPv4 addresses.'
    exit 1
}

Write-Host "Detected local zones: $($LocalZones -join ' ')"
Write-Host "Available zones from segmentation: $($Segmentation.zones.name -join ', ')"

Write-Host '[*] Capturing current Windows Firewall state...'

$ProfilesBefore = @(
    Get-NetFirewallProfile -Profile Domain,Private,Public |
        Select-Object Name,
        Enabled,
        DefaultInboundAction,
        DefaultOutboundAction,
        LogBlocked,
        LogAllowed,
        LogFileName
)

$ExistingMedDefenseRules = @(
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "$RulePrefix*" } |
        ForEach-Object {
            $Rule = $_
            $PortFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule
            $AddressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule

            [PSCustomObject]@{
                DisplayName = $Rule.DisplayName
                Direction = [string]$Rule.Direction
                Action = [string]$Rule.Action
                Enabled = [string]$Rule.Enabled
                Profile = [string]$Rule.Profile
                Protocol = [string]$PortFilter.Protocol
                LocalPort = @($PortFilter.LocalPort)
                RemoteAddress = @($AddressFilter.RemoteAddress)
            }
        }
)

$PreChangeState = [PSCustomObject]@{
    Timestamp = (Get-Date).ToUniversalTime().ToString('o')
    ComputerName = $env:COMPUTERNAME
    LocalIPv4 = $LocalIPv4
    LocalZones = @($LocalZones)
    Profiles = $ProfilesBefore
    MedDefenseRules = $ExistingMedDefenseRules
}

$PreChangeState |
    ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $PreChangeJson -Encoding UTF8

Write-Host "Pre-change state saved to: $PreChangeJson"

Write-Host '[*] Setting profile defaults...'

$Profiles = @('Domain', 'Private', 'Public')

foreach ($Profile in $Profiles) {
    Set-NetFirewallProfile `
        -Profile $Profile `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -LogBlocked True `
        -LogFileName $LogFileName

    Write-Host "  $Profile`:  DefaultInboundAction=Block  LogBlocked=True   [SET]"
}

Write-Host '[*] Clearing previous MedDefense-* rules...'

$OldRules = @(
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "$RulePrefix*" }
)

foreach ($Rule in $OldRules) {
    Remove-NetFirewallRule -Name $Rule.Name
}

Write-Host "  [$($OldRules.Count) removed]"

Write-Host '[*] Creating rules from flow matrix...'

$CreatedRules = New-Object System.Collections.Generic.List[object]

foreach ($Flow in $Segmentation.flows) {
    if ($Flow.action -ne 'allow') {
        continue
    }

    if ($Flow.src_zone -eq 'ALL') {
        continue
    }

    if (-not $LocalZones.Contains([string]$Flow.dst_zone)) {
        continue
    }

    $SourceZone = [string]$Flow.src_zone
    $Protocol = ([string]$Flow.proto).ToUpperInvariant()
    $DestinationPort = [string]$Flow.dport

    if (-not $ZoneNetworks.ContainsKey($SourceZone)) {
        Write-Error "Unknown source zone '$SourceZone'."
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($DestinationPort)) {
        Write-Error "Flow has no destination port: $($Flow | ConvertTo-Json -Compress)"
        exit 1
    }

    if ($Protocol -notin @('TCP', 'UDP')) {
        Write-Error "Unsupported protocol '$Protocol' for Windows port rule."
        exit 1
    }

    $DisplayName = "$RulePrefix$SourceZone-$Protocol-$DestinationPort"
    $RemoteAddress = $ZoneNetworks[$SourceZone]

    New-NetFirewallRule `
        -DisplayName $DisplayName `
        -Direction Inbound `
        -Action Allow `
        -Protocol $Protocol `
        -LocalPort $DestinationPort `
        -RemoteAddress $RemoteAddress `
        -Profile Any `
        -Enabled True | Out-Null

    $CreatedRules.Add(
        [PSCustomObject]@{
            DisplayName = $DisplayName
            Direction = 'Inbound'
            Action = 'Allow'
            Protocol = $Protocol
            LocalPort = $DestinationPort
            RemoteAddress = $RemoteAddress
            Profile = 'Any'
            SourceZone = $SourceZone
            DestinationZone = [string]$Flow.dst_zone
        }
    )

    $NamePadding = $DisplayName.PadRight(32)
    Write-Host "  $NamePadding Inbound Allow $($Protocol.ToLowerInvariant()) $DestinationPort    [CREATED]"
}

$ExpectedRuleCount = $CreatedRules.Count

Write-Host "[*] Expected MedDefense rules: $ExpectedRuleCount"

$LoadedRules = @(
    Get-NetFirewallRule -ErrorAction Stop |
        Where-Object { $_.DisplayName -like "$RulePrefix*" }
)

$ActualRuleCount = $LoadedRules.Count

Write-Host "[*] Verifying loaded rules..."
Write-Host "  Expected rules: $ExpectedRuleCount"
Write-Host "  Actual rules:   $ActualRuleCount"

if ($ActualRuleCount -ne $ExpectedRuleCount) {
    Write-Error 'Loaded MedDefense rule count does not match expected rule count.'
    exit 1
}

$ProfilesAfter = @(
    Get-NetFirewallProfile -Profile Domain,Private,Public |
        Select-Object Name,
        Enabled,
        DefaultInboundAction,
        DefaultOutboundAction,
        LogBlocked,
        LogAllowed,
        LogFileName
)

$PostChangeState = [PSCustomObject]@{
    Timestamp = (Get-Date).ToUniversalTime().ToString('o')
    ComputerName = $env:COMPUTERNAME
    LocalIPv4 = $LocalIPv4
    LocalZones = @($LocalZones)
    ExpectedRuleCount = $ExpectedRuleCount
    ActualRuleCount = $ActualRuleCount
    Profiles = $ProfilesAfter
    MedDefenseRules = @(
        Get-NetFirewallRule -ErrorAction Stop |
            Where-Object { $_.DisplayName -like "$RulePrefix*" } |
            ForEach-Object {
                $Rule = $_
                $PortFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule
                $AddressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule

                [PSCustomObject]@{
                    DisplayName = $Rule.DisplayName
                    Direction = [string]$Rule.Direction
                    Action = [string]$Rule.Action
                    Enabled = [string]$Rule.Enabled
                    Profile = [string]$Rule.Profile
                    Protocol = [string]$PortFilter.Protocol
                    LocalPort = @($PortFilter.LocalPort)
                    RemoteAddress = @($AddressFilter.RemoteAddress)
                }
            }
    )
}

$PostChangeState |
    ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $PostChangeJson -Encoding UTF8

Write-Host "Post-change state saved to: $PostChangeJson"
Write-Host 'Windows Firewall configuration successfully applied.'

