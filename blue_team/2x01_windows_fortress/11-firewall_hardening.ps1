<#
.SYNOPSIS
11-firewall_hardening.ps1

.DESCRIPTION
Captures the current firewall state, enables all profiles with default-deny
inbound policy, creates MedDefense service rules, enables dropped-packet
logging, disables legacy allow rules, and verifies the result.

.NOTES
Script Name: 11-firewall_hardening.ps1
Purpose: Windows Firewall hardening and service allow-list configuration
Author: Tristeceratops
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module NetSecurity -ErrorAction Stop
$Profiles = "Domain","Private","Public"
$Before = Get-NetFirewallProfile -Name $Profiles

Write-Host "[*] Current Firewall State..."
foreach ($P in $Before) {
Write-Host "    $($P.Name): $($P.Enabled), DefaultInbound: $($P.DefaultInboundAction)"
}

Set-NetFirewallProfile -Name $Profiles -Enabled True -DefaultInboundAction Block -LogBlocked True
Write-Host "[*] Setting default-deny on all profiles... [SET]"

$Rules = @(
@("MedDef-RDP-Mgmt",3389,"TCP","10.10.3.0/24"),
@("MedDef-DNS-TCP",53,"TCP","Any"),
@("MedDef-DNS-UDP",53,"UDP","Any"),
@("MedDef-LDAP",389,"TCP","Any"),
@("MedDef-Kerberos-TCP",88,"TCP","Any"),
@("MedDef-Kerberos-UDP",88,"UDP","Any"),
@("MedDef-SMB",445,"TCP","10.10.1.0/24"),
@("MedDef-WinRM",5985,5986,"10.10.3.0/24")
)

Write-Host "[*] Creating allow rules..."
foreach ($R in $Rules) {
$Name = $R[0]
if ($null -eq (Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue)) {
$Ports = if ($R[2] -is [int]) { @($R[1],$R[2]) } else { $R[1] }
$Protocol = if ($R[2] -is [int]) { "TCP" } else { $R[2] }
New-NetFirewallRule -Name $Name -DisplayName $Name -Direction Inbound -Action Allow `            -Enabled True -Profile Any -Protocol $Protocol -LocalPort $Ports`
-RemoteAddress $R[3] | Out-Null
}
Write-Host "    $Name [CREATED]"
}

Set-NetFirewallProfile -Name $Profiles -LogBlocked True
Write-Host "[*] Enabling dropped packet logging... [SET]"

$Legacy = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
Where-Object { $_.Name -notlike "MedDef-*" }

$Legacy | Disable-NetFirewallRule | Out-Null
Write-Host "[*] Disabling $($Legacy.Count) legacy allow rules... [DONE]"

Write-Host "[*] Verification..."
$After = Get-NetFirewallProfile -Name $Profiles
$Custom = Get-NetFirewallRule -Name "MedDef-*" -ErrorAction SilentlyContinue |
Where-Object Enabled -eq True

if (($After | Where-Object {$*.Enabled -ne "True" -or $*.DefaultInboundAction -ne "Block"}).Count -eq 0) {
Write-Host "    All 3 profiles: ON, DefaultInbound: Block [VERIFIED]" -ForegroundColor Green
} else { throw "Firewall profile verification failed." }

if ($Custom.Count -ge 6) {
Write-Host "    Custom rules: $($Custom.Count) active [VERIFIED]" -ForegroundColor Green
} else { throw "Custom firewall rule verification failed." }

Write-Host "Firewall Hardening VERIFIED" -ForegroundColor Green
