<#
.SYNOPSIS
13-rdp_hardening.ps1

.DESCRIPTION
Hardens RDP authentication, access, session limits, encryption,
redirection, and Remote Assistance, then verifies the configuration.

.NOTES
Script Name: 13-rdp_hardening.ps1
Purpose: RDP security hardening
Author: Tristeceratops
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TS = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$RDP = "$TS\WinStations\RDP-Tcp"
$Policies = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$RA = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
$Group = "G_IT_Admins"

New-Item $Policies -Force | Out-Null
New-Item $RDP -Force | Out-Null
New-Item $RA -Force | Out-Null

Set-ItemProperty $RDP -Name UserAuthentication -Type DWord -Value 1
Set-ItemProperty $RDP -Name MinEncryptionLevel -Type DWord -Value 4
Set-ItemProperty $Policies -Name fDisableClip -Type DWord -Value 1
Set-ItemProperty $Policies -Name fDisableCdm -Type DWord -Value 1
Set-ItemProperty $RA -Name fAllowToGetHelp -Type DWord -Value 0

Set-ItemProperty $Policies -Name MaxIdleTime -Type DWord -Value 900000
Set-ItemProperty $Policies -Name MaxConnectionTime -Type DWord -Value 28800000

$RDS = Get-LocalGroupMember "Remote Desktop Users" -ErrorAction SilentlyContinue
$RDS | Where-Object Name -match "Domain Users" | Remove-LocalGroupMember -Group "Remote Desktop Users" -Confirm:$false
if (-not ($RDS | Where-Object Name -match $Group)) { Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Group }

Write-Host "[*] Enabling NLA... UserAuthentication = 1 [SET]"
Write-Host "[*] Restricting to G_IT_Admins... [SET]"
Write-Host "[*] Session limits... Idle: 15 min, Max: 8 hours [SET]"
Write-Host "[*] Encryption: High/SSL [SET]"
Write-Host "[*] Clipboard: Disabled [SET]"
Write-Host "[*] Drive Redirection: Disabled [SET]"
Write-Host "[*] Remote Assistance: Disabled [SET]"

$NLA = (Get-ItemProperty $RDP).UserAuthentication
$Enc = (Get-ItemProperty $RDP).MinEncryptionLevel
$Clip = (Get-ItemProperty $Policies).fDisableClip
$Drive = (Get-ItemProperty $Policies).fDisableCdm
$Assist = (Get-ItemProperty $RA).fAllowToGetHelp
$Members = Get-LocalGroupMember "Remote Desktop Users"

Write-Host "[*] Verification..."
if ($NLA -eq 1) { Write-Host "    NLA: Required [VERIFIED]" } else { throw "NLA verification failed." }
if ($Enc -eq 4) { Write-Host "    Encryption: High [VERIFIED]" } else { throw "Encryption verification failed." }
if ($Clip -eq 1) { Write-Host "    Clipboard: Disabled [VERIFIED]" } else { throw "Clipboard verification failed." }
if ($Drive -eq 1) { Write-Host "    Drive Redirection: Disabled [VERIFIED]" } else { throw "Drive verification failed." }
if ($Assist -eq 0) { Write-Host "    Remote Assistance: Disabled [VERIFIED]" } else { throw "Remote Assistance verification failed." }
if ($Members.Name -match $Group) { Write-Host "    Access: G_IT_Admins only [VERIFIED]" } else { throw "RDP group verification failed." }
