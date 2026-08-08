<#
.SYNOPSIS
15-master_validation.ps1

.DESCRIPTION
Validates the MedDefense hardened Windows security configuration and returns
PASS, WARN, or FAIL for critical security controls.

.NOTES
Script Name: 15-master_validation.ps1
Purpose: Master validation of MedDefense security hardening
Author: Tristeceratops
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$Fail = 0
function Test-Check($Name,$Result,$Critical=$true) {
if ($Result) { Write-Host "[PASS] $Name" -ForegroundColor Green }
elseif ($Critical) { Write-Host "[FAIL] $Name" -ForegroundColor Red; $script:Fail = 1 }
else { Write-Host "[WARN] $Name" -ForegroundColor Yellow }
}

$Domain = Get-ADDomain
$Lock = Get-ADDefaultDomainPasswordPolicy
$Audit = (auditpol /get /subcategory:"Process Creation") -join " "
$Cmd = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ErrorAction SilentlyContinue
$SecLog = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name MaxSize).MaxSize

Write-Host "--- Password & Lockout ---"
Test-Check "Minimum length: $($Lock.MinPasswordLength)" ($Lock.MinPasswordLength -ge 14)
Test-Check "Lockout threshold: $($Lock.LockoutThreshold)" ($Lock.LockoutThreshold -le 5 -and $Lock.LockoutThreshold -gt 0)

Write-Host "`n--- Audit Policy ---"
Test-Check "Process Creation: Success" ($Audit -match "Success")
Test-Check "Command-line logging: Enabled" ($Cmd.ProcessCreationIncludeCmdLine_Enabled -eq 1)
Test-Check "Security log: 1 GB" ($SecLog -ge 1073741824)

$PSKey = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"
$PSLog = Get-ItemProperty $PSKey -ErrorAction SilentlyContinue
$Trans = Get-ItemProperty "$PSKey\Transcription" -ErrorAction SilentlyContinue

Write-Host "`n--- PowerShell ---"
Test-Check "Script Block Logging: Enabled" ($PSLog.EnableScriptBlockLogging -eq 1)
Test-Check "Transcription: Enabled" ($Trans.EnableTranscripting -eq 1)

$Sysmon = Get-Service Sysmon64 -ErrorAction SilentlyContinue
Write-Host "`n--- Sysmon ---"
Test-Check "Sysmon: Service Running" ($null -ne $Sysmon -and $Sysmon.Status -eq "Running")

$Kerb = Get-ADObject $Domain.DistinguishedName -Properties msDS-SupportedEncryptionTypes
$Enc = [int]$Kerb.'msDS-SupportedEncryptionTypes'
Write-Host "`n--- Kerberos ---"
Test-Check "DES: Disabled" (($Enc -band 3) -eq 0)
Test-Check "RC4: Disabled" (($Enc -band 4) -eq 0)

$SMB = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
Write-Host "`n--- SMB ---"
Test-Check "SMBv1: Disabled" ($null -ne $SMB -and $SMB.EnableSMB1Protocol -eq $false)
Test-Check "Signing: Required" ($null -ne $SMB -and $SMB.RequireSecuritySignature -eq $true)

$FW = Get-NetFirewallProfile
Write-Host "`n--- Firewall ---"
Test-Check "All profiles: ON, DefaultInbound: Block" (($FW | Where-Object { !$*.Enabled -or $*.DefaultInboundAction -ne "Block" }).Count -eq 0)

$RDP = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$Groups = Get-LocalGroupMember "Remote Desktop Users" -ErrorAction SilentlyContinue
Write-Host "`n--- RDP ---"
Test-Check "NLA: Required" ($RDP.UserAuthentication -eq 1)
Test-Check "G_IT_Admins only" (($Groups.Name -match "G_IT_Admins").Count -gt 0) $false

Write-Host "`n--- Service Accounts ---"
$Svc = Get-ADUser -Filter 'SamAccountName -like "svc*"' -Properties AccountNotDelegated,PasswordLastSet
$Delegation = @($Svc | Where-Object { $_.AccountNotDelegated }).Count
Test-Check "Delegation restricted: $Delegation/$($Svc.Count)" ($Svc.Count -eq 0 -or $Delegation -eq $Svc.Count)
foreach ($A in $Svc) {
if ($A.PasswordLastSet) {
$Age = [int]((Get-Date) - $A.PasswordLastSet).TotalDays
if ($Age -gt 180) { Test-Check "$($A.SamAccountName) password age: $Age days" $false $false }
}
}

if ($Fail -eq 0) { Write-Host "`nValidation complete: PASS" -ForegroundColor Green; exit 0 }
Write-Host "`nValidation complete: FAIL (critical)" -ForegroundColor Red
exit 1
