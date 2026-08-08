<#
.SYNOPSIS
15-master_validation.ps1

.DESCRIPTION
Validates MedDefense hardening settings and reports PASS, WARN, or FAIL.

.NOTES
Script Name: 15-master_validation.ps1
Purpose: MedDefense hardening validation
Author: Tristeceratops
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory -ErrorAction Stop

$Critical = $false
function Test-Check($Name,$OK,$critical=$true) {
if ($OK) { Write-Host "[PASS] $Name" -ForegroundColor Green }
elseif ($critical) { $script:Critical=$true; Write-Host "[FAIL] $Name" -ForegroundColor Red }
else { Write-Host "[WARN] $Name" -ForegroundColor Yellow }
}

$P = Get-ADDefaultDomainPasswordPolicy
Write-Host "--- Password & Lockout ---"
Test-Check "Minimum length: $($P.MinPasswordLength)" ($P.MinPasswordLength -ge 14)
Test-Check "Lockout threshold: $($P.LockoutThreshold)" ($P.LockoutThreshold -le 5 -and $P.LockoutThreshold -gt 0)

Write-Host "`n--- Audit Policy ---"
Test-Check "Process Creation: Success" ((auditpol /get /subcategory:"Process Creation") -match "Success")
$A = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ErrorAction SilentlyContinue
Test-Check "Command-line logging: Enabled" ($A.ProcessCreationIncludeCmdLine_Enabled -eq 1)
$L = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
Test-Check "Security log: 1 GB" ($L.MaxSize -eq 1073741824)

Write-Host "`n--- PowerShell ---"
$PS = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
$SB = Get-ItemProperty "$PS\ScriptBlockLogging" -ErrorAction SilentlyContinue
$TR = Get-ItemProperty "$PS\Transcription" -ErrorAction SilentlyContinue
Test-Check "Script Block Logging: Enabled" ($SB.EnableScriptBlockLogging -eq 1)
Test-Check "Transcription: Enabled" ($TR.EnableTranscripting -eq 1)

Write-Host "`n--- Sysmon ---"
$S = Get-Service Sysmon64 -ErrorAction SilentlyContinue
Test-Check "Service: Running" ($null -ne $S -and $S.Status -eq "Running")
$Rules = if (Test-Path "$env:ProgramData\Sysmon\sysmonconfig.xml") {(Select-String -Path "$env:ProgramData\Sysmon\sysmonconfig.xml" -Pattern "rclone|PsExec|-enc|vssadmin|schtasks" -AllMatches).Count} else {0}
Test-Check "Custom rules: 5 present" ($Rules -ge 5)

Write-Host "`n--- Kerberos ---"
$D = Get-ADObject (Get-ADDomain).DistinguishedName -Properties msDS-SupportedEncryptionTypes
$K = [int]$D.'msDS-SupportedEncryptionTypes'
Test-Check "DES: Disabled" (($K -band 3) -eq 0)
Test-Check "RC4: Disabled" (($K -band 4) -eq 0)

Write-Host "`n--- SMB ---"
$SMB = Get-SmbServerConfiguration
Test-Check "SMBv1: Disabled" ($SMB.EnableSMB1Protocol -eq $false)
Test-Check "Signing: Required" ($SMB.RequireSecuritySignature -eq $true)

Write-Host "`n--- Firewall ---"
$FW = Get-NetFirewallProfile
Test-Check "All profiles: ON, DefaultInbound: Block" (@($FW | Where-Object {$*.Enabled -eq $true -and $*.DefaultInboundAction -eq "Block"}).Count -eq 3)

Write-Host "`n--- RDP ---"
$RDP = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
Test-Check "NLA: Required" ($RDP.UserAuthentication -eq 1)
Test-Check "G_IT_Admins only" ((Get-LocalGroupMember "Remote Desktop Users" -ErrorAction SilentlyContinue).Name -match "G_IT_Admins")

Write-Host "`n--- Service Accounts ---"
$Svc = @(Get-ADUser -Filter 'SamAccountName -like "svc_*"' -Properties AccountNotDelegated,PasswordLastSet)
$Restricted = @($Svc | Where-Object AccountNotDelegated).Count
Test-Check "Delegation restricted: $Restricted/$($Svc.Count)" ($Restricted -eq $Svc.Count)
foreach ($A in $Svc) {
$Age = if ($A.PasswordLastSet) {[int](%28Get-Date%29-$A.PasswordLastSet).TotalDays} else {9999}
Test-Check "$($A.SamAccountName) password age: $Age days" ($Age -le 180) $false
}

Write-Host ""
if ($Critical) { Write-Host "Validation: FAIL" -ForegroundColor Red; exit 1 }
Write-Host "Validation: PASS" -ForegroundColor Green
exit 0