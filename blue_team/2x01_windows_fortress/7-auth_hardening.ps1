<#
.SYNOPSIS
7-auth_hardening.ps1

.DESCRIPTION
Hardens Kerberos encryption, removes DES from service accounts, restricts
Kerberos to AES128 and AES256, disables NTLMv1, configures Credential Guard,
and verifies the resulting authentication security configuration.

.NOTES
Script Name: 7-auth_hardening.ps1
Purpose: Active Directory authentication hardening
Author: Tristeceratops
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory -ErrorAction Stop

$Admin = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $Admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
throw "Run this script as Administrator."
}

$Domain = (Get-ADDomain).DNSRoot
$NTLMKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$DeviceGuard = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"

Write-Host "[*] Current Kerberos encryption types..."

$KDC = Get-ADUser -Identity "krbtgt" -Properties msDS-SupportedEncryptionTypes
$Types = $KDC.'msDS-SupportedEncryptionTypes'

if ($null -eq $Types -or $Types -eq 0) {
Write-Host "    Default Kerberos encryption types"
} else {
Write-Host "    msDS-SupportedEncryptionTypes: $Types"
}

Write-Host "[*] Service accounts with UseDESKeyOnly..."

$DESAccounts = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))" -Properties ServicePrincipalName

if ($DESAccounts) {
foreach ($Account in $DESAccounts) {
Write-Host "    $($Account.SamAccountName): UseDESKeyOnly = True [!]"
if ($Account.ServicePrincipalName) {
foreach ($SPN in $Account.ServicePrincipalName) {
Write-Host "    $($Account.SamAccountName): ServicePrincipalName = $SPN"
}
} else {
Write-Host "    $($Account.SamAccountName): ServicePrincipalName = None"
}
}
} else {
Write-Host "    None found"
}

Write-Host "[*] Remediating..."

foreach ($Account in $DESAccounts) {
Set-ADAccountControl -Identity $Account -UseDESKeyOnly $false
Write-Host "    $($Account.SamAccountName): DES disabled [DONE]"
}

Set-ADUser -Identity "krbtgt" -Replace @{'msDS-SupportedEncryptionTypes' = 24}
Write-Host "    Kerberos: AES128 + AES256 only [SET]"

Set-ItemProperty -Path $NTLMKey -Name LmCompatibilityLevel -Type DWord -Value 5
Write-Host "    NTLMv1: disabled, NTLMv2 only [SET]"

New-Item -Path $DeviceGuard -Force | Out-Null
Set-ItemProperty -Path $DeviceGuard -Name EnableVirtualizationBasedSecurity -Type DWord -Value 1
Set-ItemProperty -Path $DeviceGuard -Name LsaCfgFlags -Type DWord -Value 2
Write-Host "    Credential Guard: DeviceGuard configured [SET]"

Write-Host "[*] Verifying..."

$FinalKDC = Get-ADUser -Identity "krbtgt" -Properties msDS-SupportedEncryptionTypes
$FinalTypes = $FinalKDC.'msDS-SupportedEncryptionTypes'
$FinalNTLM = (Get-ItemProperty -Path $NTLMKey).LmCompatibilityLevel
$FinalCG = (Get-ItemProperty -Path $DeviceGuard).LsaCfgFlags
$RemainingDES = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))"

Write-Host "    msDS-SupportedEncryptionTypes: $FinalTypes"

if ($FinalTypes -eq 24) {
Write-Host "    Kerberos: AES128, AES256 only [VERIFIED]" -ForegroundColor Green
} else {
throw "Kerberos verification failed: expected 24, got $FinalTypes"
}

if ($FinalNTLM -eq 5) {
Write-Host "    NTLMv1: disabled / NTLMv2: allowed [VERIFIED]" -ForegroundColor Green
} else {
throw "LmCompatibilityLevel verification failed."
}

if ($FinalCG -eq 2) {
Write-Host "    Credential Guard: LsaCfgFlags = 2 [VERIFIED]" -ForegroundColor Green
} else {
throw "Credential Guard verification failed."
}

if ($null -eq $RemainingDES) {
Write-Host "    DES / UseDESKeyOnly accounts: None [VERIFIED]" -ForegroundColor Green
} else {
throw "DES-enabled accounts remain."
}

Write-Host ""
Write-Host "Authentication Hardening VERIFIED" -ForegroundColor Green
