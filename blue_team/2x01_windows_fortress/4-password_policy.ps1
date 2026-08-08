<#
.SYNOPSIS
4-password_policy.ps1

.DESCRIPTION
Creates and links the MedDefense password and lockout GPO, configures the
domain password policy, forces Group Policy refresh, and verifies the
resulting policy using live Active Directory values.

.NOTES
Script Name: 4-password_policy.ps1
Purpose: Active Directory password and account lockout policy configuration
Author:
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
Import-Module ActiveDirectory
Import-Module GroupPolicy

$gpoName = "MedDefense - Password and Lockout Policy"
$domain = Get-ADDomain
$domainDn = $domain.DistinguishedName
$domainName = $domain.DNSRoot

Write-Host "[*] Creating GPO: `"$gpoName`"... " -NoNewline
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if ($null -eq $gpo) { $gpo = New-GPO -Name $gpoName; Write-Host "CREATED" }
else { Write-Host "EXISTS" }

Write-Host "[*] Configuring Password Policy..."
Set-ADDefaultDomainPasswordPolicy -Identity $domainName `
    -MinPasswordLength 14 `
    -ComplexityEnabled $true `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge ([TimeSpan]::Zero) `
    -MinPasswordAge ([TimeSpan]::FromDays(1))

$p = Get-ADDefaultDomainPasswordPolicy -Identity $domainName

Write-Host ("    Minimum Length: {0} [SET]" -f $p.MinPasswordLength)
Write-Host ("    Complexity: {0} [SET]" -f $(if ($p.ComplexityEnabled) { "Enabled" } else { "Disabled" }))
Write-Host ("    History: {0} [SET]" -f $p.PasswordHistoryCount)
Write-Host ("    Maximum Age: {0} [SET]" -f $(if ($p.MaxPasswordAge -eq [TimeSpan]::Zero) { "Never" } else { "$($p.MaxPasswordAge.TotalDays) days" }))
Write-Host ("    Minimum Age: {0} days [SET]" -f $p.MinPasswordAge.TotalDays)

Write-Host "[*] Configuring Account Lockout..."
Set-ADDefaultDomainPasswordPolicy -Identity $domainName `
    -LockoutThreshold 5 `
    -LockoutDuration ([TimeSpan]::FromMinutes(15)) `
    -LockoutObservationWindow ([TimeSpan]::FromMinutes(15))

$p = Get-ADDefaultDomainPasswordPolicy -Identity $domainName

Write-Host ("    Threshold: {0} attempts [SET]" -f $p.LockoutThreshold)
Write-Host ("    Duration: {0} minutes [SET]" -f $p.LockoutDuration.TotalMinutes)
Write-Host ("    Reset Counter: {0} minutes [SET]" -f $p.LockoutObservationWindow.TotalMinutes)

Write-Host "[*] Linking GPO to domain root... " -NoNewline
$linked = (Get-GPInheritance -Target $domainDn).GpoLinks | Where-Object DisplayName -eq $gpoName
if ($null -eq $linked) {
    New-GPLink -Name $gpoName -Target $domainDn -LinkEnabled Yes | Out-Null
    Write-Host "LINKED"
}
else { Write-Host "ALREADY LINKED" }

Write-Host "[*] Forcing Group Policy update... " -NoNewline
Invoke-GPUpdate -Computer $env:COMPUTERNAME -Target Computer -Force | Out-Null
Write-Host "COMPLETE"

Write-Host "[*] Verifying effective policy..."
$p = Get-ADDefaultDomainPasswordPolicy -Identity $domainName

$checks = [ordered]@{
    "Minimum Length"     = $p.MinPasswordLength -eq 14
    "Complexity"         = $p.ComplexityEnabled -eq $true
    "History"            = $p.PasswordHistoryCount -eq 24
    "Maximum Age"        = $p.MaxPasswordAge -eq [TimeSpan]::Zero
    "Minimum Age"        = $p.MinPasswordAge -eq [TimeSpan]::FromDays(1)
    "Lockout Threshold"  = $p.LockoutThreshold -eq 5
    "Lockout Duration"   = $p.LockoutDuration -eq [TimeSpan]::FromMinutes(15)
    "Reset Counter"      = $p.LockoutObservationWindow -eq [TimeSpan]::FromMinutes(15)
}

foreach ($check in $checks.GetEnumerator()) {
    Write-Host ("    {0}: {1}" -f $check.Key, $(if ($check.Value) { "PASS" } else { "FAIL" }))
}

if ($checks.Values -contains $false) {
    Write-Host ""
    Write-Host "[!] Effective policy does not match the requested configuration." -ForegroundColor Yellow
    Write-Host "[!] Actual values returned by Active Directory:"
    $p | Select-Object MinPasswordLength,ComplexityEnabled,PasswordHistoryCount,
        MaxPasswordAge,MinPasswordAge,LockoutThreshold,
        LockoutDuration,LockoutObservationWindow |
        Format-List
    throw "Effective policy verification failed."
}

Write-Host "[*] Effective policy: VERIFIED" -ForegroundColor Green

}
catch {
Write-Error "Password policy configuration failed: $($_.Exception.Message)"
exit 1
}
