<#
.SYNOPSIS
4-password_policy.ps1

.DESCRIPTION
Creates and links the MedDefense password and lockout GPO, configures the
domain password and account lockout policy, forces Group Policy refresh,
and verifies the resulting policy using live Active Directory values.

.NOTES
Script Name: 4-password_policy.ps1
Purpose: Active Directory password and account lockout policy configuration
Author: Tristeceratops
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

$MinimumPasswordLength = 14
$Complexity = $true
$PasswordHistoryCount = 24
$MaxPasswordAge = [TimeSpan]::Zero
$MinPasswordAge = [TimeSpan]::FromDays(1)
$LockoutThreshold = 5
$LockoutDuration = [TimeSpan]::FromMinutes(15)
$LockoutObservationWindow = [TimeSpan]::FromMinutes(15)

Write-Host "[*] Creating GPO: `"$gpoName`"... " -NoNewline
$gpo = Get-GPO -Name $gpoName -Domain $domainName -ErrorAction SilentlyContinue
if ($null -eq $gpo) {
    $gpo = New-GPO -Name $gpoName -Domain $domainName
    Write-Host "CREATED"
}
else {
    Write-Host "EXISTS"
}

Write-Host "[*] Configuring Password Policy..."
Set-ADDefaultDomainPasswordPolicy -Identity $domainName `
    -MinPasswordLength $MinimumPasswordLength `
    -ComplexityEnabled $Complexity `
    -PasswordHistoryCount $PasswordHistoryCount `
    -MaxPasswordAge $MaxPasswordAge `
    -MinPasswordAge $MinPasswordAge

$policy = Get-ADDefaultDomainPasswordPolicy -Identity $domainName

Write-Host ("    MinimumPasswordLength: {0} [SET]" -f $policy.MinPasswordLength)
Write-Host ("    Complexity: {0} [SET]" -f $(if ($policy.ComplexityEnabled) { "Enabled" } else { "Disabled" }))
Write-Host ("    PasswordHistoryCount: {0} [SET]" -f $policy.PasswordHistoryCount)
Write-Host ("    MaxPasswordAge: {0} days [SET]" -f $policy.MaxPasswordAge.TotalDays)
Write-Host ("    MinPasswordAge: {0} days [SET]" -f $policy.MinPasswordAge.TotalDays)

Write-Host "[*] Configuring Account Lockout..."
Set-ADDefaultDomainPasswordPolicy -Identity $domainName `
    -LockoutThreshold $LockoutThreshold `
    -LockoutDuration $LockoutDuration `
    -LockoutObservationWindow $LockoutObservationWindow

$policy = Get-ADDefaultDomainPasswordPolicy -Identity $domainName

Write-Host ("    LockoutThreshold: {0} attempts [SET]" -f $policy.LockoutThreshold)
Write-Host ("    LockoutDuration: {0} minutes [SET]" -f $policy.LockoutDuration.TotalMinutes)
Write-Host ("    LockoutObservationWindow: {0} minutes [SET]" -f $policy.LockoutObservationWindow.TotalMinutes)

Write-Host "[*] Linking GPO to domain root... " -NoNewline
$linked = (Get-GPInheritance -Target $domainDn -Domain $domainName).GpoLinks |
    Where-Object DisplayName -eq $gpoName

if ($null -eq $linked) {
    New-GPLink -Name $gpoName -Target $domainDn -Domain $domainName -LinkEnabled Yes | Out-Null
    Write-Host "LINKED"
}
else {
    Write-Host "ALREADY LINKED"
}

Write-Host "[*] Forcing Group Policy update... " -NoNewline
gpupdate.exe /force | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "gpupdate failed with exit code $LASTEXITCODE."
}
Write-Host "COMPLETE"

Write-Host "[*] VERIFY effective policy..."
$policy = Get-ADDefaultDomainPasswordPolicy -Identity $domainName

$checks = [ordered]@{
    MinimumPasswordLength       = $policy.MinPasswordLength -eq $MinimumPasswordLength
    Complexity                  = $policy.ComplexityEnabled -eq $Complexity
    PasswordHistoryCount        = $policy.PasswordHistoryCount -eq $PasswordHistoryCount
    MaxPasswordAge              = $policy.MaxPasswordAge -eq $MaxPasswordAge
    MinPasswordAge              = $policy.MinPasswordAge -eq $MinPasswordAge
    LockoutThreshold            = $policy.LockoutThreshold -eq $LockoutThreshold
    LockoutDuration             = $policy.LockoutDuration -eq $LockoutDuration
    LockoutObservationWindow    = $policy.LockoutObservationWindow -eq $LockoutObservationWindow
}

foreach ($check in $checks.GetEnumerator()) {
    Write-Host ("    {0}: {1}" -f $check.Key, $(if ($check.Value) { "PASS" } else { "FAIL" }))
}

if ($checks.Values -contains $false) {
    Write-Host ""
    Write-Host "[!] VERIFY FAILED: Effective policy does not match the requested configuration." -ForegroundColor Red
    Write-Host "[!] Actual values returned by Get-ADDefaultDomainPasswordPolicy:"
    $policy |
        Select-Object MinPasswordLength,ComplexityEnabled,PasswordHistoryCount,
            MaxPasswordAge,MinPasswordAge,LockoutThreshold,
            LockoutDuration,LockoutObservationWindow |
        Format-List
    throw "Effective policy verification failed."
}

Write-Host "[+] VERIFIED: Password and lockout policy successfully applied." -ForegroundColor Green

}
catch {
Write-Error "Password policy configuration failed: $($_.Exception.Message)"
exit 1
}
