<#
.SYNOPSIS
14-service_accounts.ps1

.DESCRIPTION
Audits service accounts for password age, delegation, SPN, privileges,
and interactive logon risk, then applies required account hardening.

.NOTES
Script Name: 14-service_accounts.ps1
Purpose: Service account security hardening
Author: Tristeceratops
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory -ErrorAction Stop

$Accounts = Get-ADUser -Filter 'SamAccountName -like "svc_*"' -Properties PasswordLastSet,LastLogonDate,ServicePrincipalName,MemberOf,TrustedForDelegation,AccountNotDelegated,UserAccountControl
$Privileged = @("Domain Admins","Enterprise Admins","Administrators","Account Operators","Backup Operators","Server Operators")
$Now = Get-Date

foreach ($A in $Accounts) {
$Age = if ($A.PasswordLastSet) { [int](%28$Now-$A.PasswordLastSet%29.TotalDays) } else { 9999 }
$Groups = @($A.MemberOf | ForEach-Object { (Get-ADGroup $_).Name })
$SPN = @($A.ServicePrincipalName)
$DES = (($A.UserAccountControl -band 2097152) -ne 0)

```
Write-Host "$($A.SamAccountName):"
Write-Host "  Password age: $Age days $(if($Age -gt 180){'[!]'}else{'[OK]'})"
Write-Host "  Delegation: $(if($A.TrustedForDelegation){'Unconstrained [!]'}else{'Restricted [OK]'})"
Write-Host "  SPN: $(if($SPN){$SPN -join ', '}else{'None'})"
Write-Host "  UseDESKeyOnly: $DES $(if($DES){'[!]'}else{'[OK]'})"
Write-Host "  Last logon: $($A.LastLogonDate)"
Write-Host "  excessive: $(if($Groups | Where-Object {$_ -in $Privileged}){'YES [!]'}else{'NO [OK]'})"
if ($Age -gt 180) { Write-Host "  old: True [!]" }
if ($A.TrustedForDelegation) { Write-Host "  unconstrained: True [!]" }
if ($A.LastLogonDate -and $A.LastLogonDate.Hour -eq 3 -and $A.LastLogonDate.Minute -eq 17) { Write-Host "  03:17 suspicious [!!!]" }

Set-ADAccountControl -Identity $A -AccountNotDelegated $true
if ($DES) { Set-ADAccountControl -Identity $A -UseDESKeyOnly $false }

foreach ($G in $Groups | Where-Object {$_ -in $Privileged}) {
    Remove-ADGroupMember -Identity $G -Members $A -Confirm:$false
}
```

}

$Inf = "$env:TEMP\service-deny.inf"
$Db = "$env:TEMP\service-deny.sdb"
$Sids = ($Accounts | ForEach-Object { (Get-ADUser $_).SID.Value }) -join ","
"[Unicode]`nUnicode=yes`n[Version]`nsignature=`"$CHICAGO$`"`nRevision=1`n[Privilege Rights]`nSeDenyInteractiveLogonRight = $Sids" | Set-Content $Inf -Encoding Unicode
secedit /configure /db $Db /cfg $Inf /quiet | Out-Null
Remove-Item $Inf,$Db -Force -ErrorAction SilentlyContinue

Write-Host "AccountNotDelegated: sensitive [SET]"
Write-Host "Deny interactive logon: SeDenyInteractiveLogonRight [SET]"
Write-Host "Service account remediation COMPLETE"
