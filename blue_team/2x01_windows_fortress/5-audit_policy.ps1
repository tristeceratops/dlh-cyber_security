<#

.SYNOPSIS

5-audit_policy.ps1


.DESCRIPTION

Creates and links the MedDefense Advanced Audit Policy GPO, configures
Advanced Audit Policy, enables process command-line logging, restricts
Security log clearing, sets the Security log to 1 GB, forces Group Policy,
and verifies the resulting policy.

.NOTES

Script Name: 5-audit_policy.ps1
Purpose: Active Directory Advanced Audit Policy configuration
Author: Tristeceratops
Date: 2026-08-08

#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$Domain = Get-ADDomain
$GpoName = "MedDefense - Advanced Audit Policy"
$Gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue

Write-Host "[*] Creating GPO: $GpoName..." -NoNewline
if (!$Gpo) {
    $Gpo = New-GPO $GpoName
    Write-Host " CREATED"
} else {
    Write-Host " EXISTS"
}

Write-Host "[*] Configuring Audit Categories..."

$audit = @(
    "Credential Validation",
    "Kerberos Authentication Service",
    "Logon",
    "Logoff",
    "Special Logon",
    "User Account Management",
    "Sensitive Privilege Use",
    "File System",
    "Registry",
    "Process Creation"
)

foreach ($a in $audit) {
    $failure = $a -in @(
        "Credential Validation",
        "Kerberos Authentication Service",
        "Logon",
        "User Account Management",
        "Sensitive Privilege Use",
        "File System",
        "Registry"
    )

    if ($failure) {
        & auditpol /set /subcategory:"$a" /success:enable /failure:enable
    } else {
        & auditpol /set /subcategory:"$a" /success:enable
    }

    if ($LASTEXITCODE) { throw "auditpol failed: $a" }
    Write-Host "    $a [SET]"
}

Write-Host "[*] Enabling command-line in process creation events... [SET]"
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -ValueName "ProcessCreationIncludeCmdLine_Enabled" `
    -Type DWord -Value 1

Write-Host "[*] Setting Security log max size to 1 GB... [SET]"
Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security" `
    -ValueName "MaxSize" `
    -Type DWord -Value 1073741824

Write-Host "[*] Restricting Security log clearing... [SET]"
$admins = (Get-ADGroup "Domain Admins").SID.Value
$inf = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\{$($Gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit"
New-Item $inf -ItemType Directory -Force | Out-Null

@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeSecurityPrivilege = *$admins
"@ | Set-Content "$inf\GptTmpl.inf" -Encoding Unicode

Write-Host "[*] Saving Advanced Audit Policy to GPO..."
$temp = "$env:TEMP\audit.csv"
& auditpol /backup /file:$temp
if ($LASTEXITCODE) { throw "auditpol backup failed." }

$auditPath = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\{$($Gpo.Id)}\Machine\Microsoft\Windows NT\Audit"
New-Item $auditPath -ItemType Directory -Force | Out-Null
Copy-Item $temp "$auditPath\audit.csv" -Force

Set-GPRegistryValue -Name $GpoName `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "SCENoApplyLegacyAuditPolicy" `
    -Type DWord -Value 1

Write-Host "[*] Linking GPO and forcing update... COMPLETE"
if (!(Get-GPInheritance $Domain.DistinguishedName |
    Select-Object -ExpandProperty GpoLinks |
    Where-Object DisplayName -eq $GpoName)) {
    New-GPLink -Name $GpoName -Target $Domain.DistinguishedName | Out-Null
}

gpupdate /force | Out-Null

Write-Host "[*] Verifying with auditpol /get /category:*"
auditpol /get /category:*

Remove-Item $temp -Force -ErrorAction SilentlyContinue

Write-Host "`n[+] MedDefense Advanced Audit Policy configured successfully." -ForegroundColor Green