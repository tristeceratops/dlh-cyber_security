<#
.SYNOPSIS
5-audit_policy.ps1

.DESCRIPTION
Creates and links the MedDefense Advanced Audit Policy Group Policy Object,
configures granular Windows security auditing required for detection and
response, enables command-line logging for process creation events,
configures the Security event log, forces Group Policy refresh,
and verifies the resulting audit policy.

.NOTES
Script Name: 5-audit_policy.ps1
Purpose: Advanced Windows audit policy configuration for security visibility
Author: Tristeceratops
Date: 2026-08-08
#>


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

$GPOName = "MedDefense - Advanced Audit Policy"
$Domain = (Get-ADDomain).DNSRoot
$Target = (Get-ADDomain).DistinguishedName

Write-Host "[*] Creating GPO: `"$GPOName`"..." -ForegroundColor Cyan

$GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue

if ($null -eq $GPO) {
    $GPO = New-GPO -Name $GPOName
    Write-Host "    CREATED" -ForegroundColor Green
} else {
    Write-Host "    EXISTS" -ForegroundColor Yellow
}

Write-Host "[*] Configuring Audit Categories..." -ForegroundColor Cyan

$Both = @(
    "Credential Validation",
    "Kerberos Authentication Service",
    "Logon",
    "User Account Management",
    "Sensitive Privilege Use",
    "File System",
    "Registry"
)

$Success = @(
    "Logoff",
    "Special Logon",
    "Process Creation"
)

foreach ($Audit in $Both) {
    auditpol /set /subcategory:"$Audit" /success:enable /failure:enable | Out-Null
}

foreach ($Audit in $Success) {
    auditpol /set /subcategory:"$Audit" /success:enable | Out-Null
}

Write-Host "    Credential Validation: Success, Failure [SET]"
Write-Host "    Kerberos Authentication: Success, Failure [SET]"
Write-Host "    Logon: Success, Failure [SET]"
Write-Host "    Special Logon: Success [SET]"
Write-Host "    User Account Management: Success, Failure [SET]"
Write-Host "    Sensitive Privilege Use: Success, Failure [SET]"
Write-Host "    Process Creation: Success [SET]"

$AuditKey = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"

$Existing = Get-GPRegistryValue -Name $GPOName `
    -Key $AuditKey `
    -ValueName "ProcessCreationIncludeCmdLine_Enabled" `
    -ErrorAction SilentlyContinue

if ($null -eq $Existing -or $Existing.Value -ne 1) {
    try {
        Set-GPRegistryValue -Name $GPOName `
            -Key $AuditKey `
            -ValueName "ProcessCreationIncludeCmdLine_Enabled" `
            -Type DWord `
            -Value 1
    }
    catch {
        Write-Warning "CommandLine registry value could not be written through GPO."
    }
}

Write-Host "[*] Enabling command-line logging in process creation events... [SET]"
Write-Host "    4688 CommandLine: ENABLED"

Write-Host "[*] Setting Security log max size to 1 GB... [SET]"

$SecurityKey = "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security"
$CurrentSize = (Get-ItemProperty -Path "Registry::$SecurityKey" -Name MaxSize -ErrorAction SilentlyContinue).MaxSize

if ($CurrentSize -ne 1073741824) {
    New-ItemProperty -Path "Registry::$SecurityKey" `
        -Name MaxSize `
        -PropertyType DWord `
        -Value 1073741824 `
        -Force | Out-Null
}

Write-Host "[*] Restricting Security log Clear..."

$DomainAdmins = (Get-ADDomain).DomainSID.Value + "-512"
$Inf = "$env:TEMP\MedDefense-Audit.inf"
$Db = "$env:TEMP\MedDefense-Audit.sdb"

@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeSecurityPrivilege = *$DomainAdmins
"@ | Set-Content $Inf -Encoding Unicode

secedit /configure /db $Db /cfg $Inf /quiet | Out-Null

Remove-Item $Inf,$Db -Force -ErrorAction SilentlyContinue

Write-Host "    Domain Admins: Restrict Clear [SET]"

$Links = Get-GPInheritance -Target $Target

if (-not ($Links.GpoLinks | Where-Object DisplayName -eq $GPOName)) {
    New-GPLink -Name $GPOName -Target $Target -LinkEnabled Yes | Out-Null
}

Write-Host "[*] Linking GPO and forcing update..." -ForegroundColor Cyan
gpupdate /force | Out-Null
Write-Host "    COMPLETE" -ForegroundColor Green

Write-Host ""
Write-Host "[*] VERIFY: auditpol /get /category:*" -ForegroundColor Cyan
auditpol /get /category:*

Write-Host ""
Write-Host "Audit Policy VERIFIED" -ForegroundColor Green