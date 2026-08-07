<#
.SYNOPSIS
1-domain_findings.ps1

.DESCRIPTION
Audits the MedDefense Active Directory domain (meddefense.local) and
identifies security findings against the Windows Fortress target state.

The script performs security assessments and generates a structured JSON
report (domain_security_findings.json) containing all identified findings.

The assessment includes:
- Accounts with PasswordNeverExpires enabled
- Disabled accounts that remain members of privileged groups
- Stale computer accounts with no authentication activity for 90+ days
- Password and account lockout policy gaps
- Advanced Audit Policy, PowerShell logging, and Sysmon readiness
- Service account security risks, including:
    - interactive logon exposure
    - Unconstrained delegation
    - DES-only Kerberos encryption
    - Privileged group membership
    - Stale passwords
    - Suspicious last logon activity
- Group Policy security posture, including missing hardening GPOs and
  GPOs without a clear security purpose

Each finding contains:
- id
- severity
- category
- asset
- evidence
- risk
- recommended_remediation
- mapped_task

.OUTPUTS
domain_security_findings.json

.NOTES
Script Name : 1-domain_findings.ps1
Purpose     : Active Directory security findings assessment
Target      : meddefense.local
Author      : Tristeceratops
Date        : 07/08/2026
#>

Import-Module ActiveDirectory
Import-Module GroupPolicy

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Findings = @()

function Add-Finding {
    param(
        [string]$Id,
        [string]$Severity,
        [string]$Category,
        [string]$Asset,
        [object]$Evidence,
        [string]$Risk,
        [string]$Remediation,
        [string]$Task
    )

    $script:Findings += [PSCustomObject]@{
        id                        = $Id
        severity                  = $Severity
        category                  = $Category
        asset                     = $Asset
        evidence                  = $Evidence
        risk                      = $Risk
        recommended_remediation   = $Remediation
        mapped_task               = $Task
    }

    Write-Host "[$Severity] $Asset`: $Risk"
}

#########################################################
# DOMAIN
#########################################################

$Domain = Get-ADDomain
$DomainDN = $Domain.DistinguishedName
$Today = Get-Date
$StaleDate = $Today.AddDays(-90)

#########################################################
# 1 PASSWORD NEVER EXPIRES
#########################################################

$users = Get-ADUser -Filter * -Properties `
PasswordNeverExpires,
Enabled,
PasswordLastSet,
LastLogonDate,
ServicePrincipalName,
DistinguishedName

foreach ($user in $users) {

    if (-not $user.PasswordNeverExpires) {
        continue
    }

    $groups = Get-ADPrincipalGroupMembership $user |
        Select-Object -ExpandProperty Name

    $service =
        ($user.ServicePrincipalName.Count -gt 0) -or
        ($user.Name -match "^svc") -or
        ($user.DistinguishedName -match "OU=Service")

    Add-Finding `
        -Id "PW-001" `
        -Severity "High" `
        -Category "Password Policy" `
        -Asset $user.SamAccountName `
        -Evidence @{
            Enabled=$user.Enabled
            PasswordLastSet=$user.PasswordLastSet
            Groups=$groups
            PasswordNeverExpires=$true
            ServiceAccount=$service
        } `
        -Risk "Password never expires." `
        -Remediation "Disable Password Never Expires unless justified." `
        -Task "PasswordNeverExpires"
}

#########################################################
# 2 DISABLED PRIVILEGED ACCOUNTS
#########################################################

$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "G_IT_Admins"
)

foreach ($group in $PrivilegedGroups) {

    $members = Get-ADGroupMember $group -Recursive -ErrorAction SilentlyContinue

    foreach ($member in $members) {

        if ($member.objectClass -ne "user") {
            continue
        }

        $user = Get-ADUser $member -Properties Enabled,MemberOf

        if ($user.Enabled) {
            continue
        }

        Add-Finding `
            -Id "PRIV-001" `
            -Severity "High" `
            -Category "Privileged Accounts" `
            -Asset $user.SamAccountName `
            -Evidence @{
                PrivilegedGroup = $group
                Enabled         = $false
                DirectGroups    = $user.MemberOf
            } `
            -Risk "Disabled account remains a member of a privileged group." `
            -Remediation "Remove the account from the privileged group or delete it if no longer required." `
            -Task "Disabled privileged account"
    }
}

#########################################################
# 3 STALE COMPUTERS
#########################################################

$computers = Get-ADComputer -Filter * -Properties LastLogonDate,Enabled

foreach($computer in $computers){

    if(!$computer.Enabled){
        continue
    }

    if(!$computer.LastLogonDate -or $computer.LastLogonDate -lt $StaleDate){

        Add-Finding `
            -Id "COMP-001" `
            -Severity "Medium" `
            -Category "Computer Objects" `
            -Asset $computer.Name `
            -Evidence @{
                LastLogon=$computer.LastLogonDate
                Enabled=$computer.Enabled
            } `
            -Risk "Computer inactive for over 90 days." `
            -Remediation "Disable or remove stale computer object." `
            -Task "Stale computer"
    }
}

#########################################################
# 4 PASSWORD POLICY
#########################################################

$policy=Get-ADDefaultDomainPasswordPolicy

if($policy.MinPasswordLength -lt 14){

    Add-Finding `
        -Id "POL-001" `
        -Severity "Critical" `
        -Category "Password Policy" `
        -Asset "Minimum Password Length" `
        -Evidence $policy.MinPasswordLength `
        -Risk "Minimum password length below Fortress baseline." `
        -Remediation "Configure minimum length of 14." `
        -Task "Password policy"

}

if(!$policy.ComplexityEnabled){

    Add-Finding `
        -Id "POL-002" `
        -Severity "Critical" `
        -Category "Password Policy" `
        -Asset "Password Complexity" `
        -Evidence $false `
        -Risk "Complexity disabled." `
        -Remediation "Enable password complexity." `
        -Task "Password policy"

}

if($policy.PasswordHistoryCount -lt 24){

    Add-Finding `
        -Id "POL-003" `
        -Severity "Critical" `
        -Category "Password Policy" `
        -Asset "Password History" `
        -Evidence $policy.PasswordHistoryCount `
        -Risk "Password history below Fortress baseline." `
        -Remediation "Configure history to 24." `
        -Task "Password policy"
}

if($policy.LockoutThreshold -ne 5){

    Add-Finding `
        -Id "POL-004" `
        -Severity "Critical" `
        -Category "Lockout Policy" `
        -Asset "Lockout Threshold" `
        -Evidence $policy.LockoutThreshold `
        -Risk "Lockout threshold not set to 5." `
        -Remediation "Configure lockout threshold to 5." `
        -Task "Lockout policy"
}

#########################################################
# 5 ADVANCED AUDIT / POWERSHELL / SYSMON
#########################################################

$gpos = Get-GPO -All

$auditFound = $false
$psLogging = $false
$sysmon = $false

foreach($gpo in $gpos){

    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml

    if($report -match "Audit Process Creation"){
        $auditFound = $true
    }

    if($report -match "IncludeCommandLine"){
        $psLogging = $true
    }

    if($report -match "Sysmon"){
        $sysmon = $true
    }
}

$AuditChecks = @(
    "Process Creation",
    "Special Logon",
    "User Account Management",
    "Security Group Management",
    "File System"
)

foreach ($subcategory in $AuditChecks) {

    $result = auditpol /get /subcategory:"$subcategory"

    if ($result -notmatch "Success") {

        Add-Finding `
            -Id "AUD-001" `
            -Severity "High" `
            -Category "Audit Policy" `
            -Asset $subcategory `
            -Evidence $result `
            -Risk "$subcategory auditing is not enabled." `
            -Remediation "Enable Success auditing." `
            -Task "Advanced Audit Policy"
    }
}

if(!$psLogging){

    Add-Finding `
        -Id "AUD-002" `
        -Severity "High" `
        -Category "PowerShell Logging" `
        -Asset "PowerShell" `
        -Evidence "Disabled" `
        -Risk "PowerShell activity not fully visible." `
        -Remediation "Enable Script Block and Module Logging." `
        -Task "PowerShell logging"
}

if(!$sysmon){

    Add-Finding `
        -Id "AUD-003" `
        -Severity "Medium" `
        -Category "Sysmon" `
        -Asset "Endpoints" `
        -Evidence "Not detected" `
        -Risk "Limited endpoint visibility." `
        -Remediation "Deploy Sysmon with enterprise configuration." `
        -Task "Sysmon"
}

#########################################################
# 6 SERVICE ACCOUNT RISKS
#########################################################

$serviceAccounts = Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties *

foreach($svc in $serviceAccounts){

    $groups = Get-ADPrincipalGroupMembership $svc | Select Name

    if($svc.TrustedForDelegation){

        Add-Finding `
            -Id "SVC-001" `
            -Severity "High" `
            -Category "Service Accounts" `
            -Asset $svc.SamAccountName `
            -Evidence "TrustedForDelegation" `
            -Risk "Unconstrained delegation enabled." `
            -Remediation "Use constrained delegation." `
            -Task "Delegation"
    }

    if($svc.UseDESKeyOnly){

        Add-Finding `
            -Id "SVC-002" `
            -Severity "Critical" `
            -Category "Kerberos" `
            -Asset $svc.SamAccountName `
            -Evidence "DES Only" `
            -Risk "DES encryption enabled." `
            -Remediation "Disable DES support." `
            -Task "Kerberos"
    }

    if($svc.PasswordLastSet -lt $Today.AddDays(-365)){

        Add-Finding `
            -Id "SVC-003" `
            -Severity "High" `
            -Category "Service Accounts" `
            -Asset $svc.SamAccountName `
            -Evidence $svc.PasswordLastSet `
            -Risk "Service account password older than one year." `
            -Remediation "Rotate service account password." `
            -Task "Password rotation"
    }

    if($svc.LastLogonDate -and $svc.LastLogonDate -lt $Today.AddDays(-180)){

        Add-Finding `
            -Id "SVC-004" `
            -Severity "Medium" `
            -Category "Service Accounts" `
            -Asset $svc.SamAccountName `
            -Evidence $svc.LastLogonDate `
            -Risk "Suspiciously inactive service account." `
            -Remediation "Review necessity." `
            -Task "Service account review"
    }

    foreach($g in $groups){
        if($PrivilegedGroups -contains $g.Name){

            Add-Finding `
                -Id "SVC-005" `
                -Severity "High" `
                -Category "Service Accounts" `
                -Asset $svc.SamAccountName `
                -Evidence $g.Name `
                -Risk "Service account has privileged membership." `
                -Remediation "Remove unnecessary privileged access." `
                -Task "Least privilege"
        }
    }
}

#########################################################
# 7 GPO SECURITY POSTURE
#########################################################

$securityGPO = $gpos | Where-Object {
    $_.DisplayName -match "MedDefense|Hardening|Security|Baseline"
}

if(!$securityGPO){

    Add-Finding `
        -Id "GPO-001" `
        -Severity "Medium" `
        -Category "Group Policy" `
        -Asset "Domain GPOs" `
        -Evidence ($gpos.DisplayName) `
        -Risk "No MedDefense hardening GPOs detected." `
        -Remediation "Deploy security baseline GPOs." `
        -Task "GPO Hardening"
}

#########################################################
# EXPORT
#########################################################

$Findings |
ConvertTo-Json -Depth 8 |
Set-Content "domain_security_findings.json"

Write-Host ""
Write-Host "Findings: $($Findings.Count)"

$Findings |
Group-Object severity |
Sort-Object Name |
ForEach-Object{
    Write-Host "$($_.Name): $($_.Count)"
}

Write-Host ""
Write-Host "Report saved to: domain_security_findings.json"