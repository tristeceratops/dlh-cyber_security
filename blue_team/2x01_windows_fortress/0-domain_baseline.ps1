<#
.SYNOPSIS
    0-domain_baseline.ps1

.DESCRIPTION
    Captures the complete security state of the MedDefense domain and produces
    a structured report.

    The script collects:
    - Domain information: domain name, forest level, domain controllers
    - All user accounts: name, enabled/disabled, last logon, password last set,
      password never expires flag
    - All groups and their members
    - All service accounts (accounts with "svc" in the name or in the Service Accounts OU)
    - All GPOs linked to the domain and OUs
    - Current password policy: minimum length, complexity, history, max age
    - Current account lockout policy
    - Kerberos encryption types supported
    - All users with Domain Admin or Enterprise Admin privileges
    - Security findings summary with severity count

.NOTES
    Script Name: 0-domain_baseline.ps1
    Purpose: Active Directory domain security baseline audit
    Author: Tristeceratops
    Date: 05/08/2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy


############################################
# DOMAIN INFORMATION
############################################

function Get-DomainInformation {

    Write-Host "`n=== DOMAIN INFORMATION ==="

    $domain = Get-ADDomain
    $forest = Get-ADForest
    $dcs = Get-ADDomainController -Filter *

    Write-Host "Domain: $($domain.DNSRoot)"
    Write-Host "Forest Level: $($forest.ForestMode)"

    Write-Host "Domain Controllers:"
    foreach ($dc in $dcs) {
        Write-Host "  $($dc.HostName)"
    }
}


############################################
# USERS
############################################

function Get-DomainUsers {

    Write-Host "`n=== USER ACCOUNTS ==="

    $users = Get-ADUser -Filter * -Properties `
        Enabled,
        LastLogonDate,
        PasswordLastSet,
        PasswordNeverExpires


    Write-Host "User Accounts: $($users.Count)"

    $neverExpire = $users |
        Where-Object {$_.PasswordNeverExpires -eq $true}

    Write-Host "Password Never Expires: $($neverExpire.Count)"


    foreach ($user in $users) {

        [PSCustomObject]@{
            Name = $user.Name
            Enabled = $user.Enabled
            LastLogon = $user.LastLogonDate
            PasswordLastSet = $user.PasswordLastSet
            PasswordNeverExpires = $user.PasswordNeverExpires
        }
    }
}


############################################
# GROUPS
############################################

function Get-DomainGroups {

    Write-Host "`n=== GROUPS ==="

    $groups = Get-ADGroup -Filter *

    foreach ($group in $groups) {

        Write-Host "`nGroup: $($group.Name)"

        $members = Get-ADGroupMember $group -ErrorAction SilentlyContinue

        foreach ($member in $members) {

            Write-Host "  - $($member.Name)"
        }
    }
}


############################################
# SERVICE ACCOUNTS
############################################

function Get-ServiceAccounts {

    Write-Host "`n=== SERVICE ACCOUNTS ==="


    $users = Get-ADUser -Filter * -Properties DistinguishedName


    $svcAccounts = $users | Where-Object {

        $_.Name -like "*svc*" -or
        $_.DistinguishedName -like "*Service Accounts*"

    }


    Write-Host "Service Accounts: $($svcAccounts.Count)"


    foreach ($account in $svcAccounts) {

        Write-Host $account.Name
    }
}



############################################
# GPO
############################################

function Get-DomainGPOs {

    Write-Host "`n=== GPOs ==="


    $gpos = Get-GPO -All

    Write-Host "GPO Count: $($gpos.Count)"


    foreach ($gpo in $gpos) {

        Write-Host $gpo.DisplayName
    }
}



############################################
# PASSWORD POLICY
############################################

function Get-PasswordPolicy {


    Write-Host "`n=== PASSWORD POLICY ==="


    $policy = Get-ADDefaultDomainPasswordPolicy


    Write-Host "Minimum Length: $($policy.MinPasswordLength)"
    Write-Host "Complexity: $($policy.ComplexityEnabled)"
    Write-Host "History: $($policy.PasswordHistoryCount)"
    Write-Host "Max Age: $($policy.MaxPasswordAge)"
}



############################################
# LOCKOUT POLICY
############################################

function Get-LockoutPolicy {


    Write-Host "`n=== ACCOUNT LOCKOUT ==="


    $policy = Get-ADDefaultDomainPasswordPolicy


    if ($policy.LockoutThreshold -eq 0) {

        Write-Host "Lockout Threshold: NOT CONFIGURED"

    }
    else {

        Write-Host "Lockout Threshold: $($policy.LockoutThreshold)"

    }

}



############################################
# KERBEROS
############################################

function Get-KerberosEncryption {


    Write-Host "`n=== KERBEROS ==="


    $domain = Get-ADDomain


    $accounts = Get-ADUser -Filter * `
        -Properties msDS-SupportedEncryptionTypes


    foreach ($account in $accounts) {

        if ($account.'msDS-SupportedEncryptionTypes') {

            Write-Host "$($account.Name): $($account.'msDS-SupportedEncryptionTypes')"

        }

    }

}



############################################
# PRIVILEGED USERS
############################################

function Get-PrivilegedUsers {


    Write-Host "`n=== DOMAIN ADMINS ==="


    $groups = @(
        "Domain Admins",
        "Enterprise Admins"
    )


    foreach ($group in $groups) {

        Write-Host "`n$group"

        Get-ADGroupMember $group |
        Select-Object Name

    }

}



############################################
# FINDINGS
############################################

function Get-SecurityFindings {

    Write-Host "`n=== SECURITY FINDINGS ==="

    $findings = @()

    $domainAdmins = Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue

    if ($domainAdmins.Count -gt 5) {

        $findings += [PSCustomObject]@{
            Finding = "Excessive Domain Admin membership"
            Object = "Domain Admins"
            Severity = "Critical"
        }
    }


    $enterpriseAdmins = Get-ADGroupMember "Enterprise Admins" -ErrorAction SilentlyContinue

    foreach ($admin in $enterpriseAdmins) {

        $findings += [PSCustomObject]@{
            Finding = "Enterprise Admin account exists"
            Object = $admin.Name
            Severity = "Critical"
        }
    }


    $delegatedUsers = Get-ADUser -Filter * -Properties TrustedForDelegation

    foreach ($user in $delegatedUsers) {

        if ($user.TrustedForDelegation) {

            $findings += [PSCustomObject]@{
                Finding = "Unconstrained delegation enabled"
                Object = $user.Name
                Severity = "Critical"
            }
        }
    }


    $kerberosUsers = Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes

    foreach ($user in $kerberosUsers) {

        $enc = $user.'msDS-SupportedEncryptionTypes'

        if ($enc -eq 1 -or $enc -eq 3) {

            $findings += [PSCustomObject]@{
                Finding = "Weak Kerberos encryption (DES/RC4)"
                Object = $user.Name
                Severity = "Critical"
            }
        }
    }


    $users = Get-ADUser -Filter * -Properties PasswordNeverExpires, Description, LastLogonDate


    foreach ($user in $users) {

        if ($user.PasswordNeverExpires) {

            $findings += [PSCustomObject]@{
                Finding = "Password never expires"
                Object = $user.Name
                Severity = "High"
            }
        }
    }


    $policy = Get-ADDefaultDomainPasswordPolicy


    if (-not $policy.ComplexityEnabled) {

        $findings += [PSCustomObject]@{
            Finding = "Password complexity disabled"
            Object = "Domain Password Policy"
            Severity = "High"
        }
    }


    if ($policy.MinPasswordLength -lt 12) {

        $findings += [PSCustomObject]@{
            Finding = "Weak minimum password length"
            Object = "Domain Password Policy"
            Severity = "High"
        }
    }


    if ($policy.PasswordHistoryCount -lt 10) {

        $findings += [PSCustomObject]@{
            Finding = "Insufficient password history"
            Object = "Domain Password Policy"
            Severity = "High"
        }
    }


    $svcAccounts = $users | Where-Object {
        $_.Name -like "*svc*" -and $_.PasswordNeverExpires
    }


    foreach ($svc in $svcAccounts) {

        $findings += [PSCustomObject]@{
            Finding = "Service account with permanent password"
            Object = $svc.Name
            Severity = "High"
        }
    }


    foreach ($admin in $domainAdmins) {

        $account = Get-ADUser $admin.SamAccountName -Properties Enabled, LastLogonDate

        if (-not $account.Enabled) {

            $findings += [PSCustomObject]@{
                Finding = "Disabled privileged account"
                Object = $account.Name
                Severity = "High"
            }
        }


        if ($account.LastLogonDate -lt (Get-Date).AddDays(-90)) {

            $findings += [PSCustomObject]@{
                Finding = "Inactive privileged account"
                Object = $account.Name
                Severity = "High"
            }
        }
    }


    if ($policy.LockoutThreshold -eq 0) {

        $findings += [PSCustomObject]@{
            Finding = "Account lockout disabled"
            Object = "Domain Policy"
            Severity = "Medium"
        }
    }


    $activeUsers = Get-ADUser -Filter "Enabled -eq 'true'"

    if ($activeUsers.Count -gt 500) {

        $findings += [PSCustomObject]@{
            Finding = "Excessive active accounts"
            Object = "Domain"
            Severity = "Medium"
        }
    }


    foreach ($group in @(
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "Backup Operators"
    )) {

        $members = Get-ADGroupMember $group -ErrorAction SilentlyContinue

        foreach ($member in $members) {

            $findings += [PSCustomObject]@{
                Finding = "Direct privileged group membership"
                Object = "$group : $($member.Name)"
                Severity = "Medium"
            }
        }
    }


    foreach ($user in $users) {

        if ([string]::IsNullOrEmpty($user.Description)) {

            $findings += [PSCustomObject]@{
                Finding = "User account missing description"
                Object = $user.Name
                Severity = "Medium"
            }
        }


        if ($null -eq $user.LastLogonDate) {

            $findings += [PSCustomObject]@{
                Finding = "Account never logged in"
                Object = $user.Name
                Severity = "Medium"
            }
        }
    }


    foreach ($svc in $svcAccounts) {

        $findings += [PSCustomObject]@{
            Finding = "Traditional service account instead of gMSA"
            Object = $svc.Name
            Severity = "Medium"
        }
    }


    $summary = $findings | Group-Object Severity


    foreach ($item in $summary) {

        Write-Host "$($item.Name): $($item.Count)"
    }


    Write-Host "Total Findings: $($findings.Count)"
}



############################################
# MAIN
############################################


Get-DomainInformation

Get-DomainUsers

Get-DomainGroups

Get-ServiceAccounts

Get-DomainGPOs

Get-PasswordPolicy

Get-LockoutPolicy

Get-KerberosEncryption

Get-PrivilegedUsers

Get-SecurityFindings