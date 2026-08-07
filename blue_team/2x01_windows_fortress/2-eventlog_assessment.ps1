<#
.SYNOPSIS
2-eventlog_assessment.ps1

.DESCRIPTION
Assesses Windows Security Event Log auditing and validates that critical
security events are both configured for auditing and actively generated.

The script evaluates the current Advanced Audit Policy using auditpol,
maps critical Windows Security Event IDs to their required audit
subcategories, and verifies whether those events have been recorded in
the Security log during the last 24 hours.

The assessment includes:
- Current Advanced Audit Policy configuration
- Required audit subcategories for critical security Event IDs
- Audit policy coverage for:
    - Logon
    - Process Creation
    - Account Management
    - Special Logon
    - System Integrity
- Security Event Log activity within the last 24 hours
- Generation status for the following Event IDs:
    - 4624 (Successful Logon)
    - 4625 (Failed Logon)
    - 4648 (Explicit Credentials)
    - 4688 (Process Creation)
    - 4720 (Account Created)
    - 4726 (Account Deleted)
    - 4732 (Member Added to Security Group)
    - 4672 (Special Logon)
    - 1102 (Audit Log Cleared)

For each Event ID, the script reports:
- Event ID
- Description
- Required audit subcategory
- Audit policy status
- Event generation status

.OUTPUTS
Console report displaying audit configuration and event generation status.

.NOTES
Script Name : 2-eventlog_assessment.ps1
Purpose     : Windows Security Event Log assessment
Target      : Local Windows system
Author      : Tristeceratops
Date        : 07/08/2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#########################################################
# AUDIT POLICY
#########################################################

try {
    $AuditPolicy = & auditpol.exe /get /category:* 2>$null
}
catch {
    throw "Unable to query audit policy. Run this script from an elevated PowerShell session."
}

#########################################################
# EVENT DEFINITIONS
#########################################################

$Events = @(
    @{
        EventID = 4624
        Description = "Successful Logon"
        Subcategory = "Logon"
    },
    @{
        EventID = 4625
        Description = "Failed Logon"
        Subcategory = "Logon"
    },
    @{
        EventID = 4648
        Description = "Explicit Credentials"
        Subcategory = "Logon"
    },
    @{
        EventID = 4688
        Description = "Process Creation"
        Subcategory = "Process Tracking"
    },
    @{
        EventID = 4720
        Description = "Account Created"
        Subcategory = "User Account Management"
    },
    @{
        EventID = 4726
        Description = "Account Deleted"
        Subcategory = "User Account Management"
    },
    @{
        EventID = 4732
        Description = "Member Added to Group"
        Subcategory = "Security Group Management"
    },
    @{
        EventID = 4672
        Description = "Special Logon"
        Subcategory = "Special Logon"
    },
    @{
        EventID = 1102
        Description = "Audit Log Cleared"
        Subcategory = "System Integrity"
    }
)

#########################################################
# LAST 24 HOURS
#########################################################

$StartTime = (Get-Date).AddHours(-24)

$SecurityEvents = Get-WinEvent `
    -FilterHashtable @{
        LogName = "Security"
        StartTime = $StartTime
    }

#########################################################
# REPORT
#########################################################

$Results = foreach ($Item in $Events) {

    #####################################################
    # AUDIT CONFIGURATION
    #####################################################

    $Configured = $false

    foreach ($Line in $AuditPolicy) {

        if ($Line -match [regex]::Escape($Item.Subcategory)) {

            if ($Line -match "Success|Failure") {
                $Configured = $true
            }

            break
        }
    }

    #####################################################
    # EVENT GENERATED
    #####################################################

    $Generated = $SecurityEvents |
        Where-Object { $_.Id -eq $Item.EventID } |
        Select-Object -First 1

    if ($Generated) {
        $Status = "[GENERATING]"
    }
    elseif ($Configured) {
        $Status = "[CONFIGURED]"
    }
    else {
        $Status = "[NOT CONFIGURED]"
    }

    [PSCustomObject]@{
        "Event ID" = $Item.EventID
        Description = $Item.Description
        "Audit Subcategory" = $Item.Subcategory
        Status = $Status
    }
}

#########################################################
# OUTPUT
#########################################################

$Results | Format-Table -AutoSize