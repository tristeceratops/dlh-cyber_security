<#
.SYNOPSIS
9-windows_attack_sim.ps1

.DESCRIPTION
Runs a controlled Windows attacker simulation, records each action timestamp,
creates a ground truth JSON file, and cleans up all artifacts afterward.

.NOTES
Script name: 9-windows_attack_sim.ps1
purpose: Validate Windows attack telemetry
author: Tristeceratops
date: 10/08/2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "[*] Running Windows attacker simulation..."

$GroundTruth = @()
$UserName = "support_update"
$TaskName = "SupportUpdateTask"
$Startup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$DropFile = "$Startup\support_update.ps1"

function Record-Action($number, $description, $source, $technique) {
    $timestamp = (Get-Date).ToUniversalTime().ToString("o")
    Write-Host ("    [{0}/6] {1}...      {2}" -f $number,$description,$timestamp)

    $script:GroundTruth += [pscustomobject]@{
        action = $number
        description = $description
        timestamp = $timestamp
        expected = $source
        "MITRE technique" = $technique
    }
}

# 4720
Record-Action 1 "Creating local user 'support_update'" "Security Event ID 4720" "T1136.001 - Create Account: Local Account"
$password = ConvertTo-SecureString "Temp-P@ssw0rd!2026" -AsPlainText -Force
New-LocalUser -Name "support_update" -Password $password -Description "Telemetry test account"

# 4732
Record-Action 2 "Adding to Administrators group" "Security Event ID 4732" "T1098 - Account Manipulation"
Add-LocalGroupMember -Group "Administrators" -Member "support_update"

# -enc Write-Host C2 beacon 4104
$Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host "C2 beacon"'))
Record-Action 3 "Running encoded PowerShell" "PowerShell Event ID 4104; Sysmon Event ID 1" "T1059.001 - PowerShell"
powershell.exe -NoProfile -NonInteractive -enc $Encoded

# schtasks /create Scheduled Unregister-ScheduledTask
Record-Action 4 "Creating scheduled task" "Security Event ID 4698; Sysmon Event ID 1" "T1053.005 - Scheduled Task/Job: Scheduled Task"
schtasks /create /tn $TaskName /tr "powershell.exe -NoProfile -Command `"Write-Host 'Telemetry test'`"" /sc ONCE /st 23:59 /f

# Test-NetConnection
Record-Action 5 "Outbound network connection" "Sysmon Event ID 3" "T1049 - System Network Connections Discovery"
Test-NetConnection -ComputerName "1.1.1.1" -Port 443 -InformationLevel Quiet | Out-Null

# StartUp ProgramData Event ID 11
Record-Action 6 "Dropping file in Startup" "Sysmon Event ID 11" "T1547.001 - Registry Run Keys / Startup Folder"
New-Item -ItemType Directory -Path $Startup -Force | Out-Null
Set-Content -Path $DropFile -Value 'Write-Host "Telemetry startup test"'

Write-Host "[*] Cleaning up artifacts..."

Remove-LocalUser -Name $UserName
schtasks /delete /tn $TaskName /f
Remove-Item $DropFile -Force

$GroundTruth | ConvertTo-Json -Depth 5 |
    Set-Content windows_attack_log.json -Encoding UTF8

Write-Host "    User removed, task deleted, file removed           [CLEAN]"
Write-Host "Actions executed: $($GroundTruth.Count)"
Write-Host "Ground truth saved to: windows_attack_log.json"