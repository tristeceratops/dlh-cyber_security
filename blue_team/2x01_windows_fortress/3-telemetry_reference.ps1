<#
.SYNOPSIS
3-telemetry_reference.ps1

.DESCRIPTION
Generates windows_event_reference.json containing a compact reference for
Security, PowerShell, and Sysmon telemetry used for Windows threat detection.

.NOTES
Script Name: 3-telemetry_reference.ps1
Purpose: Windows event telemetry reference generation
Author:
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
$events = @(
# Security
[pscustomobject]@{event_id=4624;event_name="Successful Logon";log_source="Security";audit_or_sensor_dependency="Audit Logon";security_meaning="Successful account authentication";normal_frequency="High";triage_priority="Medium";crimson_tide_phase="Initial Access";example_suspicious_pattern="4624 Type 10 from unusual source or privileged account";validation_method="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624}"},
[pscustomobject]@{event_id=4625;event_name="Failed Logon";log_source="Security";audit_or_sensor_dependency="Audit Logon";security_meaning="Failed authentication attempt";normal_frequency="High";triage_priority="High";crimson_tide_phase="Initial Access";example_suspicious_pattern="Burst of failures followed by successful logon";validation_method="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625}"},
[pscustomobject]@{event_id=4648;event_name="Explicit Credential Logon";log_source="Security";audit_or_sensor_dependency="Audit Logon";security_meaning="Process supplied explicit credentials";normal_frequency="Low";triage_priority="High";crimson_tide_phase="Credential Access";example_suspicious_pattern="Unexpected runas or explicit admin credentials";validation_method="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4648}"},
[pscustomobject]@{event_id=4672;event_name="Special Privileges Assigned";log_source="Security";audit_or_sensor_dependency="Audit Special Logon";security_meaning="Privileged logon received sensitive rights";normal_frequency="Medium";triage_priority="High";crimson_tide_phase="Privilege Escalation";example_suspicious_pattern="4672 for unusual user or workstation";validation_method="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672}"},
[pscustomobject]@{event_id=4688;event_name="Process Creation";log_source="Security";audit_or_sensor_dependency="Audit Process Creation";security_meaning="New process execution";normal_frequency="Very High";triage_priority="High";crimson_tide_phase="Execution";example_suspicious_pattern="PowerShell, cmd, rundll32, or encoded command from unusual parent";validation_method="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688}"},
[pscustomobject]@{event_id=4720;event_name="User Account Created";log_source="Security";audit_or_sensor_dependency="Audit User Account Management";security_meaning="New local or domain user account";normal_frequency="Low";triage_priority="Critical";crimson_tide_phase="Persistence";example_suspicious_pattern="Unexpected account creation followed by privileged group membership";validation_method="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720}"},
[pscustomobject]@{event_id=4726;event_name="User Account Deleted";log_source="Security";audit_or_sensor_dependency="Audit User Account Management";security_meaning="User account was deleted";normal_frequency="Low";triage_priority="High";crimson_tide_phase="Defense Evasion";example_suspicious_pattern="Deletion of recently created or investigation-relevant account";validation_method="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4726}"},
[pscustomobject]@{event_id=4732;event_name="Member Added to Security-Enabled Local Group";log_source="Security";audit_or_sensor_dependency="Audit Security Group Management";security_meaning="Account added to a privileged local security group";normal_frequency="Low";triage_priority="Critical";crimson_tide_phase="Privilege Escalation";example_suspicious_pattern="Unexpected user added to Administrators";validation_method="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4732}"},
[pscustomobject]@{event_id=1102;event_name="Audit Log Cleared";log_source="Security";audit_or_sensor_dependency="Audit System";security_meaning="Security audit log was cleared";normal_frequency="Very Low";triage_priority="Critical";crimson_tide_phase="Defense Evasion";example_suspicious_pattern="Log clearing without approved maintenance";validation_method="Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102}"},
# PowerShell
[pscustomobject]@{event_id=4103;event_name="PowerShell Module Logging";log_source="PowerShell";audit_or_sensor_dependency="Module Logging";security_meaning="PowerShell module pipeline activity";normal_frequency="Medium";triage_priority="High";crimson_tide_phase="Execution";example_suspicious_pattern="Encoded commands, download activity, or security-tool manipulation";validation_method="Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4103}"},
[pscustomobject]@{event_id=4104;event_name="PowerShell Script Block Logging";log_source="PowerShell";audit_or_sensor_dependency="Script Block Logging";security_meaning="PowerShell script block content";normal_frequency="Medium";triage_priority="Critical";crimson_tide_phase="Execution";example_suspicious_pattern="Obfuscated script, credential dumping, AMSI bypass, or remote download";validation_method="Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104}"},
# Sysmon
[pscustomobject]@{event_id=1;event_name="Process Create";log_source="Sysmon";audit_or_sensor_dependency="Sysmon ProcessCreate";security_meaning="Detailed process execution telemetry";normal_frequency="Very High";triage_priority="High";crimson_tide_phase="Execution";example_suspicious_pattern="Office/browser spawning PowerShell, cmd, or scripting engines";validation_method="Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1}"},
[pscustomobject]@{event_id=3;event_name="Network Connection";log_source="Sysmon";audit_or_sensor_dependency="Sysmon NetworkConnect";security_meaning="Process initiated network connection";normal_frequency="High";triage_priority="High";crimson_tide_phase="Command and Control";example_suspicious_pattern="Unusual process connecting to external IP or rare port";validation_method="Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=3}"},
[pscustomobject]@{event_id=7;event_name="Image Loaded";log_source="Sysmon";audit_or_sensor_dependency="Sysmon ImageLoad";security_meaning="Process loaded executable or DLL image";normal_frequency="Very High";triage_priority="Medium";crimson_tide_phase="Execution";example_suspicious_pattern="Unsigned or unusual DLL loaded by trusted process";validation_method="Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=7}"},
[pscustomobject]@{event_id=11;event_name="File Created";log_source="Sysmon";audit_or_sensor_dependency="Sysmon FileCreate";security_meaning="File creation activity";normal_frequency="High";triage_priority="Medium";crimson_tide_phase="Persistence";example_suspicious_pattern="Executable or script created in startup, temp, or user profile location";validation_method="Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=11}"},
[pscustomobject]@{event_id=13;event_name="Registry Value Set";log_source="Sysmon";audit_or_sensor_dependency="Sysmon RegistryEvent";security_meaning="Registry value modified";normal_frequency="High";triage_priority="High";crimson_tide_phase="Persistence";example_suspicious_pattern="Run key, service, or security-setting modification";validation_method="Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=13}"},
[pscustomobject]@{event_id=22;event_name="DNS Query";log_source="Sysmon";audit_or_sensor_dependency="Sysmon DNSQuery";security_meaning="Process performed DNS resolution";normal_frequency="High";triage_priority="Medium";crimson_tide_phase="Command and Control";example_suspicious_pattern="Rare or suspicious domain queried by an unusual process";validation_method="Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=22}"}
)

$path = Join-Path (Get-Location) "windows_event_reference.json"
$events | ConvertTo-Json -Depth 4 | Set-Content -Path $path -Encoding UTF8

$security = @($events | Where-Object log_source -eq "Security").Count
$powershell = @($events | Where-Object log_source -eq "PowerShell").Count
$sysmon = @($events | Where-Object log_source -eq "Sysmon").Count

Write-Host "Security events mapped: $security"
Write-Host "PowerShell events mapped: $powershell"
Write-Host "Sysmon events mapped: $sysmon"
Write-Host "Total events documented: $($events.Count)"
Write-Host "Reference saved to: $path"

}
catch {
Write-Error "Failed to generate Windows event reference: $($_.Exception.Message)"
exit 1
}
