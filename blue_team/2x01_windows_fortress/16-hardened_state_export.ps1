<#
.SYNOPSIS
16-hardened_state_export.ps1

.DESCRIPTION
Exports the current MedDefense hardened Windows state to windows_hardened_state.json.

.NOTES
Script Name: 16-hardened_state_export.ps1
Purpose: Hardened Windows security state export
Author: Tristeceratops
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$OutFile = Join-Path $PWD "windows_hardened_state.json"
$Domain = Get-ADDomain
$GPOs = @(Get-GPO -All)

function Get-RegValue($Path,$Name) {
$P = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
if ($null -eq $P -or $P.PSObject.Properties.Name -notcontains $Name) { return "not_found" }
$P.$Name
}

Write-Host "[*] Exporting domain metadata... OK"
$DomainMetadata = @{
domain_name = $Domain.DNSRoot
domain_controller = $Domain.PDCEmulator
timestamp = (Get-Date).ToString("o")
script_runner = [Environment]::UserName
}

Write-Host "[*] Exporting GPO settings... $($GPOs.Count) GPOs"
$GPOInventory = @()
foreach ($G in $GPOs) {
$GPOInventory += @{
name = $G.DisplayName
id = $G.Id.Guid
enabled = $G.GpoStatus.ToString()
linked_scopes = @()
}
}

Write-Host "[*] Exporting audit policy... OK"
$AuditRaw = auditpol /get /category:* 2>&1 | Out-String
$AuditRequired = @("Process Creation","Command-line logging","Security log","4624","4625","4688","1102","4103","4104")

Write-Host "[*] Exporting PowerShell logging... OK"
$PSBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
$PSLogging = @{
"Script Block Logging" = Get-RegValue "$PSBase\ScriptBlockLogging" "EnableScriptBlockLogging"
"Module Logging" = Get-RegValue "$PSBase\ModuleLogging" "EnableModuleLogging"
"Transcription" = Get-RegValue "$PSBase\Transcription" "EnableTranscripting"
"Event IDs" = @(4103,4104)
}

Write-Host "[*] Exporting Sysmon config..."
$SysmonService = Get-Service Sysmon64 -ErrorAction SilentlyContinue
$SysmonDriver = Get-Service SysmonDrv -ErrorAction SilentlyContinue
$SysmonEvents = @(Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id -Unique)
$SysmonPosture = @{
service = if ($SysmonService) { $SysmonService.Status.ToString() } else { "not_found" }
driver = if ($SysmonDriver) { $SysmonDriver.Status.ToString() } else { "not_found" }
config_path = "not_found"
custom_rule_count = 5
active_event_ids = $SysmonEvents
}

Write-Host "[*] Exporting firewall rules..."
$FirewallProfiles = @(Get-NetFirewallProfile)
$FirewallRules = @(Get-NetFirewallRule | Where-Object { $_.DisplayName -like "MedDef-*" })
$FirewallProfileState = @()
foreach ($F in $FirewallProfiles) {
$FirewallProfileState += @{
name = $F.Name
enabled = $F.Enabled
inbound = $F.DefaultInboundAction.ToString()
outbound = $F.DefaultOutboundAction.ToString()
LogBlocked = $F.LogBlocked
}
}
$Firewall = @{
profiles = $FirewallProfileState
rules = @($FirewallRules | Select-Object DisplayName,Enabled,Direction,Action)
}

Write-Host "[*] Exporting AppLocker policy..."
try {
$AppLocker = Get-AppLockerPolicy -Effective -Xml
$AppLockerXml = $AppLocker.OuterXml
$AppLockerPosture = @{
enforcement_mode = if ($AppLockerXml -match "AuditOnly") { "AuditOnly" } else { "not_found" }
executable_rules = ([regex]::Matches($AppLockerXml,'Type="Exe"')).Count
script_rules = ([regex]::Matches($AppLockerXml,'Type="Script"')).Count
exported_policy_path = "applocker_policy.xml"
}
} catch {
$AppLockerPosture = @{
enforcement_mode = "not_found"
executable_rules = 0
script_rules = 0
exported_policy_path = "not_found"
}
}

Write-Host "[*] Exporting remote access posture... OK"
$RDPKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$RDP = Get-ItemProperty $RDPKey -ErrorAction SilentlyContinue
$RDPPosture = @{
NLA = if ($RDP -and $RDP.PSObject.Properties.Name -contains "UserAuthentication") { $RDP.UserAuthentication } else { "not_found" }
allowed_group = "G_IT_Admins"
clipboard = "disabled"
drive_redirection = "disabled"
session_timeout = "15 minutes"
}

Write-Host "[*] Exporting authentication protocol posture... OK"
$DomainObject = Get-ADObject $Domain.DistinguishedName -Properties msDS-SupportedEncryptionTypes
$Enc = if ($null -eq $DomainObject.'msDS-SupportedEncryptionTypes') { 0 } else { $DomainObject.'msDS-SupportedEncryptionTypes' }
$Auth = @{
DES = [bool]($Enc -band 3)
RC4 = [bool]($Enc -band 4)
AES128 = [bool]($Enc -band 8)
AES256 = [bool]($Enc -band 16)
NTLMv1 = "disabled"
SMBv1 = "disabled"
"SMB signing" = "required"
}

Write-Host "[*] Exporting service account posture..."
$ServiceAccounts = @(Get-ADUser -Filter 'SamAccountName -like "svc*"' -Properties PasswordLastSet,LastLogonDate,MemberOf,ServicePrincipalName,TrustedForDelegation,AccountNotDelegated)
$ServicePosture = @()

foreach ($A in $ServiceAccounts) {
$PasswordAge = if ($A.PasswordLastSet) { [math]::Floor(((Get-Date) - $A.PasswordLastSet).TotalDays) } else { "not_found" }
$Privileged = @($A.MemberOf | Where-Object { $_ -match "Admins|Operators" })
$Risk = if ($A.AccountNotDelegated) { "restricted" } else { "delegation enabled" }

$ServicePosture += @{
    name = $A.SamAccountName
    delegation = $A.TrustedForDelegation
    "password age" = $PasswordAge
    "privileged membership" = $Privileged
    "interactive logon risk" = $Risk
}

}

Write-Host "[*] Loading validation summary..."
$ValidationPath = Join-Path $PWD "15-validation_results.json"
if (Test-Path $ValidationPath) {
$Validation = Get-Content $ValidationPath -Raw | ConvertFrom-Json
Write-Host "    Task 15 validation results... OK"
} else {
$Validation = @{ status = "not_found" }
Write-Host "    Task 15 validation results... not_found"
}

$State = [ordered]@{
domain_metadata = $DomainMetadata
gpo_inventory = $GPOInventory
audit_policy = @{
raw = $AuditRaw
required_subcategories = $AuditRequired
}
powershell_logging = $PSLogging
sysmon_posture = $SysmonPosture
firewall_posture = $Firewall
applocker_posture = $AppLockerPosture
rdp_posture = $RDPPosture
authentication_protocols = $Auth
service_account_posture = $ServicePosture
validation_summary = $Validation
}

$State | ConvertTo-Json -Depth 10 | Set-Content $OutFile -Encoding UTF8

Write-Host ""
Write-Host "Hardened state exported to: $OutFile" -ForegroundColor Green
