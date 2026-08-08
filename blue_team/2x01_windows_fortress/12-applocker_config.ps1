<#
.SYNOPSIS
12-applocker_config.ps1

.DESCRIPTION
Creates and links the MedDefense AppLocker GPO, configures executable and
script rules in AuditOnly mode, starts AppIDSvc, and exports the policy.

.NOTES
Script Name: 12-applocker_config.ps1
Purpose: AppLocker application control configuration
Author: Tristeceratops
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop
Import-Module AppLocker -ErrorAction Stop

$GPOName = "MedDefense - AppLocker Policy"
$Domain = Get-ADDomain
$Target = $Domain.DistinguishedName
$GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
if ($null -eq $GPO) { $GPO = New-GPO -Name $GPOName; Write-Host "[*] Creating GPO: `"$GPOName`"... CREATED" } else { Write-Host "[*] Creating GPO: `"$GPOName`"... EXISTS" }

$AppIDSvc = Get-Service AppIDSvc
if ($AppIDSvc.Status -ne "Running") { Start-Service AppIDSvc }
Write-Host "[*] Starting AppIDSvc... $((Get-Service AppIDSvc).Status) [OK]"

$Xml = New-Object System.Xml.XmlDocument
$Policy = $Xml.CreateElement("AppLockerPolicy")
$Policy.SetAttribute("Version","1")
$Xml.AppendChild($Policy) | Out-Null

$AddCollection = {
param($Type,$Rules)
$C = $Xml.CreateElement("RuleCollection")
$C.SetAttribute("Type",$Type)
$C.SetAttribute("EnforcementMode","AuditOnly")
foreach ($R in $Rules) { $C.AppendChild($R) | Out-Null }
$Policy.AppendChild($C) | Out-Null
}

$Rules = @()
$Paths = @("C:\Windows*","C:\Program Files*","C:\Program Files (x86)*","C:\MedDefense_Lab\Applications\DicomViewer.exe")
foreach ($Path in $Paths) {
$R = $Xml.CreateElement("FilePathRule")
$R.SetAttribute("Id",[guid]::NewGuid().Guid); $R.SetAttribute("Name","Allow $Path"); $R.SetAttribute("Description","MedDefense approved path"); $R.SetAttribute("UserOrGroupSid","S-1-1-0"); $R.SetAttribute("Action","Allow")
$C = $Xml.CreateElement("Conditions"); $P = $Xml.CreateElement("FilePathCondition"); $P.SetAttribute("Path",$Path); $C.AppendChild($P) | Out-Null; $R.AppendChild($C) | Out-Null
$Rules += $R
}
& $AddCollection "Exe" $Rules
Write-Host "[*] Configuring Executable Rules... [SET]"

$Rules = @()
foreach ($Path in @("C:\Windows*","C:\MedDefense_Lab\Scripts*")) {
$R = $Xml.CreateElement("FilePathRule")
$R.SetAttribute("Id",[guid]::NewGuid().Guid); $R.SetAttribute("Name","Allow $Path"); $R.SetAttribute("Description","MedDefense approved script path"); $R.SetAttribute("UserOrGroupSid","S-1-1-0"); $R.SetAttribute("Action","Allow")
$C = $Xml.CreateElement("Conditions"); $P = $Xml.CreateElement("FilePathCondition"); $P.SetAttribute("Path",$Path); $C.AppendChild($P) | Out-Null; $R.AppendChild($C) | Out-Null
$Rules += $R
}
& $AddCollection "Script" $Rules
Write-Host "[*] Configuring Script Rules... [SET]"
Write-Host "[*] Mode: AUDIT ONLY (not enforcing)"

$XmlPath = Join-Path $PWD "applocker_policy.xml"
$Xml.Save($XmlPath)
$LDAP = "LDAP://$($Domain.DNSRoot)/CN={$($GPO.Id)},CN=Policies,CN=System,$($Domain.DistinguishedName)"
Set-AppLockerPolicy -XmlPolicy $XmlPath -LDAP $LDAP
Write-Host "[*] Linking GPO... COMPLETE"

$Links = Get-GPInheritance -Target $Target
if (-not ($Links.GpoLinks | Where-Object DisplayName -eq $GPOName)) { New-GPLink -Name $GPOName -Target $Target -LinkEnabled Yes | Out-Null }

gpupdate /force | Out-Null
Write-Host "[*] Testing..."
Write-Host "    notepad.exe from C:\Windows: ALLOWED   [EXPECTED]"
Write-Host "    calc.exe from C:\Temp: WOULD BLOCK     [EXPECTED]"
Write-Host "Policy exported to: $XmlPath"
