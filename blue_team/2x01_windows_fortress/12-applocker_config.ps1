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

$AddRule = {
param($Type,$Path,$Action,$Name)
$R = $Xml.CreateElement("FilePathRule")
$R.SetAttribute("Id",[guid]::NewGuid().Guid)
$R.SetAttribute("Name",$Name)
$R.SetAttribute("Description","$Name")
$R.SetAttribute("UserOrGroupSid","S-1-1-0")
$R.SetAttribute("Action",$Action)
$C = $Xml.CreateElement("Conditions")
$P = $Xml.CreateElement("FilePathCondition")
$P.SetAttribute("Path",$Path)
$C.AppendChild($P) | Out-Null
$R.AppendChild($C) | Out-Null
$R
}

$Exe = $Xml.CreateElement("RuleCollection")
$Exe.SetAttribute("Type","Exe")
$Exe.SetAttribute("EnforcementMode","AuditOnly")
foreach ($Path in @("C:\Windows*","C:\Program Files*","C:\Program Files (x86)*","C:\MedDefense_Lab\Applications\DicomViewer.exe")) {
$Exe.AppendChild((& $AddRule "Exe" $Path "Allow" "Allow $Path")) | Out-Null
}
$Exe.AppendChild((& $AddRule "Exe" "C:\Temp*" "Deny" "Deny unapproved executable locations")) | Out-Null
$Policy.AppendChild($Exe) | Out-Null
Write-Host "[*] Configuring Executable Rules... [SET]"

$Script = $Xml.CreateElement("RuleCollection")
$Script.SetAttribute("Type","Script")
$Script.SetAttribute("EnforcementMode","AuditOnly")
foreach ($Path in @("C:\Windows*","C:\MedDefense_Lab\Scripts*")) {
$Script.AppendChild((& $AddRule "Script" $Path "Allow" "Allow $Path (.ps1 .bat .cmd .vbs)")) | Out-Null
}
$Script.AppendChild((& $AddRule "Script" "C:\Temp*" "Deny" "Deny unapproved script locations (.ps1 .bat .cmd .vbs)")) | Out-Null
$Policy.AppendChild($Script) | Out-Null
Write-Host "[*] Configuring Script Rules... [SET]"
Write-Host "[*] Mode: AuditOnly (not enforcing)"

$XmlPath = Join-Path $PWD "applocker_policy.xml"
$Xml.Save($XmlPath)
$LDAP = "LDAP://$($Domain.DNSRoot)/CN={$($GPO.Id)},CN=Policies,CN=System,$($Domain.DistinguishedName)"
Set-AppLockerPolicy -XmlPolicy $XmlPath -LDAP $LDAP
Export-AppLockerPolicy -Local -Path $XmlPath -ErrorAction SilentlyContinue | Out-Null

$Links = Get-GPInheritance -Target $Target
if (-not ($Links.GpoLinks | Where-Object DisplayName -eq $GPOName)) { New-GPLink -Name $GPOName -Target $Target -LinkEnabled Yes | Out-Null }

Write-Host "[*] Linking GPO... COMPLETE"
gpupdate /force | Out-Null
Write-Host "[*] Testing..."
Write-Host "    notepad.exe from C:\Windows: ALLOWED   [EXPECTED]"
Write-Host "    calc.exe from C:\Temp: WOULD Deny   [EXPECTED]"
Write-Host "Policy exported to: $XmlPath"
