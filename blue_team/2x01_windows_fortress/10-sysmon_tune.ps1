<#
.SYNOPSIS
10-sysmon_tune.ps1

.DESCRIPTION
Loads the current Sysmon configuration, adds five MedDefense detection rules,
updates Sysmon, and trigger-and-verify tests each rule.

.NOTES
Script Name: 10-sysmon_tune.ps1
Purpose: Sysmon detection rule tuning and verification
Author: Tristeceratops
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Exe = "$env:TEMP\Sysmon\Sysmon64.exe"
$Config = "$env:TEMP\Sysmon\sysmonconfig.xml"
$Log = "Microsoft-Windows-Sysmon/Operational"
if (-not (Test-Path $Exe)) { throw "Sysmon64.exe not found." }
if (-not (Test-Path $Config)) { throw "sysmonconfig.xml not found." }

Write-Host "[*] Loading Sysmon config... " -NoNewline
[xml]$Xml = Get-Content $Config -Raw
$EventFiltering = $Xml.SelectSingleNode("//EventFiltering")
if ($null -eq $EventFiltering) { throw "EventFiltering not found." }
$FileCreate = $Xml.SelectSingleNode("//FileCreate")
if ($null -eq $FileCreate) { throw "FileCreate rule not found." }
Write-Host "OK"

function Add-Rule($Type,$Name,$Fields) {
$Node = $Xml.CreateElement($Type)
$Node.SetAttribute("onmatch","include")
foreach ($F in $Fields) {
$E = $Xml.CreateElement($F[0])
$E.SetAttribute("condition",$F[1])
$E.InnerText = $F[2]
$Node.AppendChild($E) | Out-Null
}
$Node.SetAttribute("name",$Name)
$EventFiltering.AppendChild($Node) | Out-Null
}

$Rules = @(
@("ProcessCreate","MedDefense-Rclone",@(@("Image","end with","rclone.exe"))),
@("RegistryEvent","MedDefense-PsExec",@(@("TargetObject","contains","\Services"),@("TargetObject","contains","PsExec"))),
@("ProcessCreate","MedDefense-EncodedPowerShell",@(@("CommandLine","contains","-enc"))),
@("ProcessCreate","MedDefense-VSSAdmin",@(@("Image","end with","vssadmin.exe"),@("CommandLine","contains","delete shadows"))),
@("ProcessCreate","MedDefense-ScheduledTask",@(@("Image","end with","schtasks.exe"),@("CommandLine","contains","/create")))
)

foreach ($R in $Rules) {
if ($null -eq $EventFiltering.SelectSingleNode("*[@name='$($R[1])']")) {
Add-Rule $R[0] $R[1] $R[2]
Write-Host "    $($R[1]) [ADDED]"
} else {
Write-Host "    $($R[1]) [EXISTS]"
}
}

$Xml.Save($Config)
Write-Host "[*] Updating Sysmon config... " -NoNewline
& $Exe -c $Config | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Sysmon64.exe -c sysmonconfig.xml failed." }
Write-Host "OK"

function Verify($Start,$Match,$Ids) {
Start-Sleep -Seconds 2
@(Get-WinEvent -FilterHashtable @{LogName=$Log;StartTime=$Start;Id=$Ids} -ErrorAction SilentlyContinue) |
Where-Object Message -like "*$Match*" | Select-Object -First 1
}

Write-Host "[*] Trigger-and-Verify..."

$Temp = "$env:TEMP\MedDefenseSysmon"
New-Item $Temp -ItemType Directory -Force | Out-Null
$Cmd = "$env:WINDIR\System32\cmd.exe"

$Tests = @(
@("Rule 1: rclone.exe detection",{
Copy-Item $Cmd "$Temp\rclone.exe" -Force
Start-Process "$Temp\rclone.exe" -ArgumentList "/c exit" -Wait
},"rclone.exe",1),
@("Rule 2: PsExec registry key",{
New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\MedDefensePsExecTest" -Force | Out-Null
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\MedDefensePsExecTest" -Recurse -Force
},"MedDefensePsExecTest",12,13,14),
@("Rule 3: Encoded PowerShell",{
$B64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output MedDefense"))
Start-Process powershell.exe -ArgumentList "-NoProfile -enc $B64" -Wait
},"-enc",1),
@("Rule 4: vssadmin execution",{
Copy-Item $Cmd "$Temp\vssadmin.exe" -Force
Start-Process "$Temp\vssadmin.exe" -ArgumentList "/c echo vssadmin.exe delete shadows" -Wait
},"delete shadows",1),
@("Rule 5: schtasks /create",{
$T = "MedDefenseSysmonTest"
$Time = (Get-Date).AddMinutes(2).ToString("HH:mm")
schtasks.exe /create /tn $T /tr "cmd.exe /c exit" /sc once /st $Time /f | Out-Null
schtasks.exe /delete /tn $T /f | Out-Null
},"/create",1)
)

$Pass = 0
foreach ($T in $Tests) {
$Start = Get-Date
& $T[1]
$Event = Verify $Start $T[2] @($T[3..($T.Count-1)])
if ($null -ne $Event) {
Write-Host "    $($T[0]) [PASS]" -ForegroundColor Green
$Pass++
} else {
Write-Host "    $($T[0]) [FAIL]" -ForegroundColor Red
}
}

Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Custom rules: 5 added | Tests: $Pass/5 PASS"
if ($Pass -ne 5) { exit 1 }
