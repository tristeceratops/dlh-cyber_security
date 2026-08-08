<#
.SYNOPSIS
8-smb_hardening.ps1

.DESCRIPTION
Checks and hardens SMB configuration, disables SMB1 and legacy protocols,
requires SMB signing, enables SMB encryption, and verifies the changes.

.NOTES
Script Name: 8-smb_hardening.ps1
Purpose: SMB and legacy protocol hardening
Author: Tristeceratops
Date: 2026-08-08
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Admin = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $Admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run this script as Administrator." }

$BeforeServer = Get-SmbServerConfiguration
$BeforeClient = Get-SmbClientConfiguration
$BeforeNB = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | Select-Object Description,TcpipNetbiosOptions
$LLMNRKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

Write-Host "[*] Current SMB Configuration..."
Write-Host "    SMBv1: $($BeforeServer.EnableSMB1Protocol)                 [$(
if ($BeforeServer.EnableSMB1Protocol) {'!'} else {'OK'}
)]"
Write-Host "    Signing Required: $($BeforeServer.RequireSecuritySignature)        [$(
if ($BeforeServer.RequireSecuritySignature) {'OK'} else {'!'}
)]"
Write-Host "    Encryption: $($BeforeServer.EncryptData)                  [$(
if ($BeforeServer.EncryptData) {'OK'} else {'!'}
)]"

Write-Host "[*] Disabling SMBv1 (server + client)..."

Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false

$SMB1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
if ($null -ne $SMB1 -and $SMB1.State -ne "Disabled") {
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
}

Write-Host "    SMB1: Disabled [DONE]"

Write-Host "[*] Enforcing SMB Signing..."
Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Confirm:$false
Set-SmbClientConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Confirm:$false
Write-Host "    RequireSecuritySignature: True [SET]"
Write-Host "    EnableSecuritySignature: True [SET]"

Write-Host "[*] Enabling SMB Encryption..."
Set-SmbServerConfiguration -EncryptData $true -Confirm:$false

$ClientEncryption = Get-SmbClientConfiguration
if ($ClientEncryption.PSObject.Properties.Name -contains "RequireEncryption") {
Set-SmbClientConfiguration -RequireEncryption $true -Confirm:$false
Write-Host "    EncryptData: True / Client encryption required [SET]"
} else {
Write-Host "    EncryptData: True / Client requirement unsupported [SET]"
}

Write-Host "[*] Disabling NetBIOS over TCP/IP..."
$NetBIOS = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($Adapter in $NetBIOS) {
Invoke-CimMethod -InputObject $Adapter -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} | Out-Null
}
Write-Host "    NetBIOS: Disabled [SET]"

Write-Host "[*] Disabling LLMNR..."
New-Item -Path $LLMNRKey -Force | Out-Null
Set-ItemProperty -Path $LLMNRKey -Name EnableMulticast -Type DWord -Value 0
Write-Host "    LLMNR: Disabled [SET]"

Write-Host "[*] Verification..."

$AfterServer = Get-SmbServerConfiguration
$AfterClient = Get-SmbClientConfiguration
$AfterNB = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
$AfterLLMNR = (Get-ItemProperty -Path $LLMNRKey -Name EnableMulticast).EnableMulticast

Write-Host "    Before SMBv1: $($BeforeServer.EnableSMB1Protocol)"
Write-Host "    After SMBv1:  $($AfterServer.EnableSMB1Protocol)"
Write-Host "    Before Signing: $($BeforeServer.RequireSecuritySignature)"
Write-Host "    After Signing:  $($AfterServer.RequireSecuritySignature)"
Write-Host "    Before Encryption: $($BeforeServer.EncryptData)"
Write-Host "    After Encryption:  $($AfterServer.EncryptData)"

if (-not $AfterServer.EnableSMB1Protocol -and
-not $AfterClient.EnableSMB1Protocol -and
$AfterServer.RequireSecuritySignature -and
$AfterClient.RequireSecuritySignature -and
$AfterServer.EncryptData -and
($AfterNB | Where-Object TcpipNetbiosOptions -ne 2).Count -eq 0 -and
$AfterLLMNR -eq 0) {
Write-Host "    SMBv1: Disabled [VERIFIED]" -ForegroundColor Green
Write-Host "    Signing: Required [VERIFIED]" -ForegroundColor Green
Write-Host "    Encryption: Enabled [VERIFIED]" -ForegroundColor Green
Write-Host "    NetBIOS: Disabled [VERIFIED]" -ForegroundColor Green
Write-Host "    LLMNR: Disabled [VERIFIED]" -ForegroundColor Green
} else {
throw "SMB hardening verification failed."
}

Write-Host ""
Write-Host "SMB Hardening VERIFIED" -ForegroundColor Green
