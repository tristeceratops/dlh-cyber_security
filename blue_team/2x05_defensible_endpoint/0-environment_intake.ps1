# Exit codes:
# 0-environment_intake.ps1
# 0 = success
# 1 = controlled failure
# 2 = environment error

$outputFile = "capstone.json"
$exitCode = 0

function Set-ControlFailure {
    param (
        [string]$Message
    )

    Write-Error $Message
    $script:exitCode = 1
}

function Stop-EnvironmentError {
    param (
        [string]$Message
    )

    Write-Error $Message
    exit 2
}

# Required commands
$requiredCommands = @(
    "Get-CimInstance",
    "Get-Service",
    "Get-Command",
    "Get-Content",
    "Get-ItemProperty",
    "Test-Path"
)

foreach ($command in $requiredCommands) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        Stop-EnvironmentError "Missing dependency: $command"
    }
}

# Host and OS
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
}
catch {
    Stop-EnvironmentError "Unable to query operating system information"
}

$hostname = $env:COMPUTERNAME
$osBuild = $os.BuildNumber
$patchLevel = $os.Version

# Installed features
$featureCount = $null

if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    try {
        $featureCount = @(
            Get-WindowsFeature -ErrorAction Stop |
                Where-Object Installed
        ).Count
    }
    catch {
        Set-ControlFailure "Unable to query Windows features"
    }
}
elseif (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
    try {
        $featureCount = @(
            Get-WindowsOptionalFeature -Online -ErrorAction Stop |
                Where-Object State -eq "Enabled"
        ).Count
    }
    catch {
        Set-ControlFailure "Unable to query Windows optional features"
    }
}
else {
    Stop-EnvironmentError "No Windows feature query command is available"
}

# Running services
$runningServices = @()

try {
    $runningServices = @(
        Get-Service -ErrorAction Stop |
            Where-Object Status -eq "Running" |
            Select-Object -ExpandProperty Name
    )
}
catch {
    Set-ControlFailure "Unable to query running services"
}

# Local users
$localUsers = @()

if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
    try {
        $localUsers = @(
            Get-LocalUser -ErrorAction Stop |
                Select-Object Name, Enabled, LastLogon
        )
    }
    catch {
        Set-ControlFailure "Unable to query local users"
    }
}
else {
    Stop-EnvironmentError "Missing dependency: Get-LocalUser"
}

# Windows Firewall
$firewallProfiles = @()

if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
    try {
        $firewallProfiles = @(
            Get-NetFirewallProfile -ErrorAction Stop |
                Select-Object Name, Enabled
        )
    }
    catch {
        Set-ControlFailure "Unable to query Windows Firewall profiles"
    }
}
else {
    Stop-EnvironmentError "Missing dependency: Get-NetFirewallProfile"
}

# Audit policy
$auditPolicy = @()

if (Get-Command auditpol.exe -ErrorAction SilentlyContinue) {
    $auditOutput = auditpol.exe /get /category:* 2>$null

    if ($LASTEXITCODE -eq 0) {
        $auditPolicy = @(
            $auditOutput |
                Where-Object {
                    $_ -and
                    $_ -notmatch "^-+$" -and
                    $_ -notmatch "^\s*Category"
                } |
                ForEach-Object {
                    $_.Trim()
                }
        )
    }
    else {
        Set-ControlFailure "auditpol failed"
    }
}
else {
    Stop-EnvironmentError "Missing dependency: auditpol.exe"
}

# Sysmon
$sysmonResult = [ordered]@{
    present = $false
    state = $null
    version = $null
    event_channel_size_bytes = $null
}

$sysmon = Get-Service -Name Sysmon -ErrorAction SilentlyContinue

if ($null -ne $sysmon) {
    $sysmonResult.present = $true
    $sysmonResult.state = $sysmon.Status.ToString()

    $sysmonService = Get-CimInstance Win32_Service `
        -Filter "Name='Sysmon'" `
        -ErrorAction SilentlyContinue

    if ($null -ne $sysmonService) {
        $sysmonPath = $sysmonService.PathName -replace '^"([^"]+)".*$', '$1'

        if (Test-Path $sysmonPath) {
            $sysmonResult.version = (
                Get-Item $sysmonPath
            ).VersionInfo.FileVersion
        }
    }

    $channel = Get-WinEvent -ListLog `
        "Microsoft-Windows-Sysmon/Operational" `
        -ErrorAction SilentlyContinue

    if ($null -ne $channel) {
        $sysmonResult.event_channel_size_bytes = $channel.FileSize
    }
    else {
        Set-ControlFailure "Sysmon event channel is unavailable"
    }
}

# PowerShell Script Block Logging
$loggingPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

$scriptBlockLogging = [ordered]@{
    enabled = $false
    configured = $false
}

if (Test-Path $loggingPath) {
    $logging = Get-ItemProperty `
        -Path $loggingPath `
        -Name EnableScriptBlockLogging `
        -ErrorAction SilentlyContinue

    if ($null -ne $logging) {
        $scriptBlockLogging.configured = $true
        $scriptBlockLogging.enabled = (
            $logging.EnableScriptBlockLogging -eq 1
        )
    }
}

# Account and password policy
$accountPolicy = @()

if (Get-Command net.exe -ErrorAction SilentlyContinue) {
    $accountPolicyOutput = net.exe accounts 2>$null

    if ($LASTEXITCODE -eq 0) {
        $accountPolicy = @(
            $accountPolicyOutput |
                Where-Object {
                    $_ -and $_.Trim()
                } |
                ForEach-Object {
                    $_.Trim()
                }
        )
    }
    else {
        Set-ControlFailure "net accounts failed"
    }
}
else {
    Stop-EnvironmentError "Missing dependency: net.exe"
}

# Build JSON
$capstone = [ordered]@{
    hostname = $hostname
    os_build = $osBuild
    patch_level = $patchLevel

    installed_feature_count = $featureCount

    running_services = $runningServices

    local_user_accounts = $localUsers

    firewall = [ordered]@{
        profiles = $firewallProfiles
    }

    audit_policy = $auditPolicy

    sysmon = $sysmonResult

    powershell_script_block_logging = $scriptBlockLogging

    account_policy = $accountPolicy
}

try {
    $capstone |
        ConvertTo-Json -Depth 6 |
        Set-Content -Path $outputFile -Encoding UTF8 -ErrorAction Stop
}
catch {
    Set-ControlFailure "Failed to create $outputFile"
}

if ($exitCode -eq 0) {
    exit 0
}

exit 1
