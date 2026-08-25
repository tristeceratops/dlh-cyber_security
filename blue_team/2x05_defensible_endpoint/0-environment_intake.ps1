# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

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

Write-Output "Collecting Windows security state..."

# Host and OS
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
}
catch {
    Stop-EnvironmentError "Unable to query operating system information"
}

Write-Output "hostname=$env:COMPUTERNAME"
Write-Output "os_build=$($os.BuildNumber)"
Write-Output "patch_level=$($os.Version)"

# Installed features
if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    try {
        $featureCount = @(Get-WindowsFeature -ErrorAction Stop |
            Where-Object Installed).Count
        Write-Output "installed_feature_count=$featureCount"
    }
    catch {
        Set-ControlFailure "Unable to query Windows features"
        Write-Output "installed_feature_count=unavailable"
    }
}
elseif (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
    try {
        $featureCount = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop |
            Where-Object State -eq 'Enabled').Count
        Write-Output "installed_feature_count=$featureCount"
    }
    catch {
        Set-ControlFailure "Unable to query Windows optional features"
        Write-Output "installed_feature_count=unavailable"
    }
}
else {
    Stop-EnvironmentError "No Windows feature query command is available"
}

# Running services
Write-Output "running_services="
try {
    Get-Service -ErrorAction Stop |
        Where-Object Status -eq 'Running' |
        Select-Object -ExpandProperty Name
}
catch {
    Set-ControlFailure "Unable to query running services"
}

# Local users
Write-Output "local_user_accounts="
if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
    try {
        Get-LocalUser -ErrorAction Stop |
            Select-Object -ExpandProperty Name
    }
    catch {
        Set-ControlFailure "Unable to query local users"
        Write-Output "unavailable"
    }
}
else {
    Stop-EnvironmentError "Missing dependency: Get-LocalUser"
}

# Windows Firewall
Write-Output "firewall_state="
if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
    try {
        Get-NetFirewallProfile -ErrorAction Stop |
            Select-Object Name, Enabled |
            ForEach-Object {
                Write-Output "$($_.Name)=$($_.Enabled)"
            }
    }
    catch {
        Set-ControlFailure "Unable to query Windows Firewall profiles"
        Write-Output "unavailable"
    }
}
else {
    Stop-EnvironmentError "Missing dependency: Get-NetFirewallProfile"
}

# Audit policy
Write-Output "audit_policy="
if (Get-Command auditpol.exe -ErrorAction SilentlyContinue) {
    $auditPolicy = auditpol.exe /get /category:* 2>$null

    if ($LASTEXITCODE -eq 0) {
        $auditPolicy
    }
    else {
        Set-ControlFailure "auditpol failed"
        Write-Output "unavailable"
    }
}
else {
    Stop-EnvironmentError "Missing dependency: auditpol.exe"
}

# Sysmon
Write-Output "sysmon="

$sysmon = Get-Service -Name Sysmon -ErrorAction SilentlyContinue

if ($null -ne $sysmon) {
    Write-Output "present=true"
    Write-Output "state=$($sysmon.Status)"

    $sysmonService = Get-CimInstance Win32_Service `
        -Filter "Name='Sysmon'" `
        -ErrorAction SilentlyContinue

    $sysmonPath = $null
    $sysmonVersion = "unknown"

    if ($null -ne $sysmonService) {
        $sysmonPath = $sysmonService.PathName -replace '^"([^"]+)".*$', '$1'

        if (Test-Path $sysmonPath) {
            $sysmonVersion = (Get-Item $sysmonPath).VersionInfo.FileVersion
        }
    }

    Write-Output "version=$sysmonVersion"

    $channel = Get-WinEvent -ListLog `
        "Microsoft-Windows-Sysmon/Operational" `
        -ErrorAction SilentlyContinue

    if ($null -ne $channel) {
        Write-Output "event_channel_size_bytes=$($channel.FileSize)"
    }
    else {
        Set-ControlFailure "Sysmon event channel is unavailable"
        Write-Output "event_channel_size_bytes=unavailable"
    }
}
else {
    Write-Output "present=false"
}

# PowerShell Script Block Logging
Write-Output "powershell_script_block_logging="

$loggingPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

if (Test-Path $loggingPath) {
    $logging = Get-ItemProperty `
        -Path $loggingPath `
        -Name EnableScriptBlockLogging `
        -ErrorAction SilentlyContinue

    if ($null -ne $logging) {
        Write-Output "enabled=$($logging.EnableScriptBlockLogging)"
    }
    else {
        Write-Output "enabled=not_configured"
    }
}
else {
    Write-Output "enabled=not_configured"
}

# Account and password policy
Write-Output "account_policy="

if (Get-Command net.exe -ErrorAction SilentlyContinue) {
    $accountPolicy = net.exe accounts 2>$null

    if ($LASTEXITCODE -eq 0) {
        $accountPolicy
    }
    else {
        Set-ControlFailure "net accounts failed"
        Write-Output "unavailable"
    }
}
else {
    Stop-EnvironmentError "Missing dependency: net.exe"
}

if ($exitCode -eq 0) {
    Write-Output "result=success"
    exit 0
}

Write-Output "result=controlled_failure"
exit 1
