# Host and OS
$os = Get-CimInstance Win32_OperatingSystem

Write-Output "hostname=$env:COMPUTERNAME"
Write-Output "os_build=$($os.BuildNumber)"
Write-Output "patch_level=$($os.Version)"

# Installed features
if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    $featureCount = @(Get-WindowsFeature | Where-Object Installed).Count
    Write-Output "installed_feature_count=$featureCount"
}
elseif (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
    $featureCount = @(
        Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
            Where-Object State -eq 'Enabled'
    ).Count
    Write-Output "installed_feature_count=$featureCount"
}
else {
    Write-Output "installed_feature_count=unavailable"
}

# Running services
Write-Output "running_services="
Get-Service |
    Where-Object Status -eq 'Running' |
    Select-Object -ExpandProperty Name

# Local users
Write-Output "local_user_accounts="
if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
    Get-LocalUser |
        Select-Object -ExpandProperty Name
}
else {
    Write-Output "unavailable"
}

# Windows Firewall
Write-Output "firewall_state="
if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
    Get-NetFirewallProfile |
        Select-Object Name, Enabled |
        ForEach-Object {
            Write-Output "$($_.Name)=$($_.Enabled)"
        }
}
else {
    Write-Output "unavailable"
}

# Audit policy
Write-Output "audit_policy="
$auditPolicy = auditpol.exe /get /category:* 2>$null
if ($LASTEXITCODE -eq 0) {
    $auditPolicy
}
else {
    Write-Output "unavailable"
}

# Sysmon
Write-Output "sysmon="
$sysmon = Get-Service -Name Sysmon -ErrorAction SilentlyContinue

if ($null -ne $sysmon) {
    $sysmonPath = (Get-CimInstance Win32_Service -Filter "Name='Sysmon'").PathName
    $sysmonVersion = "unknown"

    if ($sysmonPath -match '"([^"]+)"') {
        $sysmonPath = $Matches[1]
    }

    if (Test-Path $sysmonPath) {
        $sysmonVersion = (Get-Item $sysmonPath).VersionInfo.FileVersion
    }

    Write-Output "present=true"
    Write-Output "state=$($sysmon.Status)"
    Write-Output "version=$sysmonVersion"

    $channel = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" `
        -ErrorAction SilentlyContinue

    if ($null -ne $channel) {
        Write-Output "event_channel_size_bytes=$($channel.FileSize)"
    }
    else {
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
    $logging = Get-ItemProperty -Path $loggingPath `
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

# Account lockout and password policy
Write-Output "account_policy="
$accountPolicy = net accounts 2>$null

if ($LASTEXITCODE -eq 0) {
    $accountPolicy
}
else {
    Write-Output "unavailable"
}

exit 0
