# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

[CmdletBinding()]
param ()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$telemetryDir = Join-Path $scriptRoot "capstone\telemetry"
# capstone\telemetry\windows_events.json
$eventsFile = Join-Path $telemetryDir "windows_events.json"
# capstone\telemetry\windows_coverage.json
$coverageFile = Join-Path $telemetryDir "windows_coverage.json"

$exitCode = 0

function Set-ControlFailure {
    param (
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Error $Message
    $script:exitCode = 1
}

function Stop-EnvironmentError {
    param (
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Error $Message
    exit 2
}

function Test-Event {
    param (
        [Parameter(Mandatory)]
        [string]$LogName,

        [Parameter(Mandatory)]
        [int[]]$EventId,

        [Parameter(Mandatory)]
        [datetime]$Since
    )

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            Id        = $EventId
            StartTime = $Since
        } -MaxEvents 20 -ErrorAction Stop

        return $null -ne $events -and @($events).Count -gt 0
    }
    catch [Exception] {
        if ($_.Exception.Message -match "No events were found") {
            return $false
        }

        Set-ControlFailure "Unable to query event channel $LogName"
        return $false
    }
}

function Add-CoverageResult {
    param (
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[object]]$Coverage,

        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$Channel,

        [Parameter(Mandatory)]
        [int[]]$EventId,

        [Parameter(Mandatory)]
        [datetime]$Since,

        [Parameter(Mandatory)]
        [scriptblock]$ActionScript
    )

    $result = [ordered]@{
        action = $Action
        channel = $Channel
        expected_event_ids = $EventId
        test_started = $Since.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        action_exit_code = 0
        event_found = $false
    }

    try {
        & $ActionScript
    }
    catch {
        $result.action_exit_code = 1
        Set-ControlFailure "$Action failed: $($_.Exception.Message)"
    }

    if ($result.action_exit_code -eq 0) {
        $result.event_found = Test-Event `
            -LogName $Channel `
            -EventId $EventId `
            -Since $Since

        if (-not $result.event_found) {
            Set-ControlFailure (
                "Expected event not found for $Action in $Channel"
            )
        }
    }

    $Coverage.Add([pscustomobject]$result)
}

# Environment validation
if ($env:OS -ne "Windows_NT") {
    Stop-EnvironmentError "This script must run on Windows"
}

$requiredCommands = @(
    "Get-Service",
    "Get-CimInstance",
    "Get-WinEvent",
    "Get-LocalUser",
    "New-LocalUser",
    "Remove-LocalUser",
    "Register-ScheduledTask",
    "Start-ScheduledTask",
    "Unregister-ScheduledTask"
)

foreach ($command in $requiredCommands) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        Stop-EnvironmentError "Missing dependency: $command"
    }
}

try {
    if (-not (Test-Path -LiteralPath $telemetryDir)) {
        New-Item -ItemType Directory -Path $telemetryDir -Force |
            Out-Null
    }
}
catch {
    Stop-EnvironmentError "Unable to create telemetry directory"
}

# Verify Sysmon
$sysmonService = Get-Service `
    -Name "Sysmon" `
    -ErrorAction SilentlyContinue

if ($null -eq $sysmonService) {
    Stop-EnvironmentError "Sysmon is not installed"
}

if ($sysmonService.Status -ne "Running") {
    Set-ControlFailure "Sysmon is not running"
}

$sysmonWmi = Get-CimInstance `
    -ClassName Win32_Service `
    -Filter "Name='Sysmon'" `
    -ErrorAction SilentlyContinue

if ($null -eq $sysmonWmi) {
    Stop-EnvironmentError "Unable to query Sysmon service"
}

$sysmonCommandLine = $sysmonWmi.PathName

if ($sysmonCommandLine -notmatch "(?i)meddefense") {
    Set-ControlFailure "Sysmon service does not appear to use the MedDefense configuration"
}

$sysmonChannel = Get-WinEvent -ListLog `
    "Microsoft-Windows-Sysmon/Operational" `
    -ErrorAction SilentlyContinue

if ($null -eq $sysmonChannel) {
    Stop-EnvironmentError "Sysmon Operational event channel is unavailable"
}

# Verify Script Block Logging
$loggingPath = `
    "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

if (-not (Test-Path -LiteralPath $loggingPath)) {
    Set-ControlFailure "Script Block Logging registry key is missing"
}
else {
    $logging = Get-ItemProperty `
        -Path $loggingPath `
        -Name EnableScriptBlockLogging `
        -ErrorAction SilentlyContinue

    if ($null -eq $logging -or $logging.EnableScriptBlockLogging -ne 1) {
        Set-ControlFailure "Script Block Logging is not enabled"
    }
}

$coverage = [System.Collections.Generic.List[object]]::new()

$testUser = "MedDefenseAuditTest"
$testPassword = ConvertTo-SecureString `
    "MedDefense-Audit-2026!" `
    -AsPlainText `
    -Force

$taskName = "MedDefenseAuditTest"
$serviceName = "MedDefenseAuditTestSvc"
$servicePath = Join-Path $env:TEMP "MedDefenseAuditTest.exe"

# Clean up stale test objects.
$existingUser = Get-LocalUser `
    -Name $testUser `
    -ErrorAction SilentlyContinue

if ($null -ne $existingUser) {
    Remove-LocalUser -Name $testUser -ErrorAction SilentlyContinue
}

$existingTask = Get-ScheduledTask `
    -TaskName $taskName `
    -ErrorAction SilentlyContinue

if ($null -ne $existingTask) {
    Unregister-ScheduledTask `
        -TaskName $taskName `
        -Confirm:$false `
        -ErrorAction SilentlyContinue
}

$existingService = Get-Service `
    -Name $serviceName `
    -ErrorAction SilentlyContinue

if ($null -ne $existingService) {
    & sc.exe delete $serviceName | Out-Null
}

# Create local user.
$userTestStart = Get-Date

Add-CoverageResult `
    -Coverage $coverage `
    -Action "create_local_user" `
    -Channel "Security" `
    -EventId @(4720) `
    -Since $userTestStart `
    -ActionScript {
        New-LocalUser `
            -Name $testUser `
            -Password $testPassword `
            -Description "Temporary MedDefense audit test user" `
            -PasswordNeverExpires `
            -ErrorAction Stop |
            Out-Null
    }

# Create and run scheduled task.
$taskTestStart = Get-Date

Add-CoverageResult `
    -Coverage $coverage `
    -Action "create_and_run_scheduled_task" `
    -Channel "Security" `
    -EventId @(4698) `
    -Since $taskTestStart `
    -ActionScript {
        $action = New-ScheduledTaskAction `
            -Execute "cmd.exe" `
            -Argument "/c exit 0"

        $trigger = New-ScheduledTaskTrigger `
            -Once `
            -At (Get-Date).AddMinutes(1)

        Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Trigger $trigger `
            -User "SYSTEM" `
            -RunLevel Highest `
            -Force `
            -ErrorAction Stop |
            Out-Null

        Start-ScheduledTask `
            -TaskName $taskName `
            -ErrorAction Stop
    }

# Create temporary service.
if (-not (Test-Path -LiteralPath "$env:SystemRoot\System32\cmd.exe")) {
    Set-ControlFailure "cmd.exe is unavailable for service test"
}
else {
    $serviceTestStart = Get-Date

    try {
        & sc.exe create $serviceName `
            binPath= "cmd.exe /c exit 0" `
            start= demand | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe create failed with exit code $LASTEXITCODE"
        }

        $service = Get-Service `
            -Name $serviceName `
            -ErrorAction Stop

        Start-Service `
            -Name $serviceName `
            -ErrorAction Stop

        Stop-Service `
            -Name $serviceName `
            -Force `
            -ErrorAction Stop

        $serviceEventFound = Test-Event `
            -LogName "Security" `
            -EventId @(4697) `
            -Since $serviceTestStart

        $coverage.Add(
            [pscustomobject][ordered]@{
                action = "start_and_stop_service"
                channel = "Security"
                expected_event_ids = @(4697)
                test_started = $serviceTestStart.ToUniversalTime().ToString(
                    "yyyy-MM-ddTHH:mm:ssZ"
                )
                action_exit_code = 0
                event_found = $serviceEventFound
            }
        )

        if (-not $serviceEventFound) {
            Set-ControlFailure "Expected service event was not found"
        }
    }
    catch {
        $coverage.Add(
            [pscustomobject][ordered]@{
                action = "start_and_stop_service"
                channel = "Security"
                expected_event_ids = @(4697)
                test_started = $serviceTestStart.ToUniversalTime().ToString(
                    "yyyy-MM-ddTHH:mm:ssZ"
                )
                action_exit_code = 1
                event_found = $false
            }
        )

        Set-ControlFailure "Service test failed: $($_.Exception.Message)"
    }
}

# Authorized PowerShell test.
$powerShellTestStart = Get-Date

Add-CoverageResult `
    -Coverage $coverage `
    -Action "authorized_powershell_command" `
    -Channel "Microsoft-Windows-PowerShell/Operational" `
    -EventId @(4104) `
    -Since $powerShellTestStart `
    -ActionScript {
        & powershell.exe `
            -NoProfile `
            -NonInteractive `
            -Command 'Write-Output "MedDefense authorized telemetry test"' |
            Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "PowerShell test command failed"
        }
    }

# Cleanup.
Remove-LocalUser `
    -Name $testUser `
    -ErrorAction SilentlyContinue

Unregister-ScheduledTask `
    -TaskName $taskName `
    -Confirm:$false `
    -ErrorAction SilentlyContinue

& sc.exe stop $serviceName | Out-Null
& sc.exe delete $serviceName | Out-Null

# Export last 30 minutes.
$exportSince = (Get-Date).AddMinutes(-30)

$sysmonEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        StartTime = $exportSince
    } -ErrorAction SilentlyContinue |
        ForEach-Object {
            [ordered]@{
                time_created = $_.TimeCreated.ToUniversalTime().ToString(
                    "yyyy-MM-ddTHH:mm:ss.fffZ"
                )
                id = $_.Id
                provider = $_.ProviderName
                level = $_.LevelDisplayName
                machine = $_.MachineName
                message = $_.Message
            }
        }
)

$powerShellEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-PowerShell/Operational"
        StartTime = $exportSince
    } -ErrorAction SilentlyContinue |
        ForEach-Object {
            [ordered]@{
                time_created = $_.TimeCreated.ToUniversalTime().ToString(
                    "yyyy-MM-ddTHH:mm:ss.fffZ"
                )
                id = $_.Id
                provider = $_.ProviderName
                level = $_.LevelDisplayName
                machine = $_.MachineName
                message = $_.Message
            }
        }
)

$events = [ordered]@{
    timestamp = (Get-Date).ToUniversalTime().ToString(
        "yyyy-MM-ddTHH:mm:ssZ"
    )
    hostname = $env:COMPUTERNAME
    collection_window_minutes = 30
    sysmon = [ordered]@{
        channel = "Microsoft-Windows-Sysmon/Operational"
        records = $sysmonEvents
    }
    powershell = [ordered]@{
        channel = "Microsoft-Windows-PowerShell/Operational"
        records = $powerShellEvents
    }
}

try {
    $events |
        ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $eventsFile -Encoding UTF8 -ErrorAction Stop

    $coverageOutput = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString(
            "yyyy-MM-ddTHH:mm:ssZ"
        )
        hostname = $env:COMPUTERNAME
		# last 10 minutes
        collection_window_minutes = 10
        actions = @($coverage)
    }

    $coverageOutput |
        ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $coverageFile -Encoding UTF8 -ErrorAction Stop
}
catch {
    Stop-EnvironmentError "Unable to write telemetry JSON: $($_.Exception.Message)"
}

# expected record are fine
# expected event
if ($exitCode -eq 0) {
    exit 0
}

exit 1
