# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

[CmdletBinding()]
param ()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$capstoneDir = Join-Path $scriptRoot "capstone"
$execDir = Join-Path $capstoneDir "exec"
$logFile = Join-Path $execDir "windows_harden.log"
$resultFile = Join-Path $execDir "windows_harden.json"
$baselineFile = Join-Path $capstoneDir "baseline_windows.json"
$targetFile = Join-Path $capstoneDir "target_state.json"

$helperFile = "/home/analyst/MedDefense_Lab/capstone/win_audit.ps1"

$exitCode = 0
$steps = [System.Collections.Generic.List[object]]::new()
$controlsTouched = [System.Collections.Generic.List[string]]::new()

function Stop-EnvironmentError {
    param (
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Error $Message
    exit 2
}

function Set-ControlFailure {
    param (
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Error $Message
    $script:exitCode = 1
}

function Get-JsonFile {
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Stop-EnvironmentError "Missing input file: $Path"
    }

    try {
        $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        return $content | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Stop-EnvironmentError "Invalid JSON: $Path"
    }
}

function Get-TargetPassRate {
    param (
        [Parameter(Mandatory)]
        [object]$Target
    )

    $value = $null

    if ($null -ne $Target.windows -and
        $null -ne $Target.windows.pass_rate) {
        $value = $Target.windows.pass_rate
    }

    if ($null -eq $value -and $null -ne $Target.controls) {
        $control = @(
            $Target.controls |
                Where-Object { $_.id -eq "WIN-CIS-01" }
        ) | Select-Object -First 1

        if ($null -ne $control) {
            $value = $control.expected_value
        }
    }

    if ($null -eq $value) {
        Stop-EnvironmentError "Windows target pass rate is missing from target_state.json"
    }

    $number = 0.0

    if (-not [double]::TryParse(
        $value.ToString(),
        [Globalization.NumberStyles]::Float,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$number
    )) {
        Stop-EnvironmentError "Windows target pass rate is invalid"
    }

    return $number
}

function Get-BaselinePassRate {
    param (
        [Parameter(Mandatory)]
        [object]$Baseline
    )

    $properties = @(
        "pass_rate",
        "cis_level_1_pass_rate",
        "level_1_pass_rate",
        "post_pass_rate"
    )

    foreach ($property in $properties) {
        if ($null -ne $Baseline.$property) {
            return [double]$Baseline.$property
        }
    }

    Stop-EnvironmentError "Windows baseline pass rate is missing"
}

function Invoke-HardeningStep {
    param (
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$ScriptPath,

        [Parameter(Mandatory)]
        [string[]]$ControlIds
    )

    $start = Get-Date

    Add-Content -LiteralPath $logFile -Value ""
    Add-Content -LiteralPath $logFile -Value (
        "[{0}] START {1}" -f
        (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
        $Name
    )
    Add-Content -LiteralPath $logFile -Value "SCRIPT=$ScriptPath"

    $tempOutput = Join-Path $env:TEMP (
        "windows_harden_{0}.log" -f [Guid]::NewGuid()
    )

    $stepExitCode = 1
    $changed = $false

    try {
        & powershell.exe `
            -NoProfile `
            -NonInteractive `
            -ExecutionPolicy Bypass `
            -File $ScriptPath *> $tempOutput

        $stepExitCode = $LASTEXITCODE

        if (Test-Path -LiteralPath $tempOutput) {
            Get-Content -LiteralPath $tempOutput |
                Add-Content -LiteralPath $logFile
        }

        if (Test-Path -LiteralPath $tempOutput) {
            $stepOutput = Get-Content -LiteralPath $tempOutput -Raw
            $changed = $stepOutput -match "(?im)^\s*changed\s*=\s*true\s*$"
        }
    }
    catch {
        Add-Content -LiteralPath $logFile -Value $_.Exception.Message
        $stepExitCode = 1
    }
    finally {
        Remove-Item -LiteralPath $tempOutput -Force -ErrorAction SilentlyContinue
    }

    Add-Content -LiteralPath $logFile -Value (
        "[{0}] EXIT_CODE={1}" -f
        (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
        $stepExitCode
    )

    $duration = ((Get-Date) - $start).TotalSeconds

    $steps.Add(
        [ordered]@{
            name = $Name
            script_path = $ScriptPath
            exit_code = $stepExitCode
            duration_seconds = [math]::Round($duration, 3)
            changed = [bool]$changed
        }
    )

    if ($stepExitCode -ne 0) {
        Set-ControlFailure "$Name failed with exit code $stepExitCode"
    }

    foreach ($controlId in $ControlIds) {
        if (-not $controlsTouched.Contains($controlId)) {
            $controlsTouched.Add($controlId)
        }
    }
}

# Environment validation
if ($env:OS -ne "Windows_NT") {
    Stop-EnvironmentError "This script must run on Windows"
}

if (-not (Get-Command powershell.exe -ErrorAction SilentlyContinue)) {
    Stop-EnvironmentError "Missing dependency: powershell.exe"
}

if (-not (Test-Path -LiteralPath $execDir)) {
    try {
        New-Item -ItemType Directory -Path $execDir -Force |
            Out-Null
    }
    catch {
        Stop-EnvironmentError "Unable to create $execDir"
    }
}

$baseline = Get-JsonFile -Path $baselineFile
$target = Get-JsonFile -Path $targetFile

$baselinePassRate = Get-BaselinePassRate -Baseline $baseline
$targetPassRate = Get-TargetPassRate -Target $target

$stepsDefinition = @(
    @{
        Name = "account policy"
        Script = "4-password_policy.ps1"
        Controls = @("WIN-ACC-01")
    },
    @{
        Name = "audit policy"
        Script = "5-audit_policy.ps1"
        Controls = @("WIN-AUD-01")
    },
    @{
        Name = "Windows Firewall baseline"
        Script = "11-firewall_hardening.ps1"
        Controls = @("WIN-FW-01")
    },
    @{
        Name = "Sysmon installation"
        Script = "9-sysmon_deploy.ps1"
        Controls = @("WIN-SYM-01", "WIN-SYM-02")
    },
    @{
        Name = "PowerShell Script Block Logging"
        Script = "6-powershell_security.ps1"
        Controls = @("WIN-PS-01", "WIN-PS-02")
    },
    @{
        Name = "AppLocker or Defender Application Control baseline"
        Script = "12-applocker_config.ps1"
        Controls = @("WIN-APP-01")
    },
    @{
        Name = "service minimization"
        Script = "14-service_accounts.ps1"
        Controls = @("WIN-SVC-01")
    }
)

Set-Content -LiteralPath $logFile -Value (
    "[{0}] Windows hardening started" -f
    (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
)

foreach ($step in $stepsDefinition) {
    $stepPath = Join-Path $scriptRoot $step.Script

    if (-not (Test-Path -LiteralPath $stepPath -PathType Leaf)) {
        Set-ControlFailure "Missing hardening script: $stepPath"

        $steps.Add(
            [ordered]@{
                name = $step.Name
                script_path = $stepPath
                exit_code = 2
                duration_seconds = 0
                changed = $false
            }
        )

        continue
    }

    Invoke-HardeningStep `
        -Name $step.Name `
        -ScriptPath $stepPath `
        -ControlIds $step.Controls
}

# Post-hardening audit
if (-not (Test-Path -LiteralPath $helperFile -PathType Leaf)) {
    Set-ControlFailure "Missing audit helper: $helperFile"
    $postPassRate = $null
}
else {
    Add-Content -LiteralPath $logFile -Value ""
    Add-Content -LiteralPath $logFile -Value (
        "[{0}] START post-hardening Windows audit" -f
        (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    )

    $auditOutputFile = Join-Path $env:TEMP (
        "windows_audit_{0}.log" -f [Guid]::NewGuid()
    )

    try {
        & powershell.exe `
            -NoProfile `
            -NonInteractive `
            -ExecutionPolicy Bypass `
            -File $helperFile *> $auditOutputFile

        $auditExitCode = $LASTEXITCODE

        if (Test-Path -LiteralPath $auditOutputFile) {
            Get-Content -LiteralPath $auditOutputFile |
                Add-Content -LiteralPath $logFile
        }

        if ($auditExitCode -ne 0) {
            Set-ControlFailure "win_audit.ps1 failed with exit code $auditExitCode"
            $postPassRate = $null
        }
        else {
            $auditText = Get-Content `
                -LiteralPath $auditOutputFile `
                -Raw `
                -ErrorAction Stop

            $match = [regex]::Match(
                $auditText,
                "(?im)(?:CIS\s+Level\s+1\s+pass\s+rate|pass\s+rate)\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)\s*%?"
            )

            if (-not $match.Success) {
                Set-ControlFailure "Unable to determine CIS Level 1 pass rate"
                $postPassRate = $null
            }
            else {
                $postPassRate = [double]$match.Groups[1].Value
            }
        }
    }
    catch {
        Set-ControlFailure "Unable to execute win_audit.ps1: $($_.Exception.Message)"
        $postPassRate = $null
    }
    finally {
        Remove-Item `
            -LiteralPath $auditOutputFile `
            -Force `
            -ErrorAction SilentlyContinue
    }

    Add-Content -LiteralPath $logFile -Value (
        "[{0}] POST_AUDIT_PASS_RATE={1}" -f
        (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
        $(if ($null -eq $postPassRate) { "unavailable" } else { $postPassRate })
    )
}

$indexDelta = $null

if ($null -ne $postPassRate) {
    $indexDelta = [math]::Round(
        $postPassRate - $baselinePassRate,
        2
    )

    if ($postPassRate -lt $targetPassRate) {
        Set-ControlFailure (
            "CIS Level 1 pass rate $postPassRate is below target $targetPassRate"
        )
    }
}

$timestamp = (Get-Date).ToUniversalTime().ToString(
    "yyyy-MM-ddTHH:mm:ssZ"
)

$result = [ordered]@{
    timestamp = $timestamp
    hostname = $env:COMPUTERNAME
    steps = @($steps)
    lynis_before = $baselinePassRate
    lynis_after = $postPassRate
    index_delta = $indexDelta
    controls_touched = @($controlsTouched)
}

try {
    $result |
        ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $resultFile -Encoding UTF8 -ErrorAction Stop
}
catch {
    Stop-EnvironmentError "Unable to create $resultFile"
}

if ($exitCode -eq 0) {
    exit 0
}

exit 1
