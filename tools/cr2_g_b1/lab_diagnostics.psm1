Set-StrictMode -Version Latest

$script:LabDiagnosticPhases = @(
    "EVENT_GUARD",
    "HOST_PREFLIGHT",
    "ACCOUNT_SETUP",
    "CLIENT_STAGING",
    "SERVICE_STAGING",
    "SERVICE_INSTALL",
    "PIPE_PRECREATE",
    "SERVICE_START",
    "TOKEN_ACL_CHECKS",
    "IPC_PROBES",
    "STORAGE_PROBES",
    "LIFECYCLE_PROBES",
    "SERVICE_REMOVAL",
    "FINAL_CLEANUP"
)

$script:LabCleanupContracts = @{
    PROCESS_CLEANUP = "PROCESS_CLEANUP_FAILED"
    SERVICE_REMOVAL = "SERVICE_REMOVAL_FAILED"
    ACCOUNT_CLEANUP = "ACCOUNT_CLEANUP_FAILED"
    TEMP_FILE_CLEANUP = "TEMP_FILE_CLEANUP_FAILED"
    CLIENT_ROOT_REMOVAL = "CLIENT_ROOT_CLEANUP_FAILED"
    SERVICE_ROOT_REMOVAL = "SERVICE_ROOT_CLEANUP_FAILED"
    PASSWORD_DISPOSAL = "PASSWORD_DISPOSAL_FAILED"
}

function Get-LabSafeCategory {
    param([System.Exception]$Exception)

    if ($null -eq $Exception) { return "UNKNOWN" }
    if ($Exception -is [System.UnauthorizedAccessException] -or $Exception -is [System.Security.SecurityException]) {
        return "ACCESS"
    }
    if ($Exception -is [System.IO.IOException]) { return "IO" }
    if ($Exception -is [System.ArgumentException]) { return "INPUT" }
    if ($Exception -is [System.InvalidOperationException]) { return "INVALID_STATE" }
    if ($Exception -is [System.TimeoutException]) { return "TIMEOUT" }
    return "OTHER"
}

function New-LabDiagnosticRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "EVENT_GUARD", "HOST_PREFLIGHT", "ACCOUNT_SETUP", "CLIENT_STAGING",
            "SERVICE_STAGING", "SERVICE_INSTALL", "PIPE_PRECREATE", "SERVICE_START",
            "TOKEN_ACL_CHECKS", "IPC_PROBES", "STORAGE_PROBES", "LIFECYCLE_PROBES",
            "SERVICE_REMOVAL", "FINAL_CLEANUP"
        )]
        [string]$Phase,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^[A-Z0-9_]{1,64}$")]
        [string]$FallbackCode,
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )

    $exception = $ErrorRecord.Exception
    $code = $FallbackCode
    $marker = "Sentinel.LabErrorCode.v1"
    if ($null -ne $exception -and $exception.Data.Contains($marker)) {
        $candidate = [string]$exception.Data[$marker]
        if ($candidate -match "^[A-Z0-9_]{1,64}$") {
            $code = $candidate
        }
    }

    $line = $null
    $invocation = $ErrorRecord.InvocationInfo
    if ($null -ne $invocation -and $invocation.ScriptLineNumber -gt 0) {
        $expectedPath = [IO.Path]::GetFullPath($ScriptPath)
        $actualPath = [string]$invocation.ScriptName
        if (-not [string]::IsNullOrWhiteSpace($actualPath)) {
            try {
                if ([IO.Path]::GetFullPath($actualPath) -ieq $expectedPath) {
                    $candidateLine = [int]$invocation.ScriptLineNumber
                    if ($candidateLine -ge 1 -and $candidateLine -le 10000) {
                        $line = $candidateLine
                    }
                }
            }
            catch {
                $line = $null
            }
        }
    }

    return [ordered]@{
        phase = $Phase
        code = $code
        category = (Get-LabSafeCategory -Exception $exception)
        line = $line
    }
}

function Invoke-LabCleanupPlan {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Operations = @()
    )

    if ($Operations.Count -gt 16) { throw "CLEANUP_PLAN_INVALID" }
    $completed = 0
    $failures = [System.Collections.Generic.List[object]]::new()
    foreach ($operation in $Operations) {
        if ($null -eq $operation -or $operation.name -isnot [string] -or
            -not $script:LabCleanupContracts.ContainsKey([string]$operation.name) -or
            $operation.code -cne $script:LabCleanupContracts[[string]$operation.name] -or
            $operation.action -isnot [scriptblock]) {
            throw "CLEANUP_PLAN_INVALID"
        }
        try {
            & $operation.action | Out-Null
            $completed++
        }
        catch {
            $failures.Add([ordered]@{
                operation = [string]$operation.name
                code = [string]$operation.code
                category = (Get-LabSafeCategory -Exception $_.Exception)
            })
        }
    }

    $status = if ($Operations.Count -eq 0) {
        "NOT_APPLICABLE"
    }
    elseif ($failures.Count -gt 0) {
        "FAILED"
    }
    else {
        "COMPLETED"
    }
    return [pscustomobject]@{
        status = $status
        steps_attempted = $Operations.Count
        steps_completed = $completed
        failures = @($failures.ToArray())
    }
}

function New-LabRunReport {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$PrimaryFailure,
        [Parameter(Mandatory = $true)]
        [object]$CleanupResult,
        [Parameter(Mandatory = $true)]
        [bool]$LabChecksPassed
    )

    if ($null -ne $PrimaryFailure) {
        foreach ($field in @("phase", "code", "category", "line")) {
            if (-not $PrimaryFailure.Contains($field)) { throw "DIAGNOSTIC_RECORD_INVALID" }
        }
        if ($PrimaryFailure.phase -notin $script:LabDiagnosticPhases -or
            $PrimaryFailure.code -notmatch "^[A-Z0-9_]{1,64}$" -or
            $PrimaryFailure.category -notin @("ACCESS", "IO", "INPUT", "INVALID_STATE", "TIMEOUT", "OTHER", "UNKNOWN")) {
            throw "DIAGNOSTIC_RECORD_INVALID"
        }
        if ($null -ne $PrimaryFailure.line -and ($PrimaryFailure.line -isnot [int] -or $PrimaryFailure.line -lt 1 -or $PrimaryFailure.line -gt 10000)) {
            throw "DIAGNOSTIC_RECORD_INVALID"
        }
    }
    if ($CleanupResult.status -notin @("NOT_APPLICABLE", "COMPLETED", "FAILED") -or
        $CleanupResult.steps_attempted -lt 0 -or $CleanupResult.steps_attempted -gt 16 -or
        $CleanupResult.steps_completed -lt 0 -or $CleanupResult.steps_completed -gt $CleanupResult.steps_attempted) {
        throw "CLEANUP_RESULT_INVALID"
    }

    $status = if ($null -ne $PrimaryFailure -or $CleanupResult.status -eq "FAILED" -or -not $LabChecksPassed) {
        "FAILED"
    }
    else {
        "PASS"
    }
    return [ordered]@{
        schema_version = "sentinel.cr2-g-b2-run-report.v1"
        status = $status
        scope = "EPHEMERAL_GUEST_ONLY"
        primary_failure = $PrimaryFailure
        cleanup = [ordered]@{
            status = [string]$CleanupResult.status
            steps_attempted = [int]$CleanupResult.steps_attempted
            steps_completed = [int]$CleanupResult.steps_completed
            failures = @($CleanupResult.failures)
        }
        production_owner_verification = "UNAVAILABLE"
        authorization_enabled = $false
        unverified = @(
            "CROSS_SESSION",
            "REMOTE_PEER",
            "HOST_ADMINISTRATOR_OR_SYSTEM_COMPROMISE",
            "PRODUCTION_OWNER_AUTHENTICATION"
        )
    }
}

Export-ModuleMember -Function New-LabDiagnosticRecord, Invoke-LabCleanupPlan, New-LabRunReport
