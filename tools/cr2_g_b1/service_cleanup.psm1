Set-StrictMode -Version Latest

function Invoke-LabServiceRemoval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [Parameter(Mandatory = $true)]
        [hashtable]$Operations,
        [ValidateRange(1, 30000)]
        [int]$TimeoutMilliseconds = 8000,
        [ValidateRange(1, 1000)]
        [int]$PollMilliseconds = 100
    )

    if ($ServiceName -cne "SentinelCR2GB2Lab") {
        throw "SERVICE_NAME_INVALID"
    }
    $requiredOperations = @("GetState", "Stop", "Delete", "Sleep")
    if ($Operations.Count -ne $requiredOperations.Count) {
        throw "SERVICE_OPERATIONS_INVALID"
    }
    foreach ($name in $requiredOperations) {
        if (-not $Operations.ContainsKey($name) -or $Operations[$name] -isnot [scriptblock]) {
            throw "SERVICE_OPERATIONS_INVALID"
        }
    }

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $allowedStates = @("ABSENT", "RUNNING", "START_PENDING", "STOP_PENDING", "STOPPED", "DELETE_PENDING")
    $readState = {
        try {
            $state = & $Operations.GetState $ServiceName
        }
        catch {
            throw "SERVICE_STATE_QUERY_FAILED"
        }
        if ($state -isnot [string] -or $state -cnotin $allowedStates) {
            throw "SERVICE_STATE_INVALID"
        }
        return $state
    }
    $pause = {
        if ($timer.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
            throw "SERVICE_REMOVE_TIMEOUT"
        }
        try {
            & $Operations.Sleep $PollMilliseconds
        }
        catch {
            throw "SERVICE_WAIT_FAILED"
        }
    }

    $state = & $readState
    if ($state -eq "ABSENT") {
        return "REMOVED"
    }

    if ($state -in @("RUNNING", "START_PENDING")) {
        try {
            & $Operations.Stop $ServiceName
        }
        catch {
            throw "SERVICE_STOP_FAILED"
        }
    }
    while ($state -in @("RUNNING", "START_PENDING", "STOP_PENDING")) {
        & $pause
        $state = & $readState
    }
    if ($state -eq "ABSENT") {
        return "REMOVED"
    }
    if ($state -eq "STOPPED") {
        try {
            $deleteResult = & $Operations.Delete $ServiceName
        }
        catch {
            throw "SERVICE_DELETE_FAILED"
        }
        if ($deleteResult -cnotin @("REQUESTED", "ALREADY_PENDING")) {
            throw "SERVICE_DELETE_FAILED"
        }
    }
    elseif ($state -ne "DELETE_PENDING") {
        throw "SERVICE_STATE_INVALID"
    }

    # DeleteService/sc.exe delete marks a service for deletion; it does not
    # prove removal. Keep polling until SCM no longer reports the fixed service.
    # An already-marked service is handled by observing state and never treating
    # a redundant delete result as success.
    while ($true) {
        $state = & $readState
        if ($state -eq "ABSENT") {
            return "REMOVED"
        }
        if ($state -notin @("STOPPED", "DELETE_PENDING")) {
            throw "SERVICE_NOT_STOPPED_FOR_REMOVAL"
        }
        & $pause
    }
}

Export-ModuleMember -Function Invoke-LabServiceRemoval
