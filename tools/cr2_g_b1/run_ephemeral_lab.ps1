[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EventPath
)

$ErrorActionPreference = "Stop"
$serviceName = "SentinelCR2GB2Lab"
$serviceRoot = "C:\ProgramData\SentinelCR2GB2"
$clientRoot = $null
$clientRootCreated = $false
$clientPython = $null
$clientProbeScript = $null
$servicePipePrefix = "\\.\pipe\SentinelCR2GB2-"
$repoName = "Rakshak-D/sentinel"
$requiredBranch = "feat/cr2-g-b2-windows-ephemeral-lab"
$rootCreated = $false
$serviceCreated = $false
$failureCode = $null
$cleanupFailure = $false
$createdUsers = [System.Collections.Generic.List[string]]::new()
$createdUserSids = @{}
$processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$tempFiles = [System.Collections.Generic.List[string]]::new()

function Stop-WithCode([string]$Code) {
    throw $Code
}

function Invoke-Sc([string[]]$Arguments, [string]$Code) {
    $output = & "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        Stop-WithCode $Code
    }
    return ($output -join "`n")
}

function Invoke-Icacls([string[]]$Arguments, [string]$Code) {
    $output = & "$env:SystemRoot\System32\icacls.exe" @Arguments 2>&1
    if ($LASTEXITCODE -ne 0 -or ($output -join "`n") -match "Failed processing [1-9][0-9]* files") {
        Stop-WithCode $Code
    }
}

function Quote-WinArg([string]$Value) {
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-ChildAsUser(
    [string]$UserName,
    [securestring]$Password,
    [string[]]$ProbeArguments,
    [string]$Mode
) {
    $stdout = Join-Path $env:RUNNER_TEMP ("sgb2-" + [guid]::NewGuid().ToString("N") + ".out")
    $stderr = Join-Path $env:RUNNER_TEMP ("sgb2-" + [guid]::NewGuid().ToString("N") + ".err")
    $tempFiles.Add($stdout)
    $tempFiles.Add($stderr)
    $arguments = @("-I", "-S", "-B", $clientProbeScript) + $ProbeArguments
    $line = ($arguments | ForEach-Object { Quote-WinArg $_ }) -join " "
    $credential = [System.Management.Automation.PSCredential]::new(
        "$env:COMPUTERNAME\$UserName", $Password
    )
    $child = Start-Process `
        -FilePath $clientPython `
        -ArgumentList $line `
        -Credential $credential `
        -LoadUserProfile `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru
    if (-not $child.WaitForExit(15000)) {
        Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue
        $child.WaitForExit()
        Stop-WithCode "UNPRIVILEGED_CHILD_TIMEOUT_$Mode"
    }
    if ($child.ExitCode -ne 0) {
        Stop-WithCode "UNPRIVILEGED_CHILD_FAILED_$Mode"
    }
    $text = Get-Content -LiteralPath $stdout -Raw
    try {
        return $text | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    }
    catch {
        Stop-WithCode "UNPRIVILEGED_CHILD_OUTPUT_INVALID_$Mode"
    }
}

function New-DisposableLocalUser([string]$Prefix) {
    $suffix = [guid]::NewGuid().ToString("N").Substring(0, 12)
    $name = "$Prefix$suffix"
    $raw = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $passwordText = ($raw -replace '[^A-Za-z0-9]', '') + "a1!Z"
    $password = ConvertTo-SecureString $passwordText -AsPlainText -Force
    $raw = $null
    $passwordText = $null
    try {
        New-LocalUser `
            -Name $name `
            -Password $password `
            -UserMayNotChangePassword `
            -PasswordNeverExpires `
            -AccountNeverExpires `
            -Description "Ephemeral CR2-G-B2 synthetic lab identity" | Out-Null
        $createdUsers.Add($name)
        $sid = (Get-LocalUser -Name $name).SID.Value
        $usersMember = @(
            Get-LocalGroupMember -Group "Users" -ErrorAction Stop |
                Where-Object { $_.SID.Value -eq $sid }
        ).Count -eq 1
        if (-not $usersMember) {
            Add-LocalGroupMember -Group "Users" -Member $name | Out-Null
        }
        $verifiedUsersMember = @(
            Get-LocalGroupMember -Group "Users" -ErrorAction Stop |
                Where-Object { $_.SID.Value -eq $sid }
        ).Count -eq 1
        if (-not $verifiedUsersMember) {
            Stop-WithCode "DISPOSABLE_USER_GROUP_MEMBERSHIP_FAILED"
        }
        $createdUserSids[$name] = $sid
        return [pscustomobject]@{ Name = $name; Password = $password; Sid = $sid }
    }
    catch {
        $password.Dispose()
        throw "DISPOSABLE_USER_CREATION_FAILED"
    }
}

function Wait-ServiceStatus([string]$Status, [int]$Seconds) {
    $until = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $current = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $current -and $current.Status.ToString() -eq $Status) {
            return $current
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $until)
    Stop-WithCode "SERVICE_STATE_TIMEOUT_$Status"
}

function Get-ServicePid {
    $until = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $row = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
        if ($null -ne $row -and [uint32]$row.ProcessId -gt 0) {
            return [int]$row.ProcessId
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $until)
    Stop-WithCode "SERVICE_PID_UNAVAILABLE"
}

function Wait-PrecreateFailure {
    $until = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $query = & "$env:SystemRoot\System32\sc.exe" query $serviceName 2>&1
        $joined = $query -join "`n"
        if (
            $joined -match "STATE\s+:\s+4\s+RUNNING" -or
            $joined -match "STATE\s+:\s+2\s+START_PENDING"
        ) {
            Start-Sleep -Milliseconds 100
        }
        elseif ($joined -match "STATE\s+:\s+1\s+STOPPED") {
            if ($joined -match "WIN32_EXIT_CODE\s+:\s+1066" -and $joined -match "SERVICE_EXIT_CODE\s+:\s+[1-9][0-9]*") {
                return
            }
            Start-Sleep -Milliseconds 100
        }
        else {
            Start-Sleep -Milliseconds 100
        }
    } while ([DateTime]::UtcNow -lt $until)
    Stop-WithCode "PIPE_PRECREATE_DID_NOT_FAIL_SERVICE_CLOSED"
}

function Assert-ServiceState([string]$Expected) {
    $actual = (Get-Service -Name $serviceName).Status.ToString()
    if ($actual -ne $Expected) {
        Stop-WithCode "SERVICE_STATE_MISMATCH"
    }
}

function Get-CriticalHashes {
    $targets = @{
        service_binary = Join-Path $serviceRoot "app\python\python.exe"
        service_module = Join-Path $serviceRoot "app\tools\cr2_g_b1\service_host.py"
        service_config = Join-Path $serviceRoot "config\service.json"
        canary_database = Join-Path $serviceRoot "data\canary.sqlite"
        app_marker = Join-Path $serviceRoot "app\access-marker.bin"
        config_marker = Join-Path $serviceRoot "config\access-marker.bin"
        data_marker = Join-Path $serviceRoot "data\access-marker.bin"
    }
    $hashes = @{}
    foreach ($label in $targets.Keys) {
        $hashes[$label] = (Get-FileHash -LiteralPath $targets[$label] -Algorithm SHA256).Hash
    }
    return $hashes
}

try {
    if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_OS -ne "Windows") {
        Stop-WithCode "GITHUB_WINDOWS_RUNNER_REQUIRED"
    }
    if ($env:GITHUB_EVENT_NAME -ne "pull_request" -or $env:GITHUB_REPOSITORY -ne $repoName) {
        Stop-WithCode "EXPECTED_SAME_REPOSITORY_PULL_REQUEST"
    }
    $event = Get-Content -LiteralPath $EventPath -Raw | ConvertFrom-Json -AsHashtable
    if (
        $event.action -notin @("opened", "synchronize", "reopened", "ready_for_review") -or
        $event.pull_request.head.repo.full_name -ne $repoName -or
        $event.pull_request.head.ref -ne $requiredBranch -or
        $event.pull_request.base.repo.full_name -ne $repoName -or
        $event.pull_request.base.ref -ne "main"
    ) {
        Stop-WithCode "PULL_REQUEST_EVENT_NOT_ALLOWLISTED"
    }
    if (-not [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Stop-WithCode "EPHEMERAL_RUNNER_ADMIN_REQUIRED"
    }
    if (Test-Path -LiteralPath $serviceRoot) {
        Stop-WithCode "LAB_ROOT_ALREADY_EXISTS"
    }
    $resolvedRoot = [IO.Path]::GetFullPath($serviceRoot)
    if ($resolvedRoot -ne $serviceRoot -or (Get-Item -LiteralPath (Split-Path $serviceRoot -Parent)).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        Stop-WithCode "LAB_ROOT_PATH_INVALID"
    }
    $runnerPython = (Get-Command python -ErrorAction Stop).Source
    $pythonInfo = & $runnerPython -I -S -B -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}'); print(sys.base_prefix)"
    if ($LASTEXITCODE -ne 0 -or $pythonInfo[0] -ne "3.11") {
        Stop-WithCode "PYTHON_311_REQUIRED"
    }
    $pythonBase = $pythonInfo[1]
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $probeScript = Join-Path $repoRoot "tools\cr2_g_b1\windows_service_lab.py"
    if (-not (Test-Path -LiteralPath $probeScript -PathType Leaf)) {
        Stop-WithCode "LAB_PROBE_MISSING"
    }
    $pipeName = $servicePipePrefix + [guid]::NewGuid().ToString("N")

    $allowed = New-DisposableLocalUser "sgb2a"
    $denied = New-DisposableLocalUser "sgb2d"
    if ($allowed.Sid -eq $denied.Sid -or $allowed.Sid -notmatch '^S-1-5-21-' -or $denied.Sid -notmatch '^S-1-5-21-') {
        Stop-WithCode "DISPOSABLE_USER_SID_INVALID"
    }

    $publicRoot = if ([string]::IsNullOrWhiteSpace($env:PUBLIC)) {
        Join-Path $env:SystemDrive "Users\Public"
    }
    else {
        $env:PUBLIC
    }
    $expectedPublicRoot = [IO.Path]::GetFullPath((Join-Path $env:SystemDrive "Users\Public")).TrimEnd('\')
    if (
        [IO.Path]::GetFullPath($publicRoot).TrimEnd('\') -ine $expectedPublicRoot -or
        (Get-Item -LiteralPath $expectedPublicRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint
    ) {
        Stop-WithCode "PUBLIC_CLIENT_ROOT_INVALID"
    }
    $clientRoot = Join-Path $expectedPublicRoot ("SentinelCR2GB2-client-" + [guid]::NewGuid().ToString("N"))
    if (Test-Path -LiteralPath $clientRoot) {
        Stop-WithCode "PUBLIC_CLIENT_ROOT_ALREADY_EXISTS"
    }
    New-Item -ItemType Directory -Path $clientRoot | Out-Null
    $clientRootCreated = $true
    $clientPackageRoot = Join-Path $clientRoot "tools\cr2_g_b1"
    $clientPythonRoot = Join-Path $clientRoot "python"
    New-Item -ItemType Directory -Path $clientPackageRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $clientPythonRoot -Force | Out-Null
    Get-ChildItem -LiteralPath $pythonBase -Force | Copy-Item -Destination $clientPythonRoot -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $repoRoot "tools\__init__.py") -Destination (Join-Path $clientRoot "tools\__init__.py")
    Get-ChildItem -LiteralPath (Join-Path $repoRoot "tools\cr2_g_b1") -Filter "*.py" -File |
        Copy-Item -Destination $clientPackageRoot -Force
    Invoke-Icacls @(
        $clientRoot,
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
        "*S-1-5-32-545:(OI)(CI)RX",
        "/T",
        "/C"
    ) "PUBLIC_CLIENT_DACL_FAILED"
    Invoke-Icacls @($clientRoot, "/setowner", "*S-1-5-18", "/T", "/C") "PUBLIC_CLIENT_OWNER_FAILED"
    $clientPython = Join-Path $clientPythonRoot "python.exe"
    $clientProbeScript = Join-Path $clientPackageRoot "windows_service_lab.py"
    if (-not (Test-Path -LiteralPath $clientPython -PathType Leaf) -or -not (Test-Path -LiteralPath $clientProbeScript -PathType Leaf)) {
        Stop-WithCode "PUBLIC_CLIENT_COPY_FAILED"
    }
    $clientAcl = & $runnerPython -I -S -B $probeScript client-acls --root $clientRoot
    if ($LASTEXITCODE -ne 0) {
        Stop-WithCode "PUBLIC_CLIENT_ACL_READBACK_FAILED"
    }
    $clientAclResult = $clientAcl | ConvertFrom-Json
    if ($clientAclResult.public_client_acl -ne "READ_EXECUTE_ONLY" -or $clientAclResult.targets_checked -ne 3) {
        Stop-WithCode "PUBLIC_CLIENT_ACL_RESULT_INVALID"
    }

    New-Item -ItemType Directory -Path $serviceRoot | Out-Null
    $rootCreated = $true
    if ((Get-Item -LiteralPath $serviceRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        Stop-WithCode "LAB_ROOT_REPARSE_POINT"
    }
    New-Item -ItemType Directory -Path (Join-Path $serviceRoot "app\python") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $serviceRoot "app\tools\cr2_g_b1") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $serviceRoot "config") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $serviceRoot "data") -Force | Out-Null
    Get-ChildItem -LiteralPath $pythonBase -Force | Copy-Item -Destination (Join-Path $serviceRoot "app\python") -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $repoRoot "tools\__init__.py") -Destination (Join-Path $serviceRoot "app\tools\__init__.py")
    Get-ChildItem -LiteralPath (Join-Path $repoRoot "tools\cr2_g_b1") -Filter "*.py" -File |
        Copy-Item -Destination (Join-Path $serviceRoot "app\tools\cr2_g_b1") -Force

    & $runnerPython -I -S -B $probeScript init-store | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Stop-WithCode "SYNTHETIC_STORE_INITIALIZATION_FAILED"
    }
    $config = @{
        schema_version = "sentinel.cr2-g-b2-service-config.v1"
        service_name = $serviceName
        pipe_name = $pipeName
        allowed_client_sid = $allowed.Sid
        database_path = Join-Path $serviceRoot "data\canary.sqlite"
    } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText(
        (Join-Path $serviceRoot "config\service.json"),
        $config,
        [Text.UTF8Encoding]::new($false)
    )
    foreach ($directory in @("app", "config", "data")) {
        [IO.File]::WriteAllBytes((Join-Path $serviceRoot "$directory\access-marker.bin"), [byte[]](0x53, 0x47, 0x42, 0x32))
    }

    $serviceImage = Join-Path $serviceRoot "app\python\python.exe"
    $serviceScript = Join-Path $serviceRoot "app\tools\cr2_g_b1\service_host.py"
    if (-not (Test-Path -LiteralPath $serviceImage -PathType Leaf) -or -not (Test-Path -LiteralPath $serviceScript -PathType Leaf)) {
        Stop-WithCode "SERVICE_IMAGE_COPY_FAILED"
    }
    $binaryPath = '"' + $serviceImage + '" -I -S -B "' + $serviceScript + '"'
    Invoke-Sc @("create", $serviceName, "type=", "own", "start=", "demand", "obj=", "NT AUTHORITY\LocalService", "binPath=", $binaryPath) "SERVICE_CREATE_FAILED" | Out-Null
    $serviceCreated = $true
    Invoke-Sc @("sidtype", $serviceName, "restricted") "SERVICE_SID_TYPE_CONFIGURATION_FAILED" | Out-Null
    $serviceSidJson = & $runnerPython -I -S -B $probeScript service-sid
    if ($LASTEXITCODE -ne 0) {
        Stop-WithCode "SERVICE_SID_RESOLUTION_FAILED"
    }
    $serviceSid = ($serviceSidJson | ConvertFrom-Json).service_sid
    if ($serviceSid -notmatch '^S-1-5-80-(?:[0-9]+-){4}[0-9]+$') {
        Stop-WithCode "SERVICE_SID_INVALID"
    }

    foreach ($path in @($serviceRoot, (Join-Path $serviceRoot "app"), (Join-Path $serviceRoot "config"), (Join-Path $serviceRoot "data"))) {
        $serviceGrant = "*{0}:(OI)(CI)RX" -f $serviceSid
        Invoke-Icacls @($path, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", $serviceGrant, "/T", "/C") "SERVICE_STORAGE_DACL_FAILED"
        Invoke-Icacls @($path, "/setowner", "*S-1-5-18", "/T", "/C") "SERVICE_STORAGE_OWNER_FAILED"
    }
    Invoke-Sc @("sdset", $serviceName, "D:(A;;GA;;;SY)(A;;GA;;;BA)") "SERVICE_OBJECT_DACL_FAILED" | Out-Null
    $storageAcl = & $runnerPython -I -S -B $probeScript storage-acls --service-sid $serviceSid --client-sid $allowed.Sid
    if ($LASTEXITCODE -ne 0) {
        Stop-WithCode "STORAGE_ACL_READBACK_FAILED"
    }
    $storageAclResult = $storageAcl | ConvertFrom-Json
    if ($storageAclResult.storage_acl_summary.PSObject.Properties.Count -ne 7) {
        Stop-WithCode "STORAGE_ACL_TARGET_SET_INVALID"
    }

    # A disposable non-admin account creates the first pipe instance. The SCM
    # host must fail closed because its own CreateNamedPipeW uses FIRST_INSTANCE.
    $precreateOut = Join-Path $env:RUNNER_TEMP ("sgb2-precreate-" + [guid]::NewGuid().ToString("N") + ".out")
    $precreateErr = Join-Path $env:RUNNER_TEMP ("sgb2-precreate-" + [guid]::NewGuid().ToString("N") + ".err")
    $tempFiles.Add($precreateOut)
    $tempFiles.Add($precreateErr)
    $preArgs = @("-I", "-S", "-B", $clientProbeScript, "precreate", "--pipe", $pipeName, "--seconds", "20")
    $preLine = ($preArgs | ForEach-Object { Quote-WinArg $_ }) -join " "
    $preCred = [System.Management.Automation.PSCredential]::new(
        "$env:COMPUTERNAME\$($denied.Name)", $denied.Password
    )
    $preProcess = Start-Process -FilePath $clientPython -ArgumentList $preLine -Credential $preCred -LoadUserProfile -WindowStyle Hidden -RedirectStandardOutput $precreateOut -RedirectStandardError $precreateErr -PassThru
    $processes.Add($preProcess)
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(8)
    do {
        Start-Sleep -Milliseconds 100
        $ready = (Test-Path -LiteralPath $precreateOut) -and (Get-Content -LiteralPath $precreateOut -Raw) -match '"pipe_precreated":true'
    } while (-not $ready -and [DateTime]::UtcNow -lt $readyDeadline -and -not $preProcess.HasExited)
    if (-not $ready) {
        Stop-WithCode "PIPE_PRECREATE_PROBE_FAILED"
    }
    try {
        & "$env:SystemRoot\System32\sc.exe" start $serviceName 2>&1 | Out-Null
        Wait-PrecreateFailure
    }
    finally {
        if (-not $preProcess.HasExited) {
            Stop-Process -Id $preProcess.Id -Force -ErrorAction SilentlyContinue
            $preProcess.WaitForExit()
        }
    }

    # The service account has read/execute, not write; SYSTEM/Admin own recovery.
    & "$env:SystemRoot\System32\sc.exe" start $serviceName 2>&1 | Out-Null
    Wait-ServiceStatus "Running" 15 | Out-Null
    $serviceConfigJson = & $runnerPython -I -S -B $probeScript service-config
    if ($LASTEXITCODE -ne 0) {
        Stop-WithCode "SERVICE_CONFIG_READBACK_FAILED"
    }
    $serviceConfig = $serviceConfigJson | ConvertFrom-Json
    if ($serviceConfig.service_sid_type -ne 3 -or $serviceConfig.service_account -ne "NT AUTHORITY\LocalService") {
        Stop-WithCode "SERVICE_CONFIGURATION_NOT_RESTRICTED"
    }
    $servicePid = Get-ServicePid
    # Service-token inspection requires the runner observer, not a denial identity.
    $tokenJson = & $runnerPython -I -S -B $probeScript service-token --pid $servicePid --service-sid $serviceSid
    if ($LASTEXITCODE -ne 0) {
        Stop-WithCode "SERVICE_TOKEN_VERIFICATION_FAILED"
    }
    $serviceToken = $tokenJson | ConvertFrom-Json
    if ($serviceToken.elevated -or $serviceToken.administrator_group_present) {
        Stop-WithCode "SERVICE_TOKEN_PRIVILEGE_MISMATCH"
    }

    $beforeHashes = Get-CriticalHashes
    $allowedFacts = Invoke-ChildAsUser $allowed.Name $allowed.Password @("identity") "identity"
    if ($allowedFacts.identity.user_sid -ne $allowed.Sid -or $allowedFacts.identity.elevated -or $allowedFacts.identity.administrator) {
        Stop-WithCode "ALLOWED_TEST_IDENTITY_NOT_STANDARD"
    }
    $health = Invoke-ChildAsUser $allowed.Name $allowed.Password @("request", "--pipe", $pipeName, "--command", "health") "health"
    $healthObject = $health
    if ($healthObject.status -ne "OK" -or $healthObject.payload.authorization -ne "DISABLED") {
        Stop-WithCode "HEALTH_REQUEST_FAILED"
    }
    $canary = Invoke-ChildAsUser $allowed.Name $allowed.Password @("request", "--pipe", $pipeName, "--command", "canary_status") "canary"
    $canaryObject = $canary
    if ($canaryObject.status -ne "OK" -or $canaryObject.payload.classification -ne "SYNTHETIC_ONLY") {
        Stop-WithCode "CANARY_REQUEST_FAILED"
    }
    $parallel = Invoke-ChildAsUser $allowed.Name $allowed.Password @("parallel-health", "--pipe", $pipeName) "parallel-health"
    if ($parallel.parallel_health_requests -ne 4 -or -not $parallel.all_ok) {
        Stop-WithCode "CONCURRENT_PIPE_TEST_FAILED"
    }
    $pipeAcl = & $runnerPython -I -S -B $probeScript pipe-acl --pipe $pipeName --client-sid $allowed.Sid --service-sid $serviceSid
    if ($LASTEXITCODE -ne 0) {
        Stop-WithCode "LIVE_PIPE_DACL_VERIFICATION_FAILED"
    }
    $rawResult = Invoke-ChildAsUser $allowed.Name $allowed.Password @("raw-tests", "--pipe", $pipeName) "raw-protocol"
    if ($rawResult.invalid_frames -ne "DISCONNECTED" -or $rawResult.disabled -ne 2) {
        Stop-WithCode "RAW_PROTOCOL_TEST_FAILED"
    }
    Invoke-ChildAsUser $allowed.Name $allowed.Password @("partial-client", "--pipe", $pipeName, "--seconds", "2") "stalled-client" | Out-Null
    Invoke-ChildAsUser $allowed.Name $allowed.Password @("request", "--pipe", $pipeName, "--command", "health") "post-timeout-health" | Out-Null
    $deniedFacts = Invoke-ChildAsUser $denied.Name $denied.Password @("identity") "denied-identity"
    if ($deniedFacts.identity.user_sid -ne $denied.Sid -or $deniedFacts.identity.elevated -or $deniedFacts.identity.administrator) {
        Stop-WithCode "DENIED_TEST_IDENTITY_NOT_STANDARD"
    }
    $deniedPipe = Invoke-ChildAsUser $denied.Name $denied.Password @("denied-request", "--pipe", $pipeName, "--command", "canary_status") "denied-pipe"
    if ($deniedPipe.denial -ne "PIPE_ACCESS_DENIED") {
        Stop-WithCode "DISALLOWED_CLIENT_NOT_DENIED"
    }
    $storageProbe = Invoke-ChildAsUser $allowed.Name $allowed.Password @("probe-storage") "storage-access"
    if ($storageProbe.storage_denials -ne "ACCESS_DENIED" -or $storageProbe.service_config_change -ne "ACCESS_DENIED") {
        Stop-WithCode "UNPRIVILEGED_STORAGE_DENIAL_FAILED"
    }
    $afterProbeHashes = Get-CriticalHashes
    foreach ($label in $beforeHashes.Keys) {
        if ($beforeHashes[$label] -ne $afterProbeHashes[$label]) {
            Stop-WithCode "UNAUTHORIZED_PROTECTED_STATE_MUTATION"
        }
    }
    if ($beforeHashes.canary_database -ne $afterProbeHashes.canary_database) {
        Stop-WithCode "UNAUTHORIZED_CANARY_MUTATION"
    }

    # Graceful stop/restart, then kill during a bounded incomplete request and
    # verify the synthetic database remains readable after recovery.
    Invoke-Sc @("stop", $serviceName) "SERVICE_STOP_FAILED" | Out-Null
    Wait-ServiceStatus "Stopped" 10 | Out-Null
    Invoke-Sc @("start", $serviceName) "SERVICE_RESTART_FAILED" | Out-Null
    Wait-ServiceStatus "Running" 15 | Out-Null
    $afterRestart = Invoke-ChildAsUser $allowed.Name $allowed.Password @("request", "--pipe", $pipeName, "--command", "canary_status") "restart-canary"
    if ($afterRestart.payload.state -ne "PRESENT") {
        Stop-WithCode "CANARY_RESTART_CHECK_FAILED"
    }

    $crashOut = Join-Path $env:RUNNER_TEMP ("sgb2-crash-" + [guid]::NewGuid().ToString("N") + ".out")
    $crashErr = Join-Path $env:RUNNER_TEMP ("sgb2-crash-" + [guid]::NewGuid().ToString("N") + ".err")
    $tempFiles.Add($crashOut)
    $tempFiles.Add($crashErr)
    $partialArgs = @("-I", "-S", "-B", $clientProbeScript, "partial-client", "--pipe", $pipeName)
    $partialLine = ($partialArgs | ForEach-Object { Quote-WinArg $_ }) -join " "
    $partialCred = [System.Management.Automation.PSCredential]::new(
        "$env:COMPUTERNAME\$($allowed.Name)", $allowed.Password
    )
    $partialProcess = Start-Process -FilePath $clientPython -ArgumentList $partialLine -Credential $partialCred -LoadUserProfile -WindowStyle Hidden -RedirectStandardOutput $crashOut -RedirectStandardError $crashErr -PassThru
    $processes.Add($partialProcess)
    $partialDeadline = [DateTime]::UtcNow.AddSeconds(8)
    do {
        Start-Sleep -Milliseconds 100
        $partialReady = (Test-Path -LiteralPath $crashOut) -and (Get-Content -LiteralPath $crashOut -Raw) -match '"partial_request_open":true'
    } while (-not $partialReady -and [DateTime]::UtcNow -lt $partialDeadline -and -not $partialProcess.HasExited)
    if (-not $partialReady) {
        Stop-WithCode "PARTIAL_REQUEST_PROBE_FAILED"
    }
    $runningPid = Get-ServicePid
    Stop-Process -Id $runningPid -Force
    Wait-ServiceStatus "Stopped" 10 | Out-Null
    if (-not $partialProcess.HasExited) {
        Stop-Process -Id $partialProcess.Id -Force -ErrorAction SilentlyContinue
    }
    Invoke-Sc @("start", $serviceName) "SERVICE_CRASH_RECOVERY_START_FAILED" | Out-Null
    Wait-ServiceStatus "Running" 15 | Out-Null
    $postCrash = Invoke-ChildAsUser $allowed.Name $allowed.Password @("request", "--pipe", $pipeName, "--command", "canary_status") "crash-recovery"
    if ($postCrash.payload.state -ne "PRESENT") {
        Stop-WithCode "CANARY_CRASH_RECOVERY_FAILED"
    }
    Invoke-ChildAsUser $allowed.Name $allowed.Password @("raw-tests", "--pipe", $pipeName) "restart-malformed-ipc" | Out-Null
    Invoke-ChildAsUser $allowed.Name $allowed.Password @("request", "--pipe", $pipeName, "--command", "health") "post-malformed-health" | Out-Null
    $finalHashes = Get-CriticalHashes
    foreach ($label in $beforeHashes.Keys) {
        if ($beforeHashes[$label] -ne $finalHashes[$label]) {
            Stop-WithCode "CANARY_CHANGED_DURING_LAB"
        }
    }
    if ($beforeHashes.canary_database -ne $finalHashes.canary_database) {
        Stop-WithCode "CANARY_CHANGED_DURING_LAB"
    }

    Invoke-Sc @("stop", $serviceName) "SERVICE_FINAL_STOP_FAILED" | Out-Null
    Wait-ServiceStatus "Stopped" 10 | Out-Null
    Invoke-Sc @("delete", $serviceName) "SERVICE_REMOVE_FAILED" | Out-Null
    $serviceCreated = $false
}
catch {
    $message = $_.Exception.Message
    if ($message -match '^[A-Z0-9_]{1,64}$') {
        $failureCode = $message
    }
    else {
        $failureCode = "EPHEMERAL_LAB_FAILED"
    }
}
finally {
    foreach ($process in $processes) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            if (-not $process.WaitForExit(5000)) {
                $cleanupFailure = $true
            }
        }
    }
    if ($serviceCreated) {
        & "$env:SystemRoot\System32\sc.exe" stop $serviceName 2>&1 | Out-Null
        $stopDeadline = [DateTime]::UtcNow.AddSeconds(8)
        do {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($null -eq $service -or $service.Status -eq "Stopped") { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $stopDeadline)
        if ($null -ne $service -and $service.Status -ne "Stopped") {
            $serviceRow = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
            if ($null -ne $serviceRow -and [uint32]$serviceRow.ProcessId -gt 0) {
                Stop-Process -Id ([int]$serviceRow.ProcessId) -Force -ErrorAction SilentlyContinue
            }
            $cleanupFailure = $true
        }
        & "$env:SystemRoot\System32\sc.exe" delete $serviceName 2>&1 | Out-Null
        $deleteDeadline = [DateTime]::UtcNow.AddSeconds(8)
        do {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($null -eq $service) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deleteDeadline)
        if ($null -ne $service) {
            $cleanupFailure = $true
        }
        else {
            $serviceCreated = $false
        }
    }
    foreach ($name in $createdUsers) {
        Remove-LocalUser -Name $name -ErrorAction SilentlyContinue | Out-Null
        $sid = $createdUserSids[$name]
        $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'" -ErrorAction SilentlyContinue
        if ($null -ne $profile) {
            $expectedProfile = [IO.Path]::GetFullPath((Join-Path $env:SystemDrive "Users\$name")).TrimEnd('\')
            $actualProfile = [IO.Path]::GetFullPath([string]$profile.LocalPath).TrimEnd('\')
            if ($profile.Special -or $profile.Loaded -or $actualProfile -ine $expectedProfile) {
                $cleanupFailure = $true
            }
            else {
                Remove-CimInstance -InputObject $profile -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath $actualProfile) {
                    $cleanupFailure = $true
                }
            }
        }
        if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) {
            $cleanupFailure = $true
        }
    }
    foreach ($file in $tempFiles) {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $file) {
            $cleanupFailure = $true
        }
    }
    if ($clientRootCreated -and (Test-Path -LiteralPath $clientRoot)) {
        $clientItem = Get-Item -LiteralPath $clientRoot -Force -ErrorAction SilentlyContinue
        $clientHasReparsePoint = $false
        if ($null -ne $clientItem -and -not ($clientItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            $clientHasReparsePoint = @(Get-ChildItem -LiteralPath $clientRoot -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0
        }
        if ($null -eq $clientItem -or ($clientItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $clientHasReparsePoint) {
            $cleanupFailure = $true
        }
        else {
            Remove-Item -LiteralPath $clientRoot -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $clientRoot) {
                $cleanupFailure = $true
            }
            else {
                $clientRootCreated = $false
            }
        }
    }
    if ($rootCreated -and (Test-Path -LiteralPath $serviceRoot)) {
        $rootItem = Get-Item -LiteralPath $serviceRoot -Force -ErrorAction SilentlyContinue
        $hasReparsePoint = $false
        if ($null -ne $rootItem -and -not ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            $hasReparsePoint = @(Get-ChildItem -LiteralPath $serviceRoot -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0
        }
        if ($serviceCreated -or $null -eq $rootItem -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $hasReparsePoint) {
            $cleanupFailure = $true
        }
        else {
            Remove-Item -LiteralPath $serviceRoot -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $serviceRoot) {
                $cleanupFailure = $true
            }
        }
    }
    if ($null -ne $allowed) { $allowed.Password.Dispose() }
    if ($null -ne $denied) { $denied.Password.Dispose() }
}

if ($null -ne $failureCode) {
    [Console]::Error.WriteLine($failureCode)
    exit 1
}
if ($cleanupFailure) {
    [Console]::Error.WriteLine("GUEST_CLEANUP_INCOMPLETE")
    exit 1
}
Write-Output "GITHUB_WINDOWS_EPHEMERAL_LAB=PASS"
Write-Output "SERVICE_ACCOUNT=NT AUTHORITY\LocalService"
Write-Output "SERVICE_SID_TYPE=RESTRICTED"
Write-Output "SERVICE_SID_ENABLED_AND_RESTRICTING=true"
Write-Output "PIPE_CLIENT_MASK=0x00100083"
Write-Output "PIPE_PRECREATE=SERVICE_FAILED_CLOSED_THEN_STARTED"
Write-Output "UNPRIVILEGED_STORAGE_PROBES=ACCESS_DENIED"
Write-Output "ALLOWED_AND_DENIED_TEST_IDENTITIES=$($allowed.Sid),$($denied.Sid)"
Write-Output "CANARY_SHA256_STABLE=true"
Write-Output "GUEST_SERVICE_USERS_PROFILES_REMOVED=true"
Write-Output "CROSS_SESSION_AND_REMOTE_PEER=UNVERIFIED"
