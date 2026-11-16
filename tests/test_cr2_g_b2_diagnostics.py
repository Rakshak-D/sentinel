from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

_DIAGNOSTICS = Path("tools/cr2_g_b1/lab_diagnostics.psm1").resolve()
_CLEANUP = Path("tools/cr2_g_b1/service_cleanup.psm1").resolve()


def _powershell() -> str:
    executable = shutil.which("pwsh") or shutil.which("powershell")
    assert executable is not None, "PowerShell is required for lab diagnostic tests"
    return executable


def _run_report(body: str) -> dict[str, object]:
    diagnostics_path = str(_DIAGNOSTICS).replace("'", "''")
    cleanup_path = str(_CLEANUP).replace("'", "''")
    command = f"""
$ErrorActionPreference = 'Stop'
Import-Module -Name '{diagnostics_path}' -Force
Import-Module -Name '{cleanup_path}' -Force
{body}
"""
    result = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, f"PowerShell diagnostic test failed: {result.stderr[-1200:]}"
    return json.loads(result.stdout.strip())


def test_preflight_failure_reports_primary_and_cleanup_not_applicable() -> None:
    report = _run_report(
        r"""
$errorRecord = $null
try { throw [System.IO.IOException]::new('synthetic local path: C:\Users\private\secret') }
catch { $errorRecord = $_ }
$primary = New-LabDiagnosticRecord `
  -Phase 'HOST_PREFLIGHT' `
  -ErrorRecord $errorRecord `
  -FallbackCode 'EPHEMERAL_LAB_FAILED' `
  -ScriptPath 'C:\repo\tools\cr2_g_b1\run_ephemeral_lab.ps1'
$cleanup = Invoke-LabCleanupPlan -Operations @()
New-LabRunReport `
  -PrimaryFailure $primary `
  -CleanupResult $cleanup `
  -LabChecksPassed $false |
  ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert report["status"] == "FAILED"
    assert report["scope"] == "EPHEMERAL_GUEST_ONLY"
    assert report["primary_failure"] == {
        "phase": "HOST_PREFLIGHT",
        "code": "EPHEMERAL_LAB_FAILED",
        "category": "IO",
        "line": None,
    }
    assert report["cleanup"]["status"] == "NOT_APPLICABLE"  # type: ignore[index]


def test_primary_failure_and_successful_cleanup_are_both_reported() -> None:
    report = _run_report(
        r"""
$errorRecord = $null
try {
  $exception = [System.InvalidOperationException]::new('private text is not emitted')
  $exception.Data['Sentinel.LabErrorCode.v1'] = 'ACCOUNT_SETUP_REJECTED'
  throw $exception
} catch { $errorRecord = $_ }
$primary = New-LabDiagnosticRecord `
  -Phase 'ACCOUNT_SETUP' `
  -ErrorRecord $errorRecord `
  -FallbackCode 'EPHEMERAL_LAB_FAILED' `
  -ScriptPath 'C:\repo\tools\cr2_g_b1\run_ephemeral_lab.ps1'
$cleaned = [System.Collections.Generic.List[string]]::new()
$operations = @(
  [pscustomobject]@{
    name = 'PROCESS_CLEANUP'
    code = 'PROCESS_CLEANUP_FAILED'
    action = { $cleaned.Add('process') }
  },
  [pscustomobject]@{
    name = 'ACCOUNT_CLEANUP'
    code = 'ACCOUNT_CLEANUP_FAILED'
    action = { $cleaned.Add('account') }
  }
)
$cleanup = Invoke-LabCleanupPlan -Operations $operations
$report = New-LabRunReport -PrimaryFailure $primary -CleanupResult $cleanup -LabChecksPassed $false
if (($cleaned -join ',') -ne 'process,account') { throw 'CLEANUP_ORDER_INVALID' }
$report | ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert report["status"] == "FAILED"
    assert report["primary_failure"]["code"] == "ACCOUNT_SETUP_REJECTED"  # type: ignore[index]
    assert report["cleanup"]["status"] == "COMPLETED"  # type: ignore[index]
    assert report["cleanup"]["steps_completed"] == 2  # type: ignore[index]


def test_primary_and_cleanup_failures_are_both_preserved() -> None:
    report = _run_report(
        r"""
$errorRecord = $null
try {
  $exception = [System.InvalidOperationException]::new('private text is not emitted')
  $exception.Data['Sentinel.LabErrorCode.v1'] = 'IPC_PROBE_FAILED'
  throw $exception
} catch { $errorRecord = $_ }
$primary = New-LabDiagnosticRecord `
  -Phase 'IPC_PROBES' `
  -ErrorRecord $errorRecord `
  -FallbackCode 'EPHEMERAL_LAB_FAILED' `
  -ScriptPath 'C:\repo\tools\cr2_g_b1\run_ephemeral_lab.ps1'
$attempts = [System.Collections.Generic.List[string]]::new()
$operations = @(
  [pscustomobject]@{
    name = 'SERVICE_REMOVAL'
    code = 'SERVICE_REMOVAL_FAILED'
    action = { $attempts.Add('service'); throw 'C:\Users\private\raw cleanup exception' }
  },
  [pscustomobject]@{
    name = 'TEMP_FILE_CLEANUP'
    code = 'TEMP_FILE_CLEANUP_FAILED'
    action = { $attempts.Add('temp') }
  }
)
$cleanup = Invoke-LabCleanupPlan -Operations $operations
if (($attempts -join ',') -ne 'service,temp') { throw 'CLEANUP_DID_NOT_CONTINUE' }
New-LabRunReport `
  -PrimaryFailure $primary `
  -CleanupResult $cleanup `
  -LabChecksPassed $false |
  ConvertTo-Json -Depth 6 -Compress
"""
    )

    serialized = json.dumps(report)
    assert report["status"] == "FAILED"
    assert report["primary_failure"]["code"] == "IPC_PROBE_FAILED"  # type: ignore[index]
    cleanup = report["cleanup"]
    assert cleanup["status"] == "FAILED"  # type: ignore[index]
    assert [item["code"] for item in cleanup["failures"]] == [  # type: ignore[index]
        "SERVICE_REMOVAL_FAILED"
    ]
    assert "C:\\Users\\private" not in serialized
    assert "raw cleanup exception" not in serialized


def test_cleanup_failure_without_primary_failure_fails_the_run() -> None:
    report = _run_report(
        r"""
$operations = @(
  [pscustomobject]@{
    name = 'CLIENT_ROOT_REMOVAL'
    code = 'CLIENT_ROOT_CLEANUP_FAILED'
    action = { throw 'arbitrary path C:\Users\private' }
  }
)
$cleanup = Invoke-LabCleanupPlan -Operations $operations
New-LabRunReport `
  -PrimaryFailure $null `
  -CleanupResult $cleanup `
  -LabChecksPassed $true |
  ConvertTo-Json -Depth 6 -Compress
"""
    )

    assert report["status"] == "FAILED"
    assert report["primary_failure"] is None
    assert report["cleanup"]["status"] == "FAILED"  # type: ignore[index]
    assert report["cleanup"]["failures"][0]["code"] == "CLIENT_ROOT_CLEANUP_FAILED"  # type: ignore[index]


def test_service_removal_poll_failure_never_removes_service_root() -> None:
    report = _run_report(
        r"""
$world = @{ servicePresent = $true; rootRemoved = $false }
$operations = @(
  [pscustomobject]@{
    name = 'SERVICE_REMOVAL'
    code = 'SERVICE_REMOVAL_FAILED'
    action = {
      $serviceOps = @{
        GetState = { param($name) 'STOPPED' }
        Stop = { param($name) throw 'UNEXPECTED_STOP' }
        Delete = { param($name) 'ALREADY_PENDING' }
        Sleep = { param($milliseconds) Start-Sleep -Milliseconds 1 }
      }
      Invoke-LabServiceRemoval `
        -ServiceName 'SentinelCR2GB2Lab' `
        -Operations $serviceOps `
        -TimeoutMilliseconds 15 `
        -PollMilliseconds 1 | Out-Null
    }.GetNewClosure()
  },
  [pscustomobject]@{
    name = 'SERVICE_ROOT_REMOVAL'
    code = 'SERVICE_ROOT_CLEANUP_FAILED'
    action = {
      if ($world.servicePresent) { throw 'service remains pending' }
      $world.rootRemoved = $true
    }.GetNewClosure()
  }
)
$cleanup = Invoke-LabCleanupPlan -Operations $operations
if ($world.rootRemoved) { throw 'SERVICE_ROOT_REMOVED_TOO_EARLY' }
New-LabRunReport `
  -PrimaryFailure $null `
  -CleanupResult $cleanup `
  -LabChecksPassed $true |
  ConvertTo-Json -Depth 6 -Compress
"""
    )

    cleanup = report["cleanup"]
    assert report["status"] == "FAILED"
    assert [item["code"] for item in cleanup["failures"]] == [  # type: ignore[index]
        "SERVICE_REMOVAL_FAILED",
        "SERVICE_ROOT_CLEANUP_FAILED",
    ]


def test_diagnostics_never_echo_arbitrary_exception_text_or_paths() -> None:
    report = _run_report(
        r"""
$errorRecord = $null
try {
  $privateText = 'password=hunter2 path=C:\Users\alice\' + 'AppData\private'
  throw [System.UnauthorizedAccessException]::new($privateText)
}
catch { $errorRecord = $_ }
$primary = New-LabDiagnosticRecord `
  -Phase 'HOST_PREFLIGHT' `
  -ErrorRecord $errorRecord `
  -FallbackCode 'EPHEMERAL_LAB_FAILED' `
  -ScriptPath 'C:\repo\tools\cr2_g_b1\run_ephemeral_lab.ps1'
$cleanup = Invoke-LabCleanupPlan -Operations @()
New-LabRunReport `
  -PrimaryFailure $primary `
  -CleanupResult $cleanup `
  -LabChecksPassed $false |
  ConvertTo-Json -Depth 6 -Compress
"""
    )

    serialized = json.dumps(report)
    assert report["primary_failure"]["category"] == "ACCESS"  # type: ignore[index]
    assert "hunter2" not in serialized
    assert "C:\\Users\\alice" not in serialized
    assert "AppData" not in serialized


def test_success_report_is_limited_to_measured_guest_scope() -> None:
    report = _run_report(
        r"""
$operations = @(
  [pscustomobject]@{
    name = 'SERVICE_REMOVAL'
    code = 'SERVICE_REMOVAL_FAILED'
    action = { 'removed' | Out-Null }
  }
)
$cleanup = Invoke-LabCleanupPlan -Operations $operations
New-LabRunReport `
  -PrimaryFailure $null `
  -CleanupResult $cleanup `
  -LabChecksPassed $true |
  ConvertTo-Json -Depth 6 -Compress
"""
    )

    serialized = json.dumps(report).lower()
    assert report["status"] == "PASS"
    assert report["scope"] == "EPHEMERAL_GUEST_ONLY"
    assert report["production_owner_verification"] == "UNAVAILABLE"
    assert report["authorization_enabled"] is False
    assert "CROSS_SESSION" in report["unverified"]
    assert "REMOTE_PEER" in report["unverified"]
    assert "owner_verified=true" not in serialized
    assert "approved" not in serialized
    assert "grant" not in serialized


def test_current_script_reports_structured_early_failure() -> None:
    script = Path("tools/cr2_g_b1/run_ephemeral_lab.ps1").resolve()
    with tempfile.TemporaryDirectory(prefix="sentinel-gb2-diagnostics-") as temp_dir:
        event_path = Path(temp_dir) / "event.json"
        event_path.write_text("{}", encoding="utf-8")
        result = subprocess.run(
            [
                _powershell(),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(script),
                "-EventPath",
                str(event_path),
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    assert result.returncode != 0
    assert result.stdout == ""
    assert result.stderr.strip().startswith("{"), "failure must be one structured diagnostic object"
    payload = json.loads(result.stderr.strip().splitlines()[-1])
    assert payload["schema_version"] == "sentinel.cr2-g-b2-run-report.v1"
    assert payload["primary_failure"]["phase"] == "EVENT_GUARD"
    assert payload["primary_failure"]["code"] == "GITHUB_WINDOWS_RUNNER_REQUIRED"
    assert payload["cleanup"]["status"] == "NOT_APPLICABLE"


def test_missing_event_parameter_has_bounded_event_guard_failure() -> None:
    script = Path("tools/cr2_g_b1/run_ephemeral_lab.ps1").resolve()
    result = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert result.stderr.strip().startswith("{"), "parameter failures must be structured"
    payload = json.loads(result.stderr.strip().splitlines()[-1])
    assert payload["primary_failure"]["phase"] == "EVENT_GUARD"
    assert payload["primary_failure"]["code"] == "EVENT_FILE_UNAVAILABLE"
    assert payload["cleanup"]["status"] == "NOT_APPLICABLE"


def test_script_tracks_the_fixed_lab_phase_sequence() -> None:
    script = Path("tools/cr2_g_b1/run_ephemeral_lab.ps1").read_text(encoding="utf-8")
    phases = (
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
        "FINAL_CLEANUP",
    )
    for phase in phases:
        assert f'Set-LabPhase "{phase}"' in script
