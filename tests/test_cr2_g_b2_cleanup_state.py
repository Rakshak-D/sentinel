from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_MODULE = Path("tools/cr2_g_b1/service_cleanup.psm1").resolve()


def _powershell() -> str:
    executable = shutil.which("pwsh") or shutil.which("powershell")
    assert executable is not None, "PowerShell is required for cleanup state tests"
    return executable


def _run_cleanup_case(body: str) -> None:
    module_path = str(_MODULE).replace("'", "''")
    command = f"""
$ErrorActionPreference = 'Stop'
Import-Module -Name '{module_path}' -Force
{body}
"""
    result = subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, f"PowerShell cleanup test failed: {result.stderr[-1200:]}"


def test_cleanup_requires_stopped_then_confirmed_absence() -> None:
    _run_cleanup_case(
        r"""
$world = @{ State = 'RUNNING'; Calls = [System.Collections.Generic.List[string]]::new() }
$ops = @{
  GetState = { param($name) $world.Calls.Add('query'); $world.State }
  Stop = { param($name) $world.Calls.Add('stop'); $world.State = 'STOPPED' }
  Delete = { param($name) $world.Calls.Add('delete'); $world.State = 'ABSENT'; 'REQUESTED' }
  Sleep = { param($milliseconds) $world.Calls.Add('sleep') }
}
$result = Invoke-LabServiceRemoval `
  -ServiceName 'SentinelCR2GB2Lab' `
  -Operations $ops `
  -TimeoutMilliseconds 200 `
  -PollMilliseconds 1
if ($result -ne 'REMOVED') { throw 'REMOVAL_RESULT_INVALID' }
if (($world.Calls -join ',') -ne 'query,stop,sleep,query,delete,query') {
  throw 'REMOVAL_ORDER_INVALID'
}
"""
    )


def test_cleanup_waits_for_delayed_scm_removal() -> None:
    _run_cleanup_case(
        r"""
$world = @{ State = 'STOPPED'; QueriesAfterDelete = 0; Removed = $false; Sleeps = 0 }
$ops = @{
  GetState = {
    param($name)
    if ($world.Removed) { return 'ABSENT' }
    if ($world.QueriesAfterDelete -gt 0) { $world.QueriesAfterDelete++ }
    if ($world.QueriesAfterDelete -ge 3) { $world.Removed = $true; return 'ABSENT' }
    return $world.State
  }
  Stop = { param($name) throw 'UNEXPECTED_STOP' }
  Delete = { param($name) $world.QueriesAfterDelete = 1; 'REQUESTED' }
  Sleep = { param($milliseconds) $world.Sleeps++ }
}
$serviceCreated = $true
$result = Invoke-LabServiceRemoval `
  -ServiceName 'SentinelCR2GB2Lab' `
  -Operations $ops `
  -TimeoutMilliseconds 500 `
  -PollMilliseconds 1
if ($result -ne 'REMOVED' -or -not $world.Removed -or $world.Sleeps -lt 1) {
  throw 'DELAYED_REMOVAL_NOT_VERIFIED'
}
$serviceCreated = $false
if ($serviceCreated) { throw 'CLEANUP_FLAG_NOT_CLEARED_AFTER_ABSENCE' }
"""
    )


def test_cleanup_treats_already_marked_delete_as_pending_until_absent() -> None:
    _run_cleanup_case(
        r"""
$world = @{ State = 'STOPPED'; QueriesAfterDelete = 0; DeleteCalls = 0; Removed = $false }
$ops = @{
  GetState = {
    param($name)
    if ($world.Removed) { return 'ABSENT' }
    if ($world.QueriesAfterDelete -gt 0) { $world.QueriesAfterDelete++ }
    if ($world.QueriesAfterDelete -ge 3) { $world.Removed = $true; return 'ABSENT' }
    return $world.State
  }
  Stop = { param($name) throw 'UNEXPECTED_STOP' }
  Delete = { param($name) $world.DeleteCalls++; $world.QueriesAfterDelete = 1; 'ALREADY_PENDING' }
  Sleep = { param($milliseconds) }
}
$result = Invoke-LabServiceRemoval `
  -ServiceName 'SentinelCR2GB2Lab' `
  -Operations $ops `
  -TimeoutMilliseconds 500 `
  -PollMilliseconds 1
if ($result -ne 'REMOVED' -or -not $world.Removed -or $world.DeleteCalls -ne 1) {
  throw 'DELETE_PENDING_HANDLED_AS_SUCCESS_TOO_EARLY'
}
"""
    )


def test_cleanup_failure_keeps_removal_responsibility_active() -> None:
    _run_cleanup_case(
        r"""
$world = @{ State = 'STOPPED'; DeleteCalls = 0 }
$ops = @{
  GetState = { param($name) $world.State }
  Stop = { param($name) throw 'UNEXPECTED_STOP' }
  Delete = { param($name) $world.DeleteCalls++; 'ALREADY_PENDING' }
  Sleep = { param($milliseconds) }
}
$serviceCreated = $true
$failure = $null
try {
  $result = Invoke-LabServiceRemoval `
    -ServiceName 'SentinelCR2GB2Lab' `
    -Operations $ops `
    -TimeoutMilliseconds 20 `
    -PollMilliseconds 1
  if ($result -eq 'REMOVED') { $serviceCreated = $false }
}
catch { $failure = $_.Exception.Message }
if ($failure -ne 'SERVICE_REMOVE_TIMEOUT') {
  throw 'PENDING_SERVICE_WAS_NOT_A_FAILURE'
}
if (-not $serviceCreated -or $world.State -ne 'STOPPED' -or $world.DeleteCalls -ne 1) {
  throw 'CLEANUP_RESPONSIBILITY_LOST'
}
"""
    )


def test_cleanup_delete_api_failure_keeps_responsibility_active() -> None:
    _run_cleanup_case(
        r"""
$world = @{ State = 'STOPPED' }
$ops = @{
  GetState = { param($name) $world.State }
  Stop = { param($name) throw 'UNEXPECTED_STOP' }
  Delete = { param($name) throw 'SCM_DELETE_DENIED' }
  Sleep = { param($milliseconds) }
}
$serviceCreated = $true
$failure = $null
try {
  $result = Invoke-LabServiceRemoval `
    -ServiceName 'SentinelCR2GB2Lab' `
    -Operations $ops `
    -TimeoutMilliseconds 20 `
    -PollMilliseconds 1
  if ($result -eq 'REMOVED') { $serviceCreated = $false }
}
catch { $failure = $_.Exception.Message }
if ($failure -ne 'SERVICE_DELETE_FAILED') { throw 'DELETE_FAILURE_NOT_BOUNDED' }
if (-not $serviceCreated) { throw 'CLEANUP_FLAG_CLEARED_AFTER_DELETE_ERROR' }
"""
    )


@pytest.mark.parametrize("service_name", ["OtherService", "SentinelCR2GB2Lab;sc delete Other"])
def test_cleanup_rejects_nonfixed_service_identity(service_name: str) -> None:
    escaped = service_name.replace("'", "''")
    _run_cleanup_case(
        f"""
$ops = @{{
  GetState = {{ param($name) 'ABSENT' }}
  Stop = {{ param($name) }}
  Delete = {{ param($name) 'REQUESTED' }}
  Sleep = {{ param($milliseconds) }}
}}
$failed = $false
try {{ Invoke-LabServiceRemoval -ServiceName '{escaped}' -Operations $ops }}
catch {{ $failed = $_.Exception.Message -eq 'SERVICE_NAME_INVALID' }}
if (-not $failed) {{ throw 'UNTRUSTED_SERVICE_NAME_ACCEPTED' }}
"""
    )
