"""Static preflight contracts; never invoke the privileged service laboratory.

D2 hosted observations establish hidden-parent behavior on the tested runner.
These tests pin source-level denial behavior only; they are not OS isolation
or access-control tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

RUNNER = Path(__file__).resolve().parents[1] / "tools/cr2_g_b1/run_ephemeral_lab.ps1"
EXPECTED_GUARD = (
    "    $resolvedRoot = [IO.Path]::GetFullPath($serviceRoot)\n"
    "    if ($resolvedRoot -ne $serviceRoot -or "
    "(Get-Item -LiteralPath (Split-Path $serviceRoot -Parent) "
    "-Force -ErrorAction Stop).Attributes -band "
    "[IO.FileAttributes]::ReparsePoint) {\n"
    '        Stop-WithCode "LAB_ROOT_PATH_INVALID"\n'
    "    }"
)


def _guard_from_source(source: str) -> str:
    start = source.index("    $resolvedRoot = [IO.Path]::GetFullPath($serviceRoot)")
    end = source.index("    $runnerPython =", start)
    return source[start:end].strip("\n")


def test_hidden_parent_metadata_query_remains_fail_closed() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    guard = _guard_from_source(source)
    assert guard == EXPECTED_GUARD
    assert source.count(EXPECTED_GUARD) == 1
    assert '$ErrorActionPreference = "Stop"' in source


@pytest.mark.parametrize(
    "old,new",
    [
        (" -Force -ErrorAction Stop", ""),
        (" -Force -ErrorAction Stop", " -Force -ErrorAction SilentlyContinue"),
        (" -Force -ErrorAction Stop", " -ErrorAction Stop"),
        ("Get-Item -LiteralPath", "Get-Item -Path"),
        ("[IO.FileAttributes]::ReparsePoint", "[IO.FileAttributes]::Hidden"),
        ('Stop-WithCode "LAB_ROOT_PATH_INVALID"', 'Write-Output "LAB_ROOT_PATH_INVALID"'),
        ("$resolvedRoot -ne $serviceRoot -or ", ""),
    ],
)
def test_preflight_guard_regression_mutations_are_rejected(old: str, new: str) -> None:
    weakened = EXPECTED_GUARD.replace(old, new, 1)
    assert weakened != EXPECTED_GUARD
    assert weakened != _guard_from_source(RUNNER.read_text(encoding="utf-8"))


def test_preflight_still_precedes_all_mutating_phases() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert source.index('Set-LabPhase "EVENT_GUARD"') < source.index(
        'Set-LabPhase "HOST_PREFLIGHT"'
    ) < source.index('Set-LabPhase "ACCOUNT_SETUP"')
    assert '$event.pull_request.head.ref -ne $requiredBranch' in source
    assert '$event.pull_request.base.ref -ne "main"' in source
    assert 'Stop-WithCode "PULL_REQUEST_EVENT_NOT_ALLOWLISTED"' in source
