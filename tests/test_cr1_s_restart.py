from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_installed_cli_source_status_is_stable_across_processes(tmp_path: Path) -> None:
    executable = Path(sys.executable).parent / "sentinel.exe"
    first = subprocess.run(
        [str(executable), "source", "status", "--format", "json"],
        cwd=tmp_path,
        capture_output=True,
        timeout=30,
        check=False,
    )
    second = subprocess.run(
        [str(executable), "source", "status", "--format", "json"],
        cwd=tmp_path,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == b""
    assert first.stdout == second.stdout
    report = json.loads(first.stdout.decode("utf-8", errors="strict"))
    assert report["schema_version"] == "sentinel.source-capability-status.v1"
    assert report["validation"] == "VALID"
    assert len(report["capabilities"]) == 14
