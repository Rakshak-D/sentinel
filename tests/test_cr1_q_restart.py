from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_installed_calendar_fixture_cli_runs_in_a_fresh_process(tmp_path: Path) -> None:
    executable = Path(sys.executable).with_name("sentinel.exe")
    assert executable.is_file()
    result = subprocess.run(
        [str(executable), "source", "calendar-fixture", "--format", "json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=os.environ.copy(),
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert '"event_count":4' in result.stdout
    assert "calendar-fixture-inspection.v1" in result.stdout
