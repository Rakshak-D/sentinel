from __future__ import annotations

import json
import os
import subprocess
import sys


def test_installed_cli_process_restarts_with_deterministic_typed_signals(tmp_path) -> None:
    root = tmp_path / "alerts"
    root.mkdir()
    first = root / "one.txt"
    second = root / "two.md"
    first.write_bytes(b"Company: Aster Sample\r\nRole: Analyst\r\n")
    second.write_bytes(
        "Company: 桜の研究所 🚀\nRole: 東京の技師\n"
        "Apply URL: https://jobs.sakura.example.test/r\n".encode()
    )
    command = [
        sys.executable,
        "-m",
        "sentinel.cli",
        "source",
        "triage-job-alerts",
        "--allow-root",
        str(root),
        "--file",
        str(first),
        "--file",
        str(second),
        "--format",
        "json",
    ]
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    first_run = subprocess.run(
        command, cwd=tmp_path, env=env, capture_output=True, timeout=45, check=False
    )
    second_run = subprocess.run(
        command, cwd=tmp_path, env=env, capture_output=True, timeout=45, check=False
    )

    assert first_run.returncode == second_run.returncode == 0
    assert first_run.stderr == second_run.stderr == b""
    assert first_run.stdout == second_run.stdout
    output = json.loads(first_run.stdout)
    assert output["selected_file_count"] == 2
    assert len(output["signals"]) == 3
    assert output["values_included"] is False
