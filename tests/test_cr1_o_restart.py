from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_installed_cli_process_parses_disposable_file_outside_checkout(tmp_path) -> None:
    root = tmp_path / "allow"
    root.mkdir()
    path = root / "alert.txt"
    body = "Company: 🚀 Comet\r\nRole: 日本語テスト担当\r\nDeadline: 2027-09-30\r\n"
    raw = body.encode("utf-8")
    path.write_bytes(raw)
    work = tmp_path / "outside-checkout"
    work.mkdir()
    command = Path(sys.executable).with_name("sentinel.exe")
    result = subprocess.run(
        [
            str(command),
            "source",
            "parse-job-alert",
            "--allow-root",
            str(root),
            "--file",
            str(path),
            "--format",
            "json",
        ],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
        check=False,
        env={**os.environ, "PYTHONUTF8": "1"},
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    document = json.loads(result.stdout)
    assert document["schema_version"] == "sentinel.job-alert-extraction.v1"
    assert document["extraction_status"] == "CANDIDATE"
    assert document["byte_length"] == len(raw)
    assert document["content_sha256"]
    assert document["values_included"] is False
    assert str(root) not in result.stdout and str(path) not in result.stdout
    assert path.read_bytes() == raw


def test_installed_cli_failure_has_empty_stdout_and_bounded_stderr(tmp_path) -> None:
    root = tmp_path / "allow"
    root.mkdir()
    path = root / "bad.txt"
    path.write_bytes(b"PRIVATE_CANARY\xff")
    work = tmp_path / "outside-checkout"
    work.mkdir()
    command = Path(sys.executable).with_name("sentinel.exe")
    result = subprocess.run(
        [str(command), "source", "parse-job-alert", "--allow-root", str(root), "--file", str(path)],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
        check=False,
    )
    assert result.returncode != 0
    assert result.stdout == ""
    assert len(result.stderr) < 300
    assert str(path) not in result.stderr and "PRIVATE_CANARY" not in result.stderr
    assert "Traceback" not in result.stderr
