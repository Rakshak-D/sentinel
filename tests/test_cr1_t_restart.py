from __future__ import annotations

import json
import os
import subprocess
import sys


def test_fresh_process_verifies_saved_baseline_detects_edit_and_restoration(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    first = root / "ascii.txt"
    second = root / "unicode.md"
    first.write_bytes(b"repeated phrase repeated phrase\n")
    original_unicode = "emoji 🧭 and Japanese 日本語\r\n".encode()
    second.write_bytes(original_unicode)
    registry = root / "registered-notes.txt"
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    cwd = str(tmp_path)

    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "source",
            "notes-registry",
            "build",
            "--allow-root",
            str(root),
            "--file",
            str(first),
            "--file",
            str(second),
        ],
        cwd=cwd,
        env=env,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert build.returncode == 0, build.stderr.decode("utf-8", errors="replace")
    assert build.stderr == b""
    baseline_bytes = build.stdout
    registry.write_bytes(baseline_bytes)

    command = [
        sys.executable,
        "-m",
        "sentinel.cli",
        "source",
        "notes-registry",
        "verify",
        "--allow-root",
        str(root),
        "--registry",
        str(registry),
        "--format",
        "json",
    ]
    unchanged = subprocess.run(
        command, cwd=cwd, env=env, capture_output=True, timeout=30, check=False
    )
    assert unchanged.returncode == 0
    assert unchanged.stderr == b""
    assert json.loads(unchanged.stdout)["unchanged_count"] == 2

    first.write_bytes(b"repeated phrase repeated phrasE\n")
    changed = subprocess.run(
        command, cwd=cwd, env=env, capture_output=True, timeout=30, check=False
    )
    assert changed.returncode == 1
    assert changed.stderr == b""
    report = json.loads(changed.stdout)
    assert report["changed_count"] == 1
    assert report["entries"][0]["status"] == "CHANGED"
    assert b"repeated phrasE" not in changed.stdout

    first.write_bytes(b"repeated phrase repeated phrase\n")
    restored = subprocess.run(
        command, cwd=cwd, env=env, capture_output=True, timeout=30, check=False
    )
    assert restored.returncode == 0
    assert restored.stderr == b""
    assert json.loads(restored.stdout)["overall_status"] == "UNCHANGED"
    assert registry.read_bytes() == baseline_bytes
