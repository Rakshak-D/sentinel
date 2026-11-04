from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def test_installed_cli_reads_synthetic_file_outside_checkout(tmp_path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    selected = root / "restart.txt"
    payload = "alpha \U0001f9ed \u65e5\u672c\u8a9e\r\nrepeat repeat".encode()
    selected.write_bytes(payload)
    outside = tmp_path / "outside"
    outside.mkdir()
    excerpt = "\U0001f9ed \u65e5\u672c\u8a9e\r\n".encode()
    start = payload.index(excerpt)
    end = start + len(excerpt)
    command = [
        str(Path(sys.executable).parent / "sentinel.exe"),
        "source",
        "inspect-file",
        "--allow-root",
        str(root),
        "--file",
        str(selected),
        "--start-byte",
        str(start),
        "--end-byte",
        str(end),
        "--format",
        "json",
    ]
    result = subprocess.run(command, cwd=outside, capture_output=True, timeout=30, check=False)

    stdout = result.stdout.decode("utf-8", errors="strict")
    stderr = result.stderr.decode("utf-8", errors="strict")
    assert result.returncode == 0, stderr
    assert stderr == ""
    assert hashlib.sha256(payload).hexdigest() in stdout
    assert str(root) not in stdout
    assert "repeat repeat" not in stdout
    document = json.loads(stdout)
    assert document["citation"]["cited_text"] == "\U0001f9ed \u65e5\u672c\u8a9e\\r\\n"
    assert document["citation"]["text_sha256"] == hashlib.sha256(excerpt).hexdigest()
