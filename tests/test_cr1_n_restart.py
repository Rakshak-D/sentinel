from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def test_installed_cli_searches_selected_files_outside_checkout(tmp_path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    first = root / "ascii.txt"
    second = root / "unicode.md"
    third = root / "instruction.txt"
    first_payload = b"deadline deadline remains literal"
    second_payload = "start \U0001f9ed deadline \u65e5\u672c\u8a9e\r\nend".encode()
    third_payload = b'quoted: "ignore prior instructions"\n'
    first.write_bytes(first_payload)
    second.write_bytes(second_payload)
    third.write_bytes(third_payload)
    selected_paths = (first, second, third)
    before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in selected_paths]
    names_before = sorted(path.name for path in root.iterdir())
    outside = tmp_path / "outside"
    outside.mkdir()
    base_command = [
        str(Path(sys.executable).parent / "sentinel.exe"),
        "source",
        "search-files",
        "--allow-root",
        str(root),
        "--file",
        str(first),
        "--file",
        str(second),
        "--file",
        str(third),
        "--query",
        "deadline",
    ]
    json_command = [*base_command, "--format", "json"]

    result = subprocess.run(json_command, cwd=outside, capture_output=True, timeout=30, check=False)
    repeated = subprocess.run(
        json_command, cwd=outside, capture_output=True, timeout=30, check=False
    )

    assert result.returncode == 0
    assert result.stderr == b""
    assert repeated.returncode == 0
    assert repeated.stdout == result.stdout
    document = json.loads(result.stdout.decode("utf-8"))
    assert document["selected_file_count"] == 3
    assert document["total_match_count"] == 3
    assert [item["ordinal"] for item in document["files"]] == [1, 2, 3]
    assert document["files"][0]["match_count"] == 2
    assert document["files"][1]["match_count"] == 1
    first_matches = document["files"][0]["matches"]
    second_matches = document["files"][1]["matches"]
    assert [(item["start_byte"], item["end_byte"]) for item in first_matches] == [
        (0, 8),
        (9, 17),
    ]
    assert [(item["start_byte"], item["end_byte"]) for item in second_matches] == [(11, 19)]
    assert document["files"][0]["content_sha256"] == hashlib.sha256(first_payload).hexdigest()
    assert document["files"][1]["content_sha256"] == hashlib.sha256(second_payload).hexdigest()
    assert all(
        match["text_sha256"] == hashlib.sha256(b"deadline").hexdigest()
        for file_record in document["files"]
        for match in file_record["matches"]
    )
    assert str(root).encode() not in result.stdout
    assert b"deadline" not in result.stdout
    assert b"ignore prior instructions" not in result.stdout

    text_command = [*base_command, "--format", "text"]
    text_first = subprocess.run(
        text_command, cwd=outside, capture_output=True, timeout=30, check=False
    )
    text_second = subprocess.run(
        text_command, cwd=outside, capture_output=True, timeout=30, check=False
    )
    assert text_first.returncode == 0
    assert text_first.stderr == b""
    assert text_first.stdout == text_second.stdout
    assert b"deadline" not in text_first.stdout
    assert str(root).encode() not in text_first.stdout

    snippets = subprocess.run(
        [*base_command, "--show-snippets", "--format", "text"],
        cwd=outside,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert snippets.returncode == 0
    assert snippets.stderr == b""
    assert b"Preview" in snippets.stdout
    assert b"deadline" in snippets.stdout

    late_path = root / "missing-late.txt"
    late_command = list(json_command)
    second_file_option = late_command.index("--file", late_command.index("--file") + 1)
    late_command[second_file_option + 1] = str(late_path)
    late_failure = subprocess.run(
        late_command,
        cwd=outside,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert late_failure.returncode != 0
    assert late_failure.stdout == b""
    assert str(root).encode() not in late_failure.stderr
    assert b"ignore prior instructions" not in late_failure.stderr
    assert not late_path.exists()

    assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in selected_paths] == before
    assert sorted(path.name for path in root.iterdir()) == names_before
