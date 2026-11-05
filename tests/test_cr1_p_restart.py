from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from tests.test_cr1_p_batch import _candidate


def test_installed_cli_process_reviews_explicit_files_outside_checkout(tmp_path) -> None:
    root = tmp_path / "allowlisted"
    root.mkdir()
    first = root / "fictional-one.txt"
    second = root / "fictional-two.md"
    first.write_bytes(_candidate("Aster Robotics", "Engineer").encode("utf-8"))
    second.write_bytes(_candidate("Comet Labs", "Analyst").encode("utf-8"))
    before = tuple(hashlib.sha256(path.read_bytes()).hexdigest() for path in (first, second))
    executable = Path(sys.executable).with_name("sentinel.exe")
    assert executable.is_file()
    process = subprocess.run(
        [
            str(executable),
            "source",
            "review-job-alerts",
            "--allow-root",
            str(root),
            "--file",
            str(first),
            "--file",
            str(second),
            "--format",
            "json",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    after = tuple(hashlib.sha256(path.read_bytes()).hexdigest() for path in (first, second))
    assert process.returncode == 0
    assert process.stderr == ""
    document = json.loads(process.stdout)
    assert document["schema_version"] == "sentinel.job-alert-batch-review.v1"
    assert document["selected_file_count"] == 2
    assert document["classification_counts"]["candidate"] == 2
    assert [item["file_ordinal"] for item in document["files"]] == [1, 2]
    assert document["citation_count"] == 4
    assert before == after
    assert str(root) not in process.stdout
    assert first.name not in process.stdout and second.name not in process.stdout
