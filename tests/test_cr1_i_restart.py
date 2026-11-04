from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.cr1_h1_support import blob_files, item_rows, span_rows
from tests.test_cr1_i_support import promoted_case

_CHILD_CLI = r"""
import sentinel.readers.github_fixture as fixture_reader
def forbidden_fixture_read():
    raise AssertionError("packaged fixture loader was used")
fixture_reader.read_packaged_github_fixture = forbidden_fixture_read
from sentinel.cli import app
app()
"""


def _invoke_child(database: Path, store_root: Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            _CHILD_CLI,
            "brief",
            "github-fixture",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--format",
            "json",
        ],
        cwd=cwd,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=25,
        check=False,
    )


def test_fresh_process_cli_reads_without_fixture_and_does_not_write(tmp_path: Path) -> None:
    database, store_root = promoted_case(tmp_path, name="cli-restart")
    before_items = item_rows(database)
    before_spans = span_rows(database)
    before_blobs = {path: path.read_bytes() for path in blob_files(store_root)}

    first = _invoke_child(database, store_root, tmp_path)
    second = _invoke_child(database, store_root, tmp_path)

    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == ""
    assert first.stdout == second.stdout
    document = json.loads(first.stdout)
    assert document["item_count"] == 3 and document["citation_count"] == 9
    assert item_rows(database) == before_items
    assert span_rows(database) == before_spans
    assert {path: path.read_bytes() for path in blob_files(store_root)} == before_blobs


def test_fresh_process_missing_blob_fails_without_stdout_or_fixture_fallback(
    tmp_path: Path,
) -> None:
    database, store_root = promoted_case(tmp_path, name="cli-missing-blob")
    blob_files(store_root)[0].unlink()

    result = _invoke_child(database, store_root, tmp_path)

    assert result.returncode != 0
    assert result.stdout == ""
    assert result.stderr == "Brief failed: verified synthetic evidence is unavailable.\n"
    assert str(database) not in result.stderr and str(store_root) not in result.stderr
