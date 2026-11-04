from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from sentinel.tasks import complete_local_task
from tests.cr1_l_support import AS_OF, add_task, overview_case, persisted_state


def _sentinel_executable() -> Path:
    return Path(sys.executable).parent / "sentinel.exe"


def _run_cli(database: Path, store_root: Path, cwd: Path, output_format: str = "text"):
    return subprocess.run(
        [
            str(_sentinel_executable()),
            "brief",
            "local-overview",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--as-of",
            AS_OF.isoformat(),
            "--format",
            output_format,
        ],
        cwd=cwd,
        capture_output=True,
        timeout=45,
        check=False,
        env=os.environ.copy(),
    )


def test_installed_cli_restarts_outside_checkout_with_deterministic_output(tmp_path) -> None:
    database, store_root = overview_case(tmp_path, name="installed-process", generation=2)
    overdue = add_task(
        database,
        key="process-overdue",
        title="Overdue manual task",
        due_at=datetime.fromisoformat("2026-11-04T18:29:59Z"),
    )
    add_task(
        database,
        key="process-today",
        title="Due today manual task",
        due_at=datetime.fromisoformat("2026-11-04T01:30:00Z"),
    )
    add_task(
        database,
        key="process-upcoming",
        title="Upcoming manual task",
        due_at=datetime.fromisoformat("2026-11-04T18:30:00Z"),
    )
    add_task(
        database,
        key="process-further-upcoming",
        title="Further upcoming manual task",
        due_at=datetime.fromisoformat("2026-11-07T12:00:00Z"),
    )
    add_task(database, key="process-undated", title="Undated manual task 🧭")
    complete_local_task(database, task_id=overdue.task_id, expected_revision=overdue.revision)
    before = persisted_state(database, store_root)
    text_first = _run_cli(database, store_root, tmp_path)
    text_second = _run_cli(database, store_root, tmp_path)
    json_result = _run_cli(database, store_root, tmp_path, "json")

    assert text_first.returncode == text_second.returncode == json_result.returncode == 0
    assert text_first.stderr == text_second.stderr == json_result.stderr == b""
    assert text_first.stdout == text_second.stdout
    text = text_first.stdout.decode("utf-8", errors="strict")
    document = json.loads(json_result.stdout.decode("utf-8", errors="strict"))
    assert "Manually entered local tasks: 5" in text
    assert "Items: 3 | Verified citations: 9" in text
    assert "Generation: 2; pages: 2/3" in text
    assert document["synthetic_evidence"]["item_count"] == 3
    assert document["synthetic_evidence"]["citation_count"] == 9
    assert document["incremental_sync"]["generation"] == 2
    assert document["incremental_sync"]["item_count"] == 2
    assert document["task_counts"] == {
        "COMPLETED": 1,
        "DUE_TODAY": 1,
        "NO_DUE_DATE": 1,
        "OVERDUE": 0,
        "UPCOMING": 2,
    }
    task_titles = {
        task["title"]
        for section in document["task_sections"]
        for task in section["tasks"]
    }
    assert task_titles == {
        "Overdue manual task",
        "Due today manual task",
        "Upcoming manual task",
        "Further upcoming manual task",
        "Undated manual task 🧭",
    }
    assert str(database).encode() not in text_first.stdout
    assert str(store_root).encode() not in json_result.stdout
    assert persisted_state(database, store_root) == before


def test_fresh_process_cli_does_not_depend_on_packaged_github_json_fixture(tmp_path) -> None:
    database, store_root = overview_case(tmp_path, name="fixture-disabled", generation=0)
    code = (
        "import sentinel.readers.github_fixture as reader; "
        "reader.read_packaged_github_fixture = lambda *a, **k: (_ for _ in ()).throw("
        "AssertionError('fixture loader called')); "
        "from typer.testing import CliRunner; from sentinel.cli import app; "
        f"r=CliRunner().invoke(app, ['brief','local-overview','--database',r'{database}',"
        f"'--store-root',r'{store_root}','--as-of','{AS_OF.isoformat()}']); "
        "import sys; sys.stdout.buffer.write(f'{r.exit_code}\\n'.encode() + r.stdout.encode()); "
        "sys.stderr.buffer.write(r.stderr.encode())"
    )
    process = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        capture_output=True,
        timeout=45,
        check=False,
        env=os.environ.copy(),
    )

    assert process.returncode == 0
    assert process.stderr == b""
    output = process.stdout.decode("utf-8", errors="strict")
    assert output.startswith("0\nSentinel - Local overview\n")
    assert "Items: 3 | Verified citations: 9" in output


def test_fresh_process_missing_blob_fails_without_partial_output(tmp_path) -> None:
    database, store_root = overview_case(tmp_path, name="process-missing-blob")
    next(store_root.rglob("*.blob")).unlink()
    process = _run_cli(database, store_root, tmp_path, "json")

    assert process.returncode != 0
    assert process.stdout == b""
    assert len(process.stderr) < 250
    assert b"Traceback" not in process.stderr
    assert str(database).encode() not in process.stderr
    assert str(store_root).encode() not in process.stderr
