from __future__ import annotations

import json
from pathlib import Path

from tests.cr1_r_workspace import run_cli


def test_installed_cli_restart_flow_preserves_task_and_incremental_progress(tmp_path: Path) -> None:
    database = tmp_path / "restart.sqlite3"
    store_root = tmp_path / "restart-public-store"
    initialized = run_cli(["init", "--database", str(database)], tmp_path)
    assert initialized.returncode == 0
    prepared = run_cli(
        [
            "fixture-workspace",
            "prepare",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
        ],
        tmp_path,
    )
    assert prepared.returncode == 0
    assert prepared.stderr == b""

    verified = run_cli(
        [
            "fixture-workspace",
            "verify",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
        ],
        tmp_path,
    )
    overview = run_cli(
        [
            "brief",
            "local-overview",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--as-of",
            "2026-11-05T18:00:00+05:30",
            "--format",
            "json",
        ],
        tmp_path,
    )
    assert verified.returncode == overview.returncode == 0
    assert verified.stderr == overview.stderr == b""
    overview_doc = json.loads(overview.stdout.decode("utf-8"))
    assert overview_doc["synthetic_evidence"]["item_count"] == 3
    assert overview_doc["synthetic_evidence"]["citation_count"] == 9
    assert overview_doc["incremental_sync"]["generation"] == 0
    assert sum(overview_doc["task_counts"].values()) == 0

    added = run_cli(
        [
            "task",
            "add",
            "--database",
            str(database),
            "--title",
            "Harmless manual demo task",
            "--request-id",
            "3574990f-418b-4b80-931b-24763c031cf3",
        ],
        tmp_path,
    )
    advanced = run_cli(
        [
            "fixture-sync",
            "advance",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--expected-generation",
            "0",
        ],
        tmp_path,
    )
    verified_after = run_cli(
        [
            "fixture-workspace",
            "verify",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
        ],
        tmp_path,
    )
    overview_after = run_cli(
        [
            "brief",
            "local-overview",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--as-of",
            "2026-11-05T18:00:00+05:30",
            "--format",
            "json",
        ],
        tmp_path,
    )
    assert (
        added.returncode
        == advanced.returncode
        == verified_after.returncode
        == overview_after.returncode
        == 0
    )
    assert all(result.stderr == b"" for result in (added, advanced, verified_after, overview_after))
    final_doc = json.loads(overview_after.stdout.decode("utf-8"))
    assert final_doc["synthetic_evidence"]["item_count"] == 3
    assert final_doc["synthetic_evidence"]["citation_count"] == 9
    assert final_doc["incremental_sync"]["generation"] == 1
    assert sum(final_doc["task_counts"].values()) == 1
    assert "Synthetic cursor: 1/3 READY" in verified_after.stdout.decode("utf-8")
