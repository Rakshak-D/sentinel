"""Crash recovery at the workspace's independently committed stages."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from sentinel.ingestion.blob_readback import read_blob_backed_github_fixture
from sentinel.ingestion.github_fixture import (
    FIXTURE_REGISTRY_SOURCE_ID,
    read_persisted_github_fixture,
)
from sentinel.sync import read_incremental_github_fixture_state
from sentinel.workspace import (
    FixtureWorkspaceStatus,
    prepare_fixture_workspace,
    verify_fixture_workspace,
)
from tests.cr1_r_workspace import new_database

_CHILD = r"""
import os
import sys
from sentinel.workspace import fixture_prepare as prepare
from sentinel.content import public_fixture_store as store
from sentinel.ingestion import blob_promotion as promotion

stage, database, root = sys.argv[1:]
die = lambda: os._exit(73)

if stage == "A":
    prepare.initialize_public_fixture_store = lambda selected: die()
elif stage == "B":
    original = prepare.initialize_public_fixture_store
    def stop_after_init(selected):
        original(selected)
        die()
    prepare.initialize_public_fixture_store = stop_after_init
elif stage == "C":
    original = store._store_one
    counter = 0
    def stop_after_first_blob(*args, **kwargs):
        global counter
        result = original(*args, **kwargs)
        counter += 1
        if counter == 1:
            die()
        return result
    store._store_one = stop_after_first_blob
elif stage == "D":
    original = prepare.store_packaged_github_public_bodies
    def stop_after_all_blobs(selected):
        original(selected)
        die()
    prepare.store_packaged_github_public_bodies = stop_after_all_blobs
elif stage == "E":
    original = prepare.ingest_packaged_github_fixture
    def stop_after_ingestion(selected):
        original(selected)
        die()
    prepare.ingest_packaged_github_fixture = stop_after_ingestion
elif stage == "F":
    original = promotion._update_content_reference
    def stop_before_promotion_commit(*args, **kwargs):
        global counter
        original(*args, **kwargs)
        counter += 1
        if counter == 3:
            die()
    counter = 0
    promotion._update_content_reference = stop_before_promotion_commit
elif stage == "G":
    original = prepare.promote_github_fixture_to_public_blobs
    def stop_after_promotion(selected, *, store_root):
        original(selected, store_root=store_root)
        die()
    prepare.promote_github_fixture_to_public_blobs = stop_after_promotion
elif stage == "H":
    original = prepare.setup_local_task_operator
    def stop_after_operator(selected):
        original(selected)
        die()
    prepare.setup_local_task_operator = stop_after_operator
elif stage == "I":
    original = prepare.setup_incremental_github_fixture
    def stop_after_cursor(selected, *, store_root):
        original(selected, store_root=store_root)
        die()
    prepare.setup_incremental_github_fixture = stop_after_cursor

if stage == "J":
    prepare.prepare_fixture_workspace(database, store_root=root)
    die()
prepare.prepare_fixture_workspace(database, store_root=root)
raise SystemExit("crash hook was not reached")
"""


@pytest.mark.parametrize("stage", tuple("ABCDEFGHIJ"))
def test_independent_process_crash_stages_recover_without_duplicate_data(
    tmp_path: Path, stage: str
) -> None:
    database, store_root = new_database(tmp_path, f"crash-{stage}")
    unrelated_principal_id = "5b4be6dc-a5bc-5da1-a5bb-c670275f4492"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """INSERT INTO principals
               (principal_id, kind, display_name, os_binding, created_at, revoked_at)
               VALUES (?, ?, ?, ?, ?, NULL)""",
            (
                unrelated_principal_id,
                "unrelated-synthetic-test",
                "Unrelated synthetic principal",
                "test-only",
                "2026-11-05T00:00:00+00:00",
            ),
        )
    with sqlite3.connect(database) as connection:
        unrelated_before = connection.execute(
            "SELECT * FROM principals WHERE principal_id = ?", (unrelated_principal_id,)
        ).fetchone()
    child = subprocess.run(
        [sys.executable, "-c", _CHILD, stage, str(database), str(store_root)],
        cwd=tmp_path,
        capture_output=True,
        timeout=60,
        check=False,
        env=os.environ.copy(),
    )
    assert child.returncode == 73, child.stderr.decode("utf-8", errors="replace")

    verification = verify_fixture_workspace(database, store_root=store_root)
    if stage in {"I", "J"}:
        assert verification.state.status is FixtureWorkspaceStatus.READY
    else:
        assert verification.state.status is FixtureWorkspaceStatus.INCOMPLETE

    if stage == "F":
        # The child died after the third reference UPDATE but before COMMIT.
        # All old fixture references and their complete source state survive.
        assert len(read_persisted_github_fixture(database).items) == 3
        with sqlite3.connect(database) as connection:
            references = connection.execute(
                "SELECT content_ref FROM source_items WHERE source_id = ?",
                (str(FIXTURE_REGISTRY_SOURCE_ID),),
            ).fetchall()
        assert len(references) == 3
        assert all(
            not reference[0].startswith("sentinel-public-blob-v1:")
            for reference in references
        )

    report = prepare_fixture_workspace(database, store_root=store_root)
    assert report.state.status is FixtureWorkspaceStatus.READY
    assert (report.state.github_items, report.state.github_citations) == (3, 9)
    assert report.state.cursor_generation == 0
    assert len(read_blob_backed_github_fixture(database, store_root=store_root).items) == 3
    assert read_incremental_github_fixture_state(database, store_root=store_root).item_count == 0
    with sqlite3.connect(database) as connection:
        unrelated_after = connection.execute(
            "SELECT * FROM principals WHERE principal_id = ?", (unrelated_principal_id,)
        ).fetchone()
    assert unrelated_after == unrelated_before
