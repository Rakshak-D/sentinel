import hashlib
from pathlib import Path

from sentinel.workspace import (
    FixtureWorkspaceStatus,
    verify_fixture_workspace,
)
from tests.cr1_r_workspace import new_database, table_rows


def test_verify_on_unprepared_database_is_read_only_incomplete(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "verify-incomplete")
    before = {
        table: table_rows(database, table)
        for table in (
            "principals",
            "sources",
            "sync_cursors",
            "source_items",
            "source_spans",
            "tasks",
            "task_creation_requests",
            "action_proposals",
        )
    }

    result = verify_fixture_workspace(database, store_root=store_root)

    after = {table: table_rows(database, table) for table in before}
    assert result.state.status is FixtureWorkspaceStatus.INCOMPLETE
    assert result.state.github_items == 0
    assert result.state.cursor_generation is None
    assert before == after
    assert not store_root.exists()


def test_verify_ready_state_and_overview_precondition(tmp_path: Path) -> None:
    from sentinel.workspace import prepare_fixture_workspace

    database, store_root = new_database(tmp_path, "verify-ready")
    prepared = prepare_fixture_workspace(database, store_root=store_root)
    result = verify_fixture_workspace(database, store_root=store_root)

    assert result.state == prepared.state
    assert result.state.status is FixtureWorkspaceStatus.READY
    assert result.state.cursor_generation == 0
    assert result.state.task_count == 0


def test_readonly_verification_preserves_rows_and_blob_files(tmp_path: Path) -> None:
    from sentinel.workspace import prepare_fixture_workspace

    database, store_root = new_database(tmp_path, "verify-no-write")
    prepare_fixture_workspace(database, store_root=store_root)
    tables = (
        "tasks",
        "task_creation_requests",
        "source_items",
        "source_spans",
        "sync_cursors",
        "action_proposals",
    )
    before_rows = {table: table_rows(database, table) for table in tables}
    blob_paths = tuple(sorted(path for path in store_root.rglob("*") if path.is_file()))
    before_blobs = {
        path.relative_to(store_root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in blob_paths
    }

    result = verify_fixture_workspace(database, store_root=store_root)

    after_rows = {table: table_rows(database, table) for table in tables}
    after_blobs = {
        path.relative_to(store_root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(path for path in store_root.rglob("*") if path.is_file())
    }
    assert result.state.status is FixtureWorkspaceStatus.READY
    assert before_rows == after_rows
    assert before_blobs == after_blobs
