"""Behavioral contract tests for explicit synthetic workspace preparation."""

import sqlite3
from pathlib import Path

from sentinel.bootstrap.init import initialize_new_database
from sentinel.workspace import (
    FixtureWorkspacePrepareDisposition,
    FixtureWorkspaceStatus,
    prepare_fixture_workspace,
    verify_fixture_workspace,
)


def test_fresh_current_database_prepares_complete_workspace(tmp_path: Path) -> None:
    database = tmp_path / "sentinel.sqlite3"
    store_root = tmp_path / "public-store"
    initialize_new_database(database)

    report = prepare_fixture_workspace(database, store_root=store_root)
    state = verify_fixture_workspace(database, store_root=store_root)

    assert report.disposition is FixtureWorkspacePrepareDisposition.PREPARED
    assert report.state.status is FixtureWorkspaceStatus.READY
    assert state.state.status is FixtureWorkspaceStatus.READY
    assert (state.state.github_items, state.state.github_citations, state.state.public_blobs) == (
        3,
        9,
        3,
    )
    assert state.state.task_operator_ready is True
    assert state.state.task_count == 0
    assert state.state.cursor_generation == 0
    assert state.state.cursor_status == "READY"
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM source_items").fetchone() == (3,)
        assert connection.execute("SELECT COUNT(*) FROM source_spans").fetchone() == (9,)
        assert connection.execute("SELECT COUNT(*) FROM sync_cursors").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM action_proposals").fetchone() == (0,)
