import hashlib
from pathlib import Path
from uuid import UUID

from sentinel.ingestion.blob_readback import read_blob_backed_github_fixture
from sentinel.sync import advance_incremental_github_fixture, read_incremental_github_fixture_state
from sentinel.tasks import create_local_task, edit_local_task, list_local_tasks
from sentinel.workspace import (
    FixtureWorkspacePrepareDisposition,
    fixture_prepare,
    prepare_fixture_workspace,
)
from tests.cr1_r_workspace import new_database, table_rows


def test_repeat_preserves_existing_manual_task_and_cursor_progress(
    tmp_path: Path, monkeypatch
) -> None:
    database, store_root = new_database(tmp_path, "repeat")
    prepare_fixture_workspace(database, store_root=store_root)
    created = create_local_task(
        database,
        request_id=UUID("3e11ab59-63a2-4dbb-8f09-249cc9095bb6"),
        title="Manual fictional task",
    )
    edited = edit_local_task(
        database,
        task_id=created.task.task_id,
        expected_revision=1,
        title="Edited fictional task",
    )
    for generation in range(3):
        advance_incremental_github_fixture(
            database,
            store_root=store_root,
            expected_generation=generation,
        )

    tasks_before = list_local_tasks(database)
    h1_before = read_blob_backed_github_fixture(database, store_root=store_root)
    cursor_before = read_incremental_github_fixture_state(database, store_root=store_root)
    persistent_rows = {
        table: table_rows(database, table)
        for table in (
            "sources",
            "source_items",
            "source_spans",
            "sync_cursors",
            "tasks",
            "task_creation_requests",
            "action_proposals",
        )
    }
    blob_hashes = {
        path.relative_to(store_root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in store_root.rglob("*")
        if path.is_file()
    }

    def forbidden(*_args, **_kwargs):
        raise AssertionError("a fully prepared repeat must not run setup mutations")

    monkeypatch.setattr(fixture_prepare, "ingest_packaged_github_fixture", forbidden)
    monkeypatch.setattr(fixture_prepare, "initialize_public_fixture_store", forbidden)
    monkeypatch.setattr(fixture_prepare, "store_packaged_github_public_bodies", forbidden)
    monkeypatch.setattr(fixture_prepare, "promote_github_fixture_to_public_blobs", forbidden)
    monkeypatch.setattr(fixture_prepare, "setup_local_task_operator", forbidden)
    monkeypatch.setattr(fixture_prepare, "setup_incremental_github_fixture", forbidden)
    report = prepare_fixture_workspace(database, store_root=store_root)

    assert report.disposition is FixtureWorkspacePrepareDisposition.ALREADY_PREPARED
    assert report.state.cursor_generation == 3
    assert list_local_tasks(database) == tasks_before
    assert list_local_tasks(database)[0].revision == edited.revision == 2
    assert read_blob_backed_github_fixture(database, store_root=store_root) == h1_before
    assert read_incremental_github_fixture_state(database, store_root=store_root) == cursor_before
    assert created.task.task_id == edited.task_id
    assert persistent_rows == {table: table_rows(database, table) for table in persistent_rows}
    assert blob_hashes == {
        path.relative_to(store_root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in store_root.rglob("*")
        if path.is_file()
    }
    assert len(table_rows(database, "source_items")) == 6
    assert len(table_rows(database, "source_spans")) == 18
    assert len(table_rows(database, "tasks")) == 1
    assert len(table_rows(database, "action_proposals")) == 0


def test_valid_complete_legacy_fixture_is_promoted_without_reingestion(tmp_path: Path) -> None:
    from sentinel.ingestion.github_fixture import ingest_packaged_github_fixture

    database, store_root = new_database(tmp_path, "legacy")
    legacy = ingest_packaged_github_fixture(database)
    report = prepare_fixture_workspace(database, store_root=store_root)

    assert report.state.cursor_generation == 0
    assert report.state.github_items == 3
    assert report.state.github_citations == 9
    assert legacy.inserted_items == 3
    assert read_blob_backed_github_fixture(database, store_root=store_root).items == legacy.items


def test_prepare_preserves_each_valid_cursor_generation(tmp_path: Path) -> None:
    for target_generation in (1, 2, 3):
        database, store_root = new_database(tmp_path, f"cursor-{target_generation}")
        prepare_fixture_workspace(database, store_root=store_root)
        for generation in range(target_generation):
            advance_incremental_github_fixture(
                database,
                store_root=store_root,
                expected_generation=generation,
            )
        report = prepare_fixture_workspace(database, store_root=store_root)
        state = read_incremental_github_fixture_state(database, store_root=store_root)
        assert report.disposition is FixtureWorkspacePrepareDisposition.ALREADY_PREPARED
        assert report.state.cursor_generation == target_generation
        assert state.generation == target_generation
        assert state.item_count == target_generation
