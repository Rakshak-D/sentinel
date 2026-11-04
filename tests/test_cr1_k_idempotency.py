import hashlib
from pathlib import Path

import pytest

from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.sync import (
    FixtureSyncAdvanceResult,
    advance_incremental_github_fixture,
    read_incremental_github_fixture_state,
    setup_incremental_github_fixture,
)
from tests.cr1_h1_support import blob_files
from tests.cr1_k_support import setup_case, source_rows


def test_three_pages_progress_once_and_retries_are_explicit(tmp_path: Path) -> None:
    database, store_root, source_id = setup_case(tmp_path)
    first = advance_incremental_github_fixture(
        database, store_root=store_root, expected_generation=0
    )
    assert first.result is FixtureSyncAdvanceResult.APPLIED
    assert (first.state.generation, first.state.item_count, first.state.span_count) == (1, 1, 3)
    before_replay = source_rows(database, source_id)

    replay_first = advance_incremental_github_fixture(
        database, store_root=store_root, expected_generation=0
    )
    assert replay_first.result is FixtureSyncAdvanceResult.ALREADY_APPLIED
    assert source_rows(database, source_id) == before_replay

    second = advance_incremental_github_fixture(
        database, store_root=store_root, expected_generation=1
    )
    assert second.result is FixtureSyncAdvanceResult.APPLIED
    assert (second.state.generation, second.state.item_count, second.state.span_count) == (2, 2, 8)

    third = advance_incremental_github_fixture(
        database, store_root=store_root, expected_generation=2
    )
    assert third.result is FixtureSyncAdvanceResult.COMPLETE
    assert (third.state.generation, third.state.item_count, third.state.span_count) == (3, 3, 9)
    assert third.state.cursor_status == "COMPLETE"
    assert (
        advance_incremental_github_fixture(
            database, store_root=store_root, expected_generation=2
        ).result
        is FixtureSyncAdvanceResult.ALREADY_APPLIED
    )
    assert (
        advance_incremental_github_fixture(
            database, store_root=store_root, expected_generation=3
        ).result
        is FixtureSyncAdvanceResult.COMPLETE
    )
    assert read_incremental_github_fixture_state(database, store_root=store_root) == third.state


def test_future_and_stale_generations_have_distinct_results(tmp_path: Path) -> None:
    database, store_root, _source_id = setup_case(tmp_path)
    future = advance_incremental_github_fixture(
        database, store_root=store_root, expected_generation=1
    )
    assert future.result is FixtureSyncAdvanceResult.OUT_OF_ORDER
    one = advance_incremental_github_fixture(database, store_root=store_root, expected_generation=0)
    two = advance_incremental_github_fixture(database, store_root=store_root, expected_generation=1)
    assert two.state.generation == 2
    stale = advance_incremental_github_fixture(
        database, store_root=store_root, expected_generation=0
    )
    assert stale.result is FixtureSyncAdvanceResult.STALE
    assert one.state.generation == 1


def test_setup_is_idempotent_and_never_rewinds_progress(tmp_path: Path) -> None:
    database, store_root, source_id = setup_case(tmp_path)
    advance_incremental_github_fixture(database, store_root=store_root, expected_generation=0)
    before = source_rows(database, source_id)
    again = setup_incremental_github_fixture(database, store_root=store_root)
    after = source_rows(database, source_id)
    assert before == after
    assert again.generation == 1
    assert again.item_count == 1
    assert again.span_count == 3


def test_page_rows_use_new_deterministic_item_and_span_ids(tmp_path: Path) -> None:
    database, store_root, source_id = setup_case(tmp_path)
    advance_incremental_github_fixture(database, store_root=store_root, expected_generation=0)
    rows = source_rows(database, source_id)
    assert len(rows["items"]) == 1
    assert len(rows["spans"]) == 3
    assert all(row[1] == str(source_id) for row in rows["items"])
    original_span_ids = {
        str(span.span_id) for item in EXPECTED_MANIFEST.items for span in item.spans
    }
    assert all(span[0] not in original_span_ids for span in rows["spans"])


def test_read_status_does_not_load_packaged_fixture_or_write_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, store_root, source_id = setup_case(tmp_path)
    for generation in range(3):
        advance_incremental_github_fixture(
            database, store_root=store_root, expected_generation=generation
        )
    before = source_rows(database, source_id)
    blobs_before = tuple(
        (path.name, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in blob_files(store_root)
    )

    def forbidden() -> object:
        raise AssertionError("packaged JSON fixture must not be loaded by status")

    monkeypatch.setattr("sentinel.sync.github_fixture.read_packaged_github_fixture", forbidden)
    state = read_incremental_github_fixture_state(database, store_root=store_root)

    assert state.generation == 3
    assert (state.item_count, state.span_count) == (3, 9)
    assert source_rows(database, source_id) == before
    assert tuple(
        (path.name, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in blob_files(store_root)
    ) == blobs_before
