import hashlib
import json
from pathlib import Path
from uuid import UUID

from sentinel.content import read_public_fixture_blob
from sentinel.ingestion import read_blob_backed_github_fixture
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.readers.github_fixture import read_packaged_github_fixture
from sentinel.storage.connection import readonly_database_connection
from sentinel.sync import (
    FixtureSyncAdvanceResult,
    advance_incremental_github_fixture,
    read_incremental_github_fixture_state,
    setup_incremental_github_fixture,
)
from sentinel.tasks import create_local_task, list_local_tasks, setup_local_task_operator
from tests.cr1_k_support import promoted_case, setup_case, source_rows


def test_one_call_commits_one_fixed_page_with_its_spans_and_cursor(tmp_path: Path) -> None:
    database, store_root = promoted_case(tmp_path, name="progress-red")
    setup_incremental_github_fixture(database, store_root=store_root)

    result = advance_incremental_github_fixture(
        database, store_root=store_root, expected_generation=0
    )

    assert result is not None
    assert result.result is FixtureSyncAdvanceResult.APPLIED
    assert result.state.generation == 1
    assert result.state.item_count == 1
    assert result.state.span_count == 3
    assert read_incremental_github_fixture_state(database, store_root=store_root) == result.state


def test_three_page_sequence_preserves_original_fixture_and_manual_tasks(tmp_path: Path) -> None:
    database, store_root, source_id = setup_case(tmp_path, name="all-pages")
    setup_local_task_operator(database)
    created_task = create_local_task(
        database,
        request_id=UUID("00000000-0000-4000-8000-000000000456"),
        title="Synthetic manual task",
    ).task
    task_before = list_local_tasks(database)
    base_before = read_blob_backed_github_fixture(database, store_root=store_root)
    original_source_items = tuple(item for item in base_before.items)
    h1_source_id = UUID(EXPECTED_MANIFEST.source_row[0])
    h1_before = source_rows(database, h1_source_id)

    counts = []
    for generation, expected in enumerate(((1, 3), (2, 8), (3, 9))):
        report = advance_incremental_github_fixture(
            database, store_root=store_root, expected_generation=generation
        )
        assert report.state.generation == generation + 1
        counts.append((report.state.item_count, report.state.span_count))
        assert counts[-1] == expected

    assert counts == [(1, 3), (2, 8), (3, 9)]
    assert (
        advance_incremental_github_fixture(
            database, store_root=store_root, expected_generation=3
        ).result
        is FixtureSyncAdvanceResult.COMPLETE
    )
    final_state = read_incremental_github_fixture_state(database, store_root=store_root)
    assert final_state.generation == 3
    assert final_state.cursor_status.value == "COMPLETE"
    assert list_local_tasks(database) == task_before
    assert task_before[0] == created_task
    assert len(original_source_items) == 3

    with readonly_database_connection(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM action_proposals").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM runs").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM boundary_envelopes").fetchone() == (0,)
        incremental_rows = connection.execute(
            """SELECT item_id, provider_item_id, content_ref, content_sha256,
                      trust, sensitivity, observed_at, source_at, metadata_json
               FROM source_items WHERE source_id = ? ORDER BY provider_item_id""",
            (str(source_id),),
        ).fetchall()
        spans = connection.execute(
            """SELECT sp.span_id, sp.item_id, sp.start_byte, sp.end_byte, sp.text_sha256
               FROM source_spans AS sp JOIN source_items AS si ON si.item_id=sp.item_id
               WHERE si.source_id = ? ORDER BY si.provider_item_id, sp.start_byte""",
            (str(source_id),),
        ).fetchall()
        h1_rows = connection.execute(
            "SELECT item_id, content_sha256, content_ref FROM source_items WHERE source_id = ?",
            (str(EXPECTED_MANIFEST.source_row[0]),),
        ).fetchall()
        task_count = connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]

    assert len(incremental_rows) == 3
    assert len(spans) == 9
    assert task_count == 1
    assert len(h1_rows) == 3
    assert source_rows(database, h1_source_id) == h1_before
    assert {row[4:6] for row in incremental_rows} == {("T4 EXTERNAL", "PUBLIC")}
    assert all(row[2] == f"sentinel-public-blob-v1:sha256:{row[3]}" for row in incremental_rows)
    assert len({row[0] for row in incremental_rows}) == 3
    original_item_ids = {str(item.item_id) for item in original_source_items}
    assert all(row[0] not in original_item_ids for row in incremental_rows)

    manifest_by_provider = {item.provider_item_id: item for item in EXPECTED_MANIFEST.items}
    for provider_item_id, *row_fields in [
        (row[1], row[0], row[2], row[3], row[4], row[5], row[6], row[7], row[8])
        for row in incremental_rows
    ]:
        expected_item = manifest_by_provider[provider_item_id]
        body = read_public_fixture_blob(store_root, content_sha256=expected_item.content_sha256)
        item_rows = [row for row in spans if row[1] == row_fields[0]]
        assert len(item_rows) == len(expected_item.spans)
        assert hashlib.sha256(body).hexdigest() == expected_item.content_sha256
        for persisted, expected_span in zip(item_rows, expected_item.spans, strict=True):
            assert persisted[2:5] == (
                expected_span.start_byte,
                expected_span.end_byte,
                expected_span.text_sha256,
            )
            assert hashlib.sha256(body[persisted[2] : persisted[3]]).hexdigest() == persisted[4]
            assert body[persisted[2] : persisted[3]].decode("utf-8", errors="strict")
        metadata = json.loads(row_fields[7])
        assert "body" not in metadata

    complete_dump = "\n".join(str(value) for row in incremental_rows for value in row)
    for issue in read_packaged_github_fixture().issues:
        assert issue.body_text not in complete_dump
        assert issue.title not in complete_dump
