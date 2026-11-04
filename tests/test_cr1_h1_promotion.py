from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import sentinel.ingestion.blob_promotion as promotion_module
from sentinel.content import read_public_fixture_blob
from sentinel.ingestion import (
    GithubBlobPromotionReport,
    promote_github_fixture_to_public_blobs,
    read_blob_backed_github_fixture,
)
from sentinel.storage.connection import database_connection, readonly_database_connection
from tests.cr1_h1_support import (
    blob_files,
    blob_ref,
    expected_bodies,
    item_rows,
    prepared_case,
    refs_by_item,
    span_rows,
)


def _register_unrelated_source(database: Path) -> tuple[str, str]:
    source_id = str(uuid4())
    item_id = str(uuid4())
    with database_connection(database) as connection:
        connection.execute(
            """INSERT INTO sources
               (source_id, plugin_id, plugin_version, principal_id, source_type,
                account_alias, scope_json, host_allowlist_json, trust,
                default_sensitivity, enabled, created_at)
               SELECT ?, plugin_id, plugin_version, principal_id, source_type,
                      'unrelated/fixture-project', '{}', '[]', trust,
                      default_sensitivity, 0, created_at
               FROM sources WHERE account_alias = 'example-owner/fixture-project'""",
            (source_id,),
        )
        connection.execute(
            """INSERT INTO source_items
               (item_id, source_id, provider_item_id, provider_revision, canonical_uri,
                content_ref, content_sha256, trust, sensitivity, observed_at, source_at,
                deleted_at, metadata_json)
               SELECT ?, ?, 'unrelated/fixture-project#1', NULL, NULL,
                      'fixture:unrelated', content_sha256, trust, sensitivity,
                      observed_at, source_at, NULL, '{}' FROM source_items LIMIT 1""",
            (item_id, source_id),
        )
    return source_id, item_id


def test_promotion_changes_only_three_content_refs_after_blob_publication(tmp_path, monkeypatch):
    database, store_root = prepared_case(tmp_path, name="promote")
    old_items = item_rows(database)
    old_spans = span_rows(database)
    old_refs = refs_by_item(database)
    bodies = expected_bodies()
    observed: list[UUID] = []
    original_update = getattr(promotion_module, "_update_content_reference", None)

    def observe_update(connection, item_id, old_ref, new_ref):
        assert connection.in_transaction
        assert len(blob_files(store_root)) == 3
        for digest, body in bodies.items():
            assert read_public_fixture_blob(store_root, content_sha256=digest) == body
        observed.append(item_id)
        assert original_update is not None
        return original_update(connection, item_id, old_ref, new_ref)

    monkeypatch.setattr(
        promotion_module, "_update_content_reference", observe_update, raising=False
    )
    report = promote_github_fixture_to_public_blobs(database, store_root=store_root)

    assert isinstance(report, GithubBlobPromotionReport)
    assert report.updated_references == 3
    assert report.existing_references == 0
    assert len(observed) == 3
    assert len(blob_files(store_root)) == 3
    assert read_blob_backed_github_fixture(database, store_root=store_root).items
    new_items = item_rows(database)
    assert len(new_items) == len(old_items) == 3
    for before, after in zip(old_items, new_items, strict=True):
        assert before[:5] == after[:5]
        assert before[6:] == after[6:]
        assert after[5] == blob_ref(str(after[6]))
    assert set(old_refs) == {UUID(str(row[0])) for row in new_items}
    assert span_rows(database) == old_spans
    assert {item_id: ref for item_id, ref in refs_by_item(database).items()} == {
        UUID(str(row[0])): blob_ref(str(row[6])) for row in new_items
    }
    for body in bodies.values():
        with readonly_database_connection(database) as connection:
            stored_fields = "".join(
                str(value)
                for row in connection.execute("SELECT * FROM source_items").fetchall()
                for value in row
            ).encode("utf-8")
        assert body not in stored_fields


def test_repeat_promotion_is_idempotent_and_keeps_row_identities(tmp_path):
    database, store_root = prepared_case(tmp_path, name="repeat")
    first = promote_github_fixture_to_public_blobs(database, store_root=store_root)
    items = item_rows(database)
    spans = span_rows(database)
    blob_bytes = {path.name: path.read_bytes() for path in blob_files(store_root)}

    second = promote_github_fixture_to_public_blobs(database, store_root=store_root)
    third = promote_github_fixture_to_public_blobs(database, store_root=store_root)

    assert first.updated_references == 3 and first.existing_references == 0
    for report in (second, third):
        assert report.updated_references == 0
        assert report.existing_references == 3
        assert report.blob_digests == first.blob_digests
    assert item_rows(database) == items
    assert span_rows(database) == spans
    assert {path.name: path.read_bytes() for path in blob_files(store_root)} == blob_bytes


def test_valid_unrelated_source_rows_are_not_part_of_fixture_completeness(tmp_path):
    database, store_root = prepared_case(tmp_path, name="unrelated")
    unrelated_source, unrelated_item = _register_unrelated_source(database)
    before = (item_rows(database), span_rows(database))

    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    result = read_blob_backed_github_fixture(database, store_root=store_root)

    assert len(result.items) == 3
    assert any(
        row[0] == unrelated_item and row[1] == unrelated_source for row in item_rows(database)
    )
    assert len(item_rows(database)) == 4
    assert len(span_rows(database)) == len(before[1]) == 9
