import hashlib
from pathlib import Path
from uuid import uuid4

import pytest

from sentinel.sync import (
    FixtureSyncError,
    advance_incremental_github_fixture,
    read_incremental_github_fixture_state,
    setup_incremental_github_fixture,
)
from tests.cr1_k_support import direct_connection, setup_case, source_rows


def _mutate_cursor(database: Path, sql: str, parameters: tuple[object, ...]) -> None:
    connection = direct_connection(database)
    try:
        connection.execute(sql, parameters)
    finally:
        connection.close()


def test_unknown_cursor_reference_fails_closed(tmp_path: Path) -> None:
    database, store_root, source_id = setup_case(tmp_path)
    _mutate_cursor(
        database,
        "UPDATE sync_cursors SET value_cipher_ref = ? WHERE source_id = ?",
        ("file:C:/private/cursor", str(source_id)),
    )
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database, store_root=store_root)


def test_cursor_generation_tampering_fails_closed(tmp_path: Path) -> None:
    database, store_root, source_id = setup_case(tmp_path)
    _mutate_cursor(
        database,
        "UPDATE sync_cursors SET generation = 2 WHERE source_id = ?",
        (str(source_id),),
    )
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database, store_root=store_root)


def test_cursor_source_mismatch_fails_closed(tmp_path: Path) -> None:
    database, store_root, source_id = setup_case(tmp_path)
    _mutate_cursor(
        database,
        "UPDATE sync_cursors SET source_id = ? WHERE source_id = ?",
        ("9338577b-4f6d-5507-9422-598c6ffc16bd", str(source_id)),
    )
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database, store_root=store_root)


def test_conflicting_source_metadata_fails_closed(tmp_path: Path) -> None:
    database, store_root, source_id = setup_case(tmp_path)
    connection = direct_connection(database)
    try:
        connection.execute(
            "UPDATE sources SET default_sensitivity = 'PRIVATE' WHERE source_id = ?",
            (str(source_id),),
        )
    finally:
        connection.close()
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database, store_root=store_root)


def test_setup_does_not_repair_conflicting_source_registration(tmp_path: Path) -> None:
    database, store_root, source_id = setup_case(tmp_path, name="source-conflict")
    connection = direct_connection(database)
    try:
        connection.execute(
            "UPDATE sources SET source_type = 'other' WHERE source_id = ?",
            (str(source_id),),
        )
    finally:
        connection.close()
    with pytest.raises(FixtureSyncError):
        setup_incremental_github_fixture(database, store_root=store_root)
    connection = direct_connection(database)
    try:
        row = connection.execute(
            "SELECT source_type FROM sources WHERE source_id = ?", (str(source_id),)
        ).fetchone()
    finally:
        connection.close()
    assert row == ("other",)


@pytest.mark.parametrize(
    "new_ref",
    (
        "file:C:/private/fixture.blob",
        "https://example.invalid/fixture",
        "fixture:unknown-scheme",
    ),
)
def test_unknown_or_path_content_reference_fails_closed(tmp_path: Path, new_ref: str) -> None:
    database, store_root, source_id = setup_case(tmp_path)
    advance_incremental_github_fixture(database, store_root=store_root, expected_generation=0)
    connection = direct_connection(database)
    try:
        connection.execute(
            "UPDATE source_items SET content_ref = ? WHERE source_id = ?",
            (new_ref, str(source_id)),
        )
    finally:
        connection.close()
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database, store_root=store_root)


def test_altered_item_digest_and_metadata_fail_closed(tmp_path: Path) -> None:
    database, store_root, source_id = setup_case(tmp_path)
    advance_incremental_github_fixture(database, store_root=store_root, expected_generation=0)
    connection = direct_connection(database)
    try:
        connection.execute(
            "UPDATE source_items SET content_sha256 = ? WHERE source_id = ?",
            ("0" * 64, str(source_id)),
        )
    finally:
        connection.close()
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database, store_root=store_root)


def test_altered_span_range_and_missing_span_fail_closed(tmp_path: Path) -> None:
    database, store_root, source_id = setup_case(tmp_path)
    advance_incremental_github_fixture(database, store_root=store_root, expected_generation=0)
    connection = direct_connection(database)
    try:
        connection.execute(
            "UPDATE source_spans SET start_byte = start_byte + 1 WHERE span_id = "
            "(SELECT sp.span_id FROM source_spans AS sp JOIN source_items AS si "
            "ON si.item_id = sp.item_id WHERE si.source_id = ? LIMIT 1)",
            (str(source_id),),
        )
    finally:
        connection.close()
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database, store_root=store_root)

    database2, store_root2, source_id2 = setup_case(tmp_path, name="missing-span")
    advance_incremental_github_fixture(database2, store_root=store_root2, expected_generation=0)
    connection = direct_connection(database2)
    try:
        connection.execute(
            "DELETE FROM source_spans WHERE span_id = (SELECT sp.span_id FROM source_spans AS sp "
            "JOIN source_items AS si ON si.item_id=sp.item_id WHERE si.source_id = ? LIMIT 1)",
            (str(source_id2),),
        )
    finally:
        connection.close()
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database2, store_root=store_root2)

    database3, store_root3, source_id3 = setup_case(tmp_path, name="missing-item")
    advance_incremental_github_fixture(database3, store_root=store_root3, expected_generation=0)
    connection = direct_connection(database3)
    try:
        connection.execute(
            "DELETE FROM source_spans WHERE item_id IN "
            "(SELECT item_id FROM source_items WHERE source_id = ?)",
            (str(source_id3),),
        )
        connection.execute("DELETE FROM source_items WHERE source_id = ?", (str(source_id3),))
    finally:
        connection.close()
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database3, store_root=store_root3)


def test_extra_fixture_owned_item_and_span_fail_closed(tmp_path: Path) -> None:
    database, store_root, source_id = setup_case(tmp_path)
    advance_incremental_github_fixture(database, store_root=store_root, expected_generation=0)
    connection = direct_connection(database)
    try:
        connection.execute(
            """INSERT INTO source_items
               (item_id, source_id, provider_item_id, provider_revision, canonical_uri,
                content_ref, content_sha256, trust, sensitivity, observed_at, source_at,
                deleted_at, metadata_json)
               VALUES (?, ?, ?, NULL, NULL, ?, ?, 'T4 EXTERNAL', 'PUBLIC', ?, ?, NULL, '{}')""",
            (
                str(uuid4()),
                str(source_id),
                "example-owner/fixture-project#999",
                "sentinel-public-blob-v1:sha256:4ed9123596eda8d6095d288d39f3ee267faef342e515da10d22cd2013a9509b2",
                "4ed9123596eda8d6095d288d39f3ee267faef342e515da10d22cd2013a9509b2",
                "2026-11-03T12:00:00Z",
                "2026-11-03T12:00:00Z",
            ),
        )
    finally:
        connection.close()
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database, store_root=store_root)

    database2, store_root2, source_id2 = setup_case(tmp_path, name="extra-span")
    advance_incremental_github_fixture(database2, store_root=store_root2, expected_generation=0)
    connection = direct_connection(database2)
    try:
        item_id = connection.execute(
            "SELECT item_id FROM source_items WHERE source_id = ?",
            (str(source_id2),),
        ).fetchone()[0]
        connection.execute(
            """INSERT INTO source_spans
               (span_id, item_id, start_byte, end_byte, text_sha256, context_ref,
                derived_by_boundary_id) VALUES (?, ?, 0, 1, ?, NULL, NULL)""",
            (str(uuid4()), item_id, hashlib.sha256(b"x").hexdigest()),
        )
    finally:
        connection.close()
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database2, store_root=store_root2)


def test_missing_blob_fails_without_fixture_fallback(tmp_path: Path) -> None:
    database, store_root, _source_id = setup_case(tmp_path)
    blobs = list((store_root / "public-v1" / "sha256").glob("*.blob"))
    blobs[0].unlink()
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database, store_root=store_root)


def test_corrupted_blob_fails_without_reconstruction(tmp_path: Path) -> None:
    database, store_root, _source_id = setup_case(tmp_path, name="corrupt-blob")
    blob_path = next((store_root / "public-v1" / "sha256").rglob("*.blob"))
    content = bytearray(blob_path.read_bytes())
    content[-1] ^= 0x01
    blob_path.write_bytes(content)
    with pytest.raises(FixtureSyncError):
        read_incremental_github_fixture_state(database, store_root=store_root)


def test_failed_page_verification_rolls_back_all_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sentinel.sync.github_fixture as sync_module

    database, store_root, source_id = setup_case(tmp_path)
    before = source_rows(database, source_id)
    original = sync_module._verify_complete_state
    calls = 0

    def fail_on_postcondition(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("synthetic postcondition failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(sync_module, "_verify_complete_state", fail_on_postcondition)
    with pytest.raises(FixtureSyncError):
        advance_incremental_github_fixture(database, store_root=store_root, expected_generation=0)
    assert source_rows(database, source_id) == before


@pytest.mark.parametrize("phase", ("item", "span", "cursor"))
def test_stage_failure_rolls_back_item_spans_and_cursor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    import sentinel.sync.github_fixture as sync_module

    database, store_root, source_id = setup_case(tmp_path, name=f"rollback-{phase}")
    before = source_rows(database, source_id)
    if phase == "item":
        original = sync_module._insert_page_item

        def fail_after_item(*args: object, **kwargs: object) -> None:
            original(*args, **kwargs)
            raise RuntimeError("injected")

        monkeypatch.setattr(sync_module, "_insert_page_item", fail_after_item)
    elif phase == "span":
        original = sync_module._insert_page_span
        count = 0

        def fail_after_span(*args: object, **kwargs: object) -> None:
            nonlocal count
            count += 1
            original(*args, **kwargs)
            if count == 1:
                raise RuntimeError("injected")

        monkeypatch.setattr(sync_module, "_insert_page_span", fail_after_span)
    else:
        original = sync_module._advance_cursor

        def fail_after_cursor(*args: object, **kwargs: object) -> None:
            original(*args, **kwargs)
            raise RuntimeError("injected")

        monkeypatch.setattr(sync_module, "_advance_cursor", fail_after_cursor)

    with pytest.raises(FixtureSyncError):
        advance_incremental_github_fixture(database, store_root=store_root, expected_generation=0)
    assert source_rows(database, source_id) == before
