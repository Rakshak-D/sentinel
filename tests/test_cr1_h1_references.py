from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.ingestion import (
    GithubBlobIntegrationError,
    GithubBlobIntegrationErrorCode,
    GithubFixtureIngestionError,
    GithubFixtureIngestionErrorCode,
    ingest_packaged_github_fixture,
    promote_github_fixture_to_public_blobs,
    read_blob_backed_github_fixture,
    read_persisted_github_fixture,
)
from sentinel.storage.connection import database_connection
from tests.cr1_h1_support import (
    blob_files,
    expected_bodies,
    item_rows,
    prepared_case,
)


@pytest.mark.parametrize(
    "bad_ref",
    [
        "fixture:sentinel.github-issues-fixture.v1:example-owner/fixture-project#101",
        "file:///C:/outside/private.txt",
        "https://example.invalid/body",
        "unknown:sha256:" + "0" * 64,
        "sentinel-public-blob-v1:sha256:" + "0" * 64,
    ],
)
def test_blob_reader_rejects_legacy_unknown_path_url_and_wrong_digest_refs(
    tmp_path: Path, bad_ref: str
) -> None:
    database, store_root = prepared_case(tmp_path, name="badref")
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    item_id = item_rows(database)[0][0]
    with database_connection(database) as connection:
        connection.execute(
            "UPDATE source_items SET content_ref = ? WHERE item_id = ?",
            (bad_ref, item_id),
        )

    with pytest.raises(GithubBlobIntegrationError) as error:
        read_blob_backed_github_fixture(database, store_root=store_root)
    assert error.value.code is GithubBlobIntegrationErrorCode.CONTENT_REF_INVALID
    assert bad_ref not in str(error.value)
    assert str(database) not in str(error.value)


def test_missing_and_corrupted_blobs_fail_without_fixture_fallback(tmp_path: Path) -> None:
    database, store_root = prepared_case(tmp_path, name="missingblob")
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    files = blob_files(store_root)
    assert len(files) == 3
    files[0].unlink()
    with pytest.raises(GithubBlobIntegrationError) as missing:
        read_blob_backed_github_fixture(database, store_root=store_root)
    assert missing.value.code is GithubBlobIntegrationErrorCode.BLOB_UNAVAILABLE
    assert not files[0].exists()

    database, store_root = prepared_case(tmp_path, name="missing-repeat-blob")
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    files = blob_files(store_root)
    refs_before = {row[0]: row[5] for row in item_rows(database)}
    files[0].unlink()
    with pytest.raises(GithubBlobIntegrationError) as repeat_missing:
        promote_github_fixture_to_public_blobs(database, store_root=store_root)
    assert repeat_missing.value.code is GithubBlobIntegrationErrorCode.BLOB_UNAVAILABLE
    assert not files[0].exists()
    assert {row[0]: row[5] for row in item_rows(database)} == refs_before

    database, store_root = prepared_case(tmp_path, name="corruptblob")
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    files = blob_files(store_root)
    files[0].write_bytes(b"synthetic altered blob")
    with pytest.raises(GithubBlobIntegrationError) as corrupt:
        read_blob_backed_github_fixture(database, store_root=store_root)
    assert corrupt.value.code is GithubBlobIntegrationErrorCode.BLOB_INVALID


def test_missing_store_root_and_old_api_mode_are_explicit(tmp_path: Path) -> None:
    database, store_root = prepared_case(tmp_path, name="legacy")
    assert len(read_persisted_github_fixture(database).items) == 3

    with pytest.raises(GithubBlobIntegrationError) as legacy:
        read_blob_backed_github_fixture(database, store_root=store_root)
    assert legacy.value.code is GithubBlobIntegrationErrorCode.CONTENT_REF_INVALID
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    with pytest.raises(GithubFixtureIngestionError) as legacy_read:
        read_persisted_github_fixture(database)
    assert legacy_read.value.code is GithubFixtureIngestionErrorCode.ITEM_CONFLICT
    with pytest.raises(GithubFixtureIngestionError) as legacy_ingest:
        ingest_packaged_github_fixture(database)
    assert legacy_ingest.value.code is GithubFixtureIngestionErrorCode.ITEM_CONFLICT

    with pytest.raises(GithubBlobIntegrationError) as missing:
        read_blob_backed_github_fixture(database, store_root=tmp_path / "missing-store")
    assert missing.value.code is GithubBlobIntegrationErrorCode.BLOB_UNAVAILABLE


def test_blob_root_is_required_and_refs_never_contain_paths(tmp_path: Path) -> None:
    database, store_root = prepared_case(tmp_path, name="grammar")
    report = promote_github_fixture_to_public_blobs(database, store_root=store_root)
    rows = item_rows(database)
    digests = set(expected_bodies())
    refs = {str(row[5]) for row in rows}
    assert len(report.blob_digests) == 3
    assert refs == {f"sentinel-public-blob-v1:sha256:{digest}" for digest in digests}
    assert all("\\" not in value and "/" not in value and "://" not in value for value in refs)
    with pytest.raises(GithubBlobIntegrationError) as error:
        read_blob_backed_github_fixture(database, store_root=Path("relative-store"))
    assert error.value.code is GithubBlobIntegrationErrorCode.INVALID_PATH


def test_mixed_fixture_and_blob_refs_are_rejected_without_repair(tmp_path: Path) -> None:
    database, store_root = prepared_case(tmp_path, name="mixed-refs")
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    first_item_id = next(
        row[0] for row in item_rows(database) if row[2] == "example-owner/fixture-project#101"
    )
    with database_connection(database) as connection:
        connection.execute(
            "UPDATE source_items SET content_ref = ? WHERE item_id = ?",
            (
                "fixture:sentinel.github-issues-fixture.v1:example-owner/fixture-project#101",
                first_item_id,
            ),
        )
    before = item_rows(database)
    with pytest.raises(GithubBlobIntegrationError) as promotion_error:
        promote_github_fixture_to_public_blobs(database, store_root=store_root)
    assert promotion_error.value.code is GithubBlobIntegrationErrorCode.PROMOTION_INCOMPLETE
    with pytest.raises(GithubBlobIntegrationError) as read_error:
        read_blob_backed_github_fixture(database, store_root=store_root)
    assert read_error.value.code is GithubBlobIntegrationErrorCode.PROMOTION_INCOMPLETE
    assert item_rows(database) == before
