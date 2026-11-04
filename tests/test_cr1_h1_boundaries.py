from __future__ import annotations

import hashlib
import socket
from pathlib import Path
from uuid import uuid4

import pytest

from sentinel.gateways.model import ModelGateway
from sentinel.gateways.tool import ToolGateway
from sentinel.ingestion import (
    GithubBlobIntegrationError,
    GithubBlobIntegrationErrorCode,
    promote_github_fixture_to_public_blobs,
    read_blob_backed_github_fixture,
)
from sentinel.storage.connection import database_connection
from tests.cr1_g_support import migration_prefix_database
from tests.cr1_h1_support import (
    blob_files,
    initialized_unpromoted_database,
    prepared_case,
)


def test_historical_prefixes_are_rejected_before_blob_publication(tmp_path: Path) -> None:
    for count in (1, 2):
        database = migration_prefix_database(tmp_path / f"historical-{count}.sqlite3", count)
        store = tmp_path / f"store-{count}"
        from sentinel.content import initialize_public_fixture_store

        initialize_public_fixture_store(store)
        with pytest.raises(GithubBlobIntegrationError) as error:
            promote_github_fixture_to_public_blobs(database, store_root=store)
        assert error.value.code is GithubBlobIntegrationErrorCode.SCHEMA_NOT_CURRENT
        assert not blob_files(store)


@pytest.mark.parametrize("corruption", ["migration", "schema"])
def test_migration_tampering_and_schema_drift_fail_before_publication(tmp_path, corruption):
    database, store_root = prepared_case(tmp_path, name=f"{corruption}-drift")
    with database_connection(database) as connection:
        if corruption == "migration":
            connection.execute(
                "UPDATE schema_migrations SET artifact_sha256 = ? WHERE migration_id = ?",
                ("0" * 64, "cr1-f-0003-source-spans"),
            )
        else:
            connection.execute("CREATE TABLE unauthorized_h1_object(value TEXT)")
    with pytest.raises(GithubBlobIntegrationError) as error:
        promote_github_fixture_to_public_blobs(database, store_root=store_root)
    assert error.value.code is GithubBlobIntegrationErrorCode.SCHEMA_NOT_CURRENT
    assert not blob_files(store_root)


@pytest.mark.parametrize("tamper", ["item_digest", "item_identity", "missing_span", "extra_span"])
def test_incomplete_or_tampered_expected_rows_are_rejected_before_publish(
    tmp_path: Path, tamper: str
) -> None:
    database, store_root = prepared_case(tmp_path, name=f"tamper-{tamper}")
    with database_connection(database) as connection:
        item_id, _source_id = connection.execute(
            "SELECT item_id, source_id FROM source_items ORDER BY provider_item_id LIMIT 1"
        ).fetchone()
        if tamper == "item_digest":
            connection.execute(
                "UPDATE source_items SET content_sha256 = ? WHERE item_id = ?",
                ("0" * 64, item_id),
            )
        elif tamper == "item_identity":
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(
                "UPDATE source_items SET item_id = ? WHERE item_id = ?",
                (str(uuid4()), item_id),
            )
        elif tamper == "missing_span":
            connection.execute(
                "DELETE FROM source_spans WHERE span_id = "
                "(SELECT span_id FROM source_spans WHERE item_id = ? LIMIT 1)",
                (item_id,),
            )
        else:
            connection.execute(
                """INSERT INTO source_spans
                   (span_id, item_id, start_byte, end_byte, text_sha256, context_ref,
                    derived_by_boundary_id)
                   VALUES (?, ?, 0, 1, ?, NULL, NULL)""",
                (str(uuid4()), item_id, hashlib.sha256(b"x").hexdigest()),
            )
    with pytest.raises(GithubBlobIntegrationError) as error:
        promote_github_fixture_to_public_blobs(database, store_root=store_root)
    assert error.value.code in {
        GithubBlobIntegrationErrorCode.ITEM_CONFLICT,
        GithubBlobIntegrationErrorCode.SPAN_CONFLICT,
        GithubBlobIntegrationErrorCode.INTEGRITY_FAILURE,
    }
    assert not blob_files(store_root)


def test_missing_database_and_uninitialized_store_fail_closed(tmp_path: Path) -> None:
    from sentinel.content import initialize_public_fixture_store

    store = tmp_path / "store"
    initialize_public_fixture_store(store)
    with pytest.raises(GithubBlobIntegrationError) as missing:
        promote_github_fixture_to_public_blobs(tmp_path / "missing.sqlite3", store_root=store)
    assert missing.value.code is GithubBlobIntegrationErrorCode.DATABASE_UNAVAILABLE
    assert not blob_files(store)

    database = initialized_unpromoted_database(tmp_path / "uninitialized-store.sqlite3")
    uninitialized = tmp_path / "not-created-store"
    with pytest.raises(GithubBlobIntegrationError) as unavailable:
        promote_github_fixture_to_public_blobs(database, store_root=uninitialized)
    assert unavailable.value.code is GithubBlobIntegrationErrorCode.BLOB_UNAVAILABLE


def test_promotion_does_not_call_external_capability_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, store_root = prepared_case(tmp_path, name="no-effects")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("external capability invoked")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(ModelGateway, "generate", forbidden)
    monkeypatch.setattr(ToolGateway, "call", forbidden)
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    assert len(read_blob_backed_github_fixture(database, store_root=store_root).items) == 3
