"""Explicit promotion of fixed CR1-G source refs to verified PUBLIC blob refs."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Literal, NoReturn
from uuid import UUID

from sentinel.content import (
    PublicFixtureStoreError,
    PublicFixtureStoreErrorCode,
    read_public_fixture_blob,
    store_packaged_github_public_bodies,
)
from sentinel.ingestion import blob_validation
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.ingestion.blob_validation import (
    blob_ref,
    fail,
    verify_fixture_matches_manifest,
)
from sentinel.ingestion.github_fixture import (
    _database_file_identity,
    _prepare_fixture,
    _PreparedFixture,
    _validate_database_path,
    _validate_migration_state,
    _verify_current_schema_inside_transaction,
)
from sentinel.ingestion.types import (
    GithubBlobIntegrationError,
    GithubBlobIntegrationErrorCode,
    GithubBlobPromotionReport,
    GithubFixtureIngestionError,
    GithubFixtureIngestionErrorCode,
)
from sentinel.storage.connection import DatabaseOpenError, readonly_database_connection
from sentinel.storage.migrations import MigrationIntegrityError
from sentinel.storage.schema import SchemaIntegrityError
from sentinel.storage.writer import (
    WriterLeaseError,
    WriterLeaseErrorCode,
    acquire_writer_lease,
)


def _map_fixture_error(error: GithubFixtureIngestionError) -> NoReturn:
    mapping = {
        GithubFixtureIngestionErrorCode.INVALID_PATH: (GithubBlobIntegrationErrorCode.INVALID_PATH),
        GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE: (
            GithubBlobIntegrationErrorCode.DATABASE_UNAVAILABLE
        ),
        GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT: (
            GithubBlobIntegrationErrorCode.SCHEMA_NOT_CURRENT
        ),
        GithubFixtureIngestionErrorCode.INTEGRITY_FAILURE: (
            GithubBlobIntegrationErrorCode.INTEGRITY_FAILURE
        ),
        GithubFixtureIngestionErrorCode.REGISTRATION_CONFLICT: (
            GithubBlobIntegrationErrorCode.REGISTRATION_CONFLICT
        ),
        GithubFixtureIngestionErrorCode.ITEM_CONFLICT: GithubBlobIntegrationErrorCode.ITEM_CONFLICT,
        GithubFixtureIngestionErrorCode.SPAN_CONFLICT: GithubBlobIntegrationErrorCode.SPAN_CONFLICT,
        GithubFixtureIngestionErrorCode.MULTIPLE_HARD_LINKS: (
            GithubBlobIntegrationErrorCode.DATABASE_UNAVAILABLE
        ),
    }
    fail(mapping.get(error.code, GithubBlobIntegrationErrorCode.PROMOTION_FAILURE))


def _map_store_error(error: PublicFixtureStoreError) -> NoReturn:
    if error.code in {
        PublicFixtureStoreErrorCode.INVALID_ROOT,
        PublicFixtureStoreErrorCode.UNSUPPORTED_FILESYSTEM,
    }:
        fail(GithubBlobIntegrationErrorCode.INVALID_PATH)
    if error.code in {
        PublicFixtureStoreErrorCode.STORE_UNINITIALIZED,
        PublicFixtureStoreErrorCode.BLOB_NOT_FOUND,
    }:
        fail(GithubBlobIntegrationErrorCode.BLOB_UNAVAILABLE)
    if error.code in {
        PublicFixtureStoreErrorCode.BLOB_INVALID,
        PublicFixtureStoreErrorCode.STORE_INVALID,
        PublicFixtureStoreErrorCode.FIXTURE_INVALID,
    }:
        fail(GithubBlobIntegrationErrorCode.BLOB_INVALID)
    fail(GithubBlobIntegrationErrorCode.PROMOTION_FAILURE)


def _map_writer_error(error: WriterLeaseError) -> NoReturn:
    if error.code is WriterLeaseErrorCode.INVALID_PATH:
        fail(GithubBlobIntegrationErrorCode.INVALID_PATH)
    if error.code in {
        WriterLeaseErrorCode.DATABASE_MISSING,
        WriterLeaseErrorCode.DATABASE_UNAVAILABLE,
    }:
        fail(GithubBlobIntegrationErrorCode.DATABASE_UNAVAILABLE)
    if error.code in {
        WriterLeaseErrorCode.LOCK_CONTENDED,
        WriterLeaseErrorCode.LOCK_UNAVAILABLE,
        WriterLeaseErrorCode.REENTRANT,
        WriterLeaseErrorCode.UNSUPPORTED_PLATFORM,
    }:
        fail(GithubBlobIntegrationErrorCode.WRITER_UNAVAILABLE)
    if error.code in {
        WriterLeaseErrorCode.MIGRATION_INVALID,
        WriterLeaseErrorCode.DATABASE_INVALID,
    }:
        fail(GithubBlobIntegrationErrorCode.SCHEMA_NOT_CURRENT)
    fail(GithubBlobIntegrationErrorCode.PROMOTION_FAILURE)


def _verify_complete_state(
    connection: sqlite3.Connection,
    *,
    accepted_states: tuple[Literal["fixture", "blob"], ...],
) -> Literal["fixture", "blob"]:
    blob_validation.verify_registration(connection)
    state = blob_validation.verify_items(
        connection,
        accepted_states=accepted_states,
    )
    blob_validation.verify_spans(connection)
    return state


def _validate_phase_a(
    path: Path,
) -> tuple[tuple[int, int], Literal["fixture", "blob"]]:
    try:
        identity = _database_file_identity(path)
        with readonly_database_connection(path) as connection:
            connection.execute("BEGIN")
            state = _validate_migration_state(connection)
            if not state.is_current:
                fail(GithubBlobIntegrationErrorCode.SCHEMA_NOT_CURRENT)
            ref_state = _verify_complete_state(
                connection,
                accepted_states=("fixture", "blob"),
            )
            return (identity[1], identity[2]), ref_state
    except GithubBlobIntegrationError:
        raise
    except GithubFixtureIngestionError as error:
        _map_fixture_error(error)
    except DatabaseOpenError:
        fail(GithubBlobIntegrationErrorCode.DATABASE_UNAVAILABLE)
    except (MigrationIntegrityError, SchemaIntegrityError):
        fail(GithubBlobIntegrationErrorCode.SCHEMA_NOT_CURRENT)
    except sqlite3.Error:
        fail(GithubBlobIntegrationErrorCode.INTEGRITY_FAILURE)
    except (OSError, RuntimeError, TypeError, ValueError):
        fail(GithubBlobIntegrationErrorCode.DATABASE_UNAVAILABLE)


def _verify_published_blobs(prepared: _PreparedFixture, store_root: str | Path) -> None:
    try:
        items = prepared.items
        if len(items) != len(EXPECTED_MANIFEST.items):
            fail(GithubBlobIntegrationErrorCode.PROMOTION_INCOMPLETE)
        report = store_packaged_github_public_bodies(store_root)
        expected_digests = {item.content_sha256 for item in EXPECTED_MANIFEST.items}
        report_digests = {blob.content_sha256 for blob in report.blobs}
        if (
            report.fixture_version != EXPECTED_MANIFEST.fixture_version
            or report.fixture_sha256 != EXPECTED_MANIFEST.fixture_sha256
            or report.inserted_count + report.existing_count != 3
            or len(report.blobs) != 3
            or report_digests != expected_digests
        ):
            fail(GithubBlobIntegrationErrorCode.BLOB_INVALID)

        expected_payloads = {
            item.issue.normalized_source.envelope.content_sha256: (
                item.issue.normalized_source.original_bytes
            )
            for item in items
        }
        if set(expected_payloads) != expected_digests:
            fail(GithubBlobIntegrationErrorCode.BLOB_INVALID)
        for digest in sorted(expected_digests):
            payload = read_public_fixture_blob(store_root, content_sha256=digest)
            if payload != expected_payloads[digest]:
                fail(GithubBlobIntegrationErrorCode.BLOB_INVALID)
    except GithubBlobIntegrationError:
        raise
    except PublicFixtureStoreError as error:
        _map_store_error(error)
    except Exception:
        fail(GithubBlobIntegrationErrorCode.BLOB_INVALID)


def _verify_existing_blobs(prepared: _PreparedFixture, store_root: str | Path) -> None:
    """Validate already-referenced blobs before any write-capable store call."""

    try:
        expected_payloads = {
            item.issue.normalized_source.envelope.content_sha256: (
                item.issue.normalized_source.original_bytes
            )
            for item in prepared.items
        }
        for digest, expected_payload in expected_payloads.items():
            payload = read_public_fixture_blob(store_root, content_sha256=digest)
            if payload != expected_payload:
                fail(GithubBlobIntegrationErrorCode.BLOB_INVALID)
    except GithubBlobIntegrationError:
        raise
    except PublicFixtureStoreError as error:
        _map_store_error(error)
    except Exception:
        fail(GithubBlobIntegrationErrorCode.BLOB_INVALID)


def _update_content_reference(
    connection: sqlite3.Connection,
    item_id: UUID,
    old_ref: str,
    new_ref: str,
) -> None:
    """Update exactly one existing item ref through the active lease transaction."""

    cursor = connection.execute(
        "UPDATE source_items SET content_ref = ? WHERE item_id = ? AND content_ref = ?",
        (new_ref, str(item_id), old_ref),
    )
    if cursor.rowcount != 1:
        fail(GithubBlobIntegrationErrorCode.ITEM_CONFLICT)


def promote_github_fixture_to_public_blobs(
    database: str | Path,
    *,
    store_root: str | Path,
) -> GithubBlobPromotionReport:
    """Publish the three pinned PUBLIC bodies, then atomically promote their refs.

    Blob files are durable independently from SQLite, so a failure after publish
    can leave harmless orphan blobs. SQLite transitions all three references in
    one writer-lease transaction or rolls them all back.
    """

    try:
        path = _validate_database_path(database)
        prepared = _prepare_fixture()
        verify_fixture_matches_manifest(prepared)

        # Phase A: validate the entire existing fixed-source dataset before any
        # blob publication. Current schema and integrity are verified read-only.
        initial_identity, initial_state = _validate_phase_a(path)

        # An already-promoted reference must already resolve to valid content.
        # Refuse it before calling the writer API, which could otherwise repair
        # a missing blob from the package fixture.
        if initial_state == "blob":
            _verify_existing_blobs(prepared, store_root)

        # Phase B: the content-store API accepts only the pinned fixture. Read
        # back all exact bytes before beginning any SQLite reference update.
        _verify_published_blobs(prepared, store_root)

        # Phase C: hold the cooperative session lease and move refs in one
        # BEGIN IMMEDIATE transaction after rechecking complete state.
        with acquire_writer_lease(path) as lease:
            current_identity = _database_file_identity(path)
            if (current_identity[1], current_identity[2]) != initial_identity:
                fail(GithubBlobIntegrationErrorCode.DATABASE_UNAVAILABLE)
            updated = 0
            existing = 0
            with lease.transaction() as connection:
                _verify_current_schema_inside_transaction(connection)
                before_state = _verify_complete_state(
                    connection,
                    accepted_states=("fixture", "blob"),
                )

                # The read-back occurs under BEGIN IMMEDIATE and before the
                # first content_ref UPDATE. Filesystem and SQLite are not one
                # atomic transaction; already-published blobs remain harmless.
                expected_payloads = {
                    item.issue.normalized_source.envelope.content_sha256: (
                        item.issue.normalized_source.original_bytes
                    )
                    for item in prepared.items
                }
                for digest, expected_payload in expected_payloads.items():
                    try:
                        actual_payload = read_public_fixture_blob(
                            store_root,
                            content_sha256=digest,
                        )
                    except PublicFixtureStoreError as error:
                        _map_store_error(error)
                    if actual_payload != expected_payload:
                        fail(GithubBlobIntegrationErrorCode.BLOB_INVALID)

                if before_state == "fixture":
                    for item in EXPECTED_MANIFEST.items:
                        _update_content_reference(
                            connection,
                            item.item_id,
                            str(item.values[5]),
                            blob_ref(item),
                        )
                        updated += 1
                else:
                    existing = 3

                # A commit is permitted only with all expected registrations,
                # item rows, and span rows in the fully promoted state.
                _verify_complete_state(connection, accepted_states=("blob",))

            # If Phase A saw legacy rows but another cooperating promotion won
            # before this lease, the in-transaction state still defines counts.
            return GithubBlobPromotionReport(
                registry_source_id=UUID(str(EXPECTED_MANIFEST.source_row[0])),
                fixture_sha256=EXPECTED_MANIFEST.fixture_sha256,
                manifest_sha256=EXPECTED_MANIFEST.sha256,
                updated_references=updated,
                existing_references=existing,
                blob_digests=tuple(item.content_sha256 for item in EXPECTED_MANIFEST.items),
            )
    except GithubBlobIntegrationError:
        raise
    except GithubFixtureIngestionError as error:
        _map_fixture_error(error)
    except PublicFixtureStoreError as error:
        _map_store_error(error)
    except WriterLeaseError as error:
        _map_writer_error(error)
    except DatabaseOpenError:
        fail(GithubBlobIntegrationErrorCode.DATABASE_UNAVAILABLE)
    except (MigrationIntegrityError, SchemaIntegrityError):
        fail(GithubBlobIntegrationErrorCode.SCHEMA_NOT_CURRENT)
    except sqlite3.Error:
        fail(GithubBlobIntegrationErrorCode.PROMOTION_FAILURE)
    except (OSError, RuntimeError, TypeError, ValueError):
        fail(GithubBlobIntegrationErrorCode.PROMOTION_FAILURE)
    except Exception:
        fail(GithubBlobIntegrationErrorCode.PROMOTION_FAILURE)


__all__ = ["promote_github_fixture_to_public_blobs"]
