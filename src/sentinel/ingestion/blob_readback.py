"""Read-only, fixture-independent verification of promoted GitHub blobs."""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import NoReturn, TypeAlias
from uuid import UUID

from sentinel.content import (
    PublicFixtureStoreError,
    PublicFixtureStoreErrorCode,
    read_public_fixture_blob,
)
from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.ingestion.blob_validation import (
    blob_ref,
    fail,
    verify_items,
    verify_registration,
    verify_spans,
)
from sentinel.ingestion.github_fixture import _validate_database_path
from sentinel.ingestion.types import (
    BlobBackedGithubFixture,
    GithubBlobIntegrationError,
    GithubBlobIntegrationErrorCode,
    GithubFixtureIngestionError,
    GithubFixtureIngestionErrorCode,
    PersistedGithubItem,
    PersistedGithubSpan,
    VerifiedBlobBackedGithubEvidence,
    VerifiedGithubEvidenceCitation,
    VerifiedGithubEvidenceItem,
)
from sentinel.normalization import (
    NormalizationError,
    PlainTextSourceDescriptor,
    add_citation,
    bind_citation,
    normalize_plain_text,
    verify_bound_citation,
)
from sentinel.normalization.types import NormalizedPlainTextSource, SourceBoundCitation
from sentinel.storage.connection import DatabaseOpenError, readonly_database_connection
from sentinel.storage.migrations import (
    MIGRATIONS,
    MigrationIntegrityError,
    has_registered_migration,
    inspect_migration_state_readonly,
    verify_integrity,
)
from sentinel.storage.schema import SchemaIntegrityError

_VerifiedItemData: TypeAlias = tuple[
    bytes,
    NormalizedPlainTextSource,
    dict[UUID, SourceBoundCitation],
]


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


def _open_verified_database(database: str | Path) -> tuple[Path, dict[str, str]]:
    try:
        path = _validate_database_path(database)
        with readonly_database_connection(path) as connection:
            connection.execute("BEGIN")
            state = inspect_migration_state_readonly(connection)
            if not has_registered_migration(state, MIGRATIONS[2].migration_id):
                fail(GithubBlobIntegrationErrorCode.SCHEMA_NOT_CURRENT)
            try:
                verify_integrity(connection)
            except (MigrationIntegrityError, sqlite3.Error):
                fail(GithubBlobIntegrationErrorCode.INTEGRITY_FAILURE)
            verify_registration(connection)
            ref_state = verify_items(connection, accepted_states=("blob",))
            if ref_state != "blob":
                fail(GithubBlobIntegrationErrorCode.CONTENT_REF_INVALID)
            verify_spans(connection)
            rows = connection.execute(
                "SELECT item_id, content_ref FROM source_items WHERE source_id = ?",
                (EXPECTED_MANIFEST.source_row[0],),
            ).fetchall()
            refs = {str(item_id): str(content_ref) for item_id, content_ref in rows}
            return path, refs
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
    except Exception:
        fail(GithubBlobIntegrationErrorCode.PROMOTION_FAILURE)


def _read_and_normalize_items(
    refs: dict[str, str], store_root: str | Path
) -> tuple[tuple[PersistedGithubItem, ...], dict[UUID, _VerifiedItemData]]:
    items: list[PersistedGithubItem] = []
    body_data: dict[UUID, _VerifiedItemData] = {}
    for expected in EXPECTED_MANIFEST.items:
        reference = refs.get(str(expected.item_id))
        if reference is None or reference != blob_ref(expected):
            fail(GithubBlobIntegrationErrorCode.CONTENT_REF_INVALID)
        digest = expected.content_sha256
        try:
            body = read_public_fixture_blob(store_root, content_sha256=digest)
        except PublicFixtureStoreError as error:
            _map_store_error(error)
        if type(body) is not bytes or hashlib.sha256(body).hexdigest() != digest:
            fail(GithubBlobIntegrationErrorCode.BLOB_INVALID)

        try:
            descriptor = PlainTextSourceDescriptor(
                source_id=expected.source_envelope_id,
                provider_id="github.fixture",
                observed_at=datetime.fromisoformat(EXPECTED_MANIFEST.observed_at),
                trust=TrustLabel.T4_EXTERNAL,
                sensitivity=SensitivityLabel.PUBLIC,
            )
            normalized = normalize_plain_text(
                descriptor,
                body,
                "text/plain; charset=utf-8",
            )
            if normalized.envelope.content_sha256 != digest:
                fail(GithubBlobIntegrationErrorCode.BLOB_INVALID)
            bound_by_id: dict[UUID, SourceBoundCitation] = {}
            for expected_span in expected.spans:
                normalized = add_citation(
                    normalized,
                    span_id=expected_span.in_memory_span_id,
                    start_byte=expected_span.start_byte,
                    end_byte=expected_span.end_byte,
                )
                citation = bind_citation(normalized, normalized.citations[-1])
                if (
                    citation.source_id != expected_span.source_id
                    or citation.content_sha256 != expected_span.content_sha256
                    or citation.span.span_id != expected_span.in_memory_span_id
                    or citation.span.start_byte != expected_span.start_byte
                    or citation.span.end_byte != expected_span.end_byte
                    or citation.span.text_sha256 != expected_span.text_sha256
                ):
                    fail(GithubBlobIntegrationErrorCode.SPAN_CONFLICT)
                verify_bound_citation(normalized, citation, original_bytes=body)
                bound_by_id[expected_span.span_id] = citation
        except GithubBlobIntegrationError:
            raise
        except NormalizationError:
            fail(GithubBlobIntegrationErrorCode.BLOB_INVALID)
        except (TypeError, ValueError):
            fail(GithubBlobIntegrationErrorCode.BLOB_INVALID)

        persisted_spans = tuple(
            PersistedGithubSpan(
                span_id=span.span_id,
                in_memory_span_id=span.in_memory_span_id,
                start_byte=span.start_byte,
                end_byte=span.end_byte,
                text_sha256=span.text_sha256,
            )
            for span in expected.spans
        )
        items.append(
            PersistedGithubItem(
                item_id=expected.item_id,
                provider_item_id=expected.provider_item_id,
                source_envelope_id=expected.source_envelope_id,
                content_sha256=digest,
                spans=persisted_spans,
            )
        )
        body_data[expected.item_id] = (body, normalized, bound_by_id)
    return tuple(items), body_data


def _verified_snapshot(
    database: str | Path,
    *,
    store_root: str | Path,
) -> tuple[BlobBackedGithubFixture, dict[UUID, _VerifiedItemData]]:
    _path, refs = _open_verified_database(database)
    items, body_data = _read_and_normalize_items(refs, store_root)
    report = BlobBackedGithubFixture(
        registry_source_id=UUID(str(EXPECTED_MANIFEST.source_row[0])),
        fixture_version=EXPECTED_MANIFEST.fixture_version,
        fixture_sha256=EXPECTED_MANIFEST.fixture_sha256,
        manifest_sha256=EXPECTED_MANIFEST.sha256,
        items=items,
    )
    return report, body_data


def read_blob_backed_github_fixture(
    database: str | Path,
    *,
    store_root: str | Path,
) -> BlobBackedGithubFixture:
    """Verify promoted SQLite rows against the pinned metadata manifest and blobs.

    This function never loads the GitHub fixture resource and never falls back to
    fixture bytes when a referenced blob is missing or invalid.
    """

    try:
        return _verified_snapshot(database, store_root=store_root)[0]
    except GithubBlobIntegrationError:
        raise
    except PublicFixtureStoreError as error:
        _map_store_error(error)


def read_blob_backed_github_evidence(
    database: str | Path,
    *,
    store_root: str | Path,
) -> VerifiedBlobBackedGithubEvidence:
    """Return all fixed-fixture metadata and citations from one verified snapshot."""
    try:
        report, body_data = _verified_snapshot(database, store_root=store_root)
        verified_items = []
        for expected in EXPECTED_MANIFEST.items:
            body, normalized, citation_map = body_data[expected.item_id]
            expected_row = expected.values
            source_at = datetime.fromisoformat(str(expected_row[10]))
            observed_at = datetime.fromisoformat(str(expected_row[9]))
            if source_at.utcoffset() is None or observed_at.utcoffset() is None:
                fail(GithubBlobIntegrationErrorCode.ITEM_CONFLICT)
            trust = TrustLabel(str(expected_row[7]))
            sensitivity = SensitivityLabel(str(expected_row[8]))
            if trust is not TrustLabel.T4_EXTERNAL or sensitivity is not SensitivityLabel.PUBLIC:
                fail(GithubBlobIntegrationErrorCode.ITEM_CONFLICT)

            citations: list[VerifiedGithubEvidenceCitation] = []
            for expected_span in expected.spans:
                citation = citation_map.get(expected_span.span_id)
                if citation is None:
                    fail(GithubBlobIntegrationErrorCode.SPAN_CONFLICT)
                cited_text = verify_bound_citation(normalized, citation, original_bytes=body)
                citations.append(
                    VerifiedGithubEvidenceCitation(
                        span_id=expected_span.span_id,
                        start_byte=expected_span.start_byte,
                        end_byte=expected_span.end_byte,
                        text_sha256=expected_span.text_sha256,
                        cited_text=cited_text,
                    )
                )
            verified_items.append(
                VerifiedGithubEvidenceItem(
                    provider_item_id=expected.provider_item_id,
                    item_id=expected.item_id,
                    source_envelope_id=expected.source_envelope_id,
                    content_sha256=expected.content_sha256,
                    source_at=source_at,
                    observed_at=observed_at,
                    trust=trust,
                    sensitivity=sensitivity,
                    citations=tuple(citations),
                )
            )
        return VerifiedBlobBackedGithubEvidence(
            provider_id="github.fixture",
            fixture_version=report.fixture_version,
            fixture_sha256=report.fixture_sha256,
            manifest_sha256=report.manifest_sha256,
            items=tuple(verified_items),
        )
    except GithubBlobIntegrationError:
        raise
    except (KeyError, TypeError, ValueError, NormalizationError):
        fail(GithubBlobIntegrationErrorCode.PROMOTION_INCOMPLETE)


def read_blob_backed_github_body(
    database: str | Path,
    *,
    store_root: str | Path,
    item_id: UUID,
) -> bytes:
    """Return exact verified body bytes to an explicit trusted internal caller."""

    if type(item_id) is not UUID:
        fail(GithubBlobIntegrationErrorCode.ITEM_CONFLICT)
    _report, body_data = _verified_snapshot(database, store_root=store_root)
    value = body_data.get(item_id)
    if value is None:
        fail(GithubBlobIntegrationErrorCode.ITEM_CONFLICT)
    return value[0]


def verify_blob_backed_github_citation(
    database: str | Path,
    *,
    store_root: str | Path,
    item_id: UUID,
    span_id: UUID,
) -> str:
    """Return the exact UTF-8 citation after complete database/blob verification."""

    if type(item_id) is not UUID or type(span_id) is not UUID:
        fail(GithubBlobIntegrationErrorCode.SPAN_CONFLICT)
    _report, body_data = _verified_snapshot(database, store_root=store_root)
    value = body_data.get(item_id)
    if value is None:
        fail(GithubBlobIntegrationErrorCode.ITEM_CONFLICT)
    _body, normalized, citations = value
    citation = citations.get(span_id)
    if citation is None:
        fail(GithubBlobIntegrationErrorCode.SPAN_CONFLICT)
    try:
        return verify_bound_citation(normalized, citation, original_bytes=_body)
    except NormalizationError:
        fail(GithubBlobIntegrationErrorCode.SPAN_CONFLICT)


__all__ = [
    "read_blob_backed_github_body",
    "read_blob_backed_github_evidence",
    "read_blob_backed_github_fixture",
    "verify_blob_backed_github_citation",
]
