"""One-page-at-a-time persistence for a fixed synthetic GitHub fixture.

This is deterministic local replay, not a GitHub client. It stores metadata and
references the existing PUBLIC fixture blobs; it never writes blob content.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, NoReturn, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from sentinel.content import (
    PublicFixtureStoreError,
    PublicFixtureStoreErrorCode,
    read_public_fixture_blob,
)
from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.ingestion.blob_manifest import (
    EXPECTED_MANIFEST,
    ExpectedItem,
    load_expected_manifest,
)
from sentinel.ingestion.blob_readback import read_blob_backed_github_fixture
from sentinel.ingestion.blob_validation import (
    blob_ref,
)
from sentinel.ingestion.blob_validation import (
    verify_items as verify_h1_items,
)
from sentinel.ingestion.blob_validation import (
    verify_registration as verify_h1_registration,
)
from sentinel.ingestion.blob_validation import (
    verify_spans as verify_h1_spans,
)
from sentinel.ingestion.github_fixture import (
    _database_file_identity,
    _validate_database_path,
)
from sentinel.ingestion.types import (
    GithubBlobIntegrationError,
    GithubBlobIntegrationErrorCode,
    GithubFixtureIngestionError,
)
from sentinel.normalization import (
    NormalizationError,
    PlainTextSourceDescriptor,
    add_citation,
    bind_citation,
    normalize_plain_text,
    verify_bound_citation,
)
from sentinel.readers.github_fixture import (
    FIXTURE_OBSERVED_AT,
    FIXTURE_SCHEMA_VERSION,
    FIXTURE_SHA256,
    GithubFixtureError,
    GithubFixtureIssue,
    GithubFixtureRead,
    read_packaged_github_fixture,
)
from sentinel.storage.connection import DatabaseOpenError, readonly_database_connection
from sentinel.storage.migrations import (
    MIGRATIONS,
    MigrationIntegrityError,
    MigrationState,
    inspect_migration_state_readonly,
    verify_integrity,
)
from sentinel.storage.schema import CURRENT_SCHEMA
from sentinel.storage.writer import (
    WriterLeaseError,
    WriterLeaseErrorCode,
    acquire_writer_lease,
)
from sentinel.sync.types import (
    FixtureSyncAdvanceReport,
    FixtureSyncAdvanceResult,
    FixtureSyncCursorStatus,
    FixtureSyncError,
    FixtureSyncErrorCode,
    IncrementalGithubFixtureState,
)

INCREMENTAL_SOURCE_ID: Final = uuid5(
    NAMESPACE_URL,
    "sentinel:github.fixture:incremental-fixture:v1:example-owner/fixture-project",
)
INCREMENTAL_CURSOR_KIND: Final = "github_fixture_page_v1"
INCREMENTAL_CURSOR_ID: Final = uuid5(
    NAMESPACE_URL,
    f"sentinel:github.fixture:incremental-cursor:v1:{INCREMENTAL_SOURCE_ID}:"
    f"{INCREMENTAL_CURSOR_KIND}",
)
INCREMENTAL_ACCOUNT_ALIAS: Final = "example-owner/fixture-project::incremental-fixture-v1"
INCREMENTAL_SOURCE_TYPE: Final = "github_issue_incremental_fixture"
INCREMENTAL_SOURCE_LABEL: Final = "synthetic incremental fixture replay"
_EXPECTED_PROVIDER_ITEM_IDS: Final = tuple(
    item.provider_item_id for item in EXPECTED_MANIFEST.items
)
_EXPECTED_MIGRATION_IDS: Final = tuple(migration.migration_id for migration in MIGRATIONS)
_UTC_SUFFIX: Final = "Z"
_MAX_PAGE_GENERATION: Final = len(EXPECTED_MANIFEST.items)
_CURSOR_REF_PREFIX: Final = "sentinel-github-fixture-cursor-v1:sha256:"
_EXPECTED_CURSOR_REFERENCES: Final = (
    "sentinel-github-fixture-cursor-v1:sha256:"
    "b0a86a69093d798fd131a592db0e23d48763f00e226d241c20e3a2c0b2627173",
    "sentinel-github-fixture-cursor-v1:sha256:"
    "24a0c93aac9300969bb7af5229955350649648d26b8c81d5458b99635228e2ad",
    "sentinel-github-fixture-cursor-v1:sha256:"
    "1b766238c2310bf81d1bb6b4faf03469ade2006c67e8dbbb7a40aed538776604",
    "sentinel-github-fixture-cursor-v1:sha256:"
    "58ec1cb3456a12e07d1f45ed444a7db8df7d99f67ae9d435c1bacb930282861b",
)
_FIXED_OBSERVED_AT: Final = EXPECTED_MANIFEST.observed_at


@dataclass(frozen=True, slots=True)
class _ExpectedPageSpan:
    values: tuple[object, ...]
    original_span_id: UUID
    source_id: UUID
    content_sha256: str

    @property
    def start_byte(self) -> int:
        return cast(int, self.values[2])

    @property
    def end_byte(self) -> int:
        return cast(int, self.values[3])

    @property
    def text_sha256(self) -> str:
        return cast(str, self.values[4])


@dataclass(frozen=True, slots=True)
class _ExpectedPageItem:
    values: tuple[object, ...]
    source_envelope_id: UUID
    page_index: int
    spans: tuple[_ExpectedPageSpan, ...]
    body: bytes = field(repr=False)

    @property
    def item_id(self) -> UUID:
        return UUID(str(self.values[0]))

    @property
    def provider_item_id(self) -> str:
        return str(self.values[2])

    @property
    def content_sha256(self) -> str:
        return str(self.values[6])


def _fail(code: FixtureSyncErrorCode) -> NoReturn:
    raise FixtureSyncError(code) from None


def _map_writer_error(error: WriterLeaseError) -> FixtureSyncError:
    if error.code in {
        WriterLeaseErrorCode.LOCK_CONTENDED,
        WriterLeaseErrorCode.LOCK_UNAVAILABLE,
        WriterLeaseErrorCode.REENTRANT,
        WriterLeaseErrorCode.UNSUPPORTED_PLATFORM,
    }:
        return FixtureSyncError(FixtureSyncErrorCode.WRITER_UNAVAILABLE)
    if error.code in {
        WriterLeaseErrorCode.MIGRATION_INVALID,
        WriterLeaseErrorCode.DATABASE_INVALID,
    }:
        return FixtureSyncError(FixtureSyncErrorCode.SCHEMA_NOT_CURRENT)
    if error.code is WriterLeaseErrorCode.INVALID_PATH:
        return FixtureSyncError(FixtureSyncErrorCode.INVALID_PATH)
    return FixtureSyncError(FixtureSyncErrorCode.DATABASE_UNAVAILABLE)


def _map_h1_error(error: GithubBlobIntegrationError) -> NoReturn:
    mapping = {
        GithubBlobIntegrationErrorCode.INVALID_PATH: FixtureSyncErrorCode.INVALID_PATH,
        GithubBlobIntegrationErrorCode.DATABASE_UNAVAILABLE: (
            FixtureSyncErrorCode.DATABASE_UNAVAILABLE
        ),
        GithubBlobIntegrationErrorCode.SCHEMA_NOT_CURRENT: (
            FixtureSyncErrorCode.SCHEMA_NOT_CURRENT
        ),
        GithubBlobIntegrationErrorCode.INTEGRITY_FAILURE: (FixtureSyncErrorCode.INTEGRITY_FAILURE),
        GithubBlobIntegrationErrorCode.REGISTRATION_CONFLICT: (
            FixtureSyncErrorCode.SOURCE_CONFLICT
        ),
        GithubBlobIntegrationErrorCode.ITEM_CONFLICT: FixtureSyncErrorCode.ITEM_CONFLICT,
        GithubBlobIntegrationErrorCode.SPAN_CONFLICT: FixtureSyncErrorCode.SPAN_CONFLICT,
        GithubBlobIntegrationErrorCode.BLOB_UNAVAILABLE: FixtureSyncErrorCode.BLOB_UNAVAILABLE,
        GithubBlobIntegrationErrorCode.BLOB_INVALID: FixtureSyncErrorCode.BLOB_INVALID,
        GithubBlobIntegrationErrorCode.CONTENT_REF_INVALID: FixtureSyncErrorCode.BLOB_INVALID,
    }
    _fail(mapping.get(error.code, FixtureSyncErrorCode.INTEGRITY_FAILURE))


def _map_store_error(error: PublicFixtureStoreError) -> NoReturn:
    if error.code in {
        PublicFixtureStoreErrorCode.INVALID_ROOT,
        PublicFixtureStoreErrorCode.UNSUPPORTED_FILESYSTEM,
    }:
        _fail(FixtureSyncErrorCode.INVALID_PATH)
    if error.code in {
        PublicFixtureStoreErrorCode.STORE_UNINITIALIZED,
        PublicFixtureStoreErrorCode.BLOB_NOT_FOUND,
    }:
        _fail(FixtureSyncErrorCode.BLOB_UNAVAILABLE)
    if error.code in {
        PublicFixtureStoreErrorCode.STORE_INVALID,
        PublicFixtureStoreErrorCode.BLOB_INVALID,
        PublicFixtureStoreErrorCode.FIXTURE_INVALID,
    }:
        _fail(FixtureSyncErrorCode.BLOB_INVALID)
    _fail(FixtureSyncErrorCode.DATABASE_UNAVAILABLE)


def _map_ingestion_error(error: GithubFixtureIngestionError) -> NoReturn:
    if error.code.value == "invalid_path":
        _fail(FixtureSyncErrorCode.INVALID_PATH)
    if error.code.value == "multiple_hard_links":
        _fail(FixtureSyncErrorCode.INVALID_PATH)
    _fail(FixtureSyncErrorCode.DATABASE_UNAVAILABLE)


def _database_path(database: str | Path) -> Path:
    try:
        return _validate_database_path(database)
    except GithubFixtureIngestionError as error:
        _map_ingestion_error(error)


def _database_identity(path: Path) -> tuple[Path, int, int]:
    try:
        return _database_file_identity(path)
    except GithubFixtureIngestionError as error:
        _map_ingestion_error(error)


def _require_current_state(connection: sqlite3.Connection) -> MigrationState:
    try:
        state = inspect_migration_state_readonly(connection)
        if (
            not state.is_current
            or state.applied_migration_ids != _EXPECTED_MIGRATION_IDS
            or state.schema_version != CURRENT_SCHEMA.schema_version
        ):
            _fail(FixtureSyncErrorCode.SCHEMA_NOT_CURRENT)
        verify_integrity(connection)
        return state
    except FixtureSyncError:
        raise
    except (MigrationIntegrityError, sqlite3.Error):
        _fail(FixtureSyncErrorCode.INTEGRITY_FAILURE)


def _require_current_database(database: Path) -> None:
    try:
        with readonly_database_connection(database) as connection:
            _require_current_state(connection)
    except FixtureSyncError:
        raise
    except (DatabaseOpenError, OSError, sqlite3.Error):
        _fail(FixtureSyncErrorCode.DATABASE_UNAVAILABLE)


def _require_current_schema_in_transaction(connection: sqlite3.Connection) -> None:
    """Recheck all trusted migration rows and schema objects after BEGIN IMMEDIATE."""

    try:
        rows = connection.execute(
            """SELECT migration_id, artifact_sha256, success
               FROM schema_migrations ORDER BY applied_at, migration_id"""
        ).fetchall()
        expected_history = tuple(
            (migration.migration_id, migration.artifact_sha256, 1) for migration in MIGRATIONS
        )
        if tuple(tuple(row) for row in rows) != expected_history:
            _fail(FixtureSyncErrorCode.SCHEMA_NOT_CURRENT)

        actual_rows = connection.execute(
            """SELECT type, name, sql FROM sqlite_master
               WHERE name NOT GLOB 'sqlite_*'
                 AND type IN ('table', 'index', 'view', 'trigger')"""
        ).fetchall()
        actual = {(str(kind), str(name)): sql for kind, name, sql in actual_rows}
        expected = {(item.object_type, item.name): item.sql for item in CURRENT_SCHEMA.objects}
        if actual.keys() != expected.keys() or any(
            not isinstance(actual[key], str) or actual[key].strip() != sql.strip()
            for key, sql in expected.items()
        ):
            _fail(FixtureSyncErrorCode.SCHEMA_NOT_CURRENT)
    except FixtureSyncError:
        raise
    except sqlite3.Error:
        _fail(FixtureSyncErrorCode.SCHEMA_NOT_CURRENT)


def _expected_cursor_reference(generation: int) -> str:
    if type(generation) is not int or not 0 <= generation <= _MAX_PAGE_GENERATION:
        _fail(FixtureSyncErrorCode.INVALID_INPUT)
    payload = _canonical_json(
        {
            "cursor_schema": "sentinel.github-fixture-cursor.v1",
            "fixture_sha256": FIXTURE_SHA256,
            "fixture_version": FIXTURE_SCHEMA_VERSION,
            "incremental_source_id": str(INCREMENTAL_SOURCE_ID),
            "sequence": generation,
        }
    ).encode("utf-8", errors="strict")
    digest = hashlib.sha256(payload).hexdigest()
    pinned = _EXPECTED_CURSOR_REFERENCES[generation]
    if pinned != f"{_CURSOR_REF_PREFIX}{digest}":
        _fail(FixtureSyncErrorCode.FIXTURE_INVALID)
    return pinned


def _canonical_json(value: dict[str, object]) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, UnicodeEncodeError):
        _fail(FixtureSyncErrorCode.FIXTURE_INVALID)


def _source_values() -> tuple[object, ...]:
    scope = _canonical_json(
        {
            "fixture_sha256": FIXTURE_SHA256,
            "fixture_version": FIXTURE_SCHEMA_VERSION,
            "mode": INCREMENTAL_SOURCE_LABEL,
            "repository": "example-owner/fixture-project",
        }
    )
    return (
        str(INCREMENTAL_SOURCE_ID),
        "github.fixture",
        "1.0.0",
        EXPECTED_MANIFEST.principal_row[0],
        INCREMENTAL_SOURCE_TYPE,
        INCREMENTAL_ACCOUNT_ALIAS,
        scope,
        "[]",
        TrustLabel.T4_EXTERNAL.value,
        SensitivityLabel.PUBLIC.value,
        1,
        _FIXED_OBSERVED_AT,
    )


def _cursor_timestamp(value: object) -> datetime:
    if type(value) is not str:
        _fail(FixtureSyncErrorCode.CURSOR_CONFLICT)
    try:
        parsed = datetime.fromisoformat(value.replace(_UTC_SUFFIX, "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            _fail(FixtureSyncErrorCode.CURSOR_CONFLICT)
        normalized = parsed.astimezone(UTC)
        if _utc_timestamp(normalized) != value:
            _fail(FixtureSyncErrorCode.CURSOR_CONFLICT)
        return normalized
    except FixtureSyncError:
        raise
    except (OverflowError, TypeError, ValueError):
        _fail(FixtureSyncErrorCode.CURSOR_CONFLICT)


def _utc_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _utc_now() -> datetime:
    """Internal clock seam; callers cannot supply cursor commit timestamps."""

    return datetime.now(UTC)


def _next_commit_timestamp(previous: object | None) -> str:
    now = _utc_now()
    if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
        _fail(FixtureSyncErrorCode.PERSISTENCE_FAILURE)
    normalized = now.astimezone(UTC)
    if previous is not None:
        previous_time = _cursor_timestamp(previous)
        if normalized <= previous_time:
            normalized = previous_time + timedelta(microseconds=1)
    try:
        return _utc_timestamp(normalized)
    except (OverflowError, ValueError):
        _fail(FixtureSyncErrorCode.PERSISTENCE_FAILURE)


def _item_id(source_id: UUID, provider_item_id: str, content_sha256: str) -> UUID:
    return uuid5(
        NAMESPACE_URL,
        "sentinel:github.fixture:incremental-item:v1:"
        f"{source_id}:{provider_item_id}:{content_sha256}",
    )


def _persisted_span_id(item_id: UUID, original_span_id: UUID) -> UUID:
    return uuid5(
        NAMESPACE_URL,
        f"sentinel:github.fixture:incremental-span:v1:{item_id}:{original_span_id}",
    )


def _verify_h1_rows(connection: sqlite3.Connection) -> None:
    try:
        verify_h1_registration(connection)
        state = verify_h1_items(connection, accepted_states=("blob",))
        if state != "blob":
            _fail(FixtureSyncErrorCode.BLOB_INVALID)
        verify_h1_spans(connection)
    except FixtureSyncError:
        raise
    except GithubBlobIntegrationError as error:
        _map_h1_error(error)
    except sqlite3.Error:
        _fail(FixtureSyncErrorCode.INTEGRITY_FAILURE)


def _verify_h1_precondition(database: Path, store_root: str | Path) -> None:
    try:
        snapshot = read_blob_backed_github_fixture(database, store_root=store_root)
        if (
            snapshot.fixture_version != FIXTURE_SCHEMA_VERSION
            or snapshot.fixture_sha256 != FIXTURE_SHA256
            or snapshot.manifest_sha256 != EXPECTED_MANIFEST.sha256
            or len(snapshot.items) != len(EXPECTED_MANIFEST.items)
        ):
            _fail(FixtureSyncErrorCode.BLOB_INVALID)
        for expected in EXPECTED_MANIFEST.items:
            body = read_public_fixture_blob(store_root, content_sha256=expected.content_sha256)
            if (
                type(body) is not bytes
                or hashlib.sha256(body).hexdigest() != expected.content_sha256
            ):
                _fail(FixtureSyncErrorCode.BLOB_INVALID)
    except FixtureSyncError:
        raise
    except GithubBlobIntegrationError as error:
        _map_h1_error(error)
    except PublicFixtureStoreError as error:
        _map_store_error(error)
    except (TypeError, ValueError, OSError, RuntimeError):
        _fail(FixtureSyncErrorCode.BLOB_INVALID)


def _provider_item_id(issue: GithubFixtureIssue) -> str:
    return f"{issue.repository}#{issue.issue_number}"


def _build_expected_item(
    issue: GithubFixtureIssue,
    manifest_item: ExpectedItem,
    *,
    page_index: int,
) -> _ExpectedPageItem:
    original = manifest_item.values
    source_id = manifest_item.source_envelope_id
    body = issue.normalized_source.original_bytes
    digest = hashlib.sha256(body).hexdigest()
    try:
        envelope = issue.normalized_source.envelope
        if (
            envelope.source_id != source_id
            or envelope.provider_id != "github.fixture"
            or envelope.trust is not TrustLabel.T4_EXTERNAL
            or envelope.sensitivity is not SensitivityLabel.PUBLIC
            or envelope.content_sha256 != manifest_item.content_sha256
            or digest != manifest_item.content_sha256
            or issue.updated_at.isoformat() != str(original[10])
            or len(issue.citations) != len(manifest_item.spans)
        ):
            _fail(FixtureSyncErrorCode.FIXTURE_INVALID)
        for citation, expected_span in zip(issue.citations, manifest_item.spans, strict=True):
            if (
                citation.source_id != expected_span.source_id
                or citation.content_sha256 != expected_span.content_sha256
                or citation.span.span_id != expected_span.in_memory_span_id
                or citation.span.start_byte != expected_span.start_byte
                or citation.span.end_byte != expected_span.end_byte
                or citation.span.text_sha256 != expected_span.text_sha256
            ):
                _fail(FixtureSyncErrorCode.FIXTURE_INVALID)
            verify_bound_citation(
                issue.normalized_source,
                citation,
                original_bytes=body,
            )
    except FixtureSyncError:
        raise
    except (NormalizationError, TypeError, ValueError):
        _fail(FixtureSyncErrorCode.FIXTURE_INVALID)

    item_uuid = _item_id(INCREMENTAL_SOURCE_ID, manifest_item.provider_item_id, digest)
    metadata = _canonical_json(
        {
            "encoding": "utf-8",
            "fixture_sha256": FIXTURE_SHA256,
            "fixture_version": FIXTURE_SCHEMA_VERSION,
            "in_memory_source_id": str(source_id),
            "issue_number": issue.issue_number,
            "page_index": page_index,
            "repository": issue.repository,
            "source_updated_at": str(original[10]),
            "sync_mode": INCREMENTAL_SOURCE_LABEL,
        }
    )
    values: tuple[object, ...] = (
        str(item_uuid),
        str(INCREMENTAL_SOURCE_ID),
        manifest_item.provider_item_id,
        original[3],
        original[4],
        blob_ref(manifest_item),
        digest,
        TrustLabel.T4_EXTERNAL.value,
        SensitivityLabel.PUBLIC.value,
        str(original[9]),
        str(original[10]),
        None,
        metadata,
    )
    spans = tuple(
        _ExpectedPageSpan(
            values=(
                str(_persisted_span_id(item_uuid, expected_span.in_memory_span_id)),
                str(item_uuid),
                expected_span.start_byte,
                expected_span.end_byte,
                expected_span.text_sha256,
                None,
                None,
            ),
            original_span_id=expected_span.in_memory_span_id,
            source_id=expected_span.source_id,
            content_sha256=expected_span.content_sha256,
        )
        for expected_span in manifest_item.spans
    )
    return _ExpectedPageItem(
        values=values,
        source_envelope_id=source_id,
        page_index=page_index,
        spans=spans,
        body=body,
    )


def _load_fixture_pages(store_root: str | Path, database: Path) -> tuple[_ExpectedPageItem, ...]:
    _verify_h1_precondition(database, store_root)
    try:
        manifest = load_expected_manifest()
        fixture = read_packaged_github_fixture()
        if (
            type(fixture) is not GithubFixtureRead
            or fixture.fixture_version != FIXTURE_SCHEMA_VERSION
            or fixture.fixture_sha256 != FIXTURE_SHA256
            or fixture.fixture_version != manifest.fixture_version
            or fixture.fixture_sha256 != manifest.fixture_sha256
            or tuple(_provider_item_id(issue) for issue in fixture.issues)
            != _EXPECTED_PROVIDER_ITEM_IDS
            or len(fixture.issues) != len(manifest.items)
        ):
            _fail(FixtureSyncErrorCode.FIXTURE_INVALID)
        items: list[_ExpectedPageItem] = []
        for page_index, (issue, expected) in enumerate(
            zip(fixture.issues, manifest.items, strict=True), start=1
        ):
            if _provider_item_id(issue) != expected.provider_item_id:
                _fail(FixtureSyncErrorCode.FIXTURE_INVALID)
            item = _build_expected_item(issue, expected, page_index=page_index)
            blob = read_public_fixture_blob(store_root, content_sha256=item.content_sha256)
            if blob != item.body or hashlib.sha256(blob).hexdigest() != item.content_sha256:
                _fail(FixtureSyncErrorCode.BLOB_INVALID)
            items.append(item)
        return tuple(items)
    except FixtureSyncError:
        raise
    except PublicFixtureStoreError as error:
        _map_store_error(error)
    except GithubFixtureError:
        _fail(FixtureSyncErrorCode.FIXTURE_INVALID)
    except (NormalizationError, MigrationIntegrityError, TypeError, ValueError, OSError):
        _fail(FixtureSyncErrorCode.FIXTURE_INVALID)
    except Exception:
        _fail(FixtureSyncErrorCode.FIXTURE_INVALID)


def _verify_body_and_spans(
    expected: _ExpectedPageItem,
    body: bytes,
) -> None:
    if (
        type(body) is not bytes
        or hashlib.sha256(body).hexdigest() != expected.content_sha256
        or (expected.body and body != expected.body)
    ):
        _fail(FixtureSyncErrorCode.BLOB_INVALID)
    try:
        descriptor = PlainTextSourceDescriptor(
            source_id=expected.source_envelope_id,
            provider_id="github.fixture",
            observed_at=FIXTURE_OBSERVED_AT,
            trust=TrustLabel.T4_EXTERNAL,
            sensitivity=SensitivityLabel.PUBLIC,
        )
        normalized = normalize_plain_text(
            descriptor,
            body,
            "text/plain; charset=utf-8",
        )
        if normalized.envelope.content_sha256 != expected.content_sha256:
            _fail(FixtureSyncErrorCode.BLOB_INVALID)
        for span in expected.spans:
            normalized = add_citation(
                normalized,
                span_id=span.original_span_id,
                start_byte=span.start_byte,
                end_byte=span.end_byte,
            )
            bound = bind_citation(normalized, normalized.citations[-1])
            if (
                bound.source_id != span.source_id
                or bound.content_sha256 != span.content_sha256
                or bound.span.span_id != span.original_span_id
                or bound.span.text_sha256 != span.text_sha256
            ):
                _fail(FixtureSyncErrorCode.SPAN_CONFLICT)
            verify_bound_citation(normalized, bound, original_bytes=body)
    except FixtureSyncError:
        raise
    except PublicFixtureStoreError as error:
        _map_store_error(error)
    except NormalizationError:
        _fail(FixtureSyncErrorCode.SPAN_CONFLICT)
    except (TypeError, ValueError):
        _fail(FixtureSyncErrorCode.SPAN_CONFLICT)


def _cursor_values(generation: int, last_commit_at: str) -> tuple[object, ...]:
    if not 0 <= generation <= _MAX_PAGE_GENERATION:
        _fail(FixtureSyncErrorCode.CURSOR_CONFLICT)
    return (
        str(INCREMENTAL_CURSOR_ID),
        str(INCREMENTAL_SOURCE_ID),
        INCREMENTAL_CURSOR_KIND,
        _expected_cursor_reference(generation),
        None,  # This fixture replay has no provider ETag.
        generation,
        None,  # No provider full-sync operation is performed by this replay.
        last_commit_at,
        "COMPLETE" if generation == _MAX_PAGE_GENERATION else "READY",
    )


def _verify_source_row(connection: sqlite3.Connection, *, required: bool = True) -> bool:
    query = (
        "SELECT source_id, plugin_id, plugin_version, principal_id, source_type, "
        "account_alias, scope_json, host_allowlist_json, trust, default_sensitivity, "
        "enabled, created_at FROM sources WHERE source_id = ? OR "
        "(plugin_id = ? AND account_alias = ?) ORDER BY source_id LIMIT 2"
    )
    expected = _source_values()
    try:
        rows = connection.execute(
            query,
            (str(INCREMENTAL_SOURCE_ID), "github.fixture", INCREMENTAL_ACCOUNT_ALIAS),
        ).fetchall()
    except sqlite3.Error:
        _fail(FixtureSyncErrorCode.INTEGRITY_FAILURE)
    if not rows:
        if required:
            _fail(FixtureSyncErrorCode.SOURCE_CONFLICT)
        return False
    if len(rows) != 1 or tuple(rows[0]) != expected:
        _fail(FixtureSyncErrorCode.SOURCE_CONFLICT)
    return True


def _read_cursor(connection: sqlite3.Connection) -> tuple[object, ...] | None:
    try:
        rows = connection.execute(
            """SELECT cursor_id, source_id, cursor_kind, value_cipher_ref, etag,
                      generation, last_full_sync_at, last_commit_at, status
               FROM sync_cursors WHERE source_id = ? OR cursor_id = ?
               ORDER BY cursor_id LIMIT 2""",
            (str(INCREMENTAL_SOURCE_ID), str(INCREMENTAL_CURSOR_ID)),
        ).fetchall()
    except sqlite3.Error:
        _fail(FixtureSyncErrorCode.INTEGRITY_FAILURE)
    if not rows:
        return None
    if len(rows) != 1:
        _fail(FixtureSyncErrorCode.CURSOR_CONFLICT)
    return tuple(rows[0])


def _verify_cursor(
    cursor: tuple[object, ...] | None,
    *,
    expected_generation: int | None = None,
) -> int:
    if cursor is None:
        _fail(FixtureSyncErrorCode.CURSOR_CONFLICT)
    if (
        cursor[0] != str(INCREMENTAL_CURSOR_ID)
        or cursor[1] != str(INCREMENTAL_SOURCE_ID)
        or cursor[2] != INCREMENTAL_CURSOR_KIND
        or cursor[4] is not None
        or cursor[6] is not None
        or type(cursor[5]) is not int
        or not 0 <= cursor[5] <= _MAX_PAGE_GENERATION
        or cursor[3] != _expected_cursor_reference(cursor[5])
        or cursor[8] != ("COMPLETE" if cursor[5] == _MAX_PAGE_GENERATION else "READY")
    ):
        _fail(FixtureSyncErrorCode.CURSOR_CONFLICT)
    _cursor_timestamp(cursor[7])
    generation = int(cursor[5])
    if expected_generation is not None and generation != expected_generation:
        _fail(FixtureSyncErrorCode.CURSOR_CONFLICT)
    return generation


def _expected_item_for_page(
    issue: _ExpectedPageItem,
) -> tuple[object, ...]:
    return issue.values


def _verify_page_item(connection: sqlite3.Connection, expected: _ExpectedPageItem) -> None:
    columns = (
        "item_id, source_id, provider_item_id, provider_revision, canonical_uri, "
        "content_ref, content_sha256, trust, sensitivity, observed_at, source_at, "
        "deleted_at, metadata_json"
    )
    try:
        rows = connection.execute(
            f"SELECT {columns} FROM source_items WHERE item_id = ? OR "
            "(source_id = ? AND provider_item_id = ?) ORDER BY item_id LIMIT 2",
            (str(expected.item_id), str(INCREMENTAL_SOURCE_ID), expected.provider_item_id),
        ).fetchall()
    except sqlite3.Error:
        _fail(FixtureSyncErrorCode.INTEGRITY_FAILURE)
    if len(rows) != 1 or tuple(rows[0]) != _expected_item_for_page(expected):
        _fail(FixtureSyncErrorCode.ITEM_CONFLICT)


def _verify_page_spans(connection: sqlite3.Connection, expected: _ExpectedPageItem) -> None:
    columns = (
        "span_id, item_id, start_byte, end_byte, text_sha256, context_ref, derived_by_boundary_id"
    )
    try:
        rows = connection.execute(
            f"SELECT {columns} FROM source_spans WHERE item_id = ? ORDER BY span_id LIMIT ?",
            (str(expected.item_id), len(expected.spans) + 1),
        ).fetchall()
        actual = tuple(sorted((tuple(row) for row in rows), key=lambda row: str(row[0])))
        wanted = tuple(sorted(expected.spans, key=lambda span: str(span.values[0])))
        if len(actual) != len(wanted) or actual != tuple(span.values for span in wanted):
            _fail(FixtureSyncErrorCode.SPAN_CONFLICT)
        for span in expected.spans:
            by_id = connection.execute(
                f"SELECT {columns} FROM source_spans WHERE span_id = ?",
                (str(span.values[0]),),
            ).fetchone()
            if by_id is None or tuple(by_id) != span.values:
                _fail(FixtureSyncErrorCode.SPAN_CONFLICT)
    except FixtureSyncError:
        raise
    except sqlite3.Error:
        _fail(FixtureSyncErrorCode.INTEGRITY_FAILURE)


def _verify_all_incremental_items(
    connection: sqlite3.Connection,
    expected_pages: tuple[_ExpectedPageItem, ...],
    *,
    generation: int,
) -> None:
    expected = expected_pages[:generation]
    try:
        rows = connection.execute(
            """SELECT item_id, source_id, provider_item_id, provider_revision,
                      canonical_uri, content_ref, content_sha256, trust, sensitivity,
                      observed_at, source_at, deleted_at, metadata_json
               FROM source_items WHERE source_id = ? ORDER BY provider_item_id, item_id LIMIT ?""",
            (str(INCREMENTAL_SOURCE_ID), _MAX_PAGE_GENERATION + 1),
        ).fetchall()
    except sqlite3.Error:
        _fail(FixtureSyncErrorCode.INTEGRITY_FAILURE)
    actual = tuple(tuple(row) for row in rows)
    wanted = tuple(sorted((item.values for item in expected), key=lambda row: str(row[2])))
    if len(actual) != generation or actual != wanted:
        _fail(FixtureSyncErrorCode.ITEM_CONFLICT)
    for item in expected:
        _verify_page_item(connection, item)
        _verify_page_spans(connection, item)


def _verify_complete_state(
    connection: sqlite3.Connection,
    *,
    store_root: str | Path,
    expected_generation: int | None = None,
) -> IncrementalGithubFixtureState:
    _verify_h1_rows(connection)
    _verify_source_row(connection)
    cursor = _read_cursor(connection)
    generation = _verify_cursor(cursor, expected_generation=expected_generation)
    pages = _load_expected_pages_without_fixture()
    _verify_all_incremental_items(connection, pages, generation=generation)
    # Re-run the body checks using explicitly selected, allowlisted blob reads.
    for item in pages[:generation]:
        body = read_public_fixture_blob(store_root, content_sha256=item.content_sha256)
        _verify_body_and_spans(item, body)
    return _state(generation)


def _load_expected_pages_without_fixture() -> tuple[_ExpectedPageItem, ...]:
    """Construct metadata-only expectations for readback from the pinned H1 manifest."""

    try:
        manifest = load_expected_manifest()
        if (
            manifest.fixture_version != FIXTURE_SCHEMA_VERSION
            or manifest.fixture_sha256 != FIXTURE_SHA256
            or len(manifest.items) != len(_EXPECTED_PROVIDER_ITEM_IDS)
        ):
            _fail(FixtureSyncErrorCode.FIXTURE_INVALID)
        output: list[_ExpectedPageItem] = []
        for page_index, original in enumerate(manifest.items, start=1):
            original_row = original.values
            source_id = original.source_envelope_id
            item_uuid = _item_id(
                INCREMENTAL_SOURCE_ID,
                original.provider_item_id,
                original.content_sha256,
            )
            original_metadata = json.loads(str(original_row[12]))
            metadata = _canonical_json(
                {
                    "encoding": "utf-8",
                    "fixture_sha256": FIXTURE_SHA256,
                    "fixture_version": FIXTURE_SCHEMA_VERSION,
                    "in_memory_source_id": str(source_id),
                    "issue_number": original_metadata["issue_number"],
                    "page_index": page_index,
                    "repository": original_metadata["repository"],
                    "source_updated_at": str(original_row[10]),
                    "sync_mode": INCREMENTAL_SOURCE_LABEL,
                }
            )
            values: tuple[object, ...] = (
                str(item_uuid),
                str(INCREMENTAL_SOURCE_ID),
                original.provider_item_id,
                original_row[3],
                original_row[4],
                blob_ref(original),
                original.content_sha256,
                TrustLabel.T4_EXTERNAL.value,
                SensitivityLabel.PUBLIC.value,
                str(original_row[9]),
                str(original_row[10]),
                None,
                metadata,
            )
            spans = tuple(
                _ExpectedPageSpan(
                    values=(
                        str(_persisted_span_id(item_uuid, span.in_memory_span_id)),
                        str(item_uuid),
                        span.start_byte,
                        span.end_byte,
                        span.text_sha256,
                        None,
                        None,
                    ),
                    original_span_id=span.in_memory_span_id,
                    source_id=span.source_id,
                    content_sha256=span.content_sha256,
                )
                for span in original.spans
            )
            output.append(
                _ExpectedPageItem(
                    values=values,
                    source_envelope_id=source_id,
                    page_index=page_index,
                    spans=spans,
                    body=b"",
                )
            )
        if tuple(item.provider_item_id for item in output) != _EXPECTED_PROVIDER_ITEM_IDS:
            _fail(FixtureSyncErrorCode.FIXTURE_INVALID)
        return tuple(output)
    except FixtureSyncError:
        raise
    except Exception:
        _fail(FixtureSyncErrorCode.FIXTURE_INVALID)


def _state(generation: int) -> IncrementalGithubFixtureState:
    page_counts = tuple(len(item.spans) for item in EXPECTED_MANIFEST.items)
    return IncrementalGithubFixtureState(
        source_id=INCREMENTAL_SOURCE_ID,
        cursor_id=INCREMENTAL_CURSOR_ID,
        generation=generation,
        completed_pages=generation,
        total_pages=_MAX_PAGE_GENERATION,
        item_count=generation,
        span_count=sum(page_counts[:generation]),
        cursor_status=(
            FixtureSyncCursorStatus.COMPLETE
            if generation == _MAX_PAGE_GENERATION
            else FixtureSyncCursorStatus.READY
        ),
        fixture_version=FIXTURE_SCHEMA_VERSION,
        fixture_sha256=FIXTURE_SHA256,
    )


def _register_source_and_cursor(connection: sqlite3.Connection) -> bool:
    """Create both generation-zero rows or verify an existing complete pair."""

    source_rows = connection.execute(
        "SELECT source_id, plugin_id, plugin_version, principal_id, source_type, "
        "account_alias, scope_json, host_allowlist_json, trust, default_sensitivity, "
        "enabled, created_at FROM sources WHERE source_id = ? OR "
        "(plugin_id = ? AND account_alias = ?) ORDER BY source_id LIMIT 2",
        (str(INCREMENTAL_SOURCE_ID), "github.fixture", INCREMENTAL_ACCOUNT_ALIAS),
    ).fetchall()
    cursor = _read_cursor(connection)
    if not source_rows and cursor is None:
        stray_items = connection.execute(
            "SELECT 1 FROM source_items WHERE source_id = ? LIMIT 1",
            (str(INCREMENTAL_SOURCE_ID),),
        ).fetchone()
        if stray_items is not None:
            _fail(FixtureSyncErrorCode.ITEM_CONFLICT)
        try:
            connection.execute(
                """INSERT INTO sources
                   (source_id, plugin_id, plugin_version, principal_id, source_type,
                    account_alias, scope_json, host_allowlist_json, trust,
                    default_sensitivity, enabled, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                _source_values(),
            )
        except sqlite3.IntegrityError:
            _fail(FixtureSyncErrorCode.SOURCE_CONFLICT)
        try:
            connection.execute(
                """INSERT INTO sync_cursors
                   (cursor_id, source_id, cursor_kind, value_cipher_ref, etag,
                    generation, last_full_sync_at, last_commit_at, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                _cursor_values(0, _next_commit_timestamp(None)),
            )
        except sqlite3.IntegrityError:
            _fail(FixtureSyncErrorCode.CURSOR_CONFLICT)
        return True

    if not source_rows or len(source_rows) != 1 or cursor is None:
        _fail(FixtureSyncErrorCode.SOURCE_CONFLICT)
    if tuple(source_rows[0]) != _source_values():
        _fail(FixtureSyncErrorCode.SOURCE_CONFLICT)
    _verify_cursor(cursor)
    return False


def _insert_page_item(connection: sqlite3.Connection, expected: _ExpectedPageItem) -> None:
    try:
        connection.execute(
            """INSERT INTO source_items
               (item_id, source_id, provider_item_id, provider_revision, canonical_uri,
                content_ref, content_sha256, trust, sensitivity, observed_at, source_at,
                deleted_at, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            expected.values,
        )
    except sqlite3.IntegrityError:
        _fail(FixtureSyncErrorCode.ITEM_CONFLICT)


def _insert_page_span(connection: sqlite3.Connection, span: _ExpectedPageSpan) -> None:
    try:
        connection.execute(
            """INSERT INTO source_spans
               (span_id, item_id, start_byte, end_byte, text_sha256, context_ref,
                derived_by_boundary_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            span.values,
        )
    except sqlite3.IntegrityError:
        _fail(FixtureSyncErrorCode.SPAN_CONFLICT)


def _advance_cursor(
    connection: sqlite3.Connection,
    *,
    previous: tuple[object, ...],
    next_generation: int,
) -> None:
    next_values = _cursor_values(
        next_generation,
        _next_commit_timestamp(previous[7]),
    )
    try:
        cursor = connection.execute(
            """UPDATE sync_cursors
               SET value_cipher_ref = ?, etag = ?, generation = ?, last_full_sync_at = ?,
                   last_commit_at = ?, status = ?
               WHERE cursor_id = ? AND source_id = ? AND cursor_kind = ?
                 AND generation = ? AND value_cipher_ref = ?""",
            (
                next_values[3],
                next_values[4],
                next_values[5],
                next_values[6],
                next_values[7],
                next_values[8],
                previous[0],
                previous[1],
                previous[2],
                previous[5],
                previous[3],
            ),
        )
    except sqlite3.Error:
        _fail(FixtureSyncErrorCode.PERSISTENCE_FAILURE)
    if cursor.rowcount != 1:
        _fail(FixtureSyncErrorCode.CURSOR_CONFLICT)


def setup_incremental_github_fixture(
    database: str | Path,
    *,
    store_root: str | Path,
) -> IncrementalGithubFixtureState:
    """Explicitly register the isolated synthetic source and generation-zero cursor."""

    path = _database_path(database)
    initial_identity = _database_identity(path)
    _require_current_database(path)
    _verify_h1_precondition(path, store_root)
    try:
        with acquire_writer_lease(path) as lease:
            if _database_identity(path) != initial_identity:
                _fail(FixtureSyncErrorCode.DATABASE_UNAVAILABLE)
            _require_current_database(path)
            with lease.transaction() as connection:
                _require_current_schema_in_transaction(connection)
                _verify_h1_rows(connection)
                created = _register_source_and_cursor(connection)
                state = _verify_complete_state(connection, store_root=store_root)
                if created and state.generation != 0:
                    _fail(FixtureSyncErrorCode.CURSOR_CONFLICT)
            return state
    except FixtureSyncError:
        raise
    except WriterLeaseError as error:
        raise _map_writer_error(error) from None
    except GithubBlobIntegrationError as error:
        _map_h1_error(error)
    except PublicFixtureStoreError as error:
        _map_store_error(error)
    except (DatabaseOpenError, OSError, sqlite3.Error):
        _fail(FixtureSyncErrorCode.DATABASE_UNAVAILABLE)
    except Exception:
        _fail(FixtureSyncErrorCode.PERSISTENCE_FAILURE)


def advance_incremental_github_fixture(
    database: str | Path,
    *,
    store_root: str | Path,
    expected_generation: int,
) -> FixtureSyncAdvanceReport:
    """Atomically apply at most the one page after ``expected_generation``.

    ``expected_generation`` is the cursor generation observed by the caller.
    Repeating the immediately prior generation verifies and reports the already
    committed page. Older values are stale; future values are out of order.
    """

    if type(expected_generation) is not int or not 0 <= expected_generation <= _MAX_PAGE_GENERATION:
        _fail(FixtureSyncErrorCode.INVALID_INPUT)
    path = _database_path(database)
    initial_identity = _database_identity(path)
    _require_current_database(path)
    pages = _load_fixture_pages(store_root, path)

    try:
        with acquire_writer_lease(path) as lease:
            if _database_identity(path) != initial_identity:
                _fail(FixtureSyncErrorCode.DATABASE_UNAVAILABLE)
            _require_current_database(path)
            with lease.transaction() as connection:
                _require_current_schema_in_transaction(connection)
                _verify_h1_rows(connection)
                _verify_source_row(connection)
                current_cursor = _read_cursor(connection)
                current_generation = _verify_cursor(current_cursor)
                assert current_cursor is not None
                current_state = _verify_complete_state(
                    connection,
                    store_root=store_root,
                    expected_generation=current_generation,
                )

                if expected_generation > current_generation:
                    report = FixtureSyncAdvanceReport(
                        result=FixtureSyncAdvanceResult.OUT_OF_ORDER,
                        state=current_state,
                    )
                elif expected_generation < current_generation:
                    if expected_generation == current_generation - 1:
                        result = FixtureSyncAdvanceResult.ALREADY_APPLIED
                        report = FixtureSyncAdvanceReport(result=result, state=current_state)
                    else:
                        report = FixtureSyncAdvanceReport(
                            result=FixtureSyncAdvanceResult.STALE,
                            state=current_state,
                        )
                elif current_generation == _MAX_PAGE_GENERATION:
                    report = FixtureSyncAdvanceReport(
                        result=FixtureSyncAdvanceResult.COMPLETE,
                        state=current_state,
                    )
                else:
                    page = pages[current_generation]
                    _verify_body_and_spans(page, page.body)
                    _insert_page_item(connection, page)
                    for span in page.spans:
                        _insert_page_span(connection, span)
                    _advance_cursor(
                        connection,
                        previous=current_cursor,
                        next_generation=current_generation + 1,
                    )
                    next_generation = current_generation + 1
                    next_state = _verify_complete_state(
                        connection,
                        store_root=store_root,
                        expected_generation=next_generation,
                    )
                    result = (
                        FixtureSyncAdvanceResult.COMPLETE
                        if next_generation == _MAX_PAGE_GENERATION
                        else FixtureSyncAdvanceResult.APPLIED
                    )
                    report = FixtureSyncAdvanceReport(result=result, state=next_state)
            return report
    except FixtureSyncError:
        raise
    except WriterLeaseError as error:
        raise _map_writer_error(error) from None
    except GithubBlobIntegrationError as error:
        _map_h1_error(error)
    except PublicFixtureStoreError as error:
        _map_store_error(error)
    except (DatabaseOpenError, OSError, sqlite3.Error):
        _fail(FixtureSyncErrorCode.DATABASE_UNAVAILABLE)
    except Exception:
        _fail(FixtureSyncErrorCode.PERSISTENCE_FAILURE)


def read_incremental_github_fixture_state(
    database: str | Path,
    *,
    store_root: str | Path,
) -> IncrementalGithubFixtureState:
    """Read and verify complete cursor/item/span state without fixture JSON access."""

    path = _database_path(database)
    _database_identity(path)
    _require_current_database(path)
    _verify_h1_precondition(path, store_root)
    try:
        with readonly_database_connection(path) as connection:
            connection.execute("BEGIN")
            _require_current_state(connection)
            return _verify_complete_state(connection, store_root=store_root)
    except FixtureSyncError:
        raise
    except GithubBlobIntegrationError as error:
        _map_h1_error(error)
    except PublicFixtureStoreError as error:
        _map_store_error(error)
    except (DatabaseOpenError, OSError, sqlite3.Error):
        _fail(FixtureSyncErrorCode.DATABASE_UNAVAILABLE)
    except Exception:
        _fail(FixtureSyncErrorCode.PERSISTENCE_FAILURE)


__all__ = [
    "INCREMENTAL_ACCOUNT_ALIAS",
    "INCREMENTAL_CURSOR_ID",
    "INCREMENTAL_CURSOR_KIND",
    "INCREMENTAL_SOURCE_ID",
    "INCREMENTAL_SOURCE_LABEL",
    "INCREMENTAL_SOURCE_TYPE",
    "advance_incremental_github_fixture",
    "read_incremental_github_fixture_state",
    "setup_incremental_github_fixture",
]
