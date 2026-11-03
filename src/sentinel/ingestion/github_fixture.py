"""Atomic persistence for the fixed, hash-pinned PUBLIC GitHub fixture.

This module stores metadata and byte-span references only. Body bytes are
reconstructed from the fixed packaged fixture and are never stored in SQLite.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final, NoReturn
from uuid import NAMESPACE_URL, UUID, uuid5

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.ingestion.types import (
    GithubFixtureIngestionError,
    GithubFixtureIngestionErrorCode,
    GithubFixtureIngestionReport,
    PersistedGithubFixture,
    PersistedGithubItem,
    PersistedGithubSpan,
)
from sentinel.normalization import NormalizationError, verify_bound_citation
from sentinel.normalization.types import SourceBoundCitation
from sentinel.readers.github_fixture import (
    FIXTURE_OBSERVED_AT,
    FIXTURE_SCHEMA_VERSION,
    FIXTURE_SHA256,
    GITHUB_FIXTURE_NAMESPACE,
    GithubFixtureIssue,
    GithubFixtureRead,
    read_packaged_github_fixture,
)
from sentinel.storage.connection import (
    DatabaseOpenError,
    readonly_database_connection,
)
from sentinel.storage.migrations import (
    MIGRATIONS,
    MigrationIntegrityError,
    MigrationState,
    inspect_migration_state_readonly,
    verify_integrity,
)
from sentinel.storage.schema import SchemaIntegrityError
from sentinel.storage.writer import (
    WriterLeaseError,
    WriterLeaseErrorCode,
    acquire_writer_lease,
)

FIXTURE_REPOSITORY: Final = "example-owner/fixture-project"
FIXTURE_PROVIDER_ID: Final = "github.fixture"
FIXTURE_PLUGIN_ID: Final = "github.fixture"
FIXTURE_PLUGIN_VERSION: Final = "1.0.0"
FIXTURE_SOURCE_TYPE: Final = "github_issue_fixture"
FIXTURE_ACCOUNT_ALIAS: Final = FIXTURE_REPOSITORY
FIXTURE_PRINCIPAL_ID: Final = uuid5(
    NAMESPACE_URL, "sentinel:cr1-g:synthetic-fixture-principal:v1"
)
FIXTURE_REGISTRY_SOURCE_ID: Final = uuid5(
    NAMESPACE_URL, f"sentinel:github.fixture:source:{FIXTURE_REPOSITORY}"
)
FIXTURE_CREATED_AT: Final = FIXTURE_OBSERVED_AT.isoformat()
_FIXTURE_ISSUE_NUMBERS: Final = (101, 102, 103)
_CAPABILITY_JSON: Final = '["read_synthetic_fixture"]'
_PLUGIN_ENABLED: Final = 0
_HOST_ALLOWLIST_JSON: Final = "[]"
_MANIFEST_REF: Final = (
    "package-resource:sentinel.readers/fixtures/github-issues-v1.json"
)
_ORIGIN: Final = "bundled-synthetic-fixture"
_CONTENT_REF_PREFIX: Final = f"fixture:{FIXTURE_SCHEMA_VERSION}:"
_DIGEST_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
_REPARSE_POINT_ATTRIBUTE: Final = 0x0400
_SUPPORTED_LOCAL_DRIVE_TYPES: Final = frozenset({2, 3, 6})
_EXPECTED_MIGRATION_IDS: Final = tuple(migration.migration_id for migration in MIGRATIONS)

_PRINCIPAL_COLUMNS: Final = (
    "principal_id, kind, display_name, os_binding, created_at, revoked_at"
)
_PLUGIN_COLUMNS: Final = (
    "plugin_id, plugin_version, manifest_ref, manifest_sha256, origin, "
    "capability_json, trust, sensitivity, host_allowlist_json, fixture_set_sha256, "
    "enabled, registered_at"
)
_SOURCE_COLUMNS: Final = (
    "source_id, plugin_id, plugin_version, principal_id, source_type, account_alias, "
    "scope_json, host_allowlist_json, trust, default_sensitivity, enabled, created_at"
)
_ITEM_COLUMNS: Final = (
    "item_id, source_id, provider_item_id, provider_revision, canonical_uri, content_ref, "
    "content_sha256, trust, sensitivity, observed_at, source_at, deleted_at, metadata_json"
)
_SPAN_COLUMNS: Final = (
    "span_id, item_id, start_byte, end_byte, text_sha256, context_ref, "
    "derived_by_boundary_id"
)


@dataclass(frozen=True, slots=True)
class _ExpectedSpan:
    public: PersistedGithubSpan
    citation: SourceBoundCitation
    values: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class _ExpectedItem:
    issue: GithubFixtureIssue
    item_id: UUID
    provider_item_id: str
    values: tuple[object, ...]
    spans: tuple[_ExpectedSpan, ...]


@dataclass(frozen=True, slots=True)
class _ExpectedRegistry:
    principal_values: tuple[object, ...]
    plugin_values: tuple[object, ...]
    source_values: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class _PreparedFixture:
    fixture: GithubFixtureRead
    registry: _ExpectedRegistry
    items: tuple[_ExpectedItem, ...]


def _raise(code: GithubFixtureIngestionErrorCode) -> NoReturn:
    raise GithubFixtureIngestionError(code) from None


def _canonical_json(value: dict[str, str | int]) -> str:
    if type(value) is not dict or any(
        type(key) is not str or type(item) not in (str, int)
        for key, item in value.items()
    ):
        _raise(GithubFixtureIngestionErrorCode.PERSISTENCE_FAILURE)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        _raise(GithubFixtureIngestionErrorCode.PERSISTENCE_FAILURE)


def _manifest_sha256() -> str:
    manifest: dict[str, str | int] = {
        "capability_json": _CAPABILITY_JSON,
        "enabled": _PLUGIN_ENABLED,
        "fixture_set_sha256": FIXTURE_SHA256,
        "host_allowlist_json": _HOST_ALLOWLIST_JSON,
        "manifest_ref": _MANIFEST_REF,
        "origin": _ORIGIN,
        "plugin_id": FIXTURE_PLUGIN_ID,
        "plugin_version": FIXTURE_PLUGIN_VERSION,
        "registered_at": FIXTURE_CREATED_AT,
        "sensitivity": SensitivityLabel.PUBLIC.value,
        "trust": TrustLabel.T4_EXTERNAL.value,
    }
    return hashlib.sha256(_canonical_json(manifest).encode("utf-8")).hexdigest()


def _registry_values() -> _ExpectedRegistry:
    scope_json = _canonical_json(
        {
            "fixture_sha256": FIXTURE_SHA256,
            "fixture_version": FIXTURE_SCHEMA_VERSION,
            "repository": FIXTURE_REPOSITORY,
        }
    )
    principal_values: tuple[object, ...] = (
        str(FIXTURE_PRINCIPAL_ID),
        "synthetic-fixture",
        "Synthetic GitHub fixture principal",
        "synthetic:fixture-only",
        FIXTURE_CREATED_AT,
        None,
    )
    plugin_values: tuple[object, ...] = (
        FIXTURE_PLUGIN_ID,
        FIXTURE_PLUGIN_VERSION,
        _MANIFEST_REF,
        _manifest_sha256(),
        _ORIGIN,
        _CAPABILITY_JSON,
        TrustLabel.T4_EXTERNAL.value,
        SensitivityLabel.PUBLIC.value,
        _HOST_ALLOWLIST_JSON,
        FIXTURE_SHA256,
        _PLUGIN_ENABLED,
        FIXTURE_CREATED_AT,
    )
    source_values: tuple[object, ...] = (
        str(FIXTURE_REGISTRY_SOURCE_ID),
        FIXTURE_PLUGIN_ID,
        FIXTURE_PLUGIN_VERSION,
        str(FIXTURE_PRINCIPAL_ID),
        FIXTURE_SOURCE_TYPE,
        FIXTURE_ACCOUNT_ALIAS,
        scope_json,
        _HOST_ALLOWLIST_JSON,
        TrustLabel.T4_EXTERNAL.value,
        SensitivityLabel.PUBLIC.value,
        1,
        FIXTURE_CREATED_AT,
    )
    return _ExpectedRegistry(principal_values, plugin_values, source_values)


def _validate_database_path(database: str | Path) -> Path:
    if type(database) is str:
        if not database or "\x00" in database:
            _raise(GithubFixtureIngestionErrorCode.INVALID_PATH)
        path = Path(database)
    elif isinstance(database, Path):
        path = database
        if "\x00" in str(path):
            _raise(GithubFixtureIngestionErrorCode.INVALID_PATH)
    else:
        _raise(GithubFixtureIngestionErrorCode.INVALID_PATH)

    if not path.is_absolute():
        _raise(GithubFixtureIngestionErrorCode.INVALID_PATH)
    _require_local_windows_path(path)
    return path


def _require_local_windows_path(path: Path) -> None:
    """Reject network/unknown Windows drives before SQLite can open them."""
    if os.name != "nt":
        _raise(GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE)
    drive, _tail = os.path.splitdrive(str(path))
    if not drive or drive.startswith("\\\\"):
        _raise(GithubFixtureIngestionErrorCode.INVALID_PATH)
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetDriveTypeW.argtypes = (ctypes.c_wchar_p,)
        kernel.GetDriveTypeW.restype = ctypes.c_uint32
        drive_type = int(kernel.GetDriveTypeW(f"{drive}\\"))
    except (AttributeError, OSError, TypeError, ValueError):
        _raise(GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE)
    if drive_type not in _SUPPORTED_LOCAL_DRIVE_TYPES:
        _raise(GithubFixtureIngestionErrorCode.INVALID_PATH)


def _reject_reparse_components(path: Path) -> None:
    current = path
    while True:
        try:
            info = current.lstat()
        except (OSError, RuntimeError, ValueError, TypeError):
            _raise(GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE)
        attributes = getattr(info, "st_file_attributes", 0)
        if stat.S_ISLNK(info.st_mode) or bool(attributes & _REPARSE_POINT_ATTRIBUTE):
            _raise(GithubFixtureIngestionErrorCode.INVALID_PATH)
        parent = current.parent
        if parent == current:
            return
        current = parent


def _database_file_identity(path: Path) -> tuple[Path, int, int]:
    try:
        normalized = Path(os.path.abspath(path))
        _reject_reparse_components(normalized)
        canonical = normalized.resolve(strict=True)
        _reject_reparse_components(canonical)
        info = canonical.stat()
    except GithubFixtureIngestionError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError):
        _raise(GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE)

    if not stat.S_ISREG(info.st_mode):
        _raise(GithubFixtureIngestionErrorCode.INVALID_PATH)
    link_count = getattr(info, "st_nlink", None)
    if type(link_count) is int and link_count > 1:
        _raise(GithubFixtureIngestionErrorCode.MULTIPLE_HARD_LINKS)
    device = getattr(info, "st_dev", None)
    inode = getattr(info, "st_ino", None)
    if type(device) is not int or type(inode) is not int:
        _raise(GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE)
    return canonical, device, inode


def _persisted_item_id(
    registry_source_id: UUID,
    provider_item_id: str,
    content_sha256: str,
) -> UUID:
    if (
        type(registry_source_id) is not UUID
        or type(provider_item_id) is not str
        or not provider_item_id.startswith(f"{FIXTURE_REPOSITORY}#")
        or _DIGEST_PATTERN.fullmatch(content_sha256) is None
    ):
        _raise(GithubFixtureIngestionErrorCode.FIXTURE_INVALID)
    identity = (
        f"sentinel:github.fixture:item:{registry_source_id}:"
        f"{provider_item_id}:{content_sha256}"
    )
    return uuid5(NAMESPACE_URL, identity)


def _persisted_span_id(item_id: UUID, in_memory_span_id: UUID) -> UUID:
    if type(item_id) is not UUID or type(in_memory_span_id) is not UUID:
        _raise(GithubFixtureIngestionErrorCode.FIXTURE_INVALID)
    return uuid5(
        NAMESPACE_URL,
        f"sentinel:github.fixture:span:{item_id}:{in_memory_span_id}",
    )


def _prepare_fixture() -> _PreparedFixture:
    try:
        fixture = read_packaged_github_fixture()
    except Exception:
        _raise(GithubFixtureIngestionErrorCode.FIXTURE_INVALID)

    if (
        type(fixture) is not GithubFixtureRead
        or fixture.fixture_version != FIXTURE_SCHEMA_VERSION
        or fixture.fixture_sha256 != FIXTURE_SHA256
        or len(fixture.issues) != len(_FIXTURE_ISSUE_NUMBERS)
        or tuple(issue.issue_number for issue in fixture.issues) != _FIXTURE_ISSUE_NUMBERS
    ):
        _raise(GithubFixtureIngestionErrorCode.FIXTURE_INVALID)

    expected_items: list[_ExpectedItem] = []
    total_spans = 0
    for issue in fixture.issues:
        if issue.repository != FIXTURE_REPOSITORY:
            _raise(GithubFixtureIngestionErrorCode.FIXTURE_INVALID)
        normalized = issue.normalized_source
        try:
            envelope = normalized.envelope
            raw_body = normalized.original_bytes
            digest = hashlib.sha256(raw_body).hexdigest()
            if (
                type(raw_body) is not bytes
                or normalized.text.encode("utf-8", errors="strict") != raw_body
                or digest != envelope.content_sha256
                or digest != normalized.payload_sha256
                or envelope.provider_id != FIXTURE_PROVIDER_ID
                or envelope.trust is not TrustLabel.T4_EXTERNAL
                or envelope.sensitivity is not SensitivityLabel.PUBLIC
                or envelope.observed_at != FIXTURE_OBSERVED_AT
            ):
                _raise(GithubFixtureIngestionErrorCode.FIXTURE_INVALID)
            expected_source_id = uuid5(
                GITHUB_FIXTURE_NAMESPACE,
                f"sentinel:github.fixture:{issue.repository}#{issue.issue_number}",
            )
            if envelope.source_id != expected_source_id:
                _raise(GithubFixtureIngestionErrorCode.FIXTURE_INVALID)
            provider_item_id = f"{issue.repository}#{issue.issue_number}"
            item_id = _persisted_item_id(
                FIXTURE_REGISTRY_SOURCE_ID,
                provider_item_id,
                digest,
            )
            metadata_json = _canonical_json(
                {
                    "encoding": "utf-8",
                    "fixture_sha256": fixture.fixture_sha256,
                    "fixture_version": fixture.fixture_version,
                    "in_memory_source_id": str(envelope.source_id),
                    "issue_number": issue.issue_number,
                    "repository": issue.repository,
                    "source_updated_at": issue.updated_at.isoformat(),
                }
            )
            source_at = issue.updated_at.isoformat()
            values: tuple[object, ...] = (
                str(item_id),
                str(FIXTURE_REGISTRY_SOURCE_ID),
                provider_item_id,
                None,
                None,
                f"{_CONTENT_REF_PREFIX}{provider_item_id}",
                digest,
                envelope.trust.value,
                envelope.sensitivity.value,
                envelope.observed_at.isoformat(),
                source_at,
                None,
                metadata_json,
            )
            spans: list[_ExpectedSpan] = []
            for citation in issue.citations:
                if type(citation) is not SourceBoundCitation:
                    _raise(GithubFixtureIngestionErrorCode.FIXTURE_INVALID)
                verify_bound_citation(
                    normalized,
                    citation,
                    original_bytes=raw_body,
                )
                if (
                    citation.source_id != envelope.source_id
                    or citation.content_sha256 != digest
                ):
                    _raise(GithubFixtureIngestionErrorCode.FIXTURE_INVALID)
                persistent_span_id = _persisted_span_id(item_id, citation.span.span_id)
                public_span = PersistedGithubSpan(
                    span_id=persistent_span_id,
                    in_memory_span_id=citation.span.span_id,
                    start_byte=citation.span.start_byte,
                    end_byte=citation.span.end_byte,
                    text_sha256=citation.span.text_sha256,
                )
                span_values: tuple[object, ...] = (
                    str(persistent_span_id),
                    str(item_id),
                    citation.span.start_byte,
                    citation.span.end_byte,
                    citation.span.text_sha256,
                    None,
                    None,
                )
                spans.append(
                    _ExpectedSpan(
                        public=public_span,
                        citation=citation,
                        values=span_values,
                    )
                )
            total_spans += len(spans)
            expected_items.append(
                _ExpectedItem(
                    issue=issue,
                    item_id=item_id,
                    provider_item_id=provider_item_id,
                    values=values,
                    spans=tuple(spans),
                )
            )
        except GithubFixtureIngestionError:
            raise
        except (AttributeError, TypeError, ValueError, UnicodeError, NormalizationError):
            _raise(GithubFixtureIngestionErrorCode.FIXTURE_INVALID)

    if total_spans != 9:
        _raise(GithubFixtureIngestionErrorCode.FIXTURE_INVALID)
    return _PreparedFixture(
        fixture=fixture,
        registry=_registry_values(),
        items=tuple(expected_items),
    )


def _validate_migration_state(connection: sqlite3.Connection) -> MigrationState:
    try:
        state = inspect_migration_state_readonly(connection)
    except (MigrationIntegrityError, sqlite3.Error):
        _raise(GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT)
    if (
        not state.is_current
        or state.applied_migration_ids != _EXPECTED_MIGRATION_IDS
        or state.schema_version != MIGRATIONS[-1].migration_id
    ):
        _raise(GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT)
    try:
        verify_integrity(connection)
    except (MigrationIntegrityError, sqlite3.Error):
        _raise(GithubFixtureIngestionErrorCode.INTEGRITY_FAILURE)
    return state


def _verify_current_schema_inside_transaction(connection: sqlite3.Connection) -> None:
    # The lease installs an authorizer that deliberately blocks PRAGMA and DDL.
    # The complete current checkpoint was verified on a dedicated query-only
    # connection while the OS writer lease was already held. Inside the
    # BEGIN IMMEDIATE transaction, recheck the migration identity/order before
    # the first DML; SQLite now prevents another writer from changing it.
    rows = connection.execute(
        """SELECT migration_id, artifact_sha256, success
           FROM schema_migrations ORDER BY applied_at, migration_id"""
    ).fetchall()
    expected = tuple(
        (migration.migration_id, migration.artifact_sha256, 1)
        for migration in MIGRATIONS
    )
    if tuple(tuple(row) for row in rows) != expected:
        _raise(GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT)
    expected_schema = MIGRATIONS[-1].schema_after
    expected_objects = {
        (item.object_type, item.name): item.sql.strip() for item in expected_schema.objects
    }
    actual_objects = {
        (str(object_type), str(name)): sql.strip() if isinstance(sql, str) else None
        for object_type, name, sql in connection.execute(
            """SELECT type, name, sql FROM sqlite_master
               WHERE name NOT GLOB 'sqlite_*'
                 AND type IN ('table', 'index', 'view', 'trigger')"""
        ).fetchall()
    }
    if actual_objects != expected_objects:
        _raise(GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT)


def _ensure_exact_row(
    connection: sqlite3.Connection,
    *,
    select_sql: str,
    select_values: tuple[object, ...],
    insert_sql: str,
    values: tuple[object, ...],
    conflict_code: GithubFixtureIngestionErrorCode,
) -> bool:
    row = connection.execute(select_sql, select_values).fetchone()
    if row is not None:
        if tuple(row) != values:
            _raise(conflict_code)
        return False
    try:
        connection.execute(insert_sql, values)
    except sqlite3.IntegrityError:
        _raise(conflict_code)
    return True


def _register_source_rows(connection: sqlite3.Connection) -> tuple[bool, bool, bool]:
    registry = _registry_values()
    principal_new = _ensure_exact_row(
        connection,
        select_sql=f"SELECT {_PRINCIPAL_COLUMNS} FROM principals WHERE principal_id = ?",
        select_values=(registry.principal_values[0],),
        insert_sql=(
            "INSERT INTO principals "
            "(principal_id, kind, display_name, os_binding, created_at, revoked_at) "
            "VALUES (?, ?, ?, ?, ?, ?)"
        ),
        values=registry.principal_values,
        conflict_code=GithubFixtureIngestionErrorCode.REGISTRATION_CONFLICT,
    )
    plugin_new = _ensure_exact_row(
        connection,
        select_sql=(
            f"SELECT {_PLUGIN_COLUMNS} FROM plugin_manifests "
            "WHERE plugin_id = ? AND plugin_version = ?"
        ),
        select_values=(FIXTURE_PLUGIN_ID, FIXTURE_PLUGIN_VERSION),
        insert_sql=(
            "INSERT INTO plugin_manifests "
            "(plugin_id, plugin_version, manifest_ref, manifest_sha256, origin, "
            "capability_json, trust, sensitivity, host_allowlist_json, fixture_set_sha256, "
            "enabled, registered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ),
        values=registry.plugin_values,
        conflict_code=GithubFixtureIngestionErrorCode.REGISTRATION_CONFLICT,
    )
    source_new = _ensure_exact_row(
        connection,
        select_sql=f"SELECT {_SOURCE_COLUMNS} FROM sources WHERE source_id = ?",
        select_values=(str(FIXTURE_REGISTRY_SOURCE_ID),),
        insert_sql=(
            "INSERT INTO sources "
            "(source_id, plugin_id, plugin_version, principal_id, source_type, account_alias, "
            "scope_json, host_allowlist_json, trust, default_sensitivity, enabled, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ),
        values=registry.source_values,
        conflict_code=GithubFixtureIngestionErrorCode.REGISTRATION_CONFLICT,
    )
    return principal_new, plugin_new, source_new


def _ensure_item(connection: sqlite3.Connection, expected: _ExpectedItem) -> bool:
    row = connection.execute(
        f"SELECT {_ITEM_COLUMNS} FROM source_items WHERE item_id = ?",
        (str(expected.item_id),),
    ).fetchone()
    if row is not None:
        if tuple(row) != expected.values:
            _raise(GithubFixtureIngestionErrorCode.ITEM_CONFLICT)
        return False

    natural_row = connection.execute(
        f"SELECT {_ITEM_COLUMNS} FROM source_items "
        "WHERE source_id = ? AND provider_item_id = ? AND content_sha256 = ?",
        (
            str(FIXTURE_REGISTRY_SOURCE_ID),
            expected.provider_item_id,
            expected.issue.normalized_source.envelope.content_sha256,
        ),
    ).fetchone()
    if natural_row is not None:
        _raise(GithubFixtureIngestionErrorCode.ITEM_CONFLICT)
    try:
        connection.execute(
            "INSERT INTO source_items "
            "(item_id, source_id, provider_item_id, provider_revision, canonical_uri, "
            "content_ref, content_sha256, trust, sensitivity, observed_at, source_at, "
            "deleted_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            expected.values,
        )
    except sqlite3.IntegrityError:
        _raise(GithubFixtureIngestionErrorCode.ITEM_CONFLICT)
    return True


def _verify_existing_spans_for_item(
    connection: sqlite3.Connection,
    expected: _ExpectedItem,
) -> None:
    rows = connection.execute(
        f"SELECT {_SPAN_COLUMNS} FROM source_spans WHERE item_id = ? "
        "ORDER BY span_id LIMIT ?",
        (str(expected.item_id), len(expected.spans) + 1),
    ).fetchall()
    by_id = {str(span.public.span_id): span for span in expected.spans}
    for row in rows:
        span_id = str(row[0])
        span = by_id.get(span_id)
        if span is None or tuple(row) != span.values:
            _raise(GithubFixtureIngestionErrorCode.SPAN_CONFLICT)


def _ensure_span(connection: sqlite3.Connection, expected: _ExpectedSpan) -> bool:
    row = connection.execute(
        f"SELECT {_SPAN_COLUMNS} FROM source_spans WHERE span_id = ?",
        (str(expected.public.span_id),),
    ).fetchone()
    if row is not None:
        if tuple(row) != expected.values:
            _raise(GithubFixtureIngestionErrorCode.SPAN_CONFLICT)
        return False
    try:
        connection.execute(
            "INSERT INTO source_spans "
            "(span_id, item_id, start_byte, end_byte, text_sha256, context_ref, "
            "derived_by_boundary_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            expected.values,
        )
    except sqlite3.IntegrityError:
        _raise(GithubFixtureIngestionErrorCode.SPAN_CONFLICT)
    return True


def _public_item(expected: _ExpectedItem) -> PersistedGithubItem:
    return PersistedGithubItem(
        item_id=expected.item_id,
        provider_item_id=expected.provider_item_id,
        source_envelope_id=expected.issue.source_id,
        content_sha256=str(expected.values[6]),
        spans=tuple(span.public for span in expected.spans),
    )


def _verify_registration(
    connection: sqlite3.Connection,
    registry: _ExpectedRegistry,
) -> None:
    checks = (
        (
            f"SELECT {_PRINCIPAL_COLUMNS} FROM principals WHERE principal_id = ?",
            (str(FIXTURE_PRINCIPAL_ID),),
            registry.principal_values,
        ),
        (
            f"SELECT {_PLUGIN_COLUMNS} FROM plugin_manifests "
            "WHERE plugin_id = ? AND plugin_version = ?",
            (FIXTURE_PLUGIN_ID, FIXTURE_PLUGIN_VERSION),
            registry.plugin_values,
        ),
        (
            f"SELECT {_SOURCE_COLUMNS} FROM sources WHERE source_id = ?",
            (str(FIXTURE_REGISTRY_SOURCE_ID),),
            registry.source_values,
        ),
    )
    for query, parameters, expected in checks:
        row = connection.execute(query, parameters).fetchone()
        if row is None or tuple(row) != expected:
            _raise(GithubFixtureIngestionErrorCode.REGISTRATION_CONFLICT)


def _verify_persisted_items(
    connection: sqlite3.Connection,
    items: tuple[_ExpectedItem, ...],
) -> None:
    rows = connection.execute(
        f"SELECT {_ITEM_COLUMNS} FROM source_items WHERE source_id = ? "
        "ORDER BY provider_item_id, content_sha256, item_id LIMIT ?",
        (str(FIXTURE_REGISTRY_SOURCE_ID), len(items) + 1),
    ).fetchall()
    if len(rows) != len(items):
        _raise(GithubFixtureIngestionErrorCode.ITEM_CONFLICT)
    expected_by_id = {str(item.item_id): item for item in items}
    seen: set[str] = set()
    for row in rows:
        item_id = str(row[0])
        expected = expected_by_id.get(item_id)
        if expected is None or tuple(row) != expected.values or item_id in seen:
            _raise(GithubFixtureIngestionErrorCode.ITEM_CONFLICT)
        seen.add(item_id)
    if seen != set(expected_by_id):
        _raise(GithubFixtureIngestionErrorCode.ITEM_CONFLICT)


def _verify_persisted_spans(
    connection: sqlite3.Connection,
    items: tuple[_ExpectedItem, ...],
) -> None:
    for item in items:
        rows = connection.execute(
            f"SELECT {_SPAN_COLUMNS} FROM source_spans WHERE item_id = ? "
            "ORDER BY span_id LIMIT ?",
            (str(item.item_id), len(item.spans) + 1),
        ).fetchall()
        if len(rows) != len(item.spans):
            _raise(GithubFixtureIngestionErrorCode.SPAN_CONFLICT)
        expected_by_id = {str(span.public.span_id): span for span in item.spans}
        seen: set[str] = set()
        for row in rows:
            span_id = str(row[0])
            expected = expected_by_id.get(span_id)
            if expected is None or tuple(row) != expected.values or span_id in seen:
                _raise(GithubFixtureIngestionErrorCode.SPAN_CONFLICT)
            seen.add(span_id)
        if seen != set(expected_by_id):
            _raise(GithubFixtureIngestionErrorCode.SPAN_CONFLICT)

        # Also look up each deterministic ID globally. This catches a row whose
        # item_id was altered to another otherwise-valid item.
        for span in item.spans:
            row = connection.execute(
                f"SELECT {_SPAN_COLUMNS} FROM source_spans WHERE span_id = ?",
                (str(span.public.span_id),),
            ).fetchone()
            if row is None or tuple(row) != span.values:
                _raise(GithubFixtureIngestionErrorCode.SPAN_CONFLICT)


def _verify_database_snapshot(
    database: Path,
    prepared: _PreparedFixture,
) -> PersistedGithubFixture:
    try:
        with readonly_database_connection(database) as connection:
            connection.execute("BEGIN")
            _validate_migration_state(connection)
            _verify_registration(connection, prepared.registry)
            _verify_persisted_items(connection, prepared.items)
            _verify_persisted_spans(connection, prepared.items)
    except GithubFixtureIngestionError:
        raise
    except DatabaseOpenError:
        _raise(GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE)
    except (MigrationIntegrityError, sqlite3.Error, SchemaIntegrityError):
        _raise(GithubFixtureIngestionErrorCode.INTEGRITY_FAILURE)

    return PersistedGithubFixture(
        registry_source_id=FIXTURE_REGISTRY_SOURCE_ID,
        fixture_version=prepared.fixture.fixture_version,
        fixture_sha256=prepared.fixture.fixture_sha256,
        items=tuple(_public_item(item) for item in prepared.items),
    )


def _map_writer_error(error: WriterLeaseError) -> GithubFixtureIngestionError:
    if error.code is WriterLeaseErrorCode.INVALID_PATH:
        code = GithubFixtureIngestionErrorCode.INVALID_PATH
    elif error.code is WriterLeaseErrorCode.DATABASE_MISSING:
        code = GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE
    elif error.code in {
        WriterLeaseErrorCode.LOCK_CONTENDED,
        WriterLeaseErrorCode.LOCK_UNAVAILABLE,
        WriterLeaseErrorCode.REENTRANT,
        WriterLeaseErrorCode.UNSUPPORTED_PLATFORM,
    }:
        code = GithubFixtureIngestionErrorCode.WRITER_UNAVAILABLE
    elif error.code in {
        WriterLeaseErrorCode.MIGRATION_INVALID,
        WriterLeaseErrorCode.DATABASE_INVALID,
    }:
        code = GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT
    else:
        code = GithubFixtureIngestionErrorCode.PERSISTENCE_FAILURE
    return GithubFixtureIngestionError(code)


def ingest_packaged_github_fixture(
    database: str | Path,
) -> GithubFixtureIngestionReport:
    """Persist only the pinned PUBLIC fixture in one lease transaction.

    The registry source, provider issue, in-memory source, persisted item revision,
    in-memory span and persisted span each have separate deterministic identities.
    """
    path = _validate_database_path(database)
    prepared = _prepare_fixture()
    initial_identity = _database_file_identity(path)

    try:
        with acquire_writer_lease(path) as lease:
            current_identity = _database_file_identity(path)
            if current_identity != initial_identity:
                _raise(GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE)

            # The lease validates a registered historical prefix. Ingestion has a
            # stricter current-schema requirement and never runs migrations.
            try:
                with readonly_database_connection(path) as connection:
                    state = _validate_migration_state(connection)
            except DatabaseOpenError:
                _raise(GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE)
            if not state.is_current:
                _raise(GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT)

            inserted_items = 0
            existing_items = 0
            inserted_spans = 0
            existing_spans = 0
            with lease.transaction() as connection:
                # BEGIN IMMEDIATE has serialized SQLite writers. Recheck the
                # migration prefix/checkpoint before the first application DML.
                _verify_current_schema_inside_transaction(connection)
                _register_source_rows(connection)
                for item in prepared.items:
                    if _ensure_item(connection, item):
                        inserted_items += 1
                    else:
                        existing_items += 1
                for item in prepared.items:
                    _verify_existing_spans_for_item(connection, item)
                    for span in item.spans:
                        if _ensure_span(connection, span):
                            inserted_spans += 1
                        else:
                            existing_spans += 1

            return GithubFixtureIngestionReport(
                registry_source_id=FIXTURE_REGISTRY_SOURCE_ID,
                fixture_sha256=prepared.fixture.fixture_sha256,
                inserted_items=inserted_items,
                existing_items=existing_items,
                inserted_spans=inserted_spans,
                existing_spans=existing_spans,
                items=tuple(_public_item(item) for item in prepared.items),
            )
    except GithubFixtureIngestionError:
        raise
    except WriterLeaseError as error:
        raise _map_writer_error(error) from None
    except DatabaseOpenError:
        _raise(GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE)
    except (MigrationIntegrityError, SchemaIntegrityError):
        _raise(GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT)
    except sqlite3.Error:
        _raise(GithubFixtureIngestionErrorCode.PERSISTENCE_FAILURE)
    except (OSError, RuntimeError, TypeError, ValueError):
        _raise(GithubFixtureIngestionErrorCode.PERSISTENCE_FAILURE)
    except Exception:
        _raise(GithubFixtureIngestionErrorCode.PERSISTENCE_FAILURE)


def read_persisted_github_fixture(database: str | Path) -> PersistedGithubFixture:
    """Verify current persisted rows against the fixed package resource, read-only."""
    path = _validate_database_path(database)
    _database_file_identity(path)
    prepared = _prepare_fixture()
    return _verify_database_snapshot(path, prepared)


def verify_persisted_github_citation(
    database: str | Path,
    *,
    item_id: UUID,
    span_id: UUID,
) -> str:
    """Return an exact cited slice only after full fixture/database verification."""
    if type(item_id) is not UUID or type(span_id) is not UUID:
        _raise(GithubFixtureIngestionErrorCode.CONTENT_UNAVAILABLE)
    path = _validate_database_path(database)
    _database_file_identity(path)
    prepared = _prepare_fixture()
    snapshot = _verify_database_snapshot(path, prepared)
    persisted_item = next(
        (item for item in snapshot.items if item.item_id == item_id),
        None,
    )
    if persisted_item is None:
        _raise(GithubFixtureIngestionErrorCode.ITEM_CONFLICT)
    persisted_span = next(
        (span for span in persisted_item.spans if span.span_id == span_id),
        None,
    )
    if persisted_span is None:
        _raise(GithubFixtureIngestionErrorCode.SPAN_CONFLICT)
    expected_item = next(
        item for item in prepared.items if item.item_id == persisted_item.item_id
    )
    expected_span = next(
        span
        for span in expected_item.spans
        if span.public.span_id == persisted_span.span_id
    )
    try:
        return verify_bound_citation(
            expected_item.issue.normalized_source,
            expected_span.citation,
            original_bytes=expected_item.issue.normalized_source.original_bytes,
        )
    except NormalizationError:
        _raise(GithubFixtureIngestionErrorCode.CONTENT_UNAVAILABLE)


__all__ = [
    "FIXTURE_ACCOUNT_ALIAS",
    "FIXTURE_PLUGIN_ID",
    "FIXTURE_PLUGIN_VERSION",
    "FIXTURE_PROVIDER_ID",
    "FIXTURE_REGISTRY_SOURCE_ID",
    "FIXTURE_REPOSITORY",
    "FIXTURE_SOURCE_TYPE",
    "ingest_packaged_github_fixture",
    "read_persisted_github_fixture",
    "verify_persisted_github_citation",
]
