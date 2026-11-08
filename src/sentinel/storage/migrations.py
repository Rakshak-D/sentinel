"""Fixed registry and atomic application of trusted SQLite migrations."""

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from sentinel import __version__
from sentinel.storage.connection import database_connection
from sentinel.storage.schema import (
    ACTION_PROPOSALS_CR2_D_INSERT_GUARD_DDL,
    ACTION_PROPOSALS_STATUS_EXPIRES_AT_INDEX_DDL,
    ACTION_PROPOSALS_TABLE_DDL,
    BOUNDARY_ENVELOPES_KIND_ADAPTER_INDEX_DDL,
    BOUNDARY_ENVELOPES_TABLE_DDL,
    CONFIG_REVISIONS_ACTIVATION_CREATED_AT_INDEX_DDL,
    CONFIG_REVISIONS_TABLE_DDL,
    CR1_F_SCHEMA,
    CR1_F_SCHEMA_DEFINITION_SHA256,
    CR1_J_SCHEMA,
    CR1_J_SCHEMA_DEFINITION_SHA256,
    CR1_SOURCE_SCHEMA,
    CR1_SOURCE_SCHEMA_DEFINITION_SHA256,
    CR2_D_ACTION_PROPOSAL_COLUMNS,
    CR2_D_SCHEMA,
    CR2_D_SCHEMA_DEFINITION_SHA256,
    CR2_F_SCHEMA,
    CR2_F_SCHEMA_DEFINITION_SHA256,
    FOUNDATION_SCHEMA,
    FOUNDATION_SCHEMA_DEFINITION_SHA256,
    MIGRATION_INDEX_DDL,
    MIGRATION_TABLE_DDL,
    OWNER_PROOF_CHALLENGE_CONSUMPTIONS_DELETE_GUARD_DDL,
    OWNER_PROOF_CHALLENGE_CONSUMPTIONS_TABLE_DDL,
    OWNER_PROOF_CHALLENGE_CONSUMPTIONS_UPDATE_GUARD_DDL,
    OWNER_PROOF_CHALLENGES_DELETE_GUARD_DDL,
    OWNER_PROOF_CHALLENGES_PROPOSAL_INDEX_DDL,
    OWNER_PROOF_CHALLENGES_TABLE_DDL,
    OWNER_PROOF_CHALLENGES_UPDATE_GUARD_DDL,
    OWNER_PROOF_CREDENTIALS_DELETE_GUARD_DDL,
    OWNER_PROOF_CREDENTIALS_STATE_INDEX_DDL,
    OWNER_PROOF_CREDENTIALS_TABLE_DDL,
    OWNER_PROOF_CREDENTIALS_UPDATE_GUARD_DDL,
    PLUGIN_MANIFESTS_ENABLED_TRUST_INDEX_DDL,
    PLUGIN_MANIFESTS_TABLE_DDL,
    PRINCIPALS_KIND_REVOKED_AT_INDEX_DDL,
    PRINCIPALS_TABLE_DDL,
    PROPOSAL_SOURCES_ITEM_ID_INDEX_DDL,
    PROPOSAL_SOURCES_TABLE_DDL,
    RUN_MANIFESTS_CREATED_AT_INDEX_DDL,
    RUN_MANIFESTS_TABLE_DDL,
    RUNS_STATUS_STARTED_AT_INDEX_DDL,
    RUNS_TABLE_DDL,
    RUNS_THREAD_STARTED_AT_INDEX_DDL,
    SOURCE_ITEMS_CONTENT_SHA256_INDEX_DDL,
    SOURCE_ITEMS_SOURCE_OBSERVED_AT_INDEX_DDL,
    SOURCE_ITEMS_TABLE_DDL,
    SOURCE_SPANS_ITEM_SPAN_UNIQUE_INDEX_DDL,
    SOURCE_SPANS_ITEM_START_BYTE_INDEX_DDL,
    SOURCE_SPANS_TABLE_DDL,
    SOURCES_ENABLED_TYPE_INDEX_DDL,
    SOURCES_TABLE_DDL,
    SYNC_CURSORS_STATUS_INDEX_DDL,
    SYNC_CURSORS_TABLE_DDL,
    TASK_CREATION_REQUESTS_TABLE_DDL,
    TASKS_PROPOSAL_ID_UNIQUE_INDEX_DDL,
    TASKS_STATUS_DUE_AT_INDEX_DDL,
    TASKS_TABLE_DDL,
    SchemaDefinition,
    SchemaIntegrityError,
    verify_schema,
)

_MIGRATION_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_FOUNDATION_MIGRATION_ID: Final = "cr0-c-0001-schema-migrations"
_FOUNDATION_ARTIFACT_SHA256: Final = (
    "b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217"
)
_CR1_E_MIGRATION_ID: Final = "cr1-e-0002-source-registry"
_CR1_E_MIGRATION_ARTIFACT_SHA256: Final = (
    "7ef613bdb646d9b98bc18bb20dd7bba3467d4de12b2cb5c4802e4d1dd8d1c0c7"
)
_CR1_F_MIGRATION_ID: Final = "cr1-f-0003-source-spans"
_CR1_F_MIGRATION_ARTIFACT_SHA256: Final = (
    "6e6b98e60cff17f0eac94b942533964588344fdd0d8342567962ac4a1c3304b7"
)
_CR1_J_MIGRATION_ID: Final = "cr1-j-0004-local-tasks"
_CR1_J_MIGRATION_ARTIFACT_SHA256: Final = (
    "a75bfcff37255e1fb0cc49eb72254c8e83d049828faa2653a8495ca2f749120a"
)
_CR2_D_MIGRATION_ID: Final = "cr2-d-0005-durable-pending-proposals"
_CR2_D_MIGRATION_ARTIFACT_SHA256: Final = (
    "c4ac15d8270abd0d5165d94944f01d786fcb7269d74700c716de3efce5b56ffa"
)
_CR2_F_MIGRATION_ID: Final = "cr2-f-0006-owner-proof-challenges"
_CR2_F_MIGRATION_ARTIFACT_SHA256: Final = (
    "741f0084f578784ad57bafc50c2d811ee47d366e4cc5b39d8d94ec2ad2232f6b"
)


class MigrationIntegrityError(RuntimeError):
    """Raised when persisted migration history or schema cannot be trusted."""


class MigrationApplyError(RuntimeError):
    """Raised when one registered migration failed and was rolled back."""


@dataclass(frozen=True, slots=True)
class MigrationState:
    """Read-only distinction between a valid schema prefix and current schema."""

    applied_migration_ids: tuple[str, ...]
    schema_version: str
    pending_migration_ids: tuple[str, ...]

    @property
    def is_current(self) -> bool:
        """Whether the validated database has every currently registered migration."""

        return not self.pending_migration_ids


@dataclass(frozen=True, slots=True)
class Migration:
    """One trusted migration and its complete expected post-migration schema."""

    migration_id: str
    statements: tuple[str, ...]
    schema_after: SchemaDefinition
    artifact_version: int = 2

    def __post_init__(self) -> None:
        if not isinstance(self.migration_id, str) or not _MIGRATION_ID_PATTERN.fullmatch(
            self.migration_id
        ):
            raise ValueError("migration_id must be a lowercase identifier")
        if not isinstance(self.statements, tuple) or not self.statements:
            raise ValueError("migration statements must be a non-empty tuple")
        if any(
            not isinstance(statement, str) or not statement.strip() for statement in self.statements
        ):
            raise ValueError("migration statements must contain non-empty SQL strings")
        if self.artifact_version not in {1, 2}:
            raise ValueError("unsupported migration artifact version")
        if not isinstance(self.schema_after, SchemaDefinition):
            raise ValueError("migration must include a trusted schema checkpoint")
        if self.schema_after.schema_version != self.migration_id:
            raise ValueError("schema checkpoint version must match migration_id")

    @property
    def canonical_artifact(self) -> bytes:
        """Return deterministic UTF-8 bytes representing this exact migration content."""
        # Artifact v1 is the historical CR0-C encoding and remains byte-for-byte stable.
        payload: dict[str, object]
        if self.artifact_version == 1:
            payload = {"migration_id": self.migration_id, "statements": self.statements}
        else:
            payload = {
                "artifact_version": 2,
                "migration_id": self.migration_id,
                "schema_after": json.loads(self.schema_after.canonical_artifact),
                "statements": self.statements,
            }
        return json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")

    @property
    def artifact_sha256(self) -> str:
        """SHA-256 of the canonical migration artifact."""
        return hashlib.sha256(self.canonical_artifact).hexdigest()


_CR1_E_STATEMENTS: tuple[str, ...] = (
    PRINCIPALS_TABLE_DDL,
    PLUGIN_MANIFESTS_TABLE_DDL,
    SOURCES_TABLE_DDL,
    SYNC_CURSORS_TABLE_DDL,
    SOURCE_ITEMS_TABLE_DDL,
    PRINCIPALS_KIND_REVOKED_AT_INDEX_DDL,
    PLUGIN_MANIFESTS_ENABLED_TRUST_INDEX_DDL,
    SOURCES_ENABLED_TYPE_INDEX_DDL,
    SYNC_CURSORS_STATUS_INDEX_DDL,
    SOURCE_ITEMS_SOURCE_OBSERVED_AT_INDEX_DDL,
    SOURCE_ITEMS_CONTENT_SHA256_INDEX_DDL,
)

_CR1_F_STATEMENTS: tuple[str, ...] = (
    CONFIG_REVISIONS_TABLE_DDL,
    RUN_MANIFESTS_TABLE_DDL,
    RUNS_TABLE_DDL,
    BOUNDARY_ENVELOPES_TABLE_DDL,
    SOURCE_SPANS_TABLE_DDL,
    CONFIG_REVISIONS_ACTIVATION_CREATED_AT_INDEX_DDL,
    RUN_MANIFESTS_CREATED_AT_INDEX_DDL,
    RUNS_THREAD_STARTED_AT_INDEX_DDL,
    RUNS_STATUS_STARTED_AT_INDEX_DDL,
    BOUNDARY_ENVELOPES_KIND_ADAPTER_INDEX_DDL,
    SOURCE_SPANS_ITEM_START_BYTE_INDEX_DDL,
)

_CR1_J_STATEMENTS: tuple[str, ...] = (
    ACTION_PROPOSALS_TABLE_DDL,
    TASKS_TABLE_DDL,
    TASK_CREATION_REQUESTS_TABLE_DDL,
    ACTION_PROPOSALS_STATUS_EXPIRES_AT_INDEX_DDL,
    TASKS_STATUS_DUE_AT_INDEX_DDL,
    TASKS_PROPOSAL_ID_UNIQUE_INDEX_DDL,
)

_CR2_D_STATEMENTS: tuple[str, ...] = (
    *(
        f"ALTER TABLE action_proposals ADD COLUMN {column}"
        for column in CR2_D_ACTION_PROPOSAL_COLUMNS
    ),
    SOURCE_SPANS_ITEM_SPAN_UNIQUE_INDEX_DDL,
    PROPOSAL_SOURCES_TABLE_DDL,
    PROPOSAL_SOURCES_ITEM_ID_INDEX_DDL,
    ACTION_PROPOSALS_CR2_D_INSERT_GUARD_DDL,
)

_CR2_F_STATEMENTS: tuple[str, ...] = (
    OWNER_PROOF_CREDENTIALS_TABLE_DDL,
    OWNER_PROOF_CREDENTIALS_STATE_INDEX_DDL,
    OWNER_PROOF_CREDENTIALS_UPDATE_GUARD_DDL,
    OWNER_PROOF_CREDENTIALS_DELETE_GUARD_DDL,
    OWNER_PROOF_CHALLENGES_TABLE_DDL,
    OWNER_PROOF_CHALLENGES_PROPOSAL_INDEX_DDL,
    OWNER_PROOF_CHALLENGES_UPDATE_GUARD_DDL,
    OWNER_PROOF_CHALLENGES_DELETE_GUARD_DDL,
    OWNER_PROOF_CHALLENGE_CONSUMPTIONS_TABLE_DDL,
    OWNER_PROOF_CHALLENGE_CONSUMPTIONS_UPDATE_GUARD_DDL,
    OWNER_PROOF_CHALLENGE_CONSUMPTIONS_DELETE_GUARD_DDL,
)

MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        _FOUNDATION_MIGRATION_ID,
        (MIGRATION_TABLE_DDL, MIGRATION_INDEX_DDL),
        FOUNDATION_SCHEMA,
        artifact_version=1,
    ),
    Migration(
        _CR1_E_MIGRATION_ID,
        _CR1_E_STATEMENTS,
        CR1_SOURCE_SCHEMA,
        artifact_version=2,
    ),
    Migration(
        _CR1_F_MIGRATION_ID,
        _CR1_F_STATEMENTS,
        CR1_F_SCHEMA,
        artifact_version=2,
    ),
    Migration(
        _CR1_J_MIGRATION_ID,
        _CR1_J_STATEMENTS,
        CR1_J_SCHEMA,
        artifact_version=2,
    ),
    Migration(
        _CR2_D_MIGRATION_ID,
        _CR2_D_STATEMENTS,
        CR2_D_SCHEMA,
        artifact_version=2,
    ),
    Migration(
        _CR2_F_MIGRATION_ID,
        _CR2_F_STATEMENTS,
        CR2_F_SCHEMA,
        artifact_version=2,
    ),
)


def _registered_migrations() -> tuple[Migration, ...]:
    migrations = MIGRATIONS
    if not migrations:
        raise MigrationIntegrityError("registered migration set lacks its foundation migration")
    if any(not isinstance(migration, Migration) for migration in migrations):
        raise MigrationIntegrityError("registered migration set contains an invalid entry")
    if migrations[0].migration_id != _FOUNDATION_MIGRATION_ID:
        raise MigrationIntegrityError("registered migration set lacks its foundation migration")
    ids = tuple(migration.migration_id for migration in migrations)
    if len(ids) != len(set(ids)):
        raise MigrationIntegrityError("registered migration IDs are not unique")
    foundation = migrations[0]
    if (
        foundation.artifact_version != 1
        or foundation.artifact_sha256 != _FOUNDATION_ARTIFACT_SHA256
    ):
        raise MigrationIntegrityError("foundation migration artifact digest mismatch")
    if foundation.schema_after.sha256 != FOUNDATION_SCHEMA_DEFINITION_SHA256:
        raise MigrationIntegrityError("foundation schema checkpoint was modified")
    if len(migrations) < 2 or migrations[1].migration_id != _CR1_E_MIGRATION_ID:
        raise MigrationIntegrityError("registered migrations lack the CR1-E source registry")
    source_registry = migrations[1]
    if source_registry.artifact_sha256 != _CR1_E_MIGRATION_ARTIFACT_SHA256:
        raise MigrationIntegrityError("CR1-E migration artifact digest mismatch")
    if source_registry.schema_after.sha256 != CR1_SOURCE_SCHEMA_DEFINITION_SHA256:
        raise MigrationIntegrityError("CR1-E schema checkpoint digest mismatch")
    if len(migrations) < 3 or migrations[2].migration_id != _CR1_F_MIGRATION_ID:
        raise MigrationIntegrityError("registered migrations lack the CR1-F source-spans schema")
    source_spans = migrations[2]
    if source_spans.artifact_sha256 != _CR1_F_MIGRATION_ARTIFACT_SHA256:
        raise MigrationIntegrityError("CR1-F migration artifact digest mismatch")
    if source_spans.schema_after.sha256 != CR1_F_SCHEMA_DEFINITION_SHA256:
        raise MigrationIntegrityError("CR1-F schema checkpoint digest mismatch")
    if len(migrations) < 4 or migrations[3].migration_id != _CR1_J_MIGRATION_ID:
        raise MigrationIntegrityError("registered migrations lack the CR1-J task schema")
    local_tasks = migrations[3]
    if local_tasks.artifact_sha256 != _CR1_J_MIGRATION_ARTIFACT_SHA256:
        raise MigrationIntegrityError("CR1-J migration artifact digest mismatch")
    if local_tasks.schema_after.sha256 != CR1_J_SCHEMA_DEFINITION_SHA256:
        raise MigrationIntegrityError("CR1-J schema checkpoint digest mismatch")
    if len(migrations) < 5 or migrations[4].migration_id != _CR2_D_MIGRATION_ID:
        raise MigrationIntegrityError("registered migrations lack the CR2-D proposal schema")
    proposals = migrations[4]
    if proposals.artifact_sha256 != _CR2_D_MIGRATION_ARTIFACT_SHA256:
        raise MigrationIntegrityError("CR2-D migration artifact digest mismatch")
    if proposals.schema_after.sha256 != CR2_D_SCHEMA_DEFINITION_SHA256:
        raise MigrationIntegrityError("CR2-D schema checkpoint digest mismatch")
    if len(migrations) < 6 or migrations[5].migration_id != _CR2_F_MIGRATION_ID:
        raise MigrationIntegrityError("registered migrations lack the CR2-F owner-proof schema")
    owner_proof = migrations[5]
    if owner_proof.artifact_sha256 != _CR2_F_MIGRATION_ARTIFACT_SHA256:
        raise MigrationIntegrityError("CR2-F migration artifact digest mismatch")
    if owner_proof.schema_after.sha256 != CR2_F_SCHEMA_DEFINITION_SHA256:
        raise MigrationIntegrityError("CR2-F schema checkpoint digest mismatch")
    if any(migration.artifact_version != 2 for migration in migrations[1:]):
        raise MigrationIntegrityError("new migrations must use checkpoint-aware artifact v2")
    return migrations


def _user_schema_objects(connection: sqlite3.Connection) -> frozenset[tuple[str, str]]:
    return frozenset(
        connection.execute(
            """SELECT type, name FROM sqlite_master
               WHERE name NOT LIKE 'sqlite_%'"""
        ).fetchall()
    )


def _has_migration_table(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        ("schema_migrations",),
    ).fetchone()
    return row is not None


def _timestamp_is_aware(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return (
        parsed.tzinfo is not None
        and parsed.utcoffset() == timedelta(0)
        and parsed.isoformat(timespec="microseconds") == value
    )


def _validate_migration_rows(
    connection: sqlite3.Connection,
    migrations: tuple[Migration, ...],
) -> tuple[str, ...]:
    rows = connection.execute(
        """SELECT migration_id, applied_at, artifact_sha256, app_build, success
           FROM schema_migrations ORDER BY applied_at, migration_id"""
    ).fetchall()
    registry_by_id = {migration.migration_id: migration for migration in migrations}
    applied_ids: list[str] = []
    for row in rows:
        migration_id, applied_at, digest, app_build, success = row
        if (
            not isinstance(migration_id, str)
            or not _MIGRATION_ID_PATTERN.fullmatch(migration_id)
            or not _timestamp_is_aware(applied_at)
            or not isinstance(digest, str)
            or not _SHA256_PATTERN.fullmatch(digest)
            or not isinstance(app_build, str)
            or not app_build.strip()
            or isinstance(success, bool)
            or success != 1
        ):
            raise MigrationIntegrityError("malformed migration record")
        migration = registry_by_id.get(migration_id)
        if migration is None:
            raise MigrationIntegrityError("unknown applied migration")
        if digest != migration.artifact_sha256:
            raise MigrationIntegrityError("migration artifact digest mismatch")
        applied_ids.append(migration_id)

    expected_prefix = tuple(migration.migration_id for migration in migrations[: len(applied_ids)])
    if tuple(applied_ids) != expected_prefix:
        raise MigrationIntegrityError("applied migrations are not in registered order")
    if not applied_ids:
        raise MigrationIntegrityError("migration metadata exists without an applied foundation")
    return tuple(applied_ids)


def _verify_checkpoint_for_ids(
    connection: sqlite3.Connection,
    migrations: tuple[Migration, ...],
    applied_ids: tuple[str, ...],
) -> str:
    expected_prefix = tuple(migration.migration_id for migration in migrations[: len(applied_ids)])
    if not applied_ids or applied_ids != expected_prefix:
        raise MigrationIntegrityError("applied migrations are not a registered prefix")
    expected_schema = migrations[len(applied_ids) - 1].schema_after
    try:
        verify_schema(connection, expected_schema)
    except SchemaIntegrityError as exc:
        raise MigrationIntegrityError("schema drift detected") from exc
    return expected_schema.schema_version


def _read_and_validate_history(
    connection: sqlite3.Connection,
    migrations: tuple[Migration, ...],
) -> tuple[str, ...]:
    applied_ids = _validate_migration_rows(connection, migrations)
    _verify_checkpoint_for_ids(connection, migrations, applied_ids)
    return tuple(applied_ids)


def _require_readonly_connection(connection: sqlite3.Connection) -> None:
    try:
        query_only = int(connection.execute("PRAGMA query_only").fetchone()[0]) == 1
    except sqlite3.Error as exc:
        raise MigrationIntegrityError("read-only connection state could not be verified") from exc
    if not query_only:
        raise MigrationIntegrityError("read-only connection is required for inspection")


def inspect_migration_history_readonly(connection: sqlite3.Connection) -> tuple[str, ...]:
    """Validate applied IDs, order and artifact digests on a query-only connection."""
    _require_readonly_connection(connection)
    try:
        return _validate_migration_rows(connection, _registered_migrations())
    except sqlite3.Error:
        raise MigrationIntegrityError("migration history could not be read") from None


def inspect_migration_state_readonly(connection: sqlite3.Connection) -> MigrationState:
    """Validate schema integrity and report currentness without applying migrations.

    A historical registered prefix is a valid state when its checkpoint matches;
    callers can inspect ``pending_migration_ids`` to distinguish it from the current
    registered schema. This function never repairs or upgrades the database.
    """
    _require_readonly_connection(connection)
    try:
        migrations = _registered_migrations()
        applied_ids = _validate_migration_rows(connection, migrations)
        schema_version = _verify_checkpoint_for_ids(connection, migrations, applied_ids)
        return MigrationState(
            applied_migration_ids=applied_ids,
            schema_version=schema_version,
            pending_migration_ids=tuple(
                migration.migration_id for migration in migrations[len(applied_ids) :]
            ),
        )
    except sqlite3.Error:
        raise MigrationIntegrityError("migration state could not be read") from None


def has_registered_migration(state: MigrationState, migration_id: str) -> bool:
    """Return whether a validated registered schema prefix contains one migration.

    Read-only compatibility paths may accept an earlier valid checkpoint when it
    already contains the tables they consume. This helper never upgrades a database.
    Mutations continue to require the exact current schema through the writer lease.
    """
    if type(state) is not MigrationState or type(migration_id) is not str:
        return False
    return migration_id in state.applied_migration_ids


def verify_schema_checkpoint_readonly(
    connection: sqlite3.Connection, migration_ids: tuple[str, ...]
) -> str:
    """Verify the trusted schema checkpoint selected by applied migration IDs."""
    _require_readonly_connection(connection)
    if not isinstance(migration_ids, tuple):
        raise MigrationIntegrityError("applied migrations are not a registered prefix")
    try:
        return _verify_checkpoint_for_ids(
            connection,
            _registered_migrations(),
            migration_ids,
        )
    except sqlite3.Error:
        raise MigrationIntegrityError("schema checkpoint could not be verified") from None


def _next_applied_at(connection: sqlite3.Connection) -> str:
    now = datetime.now(UTC)
    previous_row = connection.execute(
        "SELECT applied_at FROM schema_migrations ORDER BY applied_at DESC LIMIT 1"
    ).fetchone()
    if previous_row is not None:
        previous = datetime.fromisoformat(str(previous_row[0])).astimezone(UTC)
        if now <= previous:
            now = previous + timedelta(microseconds=1)
    return now.isoformat(timespec="microseconds")


def _apply_migration(
    connection: sqlite3.Connection,
    migration: Migration,
    *,
    app_build: str,
) -> None:
    try:
        connection.execute("BEGIN IMMEDIATE")
        for statement in migration.statements:
            connection.execute(statement)
        applied_at = _next_applied_at(connection)
        connection.execute(
            """INSERT INTO schema_migrations
               (migration_id, applied_at, artifact_sha256, app_build, success)
               VALUES (?, ?, ?, ?, ?)""",
            (migration.migration_id, applied_at, migration.artifact_sha256, app_build, 1),
        )
        try:
            verify_schema(connection, migration.schema_after)
        except SchemaIntegrityError as exc:
            raise MigrationIntegrityError(
                f"registered migration produced schema drift ({migration.migration_id})"
            ) from exc
        verify_integrity(connection)
        connection.execute("COMMIT")
    except (sqlite3.Error, ValueError, MigrationIntegrityError) as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        if isinstance(exc, MigrationIntegrityError):
            raise
        raise MigrationApplyError(
            f"migration application failed ({migration.migration_id})"
        ) from exc


def initialize_storage(
    database: str | Path,
    *,
    app_build: str = f"sentinel-{__version__}",
    create: bool = False,
) -> tuple[str, ...]:
    """Verify existing migrations and apply missing registered migrations in order.

    Missing databases are refused by default. Passing ``create=True`` explicitly
    creates only the exact path supplied by the caller. Returns IDs newly applied
    during this invocation.
    """
    if not isinstance(app_build, str) or not app_build.strip():
        raise ValueError("app_build must be a non-empty string")
    migrations = _registered_migrations()
    newly_applied: list[str] = []

    with database_connection(database, create=create) as connection:
        if not _has_migration_table(connection):
            existing_objects = _user_schema_objects(connection)
            if existing_objects:
                raise MigrationIntegrityError("untracked schema exists without migration metadata")
            applied_ids: tuple[str, ...] = ()
        else:
            applied_ids = _read_and_validate_history(connection, migrations)

        for migration in migrations[len(applied_ids) :]:
            _apply_migration(connection, migration, app_build=app_build)
            newly_applied.append(migration.migration_id)
            try:
                verify_schema(connection, migration.schema_after)
            except SchemaIntegrityError as exc:
                raise MigrationIntegrityError("schema drift detected after migration") from exc

        _read_and_validate_history(connection, migrations)
        verify_integrity(connection)
    return tuple(newly_applied)


def verify_integrity(connection: sqlite3.Connection) -> None:
    """Run SQLite page and foreign-key integrity checks; raise on any reported issue."""
    verify_sqlite_integrity(connection)
    verify_foreign_key_integrity(connection)


def verify_sqlite_integrity(connection: sqlite3.Connection) -> None:
    """Run SQLite's full page, index and constraint integrity check."""
    try:
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
    except sqlite3.Error as exc:
        raise MigrationIntegrityError("SQLite integrity check could not complete") from exc
    if integrity_rows != [("ok",)]:
        raise MigrationIntegrityError("SQLite integrity check failed")


def verify_foreign_key_integrity(connection: sqlite3.Connection) -> None:
    """Run SQLite's foreign-key check separately for diagnostic reporting."""
    try:
        foreign_key_rows = connection.execute("PRAGMA foreign_key_check").fetchall()
    except sqlite3.Error as exc:
        raise MigrationIntegrityError("SQLite foreign-key check could not complete") from exc
    if foreign_key_rows:
        raise MigrationIntegrityError("SQLite foreign-key check failed")
