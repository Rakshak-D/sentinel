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
    MIGRATION_INDEX_DDL,
    MIGRATION_TABLE_DDL,
    SchemaIntegrityError,
    verify_schema,
)

_MIGRATION_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_FOUNDATION_MIGRATION_ID: Final = "cr0-c-0001-schema-migrations"


class MigrationIntegrityError(RuntimeError):
    """Raised when persisted migration history or schema cannot be trusted."""


class MigrationApplyError(RuntimeError):
    """Raised when one registered migration failed and was rolled back."""


@dataclass(frozen=True, slots=True)
class Migration:
    """One trusted migration artifact represented by ordered, single SQL statements."""

    migration_id: str
    statements: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.migration_id, str) or not _MIGRATION_ID_PATTERN.fullmatch(
            self.migration_id
        ):
            raise ValueError("migration_id must be a lowercase identifier")
        if not isinstance(self.statements, tuple) or not self.statements:
            raise ValueError("migration statements must be a non-empty tuple")
        if any(
            not isinstance(statement, str) or not statement.strip()
            for statement in self.statements
        ):
            raise ValueError("migration statements must contain non-empty SQL strings")

    @property
    def canonical_artifact(self) -> bytes:
        """Return deterministic UTF-8 bytes representing this exact migration content."""
        payload = {"migration_id": self.migration_id, "statements": self.statements}
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


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        _FOUNDATION_MIGRATION_ID,
        (MIGRATION_TABLE_DDL, MIGRATION_INDEX_DDL),
    ),
)


def _registered_migrations() -> tuple[Migration, ...]:
    migrations = MIGRATIONS
    if not migrations or migrations[0].migration_id != _FOUNDATION_MIGRATION_ID:
        raise MigrationIntegrityError("registered migration set lacks its foundation migration")
    ids = tuple(migration.migration_id for migration in migrations)
    if len(ids) != len(set(ids)):
        raise MigrationIntegrityError("registered migration IDs are not unique")
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


def _read_and_validate_history(
    connection: sqlite3.Connection,
    migrations: tuple[Migration, ...],
) -> tuple[str, ...]:
    try:
        verify_schema(connection)
    except SchemaIntegrityError as exc:
        raise MigrationIntegrityError("schema drift detected") from exc

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
    return tuple(applied_ids)


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
            verify_schema(connection)
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
                verify_schema(connection)
            except SchemaIntegrityError as exc:
                raise MigrationIntegrityError("schema drift detected after migration") from exc

        _read_and_validate_history(connection, migrations)
        verify_integrity(connection)
    return tuple(newly_applied)


def verify_integrity(connection: sqlite3.Connection) -> None:
    """Run SQLite page and foreign-key integrity checks; raise on any reported issue."""
    try:
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
        foreign_key_rows = connection.execute("PRAGMA foreign_key_check").fetchall()
    except sqlite3.Error as exc:
        raise MigrationIntegrityError("SQLite integrity checks could not complete") from exc
    if integrity_rows != [("ok",)]:
        raise MigrationIntegrityError("SQLite integrity check failed")
    if foreign_key_rows:
        raise MigrationIntegrityError("SQLite foreign-key check failed")
