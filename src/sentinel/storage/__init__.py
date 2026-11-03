"""Explicit local SQLite storage primitives for Sentinel."""

from sentinel.storage.connection import (
    DEFAULT_BUSY_TIMEOUT_MS,
    ConnectionSettings,
    DatabaseOpenError,
    database_connection,
    inspect_connection,
    open_database,
    open_database_readonly,
    readonly_database_connection,
)
from sentinel.storage.migrations import (
    Migration,
    MigrationApplyError,
    MigrationIntegrityError,
    initialize_storage,
    inspect_migration_history_readonly,
    verify_foreign_key_integrity,
    verify_integrity,
    verify_schema_checkpoint_readonly,
    verify_sqlite_integrity,
)

__all__ = [
    "DEFAULT_BUSY_TIMEOUT_MS",
    "ConnectionSettings",
    "DatabaseOpenError",
    "Migration",
    "MigrationApplyError",
    "MigrationIntegrityError",
    "database_connection",
    "inspect_migration_history_readonly",
    "initialize_storage",
    "inspect_connection",
    "open_database",
    "open_database_readonly",
    "readonly_database_connection",
    "verify_foreign_key_integrity",
    "verify_integrity",
    "verify_schema_checkpoint_readonly",
    "verify_sqlite_integrity",
]
