"""Explicit local SQLite storage primitives for Sentinel."""

from sentinel.storage.connection import (
    DEFAULT_BUSY_TIMEOUT_MS,
    ConnectionSettings,
    DatabaseOpenError,
    database_connection,
    inspect_connection,
    open_database,
)
from sentinel.storage.migrations import (
    Migration,
    MigrationApplyError,
    MigrationIntegrityError,
    initialize_storage,
    verify_integrity,
)

__all__ = [
    "DEFAULT_BUSY_TIMEOUT_MS",
    "ConnectionSettings",
    "DatabaseOpenError",
    "Migration",
    "MigrationApplyError",
    "MigrationIntegrityError",
    "database_connection",
    "initialize_storage",
    "inspect_connection",
    "open_database",
    "verify_integrity",
]
