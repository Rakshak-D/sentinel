"""Disposable database helpers for CR1-J tests."""

from pathlib import Path

import sentinel.storage.migrations as migration_module
from sentinel.storage.connection import database_connection
from sentinel.storage.migrations import initialize_storage


def initialized_task_database(path: Path) -> Path:
    initialize_storage(path, create=True)
    return path


def historical_prefix_database(path: Path, count: int) -> Path:
    with database_connection(path, create=True) as connection:
        for migration in migration_module.MIGRATIONS[:count]:
            migration_module._apply_migration(
                connection, migration, app_build="synthetic-cr1-j-prefix"
            )
    return path


def migration_history(path: Path) -> tuple[tuple[object, ...], ...]:
    with database_connection(path) as connection:
        return tuple(
            tuple(row)
            for row in connection.execute(
                """SELECT migration_id, applied_at, artifact_sha256, app_build, success
                   FROM schema_migrations ORDER BY applied_at, migration_id"""
            )
        )
