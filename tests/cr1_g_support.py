"""Synthetic database helpers shared by the CR1-G tests."""

from pathlib import Path

from sentinel.storage.connection import database_connection
from sentinel.storage.migrations import MIGRATIONS, _apply_migration, initialize_storage


def initialized_database(path: Path) -> Path:
    initialize_storage(path, create=True)
    return path


def migration_prefix_database(path: Path, count: int) -> Path:
    with database_connection(path, create=True) as connection:
        for migration in MIGRATIONS[:count]:
            _apply_migration(connection, migration, app_build="synthetic-cr1-g-prefix")
    return path


def scalar(path: Path, query: str, parameters: tuple[object, ...] = ()) -> object:
    with database_connection(path) as connection:
        row = connection.execute(query, parameters).fetchone()
    assert row is not None
    return row[0]
