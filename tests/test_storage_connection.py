"""Tests for explicit SQLite connection management."""

import sqlite3
from pathlib import Path

import pytest

from sentinel.storage.connection import (
    DatabaseOpenError,
    database_connection,
    inspect_connection,
    open_database,
)
from sentinel.storage.migrations import MIGRATIONS, initialize_storage


def test_file_creation_is_explicit_and_errors_are_actionable(tmp_path: Path) -> None:
    database = tmp_path / "selected.sqlite3"

    with pytest.raises(DatabaseOpenError, match="does not exist"):
        open_database(database)
    assert not database.exists()

    with database_connection(database, create=True) as connection:
        assert connection.execute("SELECT 1").fetchone() == (1,)
    assert database.is_file()


def test_connection_settings_enable_foreign_keys_wal_and_bounded_timeout(
    tmp_path: Path,
) -> None:
    database = tmp_path / "settings.sqlite3"

    with database_connection(database, create=True) as connection:
        settings = inspect_connection(connection)

    assert settings.foreign_keys_enabled is True
    assert settings.journal_mode == "wal"
    assert settings.busy_timeout_ms == 5_000


def test_every_connection_enables_foreign_keys(tmp_path: Path) -> None:
    database = tmp_path / "foreign-keys.sqlite3"
    first = open_database(database, create=True)
    first.close()

    second = open_database(database)
    try:
        assert second.execute("PRAGMA foreign_keys").fetchone() == (1,)
    finally:
        second.close()


def test_memory_database_has_foreign_keys_but_does_not_claim_wal() -> None:
    with database_connection(":memory:") as connection:
        settings = inspect_connection(connection)

    assert settings.foreign_keys_enabled is True
    assert settings.journal_mode == "memory"


def test_invalid_database_locations_fail_without_creating_parent_directories(
    tmp_path: Path,
) -> None:
    missing_parent = tmp_path / "absent" / "database.sqlite3"

    with pytest.raises(DatabaseOpenError, match="parent directory"):
        open_database(missing_parent, create=True)
    assert not missing_parent.parent.exists()

    with pytest.raises(DatabaseOpenError, match="does not exist"):
        initialize_storage(tmp_path / "uncreated.sqlite3", create=False)

    directory_target = tmp_path / "database-directory"
    directory_target.mkdir()
    with pytest.raises(DatabaseOpenError, match="is a directory"):
        open_database(directory_target)


def test_connection_context_releases_the_sqlite_resource(tmp_path: Path) -> None:
    database = tmp_path / "closed.sqlite3"

    with database_connection(database, create=True) as connection:
        connection.execute("SELECT 1")

    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        connection.execute("SELECT 1")


def test_reopening_does_not_remove_existing_data(tmp_path: Path) -> None:
    database = tmp_path / "preserve.sqlite3"
    initialize_storage(database, create=True)

    with database_connection(database) as connection:
        connection.execute(
            "UPDATE schema_migrations SET app_build = ?",
            ("synthetic-persisted-fixture",),
        )

    initialize_storage(database)

    with database_connection(database) as connection:
        rows = connection.execute("SELECT app_build FROM schema_migrations").fetchall()
    assert rows == [("synthetic-persisted-fixture",)] * len(MIGRATIONS)
