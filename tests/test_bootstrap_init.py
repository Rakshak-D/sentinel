"""Behavior tests for exclusive, explicit local database initialization."""

import sqlite3
from pathlib import Path

import pytest

import sentinel.bootstrap.init as init_module
from sentinel.bootstrap.init import (
    BootstrapInitError,
    InitializationErrorCode,
    initialize_new_database,
)
from sentinel.storage.connection import database_connection, inspect_connection
from sentinel.storage.migrations import MIGRATIONS, initialize_storage, verify_integrity

FOUNDATION_ID = "cr0-c-0001-schema-migrations"
FOUNDATION_SHA256 = "b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217"


def test_new_database_uses_only_registered_foundation_and_integrity_checks(
    tmp_path: Path,
) -> None:
    database = tmp_path / "sentinel.sqlite3"

    result = initialize_new_database(database)

    assert result.migration_ids == (FOUNDATION_ID,)
    assert MIGRATIONS[0].migration_id == FOUNDATION_ID
    assert MIGRATIONS[0].artifact_sha256 == FOUNDATION_SHA256
    with database_connection(database) as connection:
        row = connection.execute(
            "SELECT migration_id, artifact_sha256, success FROM schema_migrations"
        ).fetchone()
        settings = inspect_connection(connection)
        objects = connection.execute(
            """SELECT type, name FROM sqlite_master
               WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"""
        ).fetchall()
        verify_integrity(connection)
    assert row == (FOUNDATION_ID, FOUNDATION_SHA256, 1)
    assert settings.foreign_keys_enabled is True
    assert settings.journal_mode == "wal"
    assert objects == [
        ("index", "schema_migrations_applied_at_idx"),
        ("table", "schema_migrations"),
    ]


def test_new_database_closes_and_reopens_without_duplicate_migration(
    tmp_path: Path,
) -> None:
    database = tmp_path / "reopen.sqlite3"
    initialize_new_database(database)

    with database_connection(database) as connection:
        assert connection.execute("SELECT 1").fetchone() == (1,)
        assert connection.execute("PRAGMA foreign_keys").fetchone() == (1,)
    assert initialize_storage(database) == ()

    with database_connection(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM schema_migrations WHERE migration_id = ?",
            (FOUNDATION_ID,),
        ).fetchone() == (1,)


def test_relative_path_fails_without_creating_a_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(BootstrapInitError) as caught:
        initialize_new_database(Path("relative.sqlite3"))

    assert caught.value.code == InitializationErrorCode.PATH_NOT_ABSOLUTE
    assert not (tmp_path / "relative.sqlite3").exists()


def test_missing_parent_fails_without_creating_directories(tmp_path: Path) -> None:
    database = tmp_path / "not-created" / "nested" / "sentinel.sqlite3"

    with pytest.raises(BootstrapInitError) as caught:
        initialize_new_database(database)

    assert caught.value.code == InitializationErrorCode.PARENT_MISSING
    assert not database.parent.exists()


def test_existing_regular_file_is_unchanged(tmp_path: Path) -> None:
    database = tmp_path / "existing.txt"
    before = b"SYNTHETIC-EXISTING-FILE-CANARY\x00\x01"
    database.write_bytes(before)

    with pytest.raises(BootstrapInitError) as caught:
        initialize_new_database(database)

    assert caught.value.code == InitializationErrorCode.ALREADY_EXISTS
    assert database.read_bytes() == before


def test_existing_valid_sentinel_database_is_refused_unchanged(tmp_path: Path) -> None:
    database = tmp_path / "existing-sentinel.sqlite3"
    initialize_storage(database, create=True)
    before = database.read_bytes()

    with pytest.raises(BootstrapInitError) as caught:
        initialize_new_database(database)

    assert caught.value.code == InitializationErrorCode.ALREADY_EXISTS
    assert database.read_bytes() == before
    with database_connection(database) as connection:
        assert connection.execute("SELECT count(*) FROM schema_migrations").fetchone() == (1,)


def test_final_path_symlink_is_refused_and_target_is_unchanged(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target_bytes = b"SYNTHETIC-SYMLINK-TARGET-CANARY"
    target.write_bytes(target_bytes)
    link = tmp_path / "sentinel-link.sqlite3"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"final-component symlinks are unavailable on this host: {type(exc).__name__}")

    with pytest.raises(BootstrapInitError) as caught:
        initialize_new_database(link)

    assert caught.value.code == InitializationErrorCode.ALREADY_EXISTS
    assert link.is_symlink()
    assert target.read_bytes() == target_bytes


def test_sqlite_failure_is_bounded_and_new_file_is_left_for_inspection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "failed.sqlite3"
    canary = "SYNTHETIC_SQLITE_FAILURE_CANARY"

    def fail_initialization(_database: str | Path, **_kwargs: object) -> tuple[str, ...]:
        raise sqlite3.OperationalError(f"{canary}: {database}")

    monkeypatch.setattr(init_module, "initialize_storage", fail_initialization)
    with pytest.raises(BootstrapInitError) as caught:
        initialize_new_database(database)

    assert caught.value.code == InitializationErrorCode.STORAGE_INITIALIZATION_FAILED
    assert canary not in str(caught.value)
    assert str(database) not in str(caught.value)
    assert database.is_file()
    assert database.read_bytes() == b""


def test_file_system_permission_failure_has_a_bounded_category(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "denied.sqlite3"

    def deny_open(*_args: object, **_kwargs: object) -> int:
        raise PermissionError("SYNTHETIC_PERMISSION_CANARY")

    monkeypatch.setattr(init_module.os, "open", deny_open)
    with pytest.raises(BootstrapInitError) as caught:
        initialize_new_database(database)

    assert caught.value.code == InitializationErrorCode.PERMISSION_DENIED
    assert "SYNTHETIC_PERMISSION_CANARY" not in str(caught.value)
    assert not database.exists()
