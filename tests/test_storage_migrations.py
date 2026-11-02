"""Tests for fixed, ordered and atomic schema migrations."""

import sqlite3
from pathlib import Path

import pytest

import sentinel.storage.migrations as migration_module
from sentinel.storage.connection import database_connection
from sentinel.storage.migrations import (
    Migration,
    MigrationApplyError,
    MigrationIntegrityError,
    initialize_storage,
    verify_integrity,
)


def _applied_rows(database: Path) -> list[tuple[object, ...]]:
    with database_connection(database) as connection:
        return connection.execute(
            """SELECT migration_id, applied_at, artifact_sha256, app_build, success
               FROM schema_migrations ORDER BY applied_at, migration_id"""
        ).fetchall()


def _initialize(database: Path, *, app_build: str = "sentinel-0.1.0") -> None:
    initialize_storage(database, app_build=app_build, create=True)


def test_initial_migration_creates_only_normative_migration_metadata(
    tmp_path: Path,
) -> None:
    database = tmp_path / "initial.sqlite3"

    _initialize(database, app_build="sentinel-test")

    with database_connection(database) as connection:
        columns = connection.execute("PRAGMA table_info(schema_migrations)").fetchall()
        objects = connection.execute(
            """SELECT type, name FROM sqlite_master
               WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"""
        ).fetchall()
    assert [column[1] for column in columns] == [
        "migration_id",
        "applied_at",
        "artifact_sha256",
        "app_build",
        "success",
    ]
    assert objects == [
        ("index", "schema_migrations_applied_at_idx"),
        ("table", "schema_migrations"),
    ]
    rows = _applied_rows(database)
    assert len(rows) == 1
    assert rows[0][2] == migration_module.MIGRATIONS[0].artifact_sha256
    assert rows[0][3:] == ("sentinel-test", 1)


def test_repeated_initialization_is_idempotent(tmp_path: Path) -> None:
    database = tmp_path / "idempotent.sqlite3"
    _initialize(database)
    first_rows = _applied_rows(database)

    _initialize(database)

    assert _applied_rows(database) == first_rows


def test_registry_migrations_apply_in_declared_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "ordered.sqlite3"
    registered = (
        *migration_module.MIGRATIONS,
        Migration("test-0002", ("SELECT 2",)),
        Migration("test-0003", ("SELECT 3",)),
    )
    monkeypatch.setattr(migration_module, "MIGRATIONS", registered)

    _initialize(database)

    assert [row[0] for row in _applied_rows(database)] == [
        "cr0-c-0001-schema-migrations",
        "test-0002",
        "test-0003",
    ]


def test_unknown_previously_applied_migration_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "unknown.sqlite3"
    _initialize(database)
    with database_connection(database) as connection:
        connection.execute(
            """INSERT INTO schema_migrations
               (migration_id, applied_at, artifact_sha256, app_build, success)
               VALUES (?, ?, ?, ?, ?)""",
            (
                "foreign-0001",
                "2026-11-02T00:00:00.000000+00:00",
                "0" * 64,
                "fixture",
                1,
            ),
        )

    with pytest.raises(MigrationIntegrityError, match="unknown applied migration"):
        _initialize(database)


def test_modified_registered_migration_digest_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "tampered.sqlite3"
    _initialize(database)
    with database_connection(database) as connection:
        connection.execute(
            "UPDATE schema_migrations SET artifact_sha256 = ?",
            ("0" * 64,),
        )

    with pytest.raises(MigrationIntegrityError, match="artifact digest mismatch"):
        _initialize(database)


def test_changed_registered_migration_content_fails_digest_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "changed-artifact.sqlite3"
    _initialize(database)
    changed_foundation = Migration(
        "cr0-c-0001-schema-migrations",
        ("SELECT 'altered synthetic artifact'",),
    )
    monkeypatch.setattr(migration_module, "MIGRATIONS", (changed_foundation,))

    with pytest.raises(MigrationIntegrityError, match="artifact digest mismatch"):
        initialize_storage(database)


def test_missing_registered_migration_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "missing-registered.sqlite3"
    _initialize(database)
    monkeypatch.setattr(migration_module, "MIGRATIONS", ())

    with pytest.raises(MigrationIntegrityError, match="registered migration"):
        _initialize(database)


def test_malformed_migration_metadata_is_rejected(tmp_path: Path) -> None:
    database = tmp_path / "malformed.sqlite3"
    _initialize(database)
    with database_connection(database) as connection:
        connection.execute("UPDATE schema_migrations SET success = 2")

    with pytest.raises(MigrationIntegrityError, match="malformed migration record"):
        _initialize(database)


def test_schema_drift_is_reported_without_automatic_repair(tmp_path: Path) -> None:
    database = tmp_path / "drift.sqlite3"
    _initialize(database)
    with database_connection(database) as connection:
        connection.execute("DROP INDEX schema_migrations_applied_at_idx")

    with pytest.raises(MigrationIntegrityError, match="schema drift"):
        _initialize(database)

    with database_connection(database) as connection:
        indexes = connection.execute("PRAGMA index_list(schema_migrations)").fetchall()
    assert [row[1] for row in indexes] == ["sqlite_autoindex_schema_migrations_1"]


def test_failed_multistatement_migration_rolls_back_every_statement_and_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "rollback.sqlite3"
    failing = Migration(
        "test-0002-failure",
        (
            "CREATE TABLE should_rollback (record_id TEXT PRIMARY KEY)",
            "INSERT INTO absent_table VALUES ('synthetic')",
        ),
    )
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS, failing),
    )

    with pytest.raises(MigrationApplyError, match="migration application failed"):
        _initialize(database)

    with database_connection(database) as connection:
        created = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'should_rollback'"
        ).fetchone()
        failed_record = connection.execute(
            "SELECT migration_id FROM schema_migrations WHERE migration_id = ?",
            (failing.migration_id,),
        ).fetchone()
    assert created is None
    assert failed_record is None


def test_operational_migration_failure_is_not_reported_as_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "operational-failure.sqlite3"
    failing = Migration("test-0002-operational", ("THIS IS NOT SQL",))
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS, failing),
    )

    with pytest.raises(MigrationApplyError) as error:
        _initialize(database)
    assert isinstance(error.value.__cause__, sqlite3.Error)

    with database_connection(database) as connection:
        assert connection.execute(
            "SELECT success FROM schema_migrations WHERE migration_id = ?",
            (failing.migration_id,),
        ).fetchone() is None


def test_existing_user_schema_without_metadata_is_not_repaired(tmp_path: Path) -> None:
    database = tmp_path / "untracked-schema.sqlite3"
    with database_connection(database, create=True) as connection:
        connection.execute("CREATE TABLE unrelated (id TEXT PRIMARY KEY)")

    with pytest.raises(MigrationIntegrityError, match="untracked schema"):
        _initialize(database)

    with database_connection(database) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'unrelated'"
        ).fetchall()
    assert tables == [("unrelated",)]


def test_foreign_key_check_and_integrity_check_run(tmp_path: Path) -> None:
    database = tmp_path / "integrity.sqlite3"
    _initialize(database)

    with database_connection(database) as connection:
        traced_statements: list[str] = []
        connection.set_trace_callback(traced_statements.append)
        assert verify_integrity(connection) is None
        connection.set_trace_callback(None)
        assert any("PRAGMA integrity_check" in statement for statement in traced_statements)
        assert any("PRAGMA foreign_key_check" in statement for statement in traced_statements)
        connection.execute("CREATE TABLE fk_parent (id TEXT PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE fk_child (parent_id TEXT REFERENCES fk_parent(id))"
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO fk_child VALUES ('missing-parent')")
