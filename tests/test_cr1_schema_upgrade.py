"""Upgrade semantics for the CR1-E source-registry migration."""

from pathlib import Path

import pytest

import sentinel.storage.migrations as migration_module
from sentinel.bootstrap.doctor import run_doctor
from sentinel.storage.connection import database_connection, readonly_database_connection
from sentinel.storage.migrations import (
    Migration,
    MigrationApplyError,
    initialize_storage,
    inspect_migration_history_readonly,
    inspect_migration_state_readonly,
    verify_integrity,
    verify_schema_checkpoint_readonly,
)
from sentinel.storage.schema import SchemaDefinition, SchemaObjectDefinition
from sentinel.storage.writer import acquire_writer_lease

FOUNDATION_ID = "cr0-c-0001-schema-migrations"
CR1_E_MIGRATION_ID = "cr1-e-0002-source-registry"
CR1_F_MIGRATION_ID = "cr1-f-0003-source-spans"
CR1_J_MIGRATION_ID = "cr1-j-0004-local-tasks"
CR2_D_MIGRATION_ID = "cr2-d-0005-durable-pending-proposals"
FOUNDATION_SHA256 = "b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217"


def _foundation_only_database(
    database: Path,
) -> tuple[object, ...]:
    foundation = migration_module.MIGRATIONS[0]
    with database_connection(database, create=True) as connection:
        migration_module._apply_migration(
            connection,
            foundation,
            app_build="synthetic-cr0",
        )
    with database_connection(database) as connection:
        row = connection.execute(
            """SELECT migration_id, applied_at, artifact_sha256, app_build, success
               FROM schema_migrations"""
        ).fetchone()
    assert row is not None
    return tuple(row)


def test_existing_cr0_database_upgrades_without_rewriting_old_metadata(
    tmp_path: Path,
) -> None:
    database = tmp_path / "historical-cr0.sqlite3"
    old_row = _foundation_only_database(database)

    assert initialize_storage(database) == (
        CR1_E_MIGRATION_ID,
        CR1_F_MIGRATION_ID,
        CR1_J_MIGRATION_ID,
        CR2_D_MIGRATION_ID,
    )
    assert initialize_storage(database) == ()

    with database_connection(database) as connection:
        rows = connection.execute(
            """SELECT migration_id, applied_at, artifact_sha256, app_build, success
               FROM schema_migrations ORDER BY applied_at, migration_id"""
        ).fetchall()
        verify_integrity(connection)
    with readonly_database_connection(database) as connection:
        upgraded_state = inspect_migration_state_readonly(connection)
    assert tuple(rows[0]) == old_row
    assert rows[0][2] == FOUNDATION_SHA256
    assert rows[1][0] == CR1_E_MIGRATION_ID
    assert rows[1][4] == 1
    assert rows[2][0] == CR1_F_MIGRATION_ID
    assert rows[2][4] == 1
    assert rows[3][0] == CR1_J_MIGRATION_ID
    assert rows[3][4] == 1
    assert rows[4][0] == CR2_D_MIGRATION_ID
    assert rows[4][4] == 1
    assert upgraded_state.applied_migration_ids == (
        FOUNDATION_ID,
        CR1_E_MIGRATION_ID,
        CR1_F_MIGRATION_ID,
        CR1_J_MIGRATION_ID,
        CR2_D_MIGRATION_ID,
    )
    assert upgraded_state.pending_migration_ids == ()
    assert upgraded_state.is_current is True


def test_schema_integrity_and_pending_migrations_are_distinguished_readonly(
    tmp_path: Path,
) -> None:
    database = tmp_path / "pending-cr1-e.sqlite3"
    old_row = _foundation_only_database(database)
    before = database.read_bytes()

    with readonly_database_connection(database) as connection:
        applied = inspect_migration_history_readonly(connection)
        version = verify_schema_checkpoint_readonly(connection, applied)
        state = inspect_migration_state_readonly(connection)
    report = run_doctor(database)

    assert applied == (FOUNDATION_ID,)
    assert version == FOUNDATION_ID
    assert state.applied_migration_ids == applied
    assert state.schema_version == FOUNDATION_ID
    assert state.pending_migration_ids == (
        CR1_E_MIGRATION_ID,
        CR1_F_MIGRATION_ID,
        CR1_J_MIGRATION_ID,
        CR2_D_MIGRATION_ID,
    )
    assert state.is_current is False
    assert report.successful is True
    assert database.read_bytes() == before
    with database_connection(database) as connection:
        row = connection.execute(
            """SELECT migration_id, applied_at, artifact_sha256, app_build, success
               FROM schema_migrations"""
        ).fetchone()
        assert tuple(row) == old_row
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sources'"
        ).fetchone() is None


def test_failed_migration_rolls_back_every_schema_object_and_history_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "failed-cr1-migration.sqlite3"
    initialize_storage(database, create=True)
    before_ids = tuple(
        migration.migration_id
        for migration in migration_module.MIGRATIONS
    )
    migration_id = "test-failing-cr1-e-child"
    table_sql = "CREATE TABLE test_failed_cr1_child (item_id TEXT NOT NULL PRIMARY KEY)"
    checkpoint = migration_module.MIGRATIONS[-1].schema_after
    failed = Migration(
        migration_id,
        (table_sql, "CREATE TABLE test_failed_cr1_child (broken"),
        SchemaDefinition(
            migration_id,
            (*checkpoint.objects, SchemaObjectDefinition(
                "table", "test_failed_cr1_child", table_sql
            )),
        ),
    )
    monkeypatch.setattr(migration_module, "MIGRATIONS", (*migration_module.MIGRATIONS, failed))

    with pytest.raises(MigrationApplyError):
        initialize_storage(database)

    with database_connection(database) as connection:
        assert tuple(row[0] for row in connection.execute(
            "SELECT migration_id FROM schema_migrations ORDER BY applied_at, migration_id"
        )) == before_ids
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='test_failed_cr1_child'"
        ).fetchone() is None


def test_active_sqlite_writer_prevents_maintenance_upgrade_without_partial_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "blocked-maintenance.sqlite3"
    _foundation_only_database(database)

    original_database_connection = migration_module.database_connection

    def short_busy_timeout(database: str | Path, **kwargs: object):
        kwargs["busy_timeout_ms"] = 25
        return original_database_connection(database, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(migration_module, "database_connection", short_busy_timeout)

    with acquire_writer_lease(database) as lease:
        with lease.transaction():
            with pytest.raises(MigrationApplyError):
                initialize_storage(database)

    with database_connection(database) as connection:
        assert tuple(row[0] for row in connection.execute(
            "SELECT migration_id FROM schema_migrations ORDER BY applied_at, migration_id"
        )) == (FOUNDATION_ID,)
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='sources'"
        ).fetchone() is None
