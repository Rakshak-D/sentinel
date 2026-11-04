"""Historical-prefix upgrade and migration lifecycle tests for CR1-F."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

import sentinel.storage.migrations as migration_module
from sentinel.bootstrap.doctor import run_doctor
from sentinel.storage.connection import database_connection, readonly_database_connection
from sentinel.storage.migrations import (
    MigrationApplyError,
    MigrationIntegrityError,
    initialize_storage,
    inspect_migration_state_readonly,
)
from sentinel.storage.writer import acquire_writer_lease

CR0_ID = "cr0-c-0001-schema-migrations"
CR1_E_ID = "cr1-e-0002-source-registry"
CR1_F_ID = "cr1-f-0003-source-spans"
CR1_J_ID = "cr1-j-0004-local-tasks"


def _prefix_database(database: Path, count: int) -> Path:
    with database_connection(database, create=True) as connection:
        for migration in migration_module.MIGRATIONS[:count]:
            migration_module._apply_migration(
                connection, migration, app_build="synthetic-prefix-fixture"
            )
    return database


def _history(database: Path) -> list[tuple[object, ...]]:
    with database_connection(database) as connection:
        return connection.execute(
            """SELECT migration_id, applied_at, artifact_sha256, app_build, success
               FROM schema_migrations ORDER BY applied_at, migration_id"""
        ).fetchall()


def _tables(database: Path) -> set[str]:
    with database_connection(database) as connection:
        return {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }


def test_cr1_e_database_upgrades_once_without_rewriting_history_or_existing_data(
    tmp_path: Path,
) -> None:
    database = _prefix_database(tmp_path / "cr1-e.sqlite3", 2)
    with database_connection(database) as connection:
        connection.execute(
            """INSERT INTO principals
               (principal_id, kind, display_name, os_binding, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                "principal-before-f",
                "owner",
                "Synthetic existing",
                "opaque:os",
                "2026-11-03T00:00:00Z",
            ),
        )
    old_rows = _history(database)

    assert initialize_storage(database) == (CR1_F_ID, CR1_J_ID)
    new_rows = _history(database)
    assert [row[0] for row in new_rows] == [CR0_ID, CR1_E_ID, CR1_F_ID, CR1_J_ID]
    assert new_rows[:2] == old_rows
    assert initialize_storage(database) == ()
    assert _history(database) == new_rows
    assert {
        "config_revisions",
        "run_manifests",
        "runs",
        "boundary_envelopes",
        "source_spans",
    } <= _tables(database)
    with database_connection(database) as connection:
        assert connection.execute(
            "SELECT principal_id, display_name FROM principals WHERE principal_id = ?",
            ("principal-before-f",),
        ).fetchone() == ("principal-before-f", "Synthetic existing")


def test_cr0_only_database_upgrades_through_cr1_e_and_cr1_f_in_order(
    tmp_path: Path,
) -> None:
    database = _prefix_database(tmp_path / "cr0.sqlite3", 1)
    before = _history(database)
    assert before[0][0] == CR0_ID

    assert initialize_storage(database) == (CR1_E_ID, CR1_F_ID, CR1_J_ID)
    assert [row[0] for row in _history(database)] == [CR0_ID, CR1_E_ID, CR1_F_ID, CR1_J_ID]
    assert _history(database)[0] == before[0]
    with database_connection(database) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone() == (1,)
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
        verify = connection.execute("PRAGMA integrity_check").fetchall()
        foreign_key_rows = connection.execute("PRAGMA foreign_key_check").fetchall()
    assert verify == [("ok",)]
    assert foreign_key_rows == []


def test_readonly_state_reports_valid_cr1_e_prefix_pending_cr1_f(tmp_path: Path) -> None:
    database = _prefix_database(tmp_path / "historical-e.sqlite3", 2)
    with readonly_database_connection(database) as connection:
        state = inspect_migration_state_readonly(connection)
    assert state.applied_migration_ids == (CR0_ID, CR1_E_ID)
    assert state.schema_version == CR1_E_ID
    assert state.pending_migration_ids == (CR1_F_ID, CR1_J_ID)
    assert state.is_current is False
    assert CR1_F_ID not in tuple(row[0] for row in _history(database))


def test_doctor_does_not_apply_pending_cr1_f_migration(tmp_path: Path) -> None:
    database = _prefix_database(tmp_path / "doctor-e.sqlite3", 2)
    history_before = _history(database)
    tables_before = _tables(database)

    run_doctor(database)

    assert _history(database) == history_before
    assert _tables(database) == tables_before
    assert "source_spans" not in _tables(database)


def test_writer_lease_does_not_apply_pending_cr1_f_migration(tmp_path: Path) -> None:
    database = _prefix_database(tmp_path / "writer-e.sqlite3", 2)
    history_before = _history(database)
    tables_before = _tables(database)

    with acquire_writer_lease(database):
        pass

    assert _history(database) == history_before
    assert _tables(database) == tables_before
    assert "source_spans" not in _tables(database)


def test_failed_cr1_f_migration_rolls_back_all_new_ddl_and_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _prefix_database(tmp_path / "rollback.sqlite3", 2)
    history_before = _history(database)
    objects_before: set[tuple[str, str]]
    with database_connection(database) as connection:
        objects_before = set(
            connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
        )

    def fail_once_after_ddl(connection: sqlite3.Connection) -> None:
        raise MigrationIntegrityError("synthetic migration failure")

    monkeypatch.setattr(migration_module, "verify_integrity", fail_once_after_ddl)
    with pytest.raises(MigrationIntegrityError, match="synthetic migration failure"):
        initialize_storage(database)

    assert _history(database) == history_before
    with database_connection(database) as connection:
        objects_after = set(
            connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
        )
        verify_integrity = connection.execute("PRAGMA integrity_check").fetchall()
    assert objects_after == objects_before
    assert verify_integrity == [("ok",)]


def test_active_sqlite_writer_blocks_maintenance_upgrade_without_partial_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _prefix_database(tmp_path / "writer-blocks-f.sqlite3", 2)
    history_before = _history(database)
    tables_before = _tables(database)

    @contextmanager
    def quick_connection(
        target: str | Path, *, create: bool = False
    ) -> Iterator[sqlite3.Connection]:
        assert create is False
        connection = sqlite3.connect(target, timeout=0.02, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
        finally:
            connection.close()

    with monkeypatch.context() as local_patch:
        local_patch.setattr(migration_module, "database_connection", quick_connection)
        with acquire_writer_lease(database) as lease:
            with lease.transaction():
                with pytest.raises(MigrationApplyError):
                    initialize_storage(database)

    assert _history(database) == history_before
    assert _tables(database) == tables_before
    assert "source_spans" not in _tables(database)


def test_idle_writer_lease_does_not_arbitrate_maintenance_upgrade(tmp_path: Path) -> None:
    database = _prefix_database(tmp_path / "idle-writer-hazard.sqlite3", 2)

    with acquire_writer_lease(database):
        # A lease without an active SQLite transaction does not lock out the
        # existing maintenance path. This is a known orchestration hazard.
        assert initialize_storage(database) == (CR1_F_ID, CR1_J_ID)

    assert [row[0] for row in _history(database)] == [CR0_ID, CR1_E_ID, CR1_F_ID, CR1_J_ID]
