"""Fail-closed history and checkpoint tests for the CR1-E registry."""

from pathlib import Path

import pytest

import sentinel.storage.migrations as migration_module
from sentinel.storage.connection import database_connection
from sentinel.storage.migrations import MigrationIntegrityError, initialize_storage
from sentinel.storage.schema import (
    CR1_SOURCE_SCHEMA_DEFINITION_SHA256,
    FOUNDATION_SCHEMA_DEFINITION_SHA256,
)

FOUNDATION_SHA256 = "b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217"
CR1_E_MIGRATION_ID = "cr1-e-0002-source-registry"


def _database(tmp_path: Path, name: str = "integrity.sqlite3") -> Path:
    database = tmp_path / name
    initialize_storage(database, create=True)
    return database


def test_foundation_and_new_migration_and_full_checkpoint_have_independent_pins(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    assert migration_module.MIGRATIONS[0].artifact_sha256 == FOUNDATION_SHA256
    assert FOUNDATION_SCHEMA_DEFINITION_SHA256 == (
        "1f4d935bf45b5c09f68b4f6e3deb18846aa6d9ee14510eed89b3ab4a71139d30"
    )
    assert migration_module.MIGRATIONS[-1].migration_id == CR1_E_MIGRATION_ID
    assert migration_module.MIGRATIONS[-1].artifact_sha256 == (
        "7ef613bdb646d9b98bc18bb20dd7bba3467d4de12b2cb5c4802e4d1dd8d1c0c7"
    )
    assert migration_module.MIGRATIONS[-1].schema_after.sha256 == (
        "38eb2f69500aa21df1002691c40759ba5acbc58b09c97de4a8ab7bfdd9c40d6a"
    )
    assert CR1_SOURCE_SCHEMA_DEFINITION_SHA256 == (
        "38eb2f69500aa21df1002691c40759ba5acbc58b09c97de4a8ab7bfdd9c40d6a"
    )
    with database_connection(database) as connection:
        rows = connection.execute(
            "SELECT migration_id, artifact_sha256 FROM schema_migrations"
        ).fetchall()
    assert rows[-1][1] == migration_module.MIGRATIONS[-1].artifact_sha256


@pytest.mark.parametrize(
    "mutation",
    [
        "CREATE TABLE unauthorized_schema_table (value TEXT)",
        "CREATE INDEX unauthorized_schema_index ON sources(source_id)",
        "DROP INDEX sources_enabled_type_idx",
    ],
)
def test_unregistered_or_missing_schema_objects_are_rejected(
    tmp_path: Path,
    mutation: str,
) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        connection.execute(mutation)
    with pytest.raises(MigrationIntegrityError):
        initialize_storage(database)


def test_changed_registered_migration_artifact_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _database(tmp_path)
    registered = migration_module.MIGRATIONS[-1]
    changed = migration_module.Migration(
        registered.migration_id,
        (*registered.statements, "SELECT 1"),
        registered.schema_after,
    )
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS[:-1], changed),
    )
    with pytest.raises(MigrationIntegrityError, match="digest"):
        initialize_storage(database)


def test_unknown_deleted_or_out_of_order_history_is_rejected(tmp_path: Path) -> None:
    unknown = _database(tmp_path, "unknown.sqlite3")
    with database_connection(unknown) as connection:
        connection.execute(
            "UPDATE schema_migrations SET migration_id='unknown-registered-entry' "
            "WHERE migration_id=?",
            (CR1_E_MIGRATION_ID,),
        )
    with pytest.raises(MigrationIntegrityError):
        initialize_storage(unknown)

    deleted = _database(tmp_path, "deleted.sqlite3")
    with database_connection(deleted) as connection:
        connection.execute(
            "DELETE FROM schema_migrations WHERE migration_id=?",
            (CR1_E_MIGRATION_ID,),
        )
    with pytest.raises(MigrationIntegrityError):
        initialize_storage(deleted)

    reordered = _database(tmp_path, "reordered.sqlite3")
    with database_connection(reordered) as connection:
        connection.execute(
            "UPDATE schema_migrations SET applied_at='2000-01-01T00:00:00.000000+00:00' "
            "WHERE migration_id=?",
            (CR1_E_MIGRATION_ID,),
        )
    with pytest.raises(MigrationIntegrityError, match="order"):
        initialize_storage(reordered)


def test_modified_registered_table_definition_is_rejected(tmp_path: Path) -> None:
    database = _database(tmp_path, "altered-table.sqlite3")
    with database_connection(database) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("ALTER TABLE sources RENAME TO sources_original")
        connection.execute(
            """CREATE TABLE sources (
               source_id TEXT NOT NULL PRIMARY KEY,
               plugin_id TEXT NOT NULL,
               plugin_version TEXT NOT NULL,
               principal_id TEXT NOT NULL,
               source_type TEXT NOT NULL,
               account_alias TEXT NOT NULL,
               scope_json TEXT NOT NULL,
               host_allowlist_json TEXT NOT NULL,
               trust TEXT NOT NULL,
               default_sensitivity TEXT NOT NULL,
               enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
               created_at TEXT NOT NULL,
               UNIQUE(plugin_id, account_alias))"""
        )
        connection.execute("DROP TABLE sources_original")
    with pytest.raises(MigrationIntegrityError):
        initialize_storage(database)


def test_registry_history_update_cannot_be_silently_repaired(tmp_path: Path) -> None:
    database = _database(tmp_path, "history-tamper.sqlite3")
    with database_connection(database) as connection:
        connection.execute(
            "UPDATE schema_migrations SET artifact_sha256=? WHERE migration_id=?",
            ("0" * 64, CR1_E_MIGRATION_ID),
        )
    with pytest.raises(MigrationIntegrityError):
        initialize_storage(database)
