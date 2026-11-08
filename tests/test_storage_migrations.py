"""Tests for fixed, ordered and atomic schema migrations."""

import sqlite3
from datetime import datetime, timedelta
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
from sentinel.storage.schema import (
    FOUNDATION_SCHEMA,
    SchemaDefinition,
    SchemaObjectDefinition,
)


def _applied_rows(database: Path) -> list[tuple[object, ...]]:
    with database_connection(database) as connection:
        return connection.execute(
            """SELECT migration_id, applied_at, artifact_sha256, app_build, success
               FROM schema_migrations ORDER BY applied_at, migration_id"""
        ).fetchall()


def _initialize(database: Path, *, app_build: str = "sentinel-0.1.0") -> None:
    initialize_storage(database, app_build=app_build, create=True)


_EXPANSION_TABLE_SQL = """CREATE TABLE test_migration_items (
    item_id TEXT NOT NULL PRIMARY KEY,
    item_value TEXT NOT NULL CHECK (length(item_value) > 0)
)"""
_EXPANSION_INDEX_SQL = (
    "CREATE INDEX test_migration_items_value_idx ON test_migration_items(item_value)"
)


def _schema_checkpoint(
    migration_id: str,
    *objects: SchemaObjectDefinition,
) -> SchemaDefinition:
    return SchemaDefinition(
        schema_version=migration_id,
        objects=(*migration_module.MIGRATIONS[-1].schema_after.objects, *objects),
    )


def _schema_expansion_migration() -> Migration:
    return Migration(
        "test-0002-schema-expansion",
        (_EXPANSION_TABLE_SQL, _EXPANSION_INDEX_SQL),
        _schema_checkpoint(
            "test-0002-schema-expansion",
            SchemaObjectDefinition("table", "test_migration_items", _EXPANSION_TABLE_SQL),
            SchemaObjectDefinition("index", "test_migration_items_value_idx", _EXPANSION_INDEX_SQL),
        ),
    )


def test_historical_cr0_migration_creates_only_normative_migration_metadata(
    tmp_path: Path,
) -> None:
    database = tmp_path / "initial.sqlite3"
    with database_connection(database, create=True) as connection:
        migration_module._apply_migration(
            connection,
            migration_module.MIGRATIONS[0],
            app_build="sentinel-test",
        )

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
        Migration("test-0002", ("SELECT 2",), _schema_checkpoint("test-0002")),
        Migration("test-0003", ("SELECT 3",), _schema_checkpoint("test-0003")),
    )
    monkeypatch.setattr(migration_module, "MIGRATIONS", registered)

    _initialize(database)

    assert [row[0] for row in _applied_rows(database)] == [
        "cr0-c-0001-schema-migrations",
        "cr1-e-0002-source-registry",
        "cr1-f-0003-source-spans",
        "cr1-j-0004-local-tasks",
        "cr2-d-0005-durable-pending-proposals",
        "cr2-f-0006-owner-proof-challenges",
        "test-0002",
        "test-0003",
    ]


def test_trusted_schema_expansion_creates_a_real_table_and_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "schema-expansion.sqlite3"
    migration = _schema_expansion_migration()
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS, migration),
    )

    applied = initialize_storage(database, create=True)

    assert applied == (
        "cr0-c-0001-schema-migrations",
        "cr1-e-0002-source-registry",
        "cr1-f-0003-source-spans",
        "cr1-j-0004-local-tasks",
        "cr2-d-0005-durable-pending-proposals",
        "cr2-f-0006-owner-proof-challenges",
        migration.migration_id,
    )
    with database_connection(database) as connection:
        table = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            ("test_migration_items",),
        ).fetchone()
        index = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
            ("test_migration_items_value_idx",),
        ).fetchone()
    assert table is not None and "CHECK (length(item_value) > 0)" in table[0]
    assert index is not None and "ON test_migration_items(item_value)" in index[0]
    with database_connection(database) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO test_migration_items (item_id, item_value) VALUES (?, ?)",
                ("synthetic-invalid", ""),
            )


def test_index_only_migration_uses_registered_schema_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "index-only.sqlite3"
    index_name = "schema_migrations_build_idx"
    index_sql = f"CREATE INDEX {index_name} ON schema_migrations(app_build)"
    migration = Migration(
        "test-0002-index-only",
        (index_sql,),
        _schema_checkpoint(
            "test-0002-index-only",
            SchemaObjectDefinition("index", index_name, index_sql),
        ),
    )
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS, migration),
    )

    assert initialize_storage(database, create=True)[-1] == migration.migration_id
    with database_connection(database) as connection:
        index = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
            (index_name,),
        ).fetchone()
    assert index == (index_sql,)


def test_data_only_migration_reuses_the_complete_schema_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "data-only.sqlite3"
    create_items = _schema_expansion_migration()
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS, create_items),
    )
    initialize_storage(database, create=True)
    with database_connection(database) as connection:
        connection.execute(
            "INSERT INTO test_migration_items (item_id, item_value) VALUES (?, ?)",
            ("synthetic-before-data-migration", "before"),
        )
    data_migration_id = "test-0003-data-only"
    data_migration = Migration(
        data_migration_id,
        ("UPDATE test_migration_items SET item_value = 'after'",),
        SchemaDefinition(
            schema_version=data_migration_id,
            objects=create_items.schema_after.objects,
        ),
    )
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS, data_migration),
    )

    assert initialize_storage(database) == (data_migration_id,)
    with database_connection(database) as connection:
        row = connection.execute(
            "SELECT item_value FROM test_migration_items WHERE item_id = ?",
            ("synthetic-before-data-migration",),
        ).fetchone()
    assert row == ("after",)


def test_existing_database_upgrades_without_losing_migration_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "upgrade-existing.sqlite3"
    _initialize(database)
    with database_connection(database) as connection:
        connection.execute(
            "UPDATE schema_migrations SET app_build = ? WHERE migration_id = ?",
            ("sentinel-before-upgrade", "cr0-c-0001-schema-migrations"),
        )
    old_rows = _applied_rows(database)
    migration = _schema_expansion_migration()
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS, migration),
    )

    applied = initialize_storage(database)

    assert applied == (migration.migration_id,)
    rows = _applied_rows(database)
    assert [row[0] for row in rows] == [
        *(row[0] for row in old_rows),
        migration.migration_id,
    ]
    assert rows[: len(old_rows)] == old_rows
    assert rows[0][3] == "sentinel-before-upgrade"
    assert rows[0][2] == migration_module.MIGRATIONS[0].artifact_sha256
    assert rows[-1][2] == migration.artifact_sha256


def test_reopening_upgraded_database_is_idempotent_and_preserves_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "reopen-upgraded.sqlite3"
    migration = _schema_expansion_migration()
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS, migration),
    )
    initialize_storage(database, create=True)
    with database_connection(database) as connection:
        connection.execute(
            "INSERT INTO test_migration_items (item_id, item_value) VALUES (?, ?)",
            ("synthetic-item-1", "preserved"),
        )
    before = _applied_rows(database)

    assert initialize_storage(database) == ()

    with database_connection(database) as connection:
        items = connection.execute(
            "SELECT item_id, item_value FROM test_migration_items"
        ).fetchall()
    assert _applied_rows(database) == before
    assert items == [("synthetic-item-1", "preserved")]


@pytest.mark.parametrize(
    "missing_object",
    ("test_migration_items", "test_migration_items_value_idx"),
)
def test_missing_expected_expansion_objects_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_object: str,
) -> None:
    database = tmp_path / "missing-expanded-object.sqlite3"
    migration = _schema_expansion_migration()
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS, migration),
    )
    initialize_storage(database, create=True)
    with database_connection(database) as connection:
        object_type = "table" if missing_object == "test_migration_items" else "index"
        connection.execute(f"DROP {object_type.upper()} {missing_object}")

    with pytest.raises(MigrationIntegrityError, match="schema drift"):
        initialize_storage(database)


def test_new_artifact_hash_covers_its_expected_schema_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "schema-checkpoint-hash.sqlite3"
    migration = _schema_expansion_migration()
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS, migration),
    )
    initialize_storage(database, create=True)
    changed_table = """CREATE TABLE test_migration_items (
    item_id TEXT NOT NULL PRIMARY KEY,
    item_value TEXT NOT NULL CHECK (length(item_value) > 1)
)"""
    altered_objects = tuple(
        SchemaObjectDefinition(item.object_type, item.name, changed_table)
        if item.object_type == "table" and item.name == "test_migration_items"
        else item
        for item in migration.schema_after.objects
    )
    altered = Migration(
        migration.migration_id,
        migration.statements,
        SchemaDefinition(migration.migration_id, altered_objects),
    )
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS[:-1], altered),
    )

    with pytest.raises(MigrationIntegrityError, match="artifact digest mismatch"):
        initialize_storage(database)


def test_foundation_migration_artifact_hash_remains_unchanged() -> None:
    assert migration_module.MIGRATIONS[0].artifact_sha256 == (
        "b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217"
    )


@pytest.mark.parametrize(
    "statement",
    (
        "CREATE TABLE unauthorized_table (item_id TEXT PRIMARY KEY)",
        "CREATE INDEX unauthorized_index ON schema_migrations(app_build)",
        "CREATE TRIGGER unauthorized_trigger AFTER INSERT ON schema_migrations BEGIN SELECT 1; END",
        "CREATE VIEW unauthorized_view AS SELECT migration_id FROM schema_migrations",
    ),
)
def test_unauthorized_schema_objects_are_rejected(
    tmp_path: Path,
    statement: str,
) -> None:
    database = tmp_path / "unauthorized-object.sqlite3"
    _initialize(database)
    with database_connection(database) as connection:
        connection.execute(statement)

    with pytest.raises(MigrationIntegrityError, match="schema drift"):
        _initialize(database)


def test_altered_table_constraints_are_rejected_as_schema_drift(tmp_path: Path) -> None:
    database = tmp_path / "altered-constraint.sqlite3"
    _initialize(database)
    with database_connection(database) as connection:
        connection.execute(
            """CREATE TABLE replacement_schema_migrations (
                migration_id TEXT NOT NULL PRIMARY KEY,
                applied_at TEXT NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                app_build TEXT NOT NULL,
                success INTEGER NOT NULL CHECK (success IN (0, 1))
            )"""
        )
        connection.execute(
            """INSERT INTO replacement_schema_migrations
               SELECT migration_id, applied_at, artifact_sha256, app_build, success
               FROM schema_migrations"""
        )
        connection.execute("DROP TABLE schema_migrations")
        connection.execute("ALTER TABLE replacement_schema_migrations RENAME TO schema_migrations")
        connection.execute(
            "CREATE INDEX schema_migrations_applied_at_idx ON schema_migrations(applied_at)"
        )

    with pytest.raises(MigrationIntegrityError, match="schema drift"):
        _initialize(database)


def test_applied_migrations_must_be_a_registered_ordered_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "prefix-gap.sqlite3"
    _initialize(database)
    second = Migration("test-0002", ("SELECT 2",), _schema_checkpoint("test-0002"))
    third = Migration("test-0003", ("SELECT 3",), _schema_checkpoint("test-0003"))
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS, second, third),
    )
    with database_connection(database) as connection:
        first_applied_at = connection.execute(
            "SELECT applied_at FROM schema_migrations WHERE migration_id = ?",
            (migration_module.MIGRATIONS[0].migration_id,),
        ).fetchone()[0]
        later_applied_at = (
            datetime.fromisoformat(first_applied_at) + timedelta(microseconds=1)
        ).isoformat(timespec="microseconds")
        connection.execute(
            """INSERT INTO schema_migrations
               (migration_id, applied_at, artifact_sha256, app_build, success)
               VALUES (?, ?, ?, ?, ?)""",
            (third.migration_id, later_applied_at, third.artifact_sha256, "fixture", 1),
        )

    with pytest.raises(MigrationIntegrityError, match="registered order"):
        _initialize(database)


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
        FOUNDATION_SCHEMA,
        artifact_version=1,
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
            "CREATE TABLE should_rollback (record_id TEXT NOT NULL PRIMARY KEY)",
            "INSERT INTO absent_table VALUES ('synthetic')",
        ),
        _schema_checkpoint(
            "test-0002-failure",
            SchemaObjectDefinition(
                "table",
                "should_rollback",
                "CREATE TABLE should_rollback (record_id TEXT NOT NULL PRIMARY KEY)",
            ),
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
    failing = Migration(
        "test-0002-operational",
        ("THIS IS NOT SQL",),
        _schema_checkpoint("test-0002-operational"),
    )
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS, failing),
    )

    with pytest.raises(MigrationApplyError) as error:
        _initialize(database)
    assert isinstance(error.value.__cause__, sqlite3.Error)

    with database_connection(database) as connection:
        assert (
            connection.execute(
                "SELECT success FROM schema_migrations WHERE migration_id = ?",
                (failing.migration_id,),
            ).fetchone()
            is None
        )


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
        connection.execute("CREATE TABLE fk_child (parent_id TEXT REFERENCES fk_parent(id))")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO fk_child VALUES ('missing-parent')")
