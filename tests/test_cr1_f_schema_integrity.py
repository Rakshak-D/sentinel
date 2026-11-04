"""Pinned migration/checkpoint and fail-closed drift tests for CR1-F."""

from pathlib import Path

import pytest

import sentinel.storage.migrations as migration_module
from sentinel.storage.connection import database_connection
from sentinel.storage.migrations import Migration, MigrationIntegrityError, initialize_storage
from sentinel.storage.schema import SchemaDefinition, SchemaObjectDefinition

CR1_F_ID = "cr1-f-0003-source-spans"
CR1_F_ARTIFACT_SHA256 = "6e6b98e60cff17f0eac94b942533964588344fdd0d8342567962ac4a1c3304b7"
CR1_F_SCHEMA_SHA256 = "26f31fe4601c67cb60c6faa324eba83ff59c611b1fa283e514f0a77e3acf44ad"


def _database(tmp_path: Path, name: str = "schema-integrity.sqlite3") -> Path:
    database = tmp_path / name
    with database_connection(database, create=True) as connection:
        for migration in migration_module.MIGRATIONS[:3]:
            migration_module._apply_migration(
                connection,
                migration,
                app_build="synthetic-cr1-f-history",
            )
    return database


def test_cr1_f_artifact_and_complete_checkpoint_have_independent_pins(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    assert migration_module.MIGRATIONS[0].artifact_sha256 == (
        "b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217"
    )
    assert migration_module.MIGRATIONS[1].artifact_sha256 == (
        "7ef613bdb646d9b98bc18bb20dd7bba3467d4de12b2cb5c4802e4d1dd8d1c0c7"
    )
    assert migration_module.MIGRATIONS[1].schema_after.sha256 == (
        "38eb2f69500aa21df1002691c40759ba5acbc58b09c97de4a8ab7bfdd9c40d6a"
    )
    assert tuple(item.migration_id for item in migration_module.MIGRATIONS[:3]) == (
        "cr0-c-0001-schema-migrations",
        "cr1-e-0002-source-registry",
        CR1_F_ID,
    )
    migration = migration_module.MIGRATIONS[2]
    assert migration.artifact_sha256 == CR1_F_ARTIFACT_SHA256
    assert migration.schema_after.sha256 == CR1_F_SCHEMA_SHA256
    assert migration.schema_after.schema_version == CR1_F_ID
    with database_connection(database) as connection:
        row = connection.execute(
            "SELECT migration_id, artifact_sha256 FROM schema_migrations "
            "ORDER BY applied_at DESC LIMIT 1"
        ).fetchone()
    assert row == (CR1_F_ID, CR1_F_ARTIFACT_SHA256)


def test_f_checkpoint_contains_complete_prior_and_new_schema_inventory(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    migration = migration_module.MIGRATIONS[2]
    objects = {(item.object_type, item.name) for item in migration.schema_after.objects}
    assert {
        ("table", "schema_migrations"),
        ("table", "principals"),
        ("table", "plugin_manifests"),
        ("table", "sources"),
        ("table", "sync_cursors"),
        ("table", "source_items"),
        ("table", "config_revisions"),
        ("table", "run_manifests"),
        ("table", "runs"),
        ("table", "boundary_envelopes"),
        ("table", "source_spans"),
        ("index", "schema_migrations_applied_at_idx"),
        ("index", "source_spans_item_start_byte_idx"),
    } <= objects
    with database_connection(database) as connection:
        actual = {
            (str(row[0]), str(row[1]))
            for row in connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        }
    assert actual == objects


def test_fresh_schema_initialization_inserts_no_application_records(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        for table in (
            "principals", "plugin_manifests", "sources", "sync_cursors",
            "source_items", "config_revisions", "run_manifests", "runs",
            "boundary_envelopes", "source_spans",
        ):
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)


@pytest.mark.parametrize("mutation", ["unknown", "digest", "deleted", "out-of-order"])
def test_cr1_f_history_unknown_tampered_deleted_and_out_of_order_fail_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        if mutation == "unknown":
            connection.execute(
                "UPDATE schema_migrations SET migration_id = ? WHERE migration_id = ?",
                ("unknown-cr1-f-migration", CR1_F_ID),
            )
        elif mutation == "digest":
            connection.execute(
                "UPDATE schema_migrations SET artifact_sha256 = ? WHERE migration_id = ?",
                ("0" * 64, CR1_F_ID),
            )
        elif mutation == "deleted":
            connection.execute(
                "DELETE FROM schema_migrations WHERE migration_id = ?", (CR1_F_ID,)
            )
        else:
            connection.execute(
                "UPDATE schema_migrations SET applied_at = ? WHERE migration_id = ?",
                ("2000-01-01T00:00:00.000000+00:00", CR1_F_ID),
            )
    with pytest.raises(MigrationIntegrityError):
        initialize_storage(database)


@pytest.mark.parametrize(
    "mutation",
    [
        "CREATE TABLE unauthorized_after_f (value TEXT)",
        "CREATE INDEX unauthorized_after_f_idx ON source_spans(item_id)",
    ],
)
def test_unregistered_cr1_f_schema_objects_are_rejected(
    tmp_path: Path,
    mutation: str,
) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        connection.execute(mutation)
    with pytest.raises(MigrationIntegrityError):
        initialize_storage(database)


@pytest.mark.parametrize("object_name", ["source_spans", "source_spans_item_start_byte_idx"])
def test_missing_cr1_f_table_or_index_is_rejected(
    tmp_path: Path,
    object_name: str,
) -> None:
    database = _database(tmp_path)
    kind = "TABLE" if object_name == "source_spans" else "INDEX"
    with database_connection(database) as connection:
        connection.execute(f"DROP {kind} {object_name}")
    with pytest.raises(MigrationIntegrityError):
        initialize_storage(database)


def test_missing_source_spans_foreign_key_is_rejected(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("ALTER TABLE source_spans RENAME TO source_spans_expected")
        connection.execute(
            """CREATE TABLE source_spans (
                span_id TEXT NOT NULL PRIMARY KEY,
                item_id TEXT NOT NULL,
                start_byte INTEGER NOT NULL CHECK (
                    typeof(start_byte) = 'integer' AND start_byte >= 0
                ),
                end_byte INTEGER NOT NULL CHECK (
                    typeof(end_byte) = 'integer' AND end_byte > start_byte
                ),
                text_sha256 TEXT NOT NULL CHECK (
                    length(text_sha256) = 64 AND text_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
                context_ref TEXT,
                derived_by_boundary_id TEXT
            )"""
        )
        connection.execute("DROP TABLE source_spans_expected")
        connection.execute(
            "CREATE INDEX source_spans_item_start_byte_idx ON source_spans(item_id, start_byte)"
        )
    with pytest.raises(MigrationIntegrityError):
        initialize_storage(database)


def test_changed_cr1_f_migration_artifact_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _database(tmp_path)
    migration = migration_module.MIGRATIONS[2]
    changed = Migration(
        migration.migration_id,
        (*migration.statements, "SELECT 1"),
        migration.schema_after,
    )
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS[:2], changed, *migration_module.MIGRATIONS[3:]),
    )
    with pytest.raises(MigrationIntegrityError, match="CR1-F migration artifact"):
        initialize_storage(database)


def test_changed_cr1_f_schema_checkpoint_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _database(tmp_path)
    migration = migration_module.MIGRATIONS[2]
    altered_schema = SchemaDefinition(
        migration.migration_id,
        (
            *migration.schema_after.objects,
            SchemaObjectDefinition(
                "table",
                "unregistered_expected_table",
                "CREATE TABLE unregistered_expected_table (id TEXT)",
            ),
        ),
    )
    changed = Migration(
        migration.migration_id,
        migration.statements,
        altered_schema,
    )
    monkeypatch.setattr(
        migration_module,
        "MIGRATIONS",
        (*migration_module.MIGRATIONS[:2], changed, *migration_module.MIGRATIONS[3:]),
    )
    monkeypatch.setattr(
        migration_module,
        "_CR1_F_MIGRATION_ARTIFACT_SHA256",
        changed.artifact_sha256,
    )
    with pytest.raises(MigrationIntegrityError, match="checkpoint"):
        initialize_storage(database)
