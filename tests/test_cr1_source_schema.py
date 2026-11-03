"""CR1-E source-registry schema behavior over disposable SQLite files."""

import sqlite3
from pathlib import Path

import pytest

import sentinel.storage.migrations as migration_module
from sentinel.storage.connection import database_connection, inspect_connection
from sentinel.storage.migrations import verify_integrity

FOUNDATION_ID = "cr0-c-0001-schema-migrations"
CR1_E_MIGRATION_ID = "cr1-e-0002-source-registry"
EXPECTED_TABLES = {
    "schema_migrations",
    "principals",
    "plugin_manifests",
    "sources",
    "sync_cursors",
    "source_items",
}
EXPECTED_INDEXES = {
    "schema_migrations_applied_at_idx",
    "principals_kind_revoked_at_idx",
    "plugin_manifests_enabled_trust_idx",
    "sources_enabled_type_idx",
    "sync_cursors_status_idx",
    "source_items_source_observed_at_idx",
    "source_items_content_sha256_idx",
}


def _database(tmp_path: Path) -> Path:
    database = tmp_path / "cr1-source-schema.sqlite3"
    with database_connection(database, create=True) as connection:
        for migration in migration_module.MIGRATIONS[:2]:
            migration_module._apply_migration(
                connection, migration, app_build="synthetic-cr1-e-history"
            )
    return database


def _insert_principal(connection: sqlite3.Connection, principal_id: str = "principal-1") -> None:
    connection.execute(
        """INSERT INTO principals
           (principal_id, kind, display_name, os_binding, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (
            principal_id,
            "owner",
            "Synthetic owner",
            "synthetic-binding",
            "2026-11-03T00:00:00+00:00",
        ),
    )


def _insert_plugin(
    connection: sqlite3.Connection,
    version: str,
    digest: str,
) -> None:
    connection.execute(
        """INSERT INTO plugin_manifests
           (plugin_id, plugin_version, manifest_ref, manifest_sha256, origin,
            capability_json, trust, sensitivity, host_allowlist_json,
            fixture_set_sha256, enabled, registered_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "synthetic.reader",
            version,
            f"manifest:{version}",
            digest,
            "synthetic",
            "[]",
            "T4 EXTERNAL",
            "PUBLIC",
            "[]",
            "f" * 64,
            1,
            "2026-11-03T00:00:00+00:00",
        ),
    )


def test_cr1_e_prefix_has_its_historical_tables_and_migration_history(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        ids = tuple(row[0] for row in connection.execute(
            "SELECT migration_id FROM schema_migrations ORDER BY applied_at, migration_id"
        ))
        indexes = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
            )
        }

    assert ids == (FOUNDATION_ID, CR1_E_MIGRATION_ID)
    assert tables == EXPECTED_TABLES
    assert indexes == EXPECTED_INDEXES
    assert tuple(item.migration_id for item in migration_module.MIGRATIONS[:2]) == ids


def test_source_registry_fields_keys_and_indexes_match_declared_schema(tmp_path: Path) -> None:
    database = _database(tmp_path)
    expected_columns = {
        "principals": (
            "principal_id",
            "kind",
            "display_name",
            "os_binding",
            "created_at",
            "revoked_at",
        ),
        "plugin_manifests": (
            "plugin_id", "plugin_version", "manifest_ref", "manifest_sha256", "origin",
            "capability_json", "trust", "sensitivity", "host_allowlist_json",
            "fixture_set_sha256", "enabled", "registered_at",
        ),
        "sources": (
            "source_id", "plugin_id", "plugin_version", "principal_id", "source_type",
            "account_alias", "scope_json", "host_allowlist_json", "trust",
            "default_sensitivity", "enabled", "created_at",
        ),
        "sync_cursors": (
            "cursor_id", "source_id", "cursor_kind", "value_cipher_ref", "etag",
            "generation", "last_full_sync_at", "last_commit_at", "status",
        ),
        "source_items": (
            "item_id", "source_id", "provider_item_id", "provider_revision", "canonical_uri",
            "content_ref", "content_sha256", "trust", "sensitivity", "observed_at",
            "source_at", "deleted_at", "metadata_json",
        ),
    }
    with database_connection(database) as connection:
        for table, columns in expected_columns.items():
            info = connection.execute(f"PRAGMA table_info({table})").fetchall()
            actual = tuple(row[1] for row in info)
            assert actual == columns
            optional = {
                "principals": {"revoked_at"},
                "plugin_manifests": set(),
                "sources": set(),
                "sync_cursors": {"etag", "last_full_sync_at"},
                "source_items": {"provider_revision", "canonical_uri", "source_at", "deleted_at"},
            }[table]
            assert all(
                (int(row[3]) == 0) == (row[1] in optional)
                for row in info
            )
            primary_key = tuple(row[1] for row in sorted(info, key=lambda item: item[5]) if row[5])
            expected_primary_key = (
                ("plugin_id", "plugin_version")
                if table == "plugin_manifests"
                else ({"principals": ("principal_id",), "sources": ("source_id",),
                       "sync_cursors": ("cursor_id",), "source_items": ("item_id",)}[table])
            )
            assert primary_key == expected_primary_key
        source_fks = connection.execute("PRAGMA foreign_key_list(sources)").fetchall()
        plugin_fk = [row for row in source_fks if row[2] == "plugin_manifests"]
        principal_fk = [row for row in source_fks if row[2] == "principals"]
        assert {(row[3], row[4]) for row in plugin_fk} == {
            ("plugin_id", "plugin_id"), ("plugin_version", "plugin_version")
        }
        assert {(row[3], row[4]) for row in principal_fk} == {
            ("principal_id", "principal_id")
        }
        cursor_fks = connection.execute("PRAGMA foreign_key_list(sync_cursors)").fetchall()
        item_fks = connection.execute("PRAGMA foreign_key_list(source_items)").fetchall()
        assert {(row[2], row[3], row[4]) for row in cursor_fks} == {
            ("sources", "source_id", "source_id")
        }
        assert {(row[2], row[3], row[4]) for row in item_fks} == {
            ("sources", "source_id", "source_id")
        }
        source_indexes = connection.execute("PRAGMA index_list(sources)").fetchall()
        assert any(str(row[1]) == "sources_enabled_type_idx" for row in source_indexes)
        source_unique = next(row for row in source_indexes if row[3] == "u")
        assert tuple(
            row[2] for row in connection.execute(f"PRAGMA index_info({source_unique[1]})")
        ) == ("plugin_id", "account_alias")


def test_plugin_versions_and_explicit_source_version_are_supported(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        _insert_principal(connection)
        _insert_plugin(connection, "1.0.0", "1" * 64)
        _insert_plugin(connection, "2.0.0", "2" * 64)
        assert connection.execute(
            "SELECT count(*) FROM plugin_manifests WHERE plugin_id = ?",
            ("synthetic.reader",),
        ).fetchone() == (2,)
        connection.execute(
            """INSERT INTO sources
               (source_id, plugin_id, plugin_version, principal_id, source_type,
                account_alias, scope_json, host_allowlist_json, trust,
                default_sensitivity, enabled, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "source-v2", "synthetic.reader", "2.0.0", "principal-1", "fixture",
                "synthetic-account", "{}", "[]", "T4 EXTERNAL", "PUBLIC", 1,
                "2026-11-03T00:00:00+00:00",
            ),
        )
        source = connection.execute(
            "SELECT plugin_id, plugin_version FROM sources WHERE source_id = ?",
            ("source-v2",),
        ).fetchone()
    assert source == ("synthetic.reader", "2.0.0")


def test_all_selected_tables_enforce_foreign_keys_and_uniqueness(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        settings = inspect_connection(connection)
        assert settings.foreign_keys_enabled is True
        assert settings.journal_mode == "wal"
        _insert_principal(connection)
        _insert_plugin(connection, "1.0.0", "1" * 64)
        source_values = (
            "source-1", "synthetic.reader", "1.0.0", "principal-1", "fixture",
            "account-1", "{}", "[]", "T4 EXTERNAL", "PUBLIC", 1,
            "2026-11-03T00:00:00+00:00",
        )
        connection.execute(
            """INSERT INTO sources
               (source_id, plugin_id, plugin_version, principal_id, source_type,
                account_alias, scope_json, host_allowlist_json, trust,
                default_sensitivity, enabled, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            source_values,
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO sources
                   (source_id, plugin_id, plugin_version, principal_id, source_type,
                    account_alias, scope_json, host_allowlist_json, trust,
                    default_sensitivity, enabled, created_at)
                   VALUES ('source-duplicate-alias', 'synthetic.reader', '1.0.0',
                           'principal-1', 'fixture', 'account-1', '{}', '[]',
                           'T4 EXTERNAL', 'PUBLIC', 1,
                           '2026-11-03T00:00:00+00:00')"""
            )
        connection.execute(
            """INSERT INTO sync_cursors
               (cursor_id, source_id, cursor_kind, value_cipher_ref, generation,
                last_commit_at, status)
               VALUES ('cursor-1', 'source-1', 'delta', 'cipher-ref:synthetic', 0,
                       '2026-11-03T00:00:00+00:00', 'idle')"""
        )
        item = (
            "item-1", "source-1", "provider-item-1", None, None,
            "content-ref:synthetic", "a" * 64, "T4 EXTERNAL", "PUBLIC",
            "2026-11-03T00:00:00+00:00", None, None, "{}",
        )
        insert_item = """INSERT INTO source_items
            (item_id, source_id, provider_item_id, provider_revision, canonical_uri,
             content_ref, content_sha256, trust, sensitivity, observed_at,
             source_at, deleted_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
        connection.execute(insert_item, item)
        changed_revision = (*item[:5], item[5], "b" * 64, *item[7:])
        connection.execute(insert_item, ("item-2", *changed_revision[1:]))
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(insert_item, item)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO sync_cursors
                   (cursor_id, source_id, cursor_kind, value_cipher_ref, generation,
                    last_commit_at, status)
                   VALUES ('cursor-2', 'source-1', 'delta', 'cipher-ref:synthetic', 0,
                           '2026-11-03T00:00:00+00:00', 'idle')"""
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE sources SET enabled = 2 WHERE source_id = 'source-1'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE sync_cursors SET generation = -1 WHERE cursor_id = 'cursor-1'"
            )
        verify_integrity(connection)


@pytest.mark.parametrize(
    "statement",
    [
        """INSERT INTO sources
               (source_id, plugin_id, plugin_version, principal_id, source_type,
                account_alias, scope_json, host_allowlist_json, trust,
                default_sensitivity, enabled, created_at)
               VALUES ('bad-source', 'missing', '9.9', 'principal-1', 'fixture',
                       'bad-account', '{}', '[]', 'T4 EXTERNAL', 'PUBLIC', 1,
                       '2026-11-03T00:00:00+00:00')""",
        """INSERT INTO sources
               (source_id, plugin_id, plugin_version, principal_id, source_type,
                account_alias, scope_json, host_allowlist_json, trust,
                default_sensitivity, enabled, created_at)
               VALUES ('bad-principal-source', 'synthetic.reader', '1.0.0',
                       'missing-principal', 'fixture', 'other-account', '{}', '[]',
                       'T4 EXTERNAL', 'PUBLIC', 1, '2026-11-03T00:00:00+00:00')""",
    ],
)
def test_missing_plugin_version_or_principal_reference_is_rejected(
    tmp_path: Path,
    statement: str,
) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        _insert_principal(connection)
        _insert_plugin(connection, "1.0.0", "1" * 64)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(statement)


def test_missing_required_plugin_version_is_rejected(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        _insert_principal(connection)
        _insert_plugin(connection, "1.0.0", "1" * 64)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO sources
                   (source_id, plugin_id, principal_id, source_type, account_alias,
                    scope_json, host_allowlist_json, trust, default_sensitivity,
                    enabled, created_at)
                   VALUES ('source-no-plugin-version', 'synthetic.reader', 'principal-1',
                           'fixture', 'missing-version', '{}', '[]', 'T4 EXTERNAL',
                           'PUBLIC', 1, '2026-11-03T00:00:00+00:00')"""
            )
