"""Schema-only tests for durable source-span metadata."""

import hashlib
import sqlite3
from pathlib import Path

import pytest

import sentinel.storage.migrations as migration_module
from sentinel.storage.connection import database_connection
from sentinel.storage.migrations import initialize_storage, verify_integrity

CR1_F_MIGRATION_ID = "cr1-f-0003-source-spans"
CR1_E_MIGRATION_ID = "cr1-e-0002-source-registry"
CR1_J_MIGRATION_ID = "cr1-j-0004-local-tasks"


def _database(tmp_path: Path) -> Path:
    database = tmp_path / "source-spans.sqlite3"
    initialize_storage(database, create=True)
    return database


def _insert_item(connection: sqlite3.Connection) -> None:
    connection.execute(
        "INSERT INTO principals VALUES (?, ?, ?, ?, ?, ?)",
        (
            "principal-s",
            "owner",
            "Synthetic principal",
            "synthetic:binding",
            "2026-11-03T00:00:00Z",
            None,
        ),
    )
    connection.execute(
        """INSERT INTO plugin_manifests
           (plugin_id, plugin_version, manifest_ref, manifest_sha256, origin,
            capability_json, trust, sensitivity, host_allowlist_json,
            fixture_set_sha256, enabled, registered_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "synthetic.reader", "1.0.0", "manifest:synthetic", "1" * 64,
            "fixture", "[]", "T4_EXTERNAL", "PUBLIC", "[]", "2" * 64,
            1, "2026-11-03T00:00:00Z",
        ),
    )
    connection.execute(
        """INSERT INTO sources
           (source_id, plugin_id, plugin_version, principal_id, source_type,
            account_alias, scope_json, host_allowlist_json, trust,
            default_sensitivity, enabled, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "source-s", "synthetic.reader", "1.0.0", "principal-s",
            "fixture", "synthetic-source", "{}", "[]", "T4_EXTERNAL",
            "PUBLIC", 1, "2026-11-03T00:00:00Z",
        ),
    )
    body = "🙂".encode()
    connection.execute(
        """INSERT INTO source_items
           (item_id, source_id, provider_item_id, provider_revision, canonical_uri,
            content_ref, content_sha256, trust, sensitivity, observed_at, source_at,
            deleted_at, metadata_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "item-s", "source-s", "synthetic-item", None, None,
            "opaque:synthetic-content", hashlib.sha256(body).hexdigest(),
            "T4_EXTERNAL", "PUBLIC", "2026-11-03T00:00:00Z", None, None, "{}",
        ),
    )


def test_fresh_initialization_registers_cr1_f_and_source_spans(tmp_path: Path) -> None:
    database = _database(tmp_path)
    assert tuple(migration.migration_id for migration in migration_module.MIGRATIONS) == (
        "cr0-c-0001-schema-migrations",
        CR1_E_MIGRATION_ID,
        CR1_F_MIGRATION_ID,
        CR1_J_MIGRATION_ID,
    )
    with database_connection(database) as connection:
        row = connection.execute(
            "SELECT migration_id FROM schema_migrations ORDER BY applied_at, migration_id"
        ).fetchall()
        tables = {
            str(item[0])
            for item in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        verify_integrity(connection)
    assert [item[0] for item in row][-2:] == [CR1_F_MIGRATION_ID, CR1_J_MIGRATION_ID]
    assert {
        "config_revisions",
        "run_manifests",
        "runs",
        "boundary_envelopes",
        "source_spans",
    } <= tables


def test_source_spans_columns_types_nullability_and_primary_key(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        info = connection.execute("PRAGMA table_info(source_spans)").fetchall()
    assert tuple(row[1] for row in info) == (
        "span_id", "item_id", "start_byte", "end_byte", "text_sha256",
        "context_ref", "derived_by_boundary_id",
    )
    assert tuple(str(row[2]).upper() for row in info) == (
        "TEXT", "TEXT", "INTEGER", "INTEGER", "TEXT", "TEXT", "TEXT",
    )
    assert {row[1] for row in info if row[3] == 0} == {
        "context_ref", "derived_by_boundary_id",
    }
    assert [row[1] for row in info if row[5] == 1] == ["span_id"]


def test_source_spans_foreign_keys_and_byte_order_index(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        foreign_keys = connection.execute("PRAGMA foreign_key_list(source_spans)").fetchall()
        indexes = connection.execute("PRAGMA index_list(source_spans)").fetchall()
        index = next(row for row in indexes if row[1] == "source_spans_item_start_byte_idx")
        index_columns = tuple(
            row[2] for row in connection.execute(
                f"PRAGMA index_info({index[1]})"
            )
        )
        assert connection.execute("PRAGMA foreign_keys").fetchone() == (1,)
    assert {(row[2], row[3], row[4]) for row in foreign_keys} == {
        ("source_items", "item_id", "item_id"),
        ("boundary_envelopes", "derived_by_boundary_id", "boundary_id"),
    }
    assert index_columns == ("item_id", "start_byte")


def test_utf8_byte_offsets_are_stored_as_explicit_byte_coordinates(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        _insert_item(connection)
        connection.execute(
            """INSERT INTO source_spans
               (span_id, item_id, start_byte, end_byte, text_sha256, context_ref,
                derived_by_boundary_id)
               VALUES (?, ?, ?, ?, ?, ?, NULL)""",
            (
                "span-s", "item-s", 0, 4,
                hashlib.sha256("🙂".encode()).hexdigest(),
                "opaque:synthetic-context",
            ),
        )
        stored = connection.execute(
            "SELECT start_byte, end_byte FROM source_spans WHERE span_id = ?",
            ("span-s",),
        ).fetchone()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO source_spans
                   (span_id, item_id, start_byte, end_byte, text_sha256)
                   VALUES (?, ?, ?, ?, ?)""",
                ("span-s", "item-s", 1, 4, hashlib.sha256(b"x").hexdigest()),
            )
        verify_integrity(connection)
    assert stored == (0, 4)


@pytest.mark.parametrize(
    ("start_byte", "end_byte", "digest", "item_id"),
    [
        (-1, 1, "a" * 64, "item-s"),
        (3, 3, "a" * 64, "item-s"),
        (4, 3, "a" * 64, "item-s"),
        (0, 4, "not-a-digest", "item-s"),
        (0, 4, "a" * 64, "missing-item"),
        ("not-an-integer", 4, "a" * 64, "item-s"),
    ],
)
def test_invalid_span_offsets_digest_and_item_reference_are_rejected(
    tmp_path: Path,
    start_byte: object,
    end_byte: object,
    digest: str,
    item_id: str,
) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        _insert_item(connection)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO source_spans
                   (span_id, item_id, start_byte, end_byte, text_sha256)
                   VALUES (?, ?, ?, ?, ?)""",
                ("span-invalid", item_id, start_byte, end_byte, digest),
            )


def test_span_boundary_is_optional_but_non_null_reference_must_exist(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        _insert_item(connection)
        digest = hashlib.sha256(b"synthetic").hexdigest()
        connection.execute(
            """INSERT INTO source_spans
               (span_id, item_id, start_byte, end_byte, text_sha256,
                derived_by_boundary_id)
               VALUES (?, ?, ?, ?, ?, NULL)""",
            ("span-null-boundary", "item-s", 0, 9, digest),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO source_spans
                   (span_id, item_id, start_byte, end_byte, text_sha256,
                    derived_by_boundary_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                ("span-orphan-boundary", "item-s", 0, 9, digest, "missing-boundary"),
            )
