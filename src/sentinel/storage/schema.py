"""The CR0-C foundational schema and its structural integrity checks."""

import re
import sqlite3

MIGRATION_TABLE_DDL = """CREATE TABLE schema_migrations (
    migration_id TEXT NOT NULL PRIMARY KEY,
    applied_at TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    app_build TEXT NOT NULL,
    success INTEGER NOT NULL
)"""
MIGRATION_INDEX_DDL = """CREATE INDEX schema_migrations_applied_at_idx
    ON schema_migrations(applied_at)"""

EXPECTED_SCHEMA_OBJECTS = frozenset(
    {
        ("table", "schema_migrations"),
        ("index", "schema_migrations_applied_at_idx"),
    }
)
EXPECTED_MIGRATION_COLUMNS = (
    ("migration_id", "TEXT", 1, None, 1),
    ("applied_at", "TEXT", 1, None, 0),
    ("artifact_sha256", "TEXT", 1, None, 0),
    ("app_build", "TEXT", 1, None, 0),
    ("success", "INTEGER", 1, None, 0),
)


class SchemaIntegrityError(RuntimeError):
    """Raised when SQLite's schema differs from the registered schema."""


def _normalized_sql(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return re.sub(r"\s+", " ", value).strip().casefold()


def verify_schema(connection: sqlite3.Connection) -> None:
    """Require the exact schema objects and normative migration metadata columns."""
    objects = frozenset(
        connection.execute(
            """SELECT type, name FROM sqlite_master
               WHERE name NOT LIKE 'sqlite_%'"""
        ).fetchall()
    )
    if objects != EXPECTED_SCHEMA_OBJECTS:
        raise SchemaIntegrityError("SQLite schema objects do not match the registered schema")

    columns = connection.execute("PRAGMA table_info(schema_migrations)").fetchall()
    actual_columns = tuple(
        (
            str(name),
            str(column_type).upper(),
            int(not_null),
            default,
            int(primary_key),
        )
        for _ordinal, name, column_type, not_null, default, primary_key in columns
    )
    if actual_columns != EXPECTED_MIGRATION_COLUMNS:
        raise SchemaIntegrityError("schema_migrations columns do not match the normative schema")

    table_sql_row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        ("schema_migrations",),
    ).fetchone()
    if table_sql_row is None or _normalized_sql(table_sql_row[0]) != _normalized_sql(
        MIGRATION_TABLE_DDL
    ):
        raise SchemaIntegrityError("schema_migrations table definition has drifted")

    all_indexes = connection.execute("PRAGMA index_list(schema_migrations)").fetchall()
    indexes = [row for row in all_indexes if not str(row[1]).startswith("sqlite_")]
    primary_key_indexes = [row for row in all_indexes if str(row[1]).startswith("sqlite_")]
    if len(indexes) != 1:
        raise SchemaIntegrityError("schema_migrations indexes do not match the registered schema")
    if len(primary_key_indexes) != 1:
        raise SchemaIntegrityError("schema_migrations primary key index has drifted")
    _pk_sequence, pk_name, pk_unique, pk_origin, pk_partial = primary_key_indexes[0]
    if (pk_name, int(pk_unique), pk_origin, int(pk_partial)) != (
        "sqlite_autoindex_schema_migrations_1",
        1,
        "pk",
        0,
    ):
        raise SchemaIntegrityError("schema_migrations primary key index has drifted")
    _sequence, index_name, is_unique, origin, is_partial = indexes[0]
    if (index_name, int(is_unique), origin, int(is_partial)) != (
        "schema_migrations_applied_at_idx",
        0,
        "c",
        0,
    ):
        raise SchemaIntegrityError("schema_migrations applied_at index is malformed")
    index_columns = connection.execute(
        "PRAGMA index_info(schema_migrations_applied_at_idx)"
    ).fetchall()
    if tuple(str(row[2]) for row in index_columns) != ("applied_at",):
        raise SchemaIntegrityError("schema_migrations applied_at index is malformed")
    index_sql_row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
        ("schema_migrations_applied_at_idx",),
    ).fetchone()
    if index_sql_row is None or _normalized_sql(index_sql_row[0]) != _normalized_sql(
        MIGRATION_INDEX_DDL
    ):
        raise SchemaIntegrityError("schema_migrations applied_at index definition has drifted")
