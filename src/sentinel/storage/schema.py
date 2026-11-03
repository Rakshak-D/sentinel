"""Trusted, versioned SQLite schema checkpoints and integrity verification."""

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Literal

SchemaObjectType = Literal["table", "index", "view", "trigger"]
_ALLOWED_OBJECT_TYPES = frozenset({"table", "index", "view", "trigger"})
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

MIGRATION_TABLE_DDL = """CREATE TABLE schema_migrations (
    migration_id TEXT NOT NULL PRIMARY KEY,
    applied_at TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    app_build TEXT NOT NULL,
    success INTEGER NOT NULL
)"""
MIGRATION_INDEX_DDL = """CREATE INDEX schema_migrations_applied_at_idx
    ON schema_migrations(applied_at)"""

EXPECTED_MIGRATION_COLUMNS = (
    ("migration_id", "TEXT", 1, None, 1),
    ("applied_at", "TEXT", 1, None, 0),
    ("artifact_sha256", "TEXT", 1, None, 0),
    ("app_build", "TEXT", 1, None, 0),
    ("success", "INTEGER", 1, None, 0),
)


class SchemaIntegrityError(RuntimeError):
    """Raised when SQLite's schema differs from a trusted schema checkpoint."""


@dataclass(frozen=True, slots=True)
class SchemaObjectDefinition:
    """Expected DDL for one named table, index, view, or trigger."""

    object_type: SchemaObjectType
    name: str
    sql: str

    def __post_init__(self) -> None:
        if not isinstance(self.object_type, str) or self.object_type not in _ALLOWED_OBJECT_TYPES:
            raise ValueError("unsupported SQLite schema object type")
        if not isinstance(self.name, str) or not _IDENTIFIER_PATTERN.fullmatch(self.name):
            raise ValueError("schema object name must be a simple SQLite identifier")
        if not isinstance(self.sql, str) or not self.sql.strip():
            raise ValueError("schema object DDL must be a non-empty string")


@dataclass(frozen=True, slots=True)
class SchemaDefinition:
    """Complete, trusted post-migration schema inventory for one registry version."""

    schema_version: str
    objects: tuple[SchemaObjectDefinition, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, str) or not self.schema_version.strip():
            raise ValueError("schema_version must be non-empty")
        if not isinstance(self.objects, tuple) or not self.objects:
            raise ValueError("schema checkpoint must contain a non-empty object tuple")
        if any(not isinstance(item, SchemaObjectDefinition) for item in self.objects):
            raise ValueError("schema checkpoint entries must be schema object definitions")
        keys = tuple((item.object_type, item.name) for item in self.objects)
        if len(keys) != len(set(keys)):
            raise ValueError("schema checkpoint object identities must be unique")

    @property
    def canonical_artifact(self) -> bytes:
        """Return deterministic UTF-8 bytes for this full expected schema inventory."""
        payload = {
            "schema_version": self.schema_version,
            "objects": [
                {
                    "name": item.name,
                    "object_type": item.object_type,
                    "sql": item.sql,
                }
                for item in sorted(self.objects, key=lambda value: (value.object_type, value.name))
            ],
        }
        return json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")

    @property
    def sha256(self) -> str:
        """SHA-256 of the checkpoint representation."""
        return hashlib.sha256(self.canonical_artifact).hexdigest()


FOUNDATION_SCHEMA = SchemaDefinition(
    schema_version="cr0-c-0001-schema-migrations",
    objects=(
        SchemaObjectDefinition("table", "schema_migrations", MIGRATION_TABLE_DDL),
        SchemaObjectDefinition("index", "schema_migrations_applied_at_idx", MIGRATION_INDEX_DDL),
    ),
)

# Independent pin for the v1 schema checkpoint. It lets us add checkpoint data
# while retaining the already-persisted v1 migration artifact digest unchanged.
FOUNDATION_SCHEMA_DEFINITION_SHA256 = (
    "1f4d935bf45b5c09f68b4f6e3deb18846aa6d9ee14510eed89b3ab4a71139d30"
)

# CR1-E source registry foundation.  These are metadata/reference tables only:
# content_ref and value_cipher_ref do not establish that backing bytes are
# encrypted, available, or authorized for a particular operation.
PRINCIPALS_TABLE_DDL = """CREATE TABLE principals (
    principal_id TEXT NOT NULL PRIMARY KEY,
    kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    os_binding TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
)"""
PRINCIPALS_KIND_REVOKED_AT_INDEX_DDL = """CREATE INDEX principals_kind_revoked_at_idx
    ON principals(kind, revoked_at)"""

PLUGIN_MANIFESTS_TABLE_DDL = """CREATE TABLE plugin_manifests (
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    manifest_ref TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL CHECK (
        length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    origin TEXT NOT NULL,
    capability_json TEXT NOT NULL,
    trust TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    host_allowlist_json TEXT NOT NULL,
    fixture_set_sha256 TEXT NOT NULL CHECK (
        length(fixture_set_sha256) = 64 AND fixture_set_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    registered_at TEXT NOT NULL,
    PRIMARY KEY (plugin_id, plugin_version),
    UNIQUE (manifest_sha256)
)"""
PLUGIN_MANIFESTS_ENABLED_TRUST_INDEX_DDL = """CREATE INDEX plugin_manifests_enabled_trust_idx
    ON plugin_manifests(enabled, trust)"""

SOURCES_TABLE_DDL = """CREATE TABLE sources (
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
    UNIQUE (plugin_id, account_alias),
    FOREIGN KEY (plugin_id, plugin_version)
        REFERENCES plugin_manifests(plugin_id, plugin_version),
    FOREIGN KEY (principal_id) REFERENCES principals(principal_id)
)"""
SOURCES_ENABLED_TYPE_INDEX_DDL = """CREATE INDEX sources_enabled_type_idx
    ON sources(enabled, source_type)"""

SYNC_CURSORS_TABLE_DDL = """CREATE TABLE sync_cursors (
    cursor_id TEXT NOT NULL PRIMARY KEY,
    source_id TEXT NOT NULL,
    cursor_kind TEXT NOT NULL,
    value_cipher_ref TEXT NOT NULL,
    etag TEXT,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    last_full_sync_at TEXT,
    last_commit_at TEXT NOT NULL,
    status TEXT NOT NULL,
    UNIQUE (source_id, cursor_kind),
    FOREIGN KEY (source_id) REFERENCES sources(source_id)
)"""
SYNC_CURSORS_STATUS_INDEX_DDL = """CREATE INDEX sync_cursors_status_idx
    ON sync_cursors(status)"""

SOURCE_ITEMS_TABLE_DDL = """CREATE TABLE source_items (
    item_id TEXT NOT NULL PRIMARY KEY,
    source_id TEXT NOT NULL,
    provider_item_id TEXT NOT NULL,
    provider_revision TEXT,
    canonical_uri TEXT,
    content_ref TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (
        length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    trust TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    source_at TEXT,
    deleted_at TEXT,
    metadata_json TEXT NOT NULL,
    UNIQUE (source_id, provider_item_id, content_sha256),
    FOREIGN KEY (source_id) REFERENCES sources(source_id)
)"""
SOURCE_ITEMS_SOURCE_OBSERVED_AT_INDEX_DDL = """CREATE INDEX source_items_source_observed_at_idx
    ON source_items(source_id, observed_at)"""
SOURCE_ITEMS_CONTENT_SHA256_INDEX_DDL = """CREATE INDEX source_items_content_sha256_idx
    ON source_items(content_sha256)"""

CR1_SOURCE_SCHEMA_VERSION = "cr1-e-0002-source-registry"
CR1_SOURCE_SCHEMA = SchemaDefinition(
    schema_version=CR1_SOURCE_SCHEMA_VERSION,
    objects=(
        *FOUNDATION_SCHEMA.objects,
        SchemaObjectDefinition("table", "principals", PRINCIPALS_TABLE_DDL),
        SchemaObjectDefinition(
            "index", "principals_kind_revoked_at_idx", PRINCIPALS_KIND_REVOKED_AT_INDEX_DDL
        ),
        SchemaObjectDefinition("table", "plugin_manifests", PLUGIN_MANIFESTS_TABLE_DDL),
        SchemaObjectDefinition(
            "index",
            "plugin_manifests_enabled_trust_idx",
            PLUGIN_MANIFESTS_ENABLED_TRUST_INDEX_DDL,
        ),
        SchemaObjectDefinition("table", "sources", SOURCES_TABLE_DDL),
        SchemaObjectDefinition("index", "sources_enabled_type_idx", SOURCES_ENABLED_TYPE_INDEX_DDL),
        SchemaObjectDefinition("table", "sync_cursors", SYNC_CURSORS_TABLE_DDL),
        SchemaObjectDefinition("index", "sync_cursors_status_idx", SYNC_CURSORS_STATUS_INDEX_DDL),
        SchemaObjectDefinition("table", "source_items", SOURCE_ITEMS_TABLE_DDL),
        SchemaObjectDefinition(
            "index",
            "source_items_source_observed_at_idx",
            SOURCE_ITEMS_SOURCE_OBSERVED_AT_INDEX_DDL,
        ),
        SchemaObjectDefinition(
            "index", "source_items_content_sha256_idx", SOURCE_ITEMS_CONTENT_SHA256_INDEX_DDL
        ),
    ),
)

# Independent checkpoint pin; the registry validates this separately from the
# migration artifact hash so historical CR0 metadata remains unchanged.
CR1_SOURCE_SCHEMA_DEFINITION_SHA256 = (
    "38eb2f69500aa21df1002691c40759ba5acbc58b09c97de4a8ab7bfdd9c40d6a"
)


def _normalized_sql(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    # SQLite preserves the registered DDL text; stripping surrounding whitespace
    # keeps comparison strict, including case-sensitive literals and constraints.
    return value.strip()


def _verify_foundation_metadata_table(
    connection: sqlite3.Connection,
    expected: SchemaDefinition,
) -> None:
    columns = connection.execute("PRAGMA table_info(schema_migrations)").fetchall()
    actual_columns = {
        str(name): (
            str(column_type).upper(),
            int(not_null),
            default,
            int(primary_key),
        )
        for _ordinal, name, column_type, not_null, default, primary_key in columns
    }
    required_columns = {
        name: (column_type, not_null, default, primary_key)
        for name, column_type, not_null, default, primary_key in EXPECTED_MIGRATION_COLUMNS
    }
    if any(actual_columns.get(name) != expected for name, expected in required_columns.items()):
        raise SchemaIntegrityError("schema_migrations columns do not match the normative schema")

    all_indexes = connection.execute("PRAGMA index_list(schema_migrations)").fetchall()
    indexes = [row for row in all_indexes if not str(row[1]).startswith("sqlite_")]
    primary_key_indexes = [row for row in all_indexes if str(row[1]).startswith("sqlite_")]
    if len(primary_key_indexes) != 1:
        raise SchemaIntegrityError("schema_migrations indexes do not match the normative schema")
    expected_index_names = {
        item.name for item in expected.objects if item.object_type == "index"
    }
    if any(str(row[1]) not in expected_index_names for row in indexes):
        raise SchemaIntegrityError("schema_migrations contains an unregistered index")
    migration_index = next(
        (row for row in indexes if row[1] == "schema_migrations_applied_at_idx"),
        None,
    )
    if migration_index is None:
        raise SchemaIntegrityError("schema_migrations applied_at index is malformed")
    _sequence, _index_name, is_unique, origin, is_partial = migration_index
    if (int(is_unique), origin, int(is_partial)) != (0, "c", 0):
        raise SchemaIntegrityError("schema_migrations applied_at index is malformed")
    applied_at_columns = connection.execute(
        "PRAGMA index_info(schema_migrations_applied_at_idx)"
    ).fetchall()
    if tuple(str(row[2]) for row in applied_at_columns) != ("applied_at",):
        raise SchemaIntegrityError("schema_migrations applied_at index is malformed")
    _pk_sequence, pk_name, pk_unique, pk_origin, pk_partial = primary_key_indexes[0]
    if (pk_name, int(pk_unique), pk_origin, int(pk_partial)) != (
        "sqlite_autoindex_schema_migrations_1",
        1,
        "pk",
        0,
    ):
        raise SchemaIntegrityError("schema_migrations primary key index is malformed")


def verify_schema(connection: sqlite3.Connection, expected: SchemaDefinition) -> None:
    """Compare every persisted schema object and its exact trusted DDL checkpoint.

    The expected inventory comes only from the registered application migration
    definitions. Database-controlled object definitions never expand the allowlist.
    """
    rows = connection.execute(
        """SELECT type, name, sql FROM sqlite_master
           WHERE name NOT GLOB 'sqlite_*'
             AND type IN ('table', 'index', 'view', 'trigger')"""
    ).fetchall()
    actual = {(str(object_type), str(name)): sql for object_type, name, sql in rows}
    expected_objects = {
        (item.object_type, item.name): item.sql for item in expected.objects
    }
    if actual.keys() != expected_objects.keys():
        raise SchemaIntegrityError("SQLite schema objects do not match the registered checkpoint")

    for identity, expected_sql in expected_objects.items():
        if _normalized_sql(actual[identity]) != _normalized_sql(expected_sql):
            raise SchemaIntegrityError(
                f"SQLite {identity[0]} definition differs from the registered checkpoint"
            )

    if ("table", "schema_migrations") in expected_objects:
        _verify_foundation_metadata_table(connection, expected)
