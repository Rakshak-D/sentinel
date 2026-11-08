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

# CR1-F adds only relational foundations for configuration/run/boundary and
# persisted span metadata. Opaque refs do not establish stored content or
# cryptographic provenance. The nullable runs.briefing_id is retained without
# an FK because the blueprint's briefings table is outside this migration.
CONFIG_REVISIONS_TABLE_DDL = """CREATE TABLE config_revisions (
    config_id TEXT NOT NULL PRIMARY KEY,
    parent_config_id TEXT,
    layer_set_json TEXT NOT NULL,
    effective_schema_version TEXT NOT NULL,
    effective_config_ref TEXT NOT NULL,
    effective_sha256 TEXT NOT NULL CHECK (
        length(effective_sha256) = 64 AND effective_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    unsafe_overrides_json TEXT NOT NULL,
    activated_at TEXT,
    created_at TEXT NOT NULL,
    activation_state TEXT NOT NULL,
    UNIQUE (effective_sha256),
    FOREIGN KEY (parent_config_id) REFERENCES config_revisions(config_id)
)"""
CONFIG_REVISIONS_ACTIVATION_CREATED_AT_INDEX_DDL = (
    "CREATE INDEX config_revisions_activation_created_at_idx\n"
    "    ON config_revisions(activation_state, created_at)"
)

RUN_MANIFESTS_TABLE_DDL = """CREATE TABLE run_manifests (
    manifest_id TEXT NOT NULL PRIMARY KEY,
    config_id TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL CHECK (
        length(policy_sha256) = 64 AND policy_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    graph_build TEXT NOT NULL,
    plugin_set_sha256 TEXT NOT NULL CHECK (
        length(plugin_set_sha256) = 64 AND plugin_set_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    prompt_set_sha256 TEXT NOT NULL CHECK (
        length(prompt_set_sha256) = 64 AND prompt_set_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    model_profile_sha256 TEXT NOT NULL CHECK (
        length(model_profile_sha256) = 64 AND model_profile_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    unsafe_overrides_json TEXT NOT NULL,
    fixture_manifest_sha256 TEXT CHECK (
        fixture_manifest_sha256 IS NULL OR (
            length(fixture_manifest_sha256) = 64
            AND fixture_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    created_at TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL CHECK (
        length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    UNIQUE (manifest_sha256),
    FOREIGN KEY (config_id) REFERENCES config_revisions(config_id)
)"""
RUN_MANIFESTS_CREATED_AT_INDEX_DDL = """CREATE INDEX run_manifests_created_at_idx
    ON run_manifests(created_at)"""

RUNS_TABLE_DDL = """CREATE TABLE runs (
    run_id TEXT NOT NULL PRIMARY KEY,
    thread_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    trigger_kind TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT NOT NULL,
    error_code TEXT,
    briefing_id TEXT,
    FOREIGN KEY (principal_id) REFERENCES principals(principal_id),
    FOREIGN KEY (manifest_id) REFERENCES run_manifests(manifest_id)
)"""
RUNS_THREAD_STARTED_AT_INDEX_DDL = """CREATE INDEX runs_thread_started_at_idx
    ON runs(thread_id, started_at)"""
RUNS_STATUS_STARTED_AT_INDEX_DDL = """CREATE INDEX runs_status_started_at_idx
    ON runs(status, started_at)"""

BOUNDARY_ENVELOPES_TABLE_DDL = """CREATE TABLE boundary_envelopes (
    boundary_id TEXT NOT NULL PRIMARY KEY,
    run_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    request_ref TEXT NOT NULL,
    response_ref TEXT,
    request_sha256 TEXT NOT NULL CHECK (
        length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    response_sha256 TEXT CHECK (
        response_sha256 IS NULL OR (
            length(response_sha256) = 64 AND response_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    sensitivity TEXT NOT NULL,
    source_ids_json TEXT NOT NULL,
    replay_injected INTEGER NOT NULL CHECK (replay_injected IN (0, 1)),
    error_code TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (run_id, seq),
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
)"""
BOUNDARY_ENVELOPES_KIND_ADAPTER_INDEX_DDL = """CREATE INDEX boundary_envelopes_kind_adapter_idx
    ON boundary_envelopes(kind, adapter_id)"""

SOURCE_SPANS_TABLE_DDL = """CREATE TABLE source_spans (
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
    derived_by_boundary_id TEXT,
    FOREIGN KEY (item_id) REFERENCES source_items(item_id),
    FOREIGN KEY (derived_by_boundary_id) REFERENCES boundary_envelopes(boundary_id)
)"""
SOURCE_SPANS_ITEM_START_BYTE_INDEX_DDL = """CREATE INDEX source_spans_item_start_byte_idx
    ON source_spans(item_id, start_byte)"""

CR1_F_SCHEMA_VERSION = "cr1-f-0003-source-spans"
CR1_F_SCHEMA = SchemaDefinition(
    schema_version=CR1_F_SCHEMA_VERSION,
    objects=(
        *CR1_SOURCE_SCHEMA.objects,
        SchemaObjectDefinition("table", "config_revisions", CONFIG_REVISIONS_TABLE_DDL),
        SchemaObjectDefinition(
            "index",
            "config_revisions_activation_created_at_idx",
            CONFIG_REVISIONS_ACTIVATION_CREATED_AT_INDEX_DDL,
        ),
        SchemaObjectDefinition("table", "run_manifests", RUN_MANIFESTS_TABLE_DDL),
        SchemaObjectDefinition(
            "index", "run_manifests_created_at_idx", RUN_MANIFESTS_CREATED_AT_INDEX_DDL
        ),
        SchemaObjectDefinition("table", "runs", RUNS_TABLE_DDL),
        SchemaObjectDefinition(
            "index", "runs_thread_started_at_idx", RUNS_THREAD_STARTED_AT_INDEX_DDL
        ),
        SchemaObjectDefinition(
            "index", "runs_status_started_at_idx", RUNS_STATUS_STARTED_AT_INDEX_DDL
        ),
        SchemaObjectDefinition("table", "boundary_envelopes", BOUNDARY_ENVELOPES_TABLE_DDL),
        SchemaObjectDefinition(
            "index",
            "boundary_envelopes_kind_adapter_idx",
            BOUNDARY_ENVELOPES_KIND_ADAPTER_INDEX_DDL,
        ),
        SchemaObjectDefinition("table", "source_spans", SOURCE_SPANS_TABLE_DDL),
        SchemaObjectDefinition(
            "index", "source_spans_item_start_byte_idx", SOURCE_SPANS_ITEM_START_BYTE_INDEX_DDL
        ),
    ),
)

# Independent pin for the full post-CR1-F schema checkpoint.
CR1_F_SCHEMA_DEFINITION_SHA256 = "26f31fe4601c67cb60c6faa324eba83ff59c611b1fa283e514f0a77e3acf44ad"

# CR1-J adds a schema-only proposal parent required by the normative task FK,
# the local task table, and a minimal immutable request receipt. The receipt is
# needed because the normative task row has no request-id field while F11
# requires replay conflict detection to survive later task edits.
ACTION_PROPOSALS_TABLE_DDL = """CREATE TABLE action_proposals (
    proposal_id TEXT NOT NULL PRIMARY KEY,
    run_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    tool_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    canonical_args_ref TEXT NOT NULL,
    canonical_args_sha256 TEXT NOT NULL CHECK (
        length(canonical_args_sha256) = 64
        AND canonical_args_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    display_sha256 TEXT NOT NULL CHECK (
        length(display_sha256) = 64 AND display_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    owner_intent_id TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    credential_alias TEXT,
    UNIQUE (display_sha256, run_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id),
    FOREIGN KEY (principal_id) REFERENCES principals(principal_id)
)"""
ACTION_PROPOSALS_STATUS_EXPIRES_AT_INDEX_DDL = (
    "CREATE INDEX action_proposals_status_expires_at_idx\n"
    "    ON action_proposals(status, expires_at)"
)

TASKS_TABLE_DDL = """CREATE TABLE tasks (
    task_id TEXT NOT NULL PRIMARY KEY,
    owner_principal_id TEXT NOT NULL,
    source_item_id TEXT,
    proposal_id TEXT,
    title TEXT NOT NULL,
    body_ref TEXT,
    due_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'COMPLETED')),
    revision INTEGER NOT NULL CHECK (typeof(revision) = 'integer' AND revision >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY (owner_principal_id) REFERENCES principals(principal_id),
    FOREIGN KEY (source_item_id) REFERENCES source_items(item_id),
    FOREIGN KEY (proposal_id) REFERENCES action_proposals(proposal_id)
)"""
TASKS_STATUS_DUE_AT_INDEX_DDL = """CREATE INDEX tasks_status_due_at_idx
    ON tasks(status, due_at)"""
TASKS_PROPOSAL_ID_UNIQUE_INDEX_DDL = """CREATE UNIQUE INDEX tasks_proposal_id_unique_idx
    ON tasks(proposal_id) WHERE proposal_id IS NOT NULL"""

TASK_CREATION_REQUESTS_TABLE_DDL = """CREATE TABLE task_creation_requests (
    request_id TEXT NOT NULL PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE,
    request_sha256 TEXT NOT NULL CHECK (
        length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
)"""

CR1_J_SCHEMA_VERSION = "cr1-j-0004-local-tasks"
CR1_J_SCHEMA = SchemaDefinition(
    schema_version=CR1_J_SCHEMA_VERSION,
    objects=(
        *CR1_F_SCHEMA.objects,
        SchemaObjectDefinition("table", "action_proposals", ACTION_PROPOSALS_TABLE_DDL),
        SchemaObjectDefinition(
            "index",
            "action_proposals_status_expires_at_idx",
            ACTION_PROPOSALS_STATUS_EXPIRES_AT_INDEX_DDL,
        ),
        SchemaObjectDefinition("table", "tasks", TASKS_TABLE_DDL),
        SchemaObjectDefinition("index", "tasks_status_due_at_idx", TASKS_STATUS_DUE_AT_INDEX_DDL),
        SchemaObjectDefinition(
            "index", "tasks_proposal_id_unique_idx", TASKS_PROPOSAL_ID_UNIQUE_INDEX_DDL
        ),
        SchemaObjectDefinition("table", "task_creation_requests", TASK_CREATION_REQUESTS_TABLE_DDL),
    ),
)

# Independent pin for the complete post-CR1-J schema checkpoint.
CR1_J_SCHEMA_DEFINITION_SHA256 = "659d0643a9e1c85f839a107d4e8d1d944c38972bb0416d094cd5a73ad355979d"

# CR2-D adds durable metadata for one fixed synthetic proposal path.  CR1-J's
# checkpoint above is intentionally immutable; this complete post-migration
# table definition records the append-only ALTER TABLE result.
CR2_D_ACTION_PROPOSAL_COLUMNS = (
    "proposal_schema_version TEXT NOT NULL DEFAULT ''",
    "proposal_kind TEXT NOT NULL DEFAULT ''",
    "preview_id TEXT NOT NULL DEFAULT ''",
    "selected_source_item_id TEXT NOT NULL DEFAULT ''",
    "selected_source_envelope_id TEXT NOT NULL DEFAULT ''",
    (
        "source_content_sha256 TEXT NOT NULL DEFAULT '' CHECK (source_content_sha256 = '' OR "
        "(length(source_content_sha256) = 64 AND source_content_sha256 NOT GLOB '*[^0-9a-f]*'))"
    ),
    (
        "source_binding_sha256 TEXT NOT NULL DEFAULT '' CHECK (source_binding_sha256 = '' OR "
        "(length(source_binding_sha256) = 64 AND source_binding_sha256 NOT GLOB '*[^0-9a-f]*'))"
    ),
    (
        "source_manifest_sha256 TEXT NOT NULL DEFAULT '' CHECK (source_manifest_sha256 = '' OR "
        "(length(source_manifest_sha256) = 64 AND source_manifest_sha256 NOT GLOB '*[^0-9a-f]*'))"
    ),
    (
        "policy_request_sha256 TEXT NOT NULL DEFAULT '' CHECK (policy_request_sha256 = '' OR "
        "(length(policy_request_sha256) = 64 AND policy_request_sha256 NOT GLOB '*[^0-9a-f]*'))"
    ),
    (
        "policy_sha256 TEXT NOT NULL DEFAULT '' CHECK (policy_sha256 = '' OR "
        "(length(policy_sha256) = 64 AND policy_sha256 NOT GLOB '*[^0-9a-f]*'))"
    ),
    (
        "registry_sha256 TEXT NOT NULL DEFAULT '' CHECK (registry_sha256 = '' OR "
        "(length(registry_sha256) = 64 AND registry_sha256 NOT GLOB '*[^0-9a-f]*'))"
    ),
    (
        "config_sha256 TEXT NOT NULL DEFAULT '' CHECK (config_sha256 = '' OR "
        "(length(config_sha256) = 64 AND config_sha256 NOT GLOB '*[^0-9a-f]*'))"
    ),
    "canonical_args_json TEXT NOT NULL DEFAULT '' CHECK (length(canonical_args_json) <= 16384)",
    "executable INTEGER NOT NULL DEFAULT 0 CHECK (executable = 0)",
)
_CR2_D_PROPOSAL_COLUMNS_INLINE = ", ".join(CR2_D_ACTION_PROPOSAL_COLUMNS)
CR2_D_ACTION_PROPOSALS_TABLE_DDL = ACTION_PROPOSALS_TABLE_DDL.replace(
    "    credential_alias TEXT,\n    UNIQUE",
    f"    credential_alias TEXT, {_CR2_D_PROPOSAL_COLUMNS_INLINE},\n    UNIQUE",
)
if CR2_D_ACTION_PROPOSALS_TABLE_DDL == ACTION_PROPOSALS_TABLE_DDL:
    raise RuntimeError("CR2-D proposal schema extension point is missing")

SOURCE_SPANS_ITEM_SPAN_UNIQUE_INDEX_DDL = (
    "CREATE UNIQUE INDEX source_spans_item_span_unique_idx\n"
    "    ON source_spans(item_id, span_id)"
)

PROPOSAL_SOURCES_TABLE_DDL = """CREATE TABLE proposal_sources (
    proposal_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    argument_path TEXT NOT NULL,
    attribution_kind TEXT NOT NULL CHECK (attribution_kind = 'SOURCE_CITATION'),
    PRIMARY KEY (proposal_id, item_id, span_id, argument_path),
    UNIQUE (proposal_id, span_id),
    FOREIGN KEY (proposal_id) REFERENCES action_proposals(proposal_id),
    FOREIGN KEY (item_id, span_id) REFERENCES source_spans(item_id, span_id)
)"""
PROPOSAL_SOURCES_ITEM_ID_INDEX_DDL = (
    "CREATE INDEX proposal_sources_item_id_idx ON proposal_sources(item_id)"
)

ACTION_PROPOSALS_CR2_D_INSERT_GUARD_DDL = """CREATE TRIGGER action_proposals_cr2_d_insert_guard
BEFORE INSERT ON action_proposals
WHEN NOT (
    NEW.proposal_schema_version = 'sentinel.synthetic-pending-proposal.v1'
    AND NEW.proposal_kind = 'REVIEW_SOURCE'
    AND NEW.tool_id = 'sentinel.synthetic.proposal.persist'
    AND NEW.capability = 'C2_WRITE_LOCAL_PROPOSAL'
    AND NEW.status = 'PENDING_REVIEW'
    AND NEW.owner_intent_id IS NULL
    AND NEW.credential_alias IS NULL
    AND NEW.executable = 0
    AND length(NEW.canonical_args_json) <= 16384
)
BEGIN
    SELECT RAISE(ABORT, 'invalid bounded pending proposal');
END"""

CR2_D_SCHEMA_VERSION = "cr2-d-0005-durable-pending-proposals"
CR2_D_SCHEMA = SchemaDefinition(
    schema_version=CR2_D_SCHEMA_VERSION,
    objects=(
        *(
            SchemaObjectDefinition(
                item.object_type,
                item.name,
                CR2_D_ACTION_PROPOSALS_TABLE_DDL
                if item.object_type == "table" and item.name == "action_proposals"
                else item.sql,
            )
            for item in CR1_J_SCHEMA.objects
        ),
        SchemaObjectDefinition(
            "index",
            "source_spans_item_span_unique_idx",
            SOURCE_SPANS_ITEM_SPAN_UNIQUE_INDEX_DDL,
        ),
        SchemaObjectDefinition("table", "proposal_sources", PROPOSAL_SOURCES_TABLE_DDL),
        SchemaObjectDefinition(
            "index", "proposal_sources_item_id_idx", PROPOSAL_SOURCES_ITEM_ID_INDEX_DDL
        ),
        SchemaObjectDefinition(
            "trigger",
            "action_proposals_cr2_d_insert_guard",
            ACTION_PROPOSALS_CR2_D_INSERT_GUARD_DDL,
        ),
    ),
)
CURRENT_SCHEMA = CR2_D_SCHEMA

# Filled from the exact registered schema artifact, then pinned in migrations.py.
CR2_D_SCHEMA_DEFINITION_SHA256 = "bf0ec109fd2495d2d45253bcf79eee3cdd5e554a05b58d249adb482536907484"

# CR2-F stores synthetic-only verifier metadata and one-use challenge state.
# These rows can validate a signed challenge, but do not establish trusted owner
# enrollment or authorization. The tables deliberately contain no private keys.
OWNER_PROOF_CREDENTIALS_TABLE_DDL = """CREATE TABLE owner_proof_credentials (
    credential_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(credential_id) BETWEEN 1 AND 684
               AND credential_id NOT GLOB '*[^A-Za-z0-9_-]*'),
    owner_association TEXT NOT NULL CHECK (owner_association = 'synthetic-test-owner'),
    cose_public_key BLOB NOT NULL CHECK (length(cose_public_key) BETWEEN 1 AND 4096),
    rp_id TEXT NOT NULL CHECK (rp_id = 'sentinel.test'),
    expected_origin TEXT NOT NULL CHECK (expected_origin = 'https://sentinel.test'),
    sign_count INTEGER NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
    registration_state TEXT NOT NULL CHECK (registration_state = 'SYNTHETIC_TEST_ONLY'),
    revoked INTEGER NOT NULL CHECK (revoked IN (0, 1)),
    created_at TEXT NOT NULL
)"""
OWNER_PROOF_CREDENTIALS_STATE_INDEX_DDL = (
    "CREATE INDEX owner_proof_credentials_state_idx "
    "ON owner_proof_credentials(registration_state, revoked)"
)
OWNER_PROOF_CREDENTIALS_UPDATE_GUARD_DDL = """CREATE TRIGGER owner_proof_credentials_update_guard
BEFORE UPDATE ON owner_proof_credentials
WHEN NEW.credential_id != OLD.credential_id
  OR NEW.owner_association != OLD.owner_association
  OR NEW.cose_public_key != OLD.cose_public_key
  OR NEW.rp_id != OLD.rp_id
  OR NEW.expected_origin != OLD.expected_origin
  OR NEW.registration_state != OLD.registration_state
  OR NEW.revoked != OLD.revoked
  OR NEW.created_at != OLD.created_at
  OR (OLD.sign_count > 0 AND NEW.sign_count <= OLD.sign_count)
BEGIN
    SELECT RAISE(ABORT, 'invalid owner proof credential update');
END"""
OWNER_PROOF_CREDENTIALS_DELETE_GUARD_DDL = """CREATE TRIGGER owner_proof_credentials_delete_guard
BEFORE DELETE ON owner_proof_credentials
BEGIN
    SELECT RAISE(ABORT, 'owner proof credential records are retained');
END"""

OWNER_PROOF_CHALLENGES_TABLE_DDL = """CREATE TABLE owner_proof_challenges (
    challenge_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(challenge_id) = 32 AND challenge_id NOT GLOB '*[^0-9a-f]*'),
    schema_version TEXT NOT NULL
        CHECK (schema_version = 'sentinel.owner-proof-challenge.v1'),
    challenge_b64url TEXT NOT NULL UNIQUE
        CHECK (length(challenge_b64url) = 43
               AND challenge_b64url NOT GLOB '*[^A-Za-z0-9_-]*'),
    proposal_id TEXT NOT NULL,
    proposal_snapshot_sha256 TEXT NOT NULL
        CHECK (length(proposal_snapshot_sha256) = 64
               AND proposal_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'),
    fixture_sha256 TEXT NOT NULL
        CHECK (length(fixture_sha256) = 64 AND fixture_sha256 NOT GLOB '*[^0-9a-f]*'),
    manifest_sha256 TEXT NOT NULL
        CHECK (length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    source_set_sha256 TEXT NOT NULL
        CHECK (length(source_set_sha256) = 64 AND source_set_sha256 NOT GLOB '*[^0-9a-f]*'),
    source_item_id TEXT NOT NULL,
    source_envelope_id TEXT NOT NULL,
    source_content_sha256 TEXT NOT NULL
        CHECK (length(source_content_sha256) = 64
               AND source_content_sha256 NOT GLOB '*[^0-9a-f]*'),
    citation_bindings_json TEXT NOT NULL CHECK (length(citation_bindings_json) <= 4096),
    citation_bindings_sha256 TEXT NOT NULL
        CHECK (length(citation_bindings_sha256) = 64
               AND citation_bindings_sha256 NOT GLOB '*[^0-9a-f]*'),
    policy_request_sha256 TEXT NOT NULL
        CHECK (length(policy_request_sha256) = 64
               AND policy_request_sha256 NOT GLOB '*[^0-9a-f]*'),
    policy_sha256 TEXT NOT NULL
        CHECK (length(policy_sha256) = 64 AND policy_sha256 NOT GLOB '*[^0-9a-f]*'),
    registry_sha256 TEXT NOT NULL
        CHECK (length(registry_sha256) = 64 AND registry_sha256 NOT GLOB '*[^0-9a-f]*'),
    config_sha256 TEXT NOT NULL
        CHECK (length(config_sha256) = 64 AND config_sha256 NOT GLOB '*[^0-9a-f]*'),
    credential_id TEXT NOT NULL,
    owner_association TEXT NOT NULL CHECK (owner_association = 'synthetic-test-owner'),
    rp_id TEXT NOT NULL CHECK (rp_id = 'sentinel.test'),
    expected_origin TEXT NOT NULL CHECK (expected_origin = 'https://sentinel.test'),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    purpose TEXT NOT NULL
        CHECK (purpose = 'sentinel.pending-proposal-review.webauthn-get.v1'),
    scope TEXT NOT NULL CHECK (scope = 'SYNTHETIC_TEST_ONLY_NON_EXECUTABLE'),
    FOREIGN KEY (proposal_id) REFERENCES action_proposals(proposal_id),
    FOREIGN KEY (credential_id) REFERENCES owner_proof_credentials(credential_id)
)"""
OWNER_PROOF_CHALLENGES_PROPOSAL_INDEX_DDL = (
    "CREATE INDEX owner_proof_challenges_proposal_idx "
    "ON owner_proof_challenges(proposal_id, created_at)"
)
OWNER_PROOF_CHALLENGES_UPDATE_GUARD_DDL = """CREATE TRIGGER owner_proof_challenges_update_guard
BEFORE UPDATE ON owner_proof_challenges
BEGIN
    SELECT RAISE(ABORT, 'owner proof challenge records are immutable');
END"""
OWNER_PROOF_CHALLENGES_DELETE_GUARD_DDL = """CREATE TRIGGER owner_proof_challenges_delete_guard
BEFORE DELETE ON owner_proof_challenges
BEGIN
    SELECT RAISE(ABORT, 'owner proof challenge records are retained');
END"""

OWNER_PROOF_CHALLENGE_CONSUMPTIONS_TABLE_DDL = """CREATE TABLE owner_proof_challenge_consumptions (
    challenge_id TEXT NOT NULL PRIMARY KEY,
    consumed_at TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('VERIFIED_SYNTHETIC_ONLY', 'FAILED')),
    reason_code TEXT NOT NULL
        CHECK (reason_code IN ('ASSERTION_VERIFIED', 'ASSERTION_REJECTED')),
    verified_sign_count INTEGER
        CHECK (verified_sign_count IS NULL OR verified_sign_count BETWEEN 0 AND 4294967295),
    FOREIGN KEY (challenge_id) REFERENCES owner_proof_challenges(challenge_id),
    CHECK ((outcome = 'VERIFIED_SYNTHETIC_ONLY'
            AND reason_code = 'ASSERTION_VERIFIED'
            AND verified_sign_count IS NOT NULL)
        OR (outcome = 'FAILED'
            AND reason_code = 'ASSERTION_REJECTED'
            AND verified_sign_count IS NULL))
)"""
OWNER_PROOF_CHALLENGE_CONSUMPTIONS_UPDATE_GUARD_DDL = """\
CREATE TRIGGER owner_proof_consumptions_update_guard
BEFORE UPDATE ON owner_proof_challenge_consumptions
BEGIN
    SELECT RAISE(ABORT, 'owner proof consumption records are immutable');
END"""
OWNER_PROOF_CHALLENGE_CONSUMPTIONS_DELETE_GUARD_DDL = """\
CREATE TRIGGER owner_proof_consumptions_delete_guard
BEFORE DELETE ON owner_proof_challenge_consumptions
BEGIN
    SELECT RAISE(ABORT, 'owner proof consumption records are retained');
END"""

CR2_F_SCHEMA_VERSION = "cr2-f-0006-owner-proof-challenges"
CR2_F_SCHEMA = SchemaDefinition(
    schema_version=CR2_F_SCHEMA_VERSION,
    objects=(
        *CR2_D_SCHEMA.objects,
        SchemaObjectDefinition(
            "table",
            "owner_proof_credentials",
            OWNER_PROOF_CREDENTIALS_TABLE_DDL,
        ),
        SchemaObjectDefinition(
            "index", "owner_proof_credentials_state_idx", OWNER_PROOF_CREDENTIALS_STATE_INDEX_DDL
        ),
        SchemaObjectDefinition(
            "trigger",
            "owner_proof_credentials_update_guard",
            OWNER_PROOF_CREDENTIALS_UPDATE_GUARD_DDL,
        ),
        SchemaObjectDefinition(
            "trigger",
            "owner_proof_credentials_delete_guard",
            OWNER_PROOF_CREDENTIALS_DELETE_GUARD_DDL,
        ),
        SchemaObjectDefinition(
            "table",
            "owner_proof_challenges",
            OWNER_PROOF_CHALLENGES_TABLE_DDL,
        ),
        SchemaObjectDefinition(
            "index",
            "owner_proof_challenges_proposal_idx",
            OWNER_PROOF_CHALLENGES_PROPOSAL_INDEX_DDL,
        ),
        SchemaObjectDefinition(
            "trigger",
            "owner_proof_challenges_update_guard",
            OWNER_PROOF_CHALLENGES_UPDATE_GUARD_DDL,
        ),
        SchemaObjectDefinition(
            "trigger",
            "owner_proof_challenges_delete_guard",
            OWNER_PROOF_CHALLENGES_DELETE_GUARD_DDL,
        ),
        SchemaObjectDefinition(
            "table",
            "owner_proof_challenge_consumptions",
            OWNER_PROOF_CHALLENGE_CONSUMPTIONS_TABLE_DDL,
        ),
        SchemaObjectDefinition(
            "trigger",
            "owner_proof_consumptions_update_guard",
            OWNER_PROOF_CHALLENGE_CONSUMPTIONS_UPDATE_GUARD_DDL,
        ),
        SchemaObjectDefinition(
            "trigger",
            "owner_proof_consumptions_delete_guard",
            OWNER_PROOF_CHALLENGE_CONSUMPTIONS_DELETE_GUARD_DDL,
        ),
    ),
)
CR2_F_SCHEMA_DEFINITION_SHA256 = "996f4c5ae2e1eba6f6cf409834d8a4ec48e514c7411ed7653640b518cb6b4b51"
CURRENT_SCHEMA = CR2_F_SCHEMA


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
    expected_index_names = {item.name for item in expected.objects if item.object_type == "index"}
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
    expected_objects = {(item.object_type, item.name): item.sql for item in expected.objects}
    if actual.keys() != expected_objects.keys():
        raise SchemaIntegrityError("SQLite schema objects do not match the registered checkpoint")

    for identity, expected_sql in expected_objects.items():
        if _normalized_sql(actual[identity]) != _normalized_sql(expected_sql):
            raise SchemaIntegrityError(
                f"SQLite {identity[0]} definition differs from the registered checkpoint"
            )

    if ("table", "schema_migrations") in expected_objects:
        _verify_foundation_metadata_table(connection, expected)
