# Sentinel

Sentinel is a planned local-first personal automation application. Its authoritative design is [the Sentinel Master Blueprint](docs/spec/Sentinel%20Master%20Blueprint.pdf); [the build ledger](docs/BUILD_LEDGER.md) tracks implementation evidence and remaining gates. The architecture separates untrusted source content, model access through `ModelGateway`, tool effects through `ToolGateway`, and a deterministic policy reference monitor.

## Implemented bootstrap slices

CR0-A establishes repository governance, a Python package, and an installable CLI with `sentinel --help` and `sentinel version`. CR0-B adds immutable typed source and model/tool boundary envelopes. CR0-C adds an explicit SQLite connection API and a versioned migration foundation. These slices do not complete F43, F46, or CR0.

There is no agent, model adapter, MCP worker, policy engine, approval system, provider integration, daemon, or frontend. `init`, `doctor`, and `demo` are not available. CR0-C's only application schema is `schema_migrations`; no task, source, approval, audit, or user-data table is included. No model, HTTP provider, MCP, or external-tool calls are made. External writes are unavailable. These bootstrap slices do not demonstrate later security invariants.

## CR0-B contract API

`sentinel.contracts` exports the immutable `SourceEnvelope`, `ByteSpan`, and `BoundaryEnvelope` models, their `TrustLabel`, `SensitivityLabel`, and `BoundaryKind` enums, and `canonical_json_bytes` / `canonical_sha256` helpers. The models use UUID identifiers, timezone-aware UTC-normalized timestamps, lowercase 64-character SHA-256 hex digests, `sha256:<hex>` content references, tuples for nested collections, and reject undeclared fields.

```python
from datetime import UTC, datetime
from uuid import uuid4

from sentinel.contracts import SensitivityLabel, SourceEnvelope, TrustLabel

source = SourceEnvelope(
    source_id=uuid4(),
    provider_id="synthetic-source",
    content_sha256="a" * 64,
    observed_at=datetime.now(UTC),
    trust=TrustLabel.T4_EXTERNAL,
    sensitivity=SensitivityLabel.PRIVATE,
    parent_ids=(),
    byte_spans=(),
)
```

`BoundaryEnvelope.kind` classifies `model` or `tool`. Request and response payloads are represented by content references and matching digests, not embedded bodies. Optional response reference/digest and error code fields must be supplied explicitly as a value or `None`. Byte spans enforce `0 <= start_byte < end_byte`; because the source body length is not part of the blueprint's SourceEnvelope schema, the envelope cannot validate an upper bound against that body.

These contracts validate shape only. A `T1 OWNER_INTENT` value is a declaration, not proof of owner authentication; callers must not accept T0/T1 labels from untrusted source content. No generic external-payload factory is provided. The contracts do not authorize or execute actions. Canonical JSON is limited to exact contract types and is not the future approval digest or audit-chain algorithm.

## CR0-C SQLite storage API

`sentinel.storage` provides `open_database`, the closing `database_connection` context manager, `inspect_connection`, `initialize_storage`, and `verify_integrity`. There is no default database location. Opening an existing database is the default; creating a file requires an explicit `create=True` argument. Parent directories are never created automatically. File-backed databases must support WAL, foreign keys are enabled and checked on every connection, and the default SQLite busy timeout is 5 seconds (configurable up to 60 seconds).

```python
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinel.storage import database_connection, initialize_storage

with TemporaryDirectory() as directory:
    database = Path(directory) / "sentinel.sqlite3"
    applied = initialize_storage(database, create=True)
    with database_connection(database) as connection:
        print(applied)
        print(connection.execute("PRAGMA foreign_keys").fetchone())
```

Migrations are trusted Python artifacts registered in the ordered `MIGRATIONS` tuple in `sentinel.storage.migrations`. Every migration declares ordered single-statement SQL and a complete `SchemaDefinition` for the expected database after that migration. A checkpoint lists each expected table, index, view, and trigger with its trusted DDL. Registration is source code review; there is no runtime API for loading SQL or schema allowlists from a database, CLI input, or model output. A data-only migration still registers the full unchanged object inventory under its new migration ID.

For example, a future source migration would add trusted DDL and a checkpoint that includes all existing schema objects plus the new table and indexes:

```python
from sentinel.storage.migrations import Migration
from sentinel.storage.schema import FOUNDATION_SCHEMA, SchemaDefinition, SchemaObjectDefinition

source_items_sql = (
    "CREATE TABLE source_items "
    "(item_id TEXT NOT NULL PRIMARY KEY, created_at TEXT NOT NULL)"
)
source_index_sql = "CREATE INDEX source_items_created_at_idx ON source_items(created_at)"
source_checkpoint = SchemaDefinition(
    schema_version="cr0-example-0002-source-items",
    objects=(
        *FOUNDATION_SCHEMA.objects,
        SchemaObjectDefinition("table", "source_items", source_items_sql),
        SchemaObjectDefinition("index", "source_items_created_at_idx", source_index_sql),
    ),
)
source_migration = Migration(
    "cr0-example-0002-source-items",
    (source_items_sql, source_index_sql),
    source_checkpoint,
)
```

The application registry must include the migration in order. New migration artifact v2 hashes include both SQL and the complete schema checkpoint. The existing foundation artifact stays on its original v1 canonical bytes and SHA-256; a separate pinned schema-definition digest protects its added checkpoint without invalidating existing databases. Each registered historical artifact digest is still checked on startup.

The current initial migration, `cr0-c-0001-schema-migrations`, creates the normative `schema_migrations` table and its `applied_at` index only. It does not create production application data tables.

Initialization selects the expected schema checkpoint from the last migration in the validated applied registry prefix. It compares all persisted schema object identities and DDL against that trusted checkpoint and verifies the normative migration metadata columns and indexes. This detects unexpected or missing objects and altered table constraints, indexes, views, and triggers. It also checks applied migration IDs/order/digests and SQLite integrity and foreign keys. Untracked schema, unknown or changed migration records, malformed metadata, partial application, and schema drift fail closed without automatic repair. Every migration runs under `BEGIN IMMEDIATE`; individual statements use `execute()` rather than `executescript()`. A failure rolls back all statements and its success record together. A failed migration does not leave a successful metadata row.

These guarantees cover this local migration foundation, not application-wide ownership. WAL and `BEGIN IMMEDIATE` do not implement the §3 process-wide writer lease. Backup/restore, checkpoint workflows, encryption, redacted logs, keychain abstraction, application tables, and the rest of CR0 remain unavailable. Do not store secrets or raw private source bodies in this database. The migration registry is trusted code and is not an interface for model output, CLI SQL, or external migration files.

## Windows PowerShell setup

Install pyenv-win and Python 3.11.7 if not already available, then from the repository root:

```powershell
pyenv local 3.11.7
python --version
python -m venv .venv
```

Use the explicit virtual-environment interpreter for every package operation:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pip check
```

Do not install project packages with a global or ambiguous `pip` command. Run the supported CLI and checks with:

```powershell
.\.venv\Scripts\sentinel.exe --help
.\.venv\Scripts\sentinel.exe version
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src/sentinel
.\.venv\Scripts\python.exe -m build --wheel
```

The initial development install is registry-resolved and not yet hash-locked. See ADR-0001 and the ledger for the actual selected versions and the remaining clean offline installation gate.

## Security limitations

This bootstrap is not a security certification and does not implement the blueprint's P00-P17 policy rules or AB01-AB18 bypass tests. It has no credentials or personal-data fixtures. All consequential external capabilities remain unavailable pending their release gates. Use synthetic fixtures only in future tests.
