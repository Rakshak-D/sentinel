# Sentinel

Sentinel 0.2.0 is the bounded offline CR1 daily-read/product core described by the [Master Blueprint](docs/spec/Sentinel%20Master%20Blueprint.pdf). It provides manual local tasks, pinned fictional Gmail/GitHub/Calendar fixture readers, explicit allowlisted local-file workflows, source-bound citations, a deterministic local overview, and restart-safe synthetic GitHub fixture state. The [build ledger](docs/BUILD_LEDGER.md) records exact evidence and remaining product gates.

The historical CR1 slice notes below preserve each slice's acceptance-time status. The release owner accepted the bounded scope for promotion, subject to final release acceptance recorded in the ledger and release record. This does not mean the full Sentinel product or every broader F-feature is complete. There is no live Gmail, GitHub, Calendar, Greenhouse, or Lever connection; no model-mediated PRIVATE processing; no automatic source-derived tasks; no secure external writes; and no production-readiness claim. The ModelGateway remains synthetic PUBLIC-only, while local alert and note content remains PRIVATE/T4_EXTERNAL.

## CR1 offline workflow

Initialize a new database explicitly, prepare and verify the synthetic local workspace, then run one-shot read commands from separate CLI processes:

```powershell
sentinel init --database C:\Data\sentinel.sqlite3
sentinel fixture-workspace prepare --database C:\Data\sentinel.sqlite3 --store-root C:\Data\sentinel-public
sentinel fixture-workspace verify --database C:\Data\sentinel.sqlite3 --store-root C:\Data\sentinel-public
sentinel source status --format text
sentinel brief github-fixture --database C:\Data\sentinel.sqlite3 --store-root C:\Data\sentinel-public
sentinel source calendar-fixture --format text
sentinel brief local-overview --database C:\Data\sentinel.sqlite3 --store-root C:\Data\sentinel-public --as-of 2026-11-05T18:00:00+05:30 --format text
sentinel task add --database C:\Data\sentinel.sqlite3 --title "Review a manually selected item"
```

The overview's `--as-of` value is required and its supplied offset defines a fixed-offset local calendar day. Other selected-file workflows include `source inspect-file`, `source search-files`, `source notes-registry build|verify`, `source parse-job-alert`, `source review-job-alerts`, and `source triage-job-alerts`; each requires explicit paths beneath an allowlisted local root. The fixture readers are synthetic and do not represent connected accounts. Notes and job-alert files are PRIVATE in memory and are not persisted by these commands. Task titles are manually entered, unauthenticated local data.

CR0 remains the historical 0.1.0 package/tag scope. Its annotated tag and Windows runtime lock retain their original identities and hashes; the 0.2.0 release does not retag or rewrite CR0.

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

## CR0-D demo-only gateways

`sentinel.gateways` exports `ModelGateway.generate(request)` and `ToolGateway.call(request)`, plus immutable `ModelRequest`, `ToolRequest`, typed responses/failures, `DemoPayload`, adapter registration records, and `GatewayRegistry`. `ModelRequest` follows the §7 request shape: it contains call/run IDs, adapter and requested model IDs, task/prompt/schema IDs and hashes, source IDs, required sensitivity, a `payload_ref`, config hash, temperature, output bound, deadline, requested profile, and replay flag. It contains no raw model input. Trusted application setup may place bounded synthetic UTF-8 bytes in `GatewayRegistry.demo_payloads`; each `DemoPayload` reference must hash those exact bytes and match a registered source digest. The gateway resolves that payload only for an eligible PUBLIC, local-only DEMO request and gives the bytes to the registered in-memory adapter.

The registry is a fixed tuple of trusted application-code registrations, source envelopes, and (for model demo calls) bounded payload references. Requests can name an adapter, model, or tool, but exact lookup is required; request data cannot supply a handler, executable, URL, shell command, approval, trust label, or mode that installs an adapter. The registry accepts only an explicitly constructed `ExecutionMode.DEMO` context and revalidates registered source envelopes and payload digests. Source trust and sensitivity are read from registered envelopes, and the requested sensitivity must equal the most restrictive registered source label. Source trust remains a label, not authentication evidence.

Provider model IDs share the same `ModelIdentifier` validation contract in registrations, requests, adapter invocations, and responses. Slash-separated identifiers such as `synthetic/example-v1` are supported; execution still requires an exact trusted registry match.

The only successful model path is a registered demo adapter classified as loopback, using the `local-only` profile, `PUBLIC` source data, and the fixed `sentinel.text.v1` text schema. `INTERNAL`, `PRIVATE`, and `SECRET` model inputs are denied in this slice; `SECRET` is always denied, and private data is denied before any cloud-classified adapter could be called. Cloud-classified adapters, `hybrid`/`cloud-max` profiles, live execution, and replay are unavailable. Model outputs are typed as `T3 DERIVED`; model text cannot set owner intent.

The tool path permits a registered demo adapter only when its registered capability is `READ_ONLY` and its argument names exactly match the registration. Local/external writes, send, approval, and execute capabilities are denied. An `approved` request field is undeclared and has no authority. The included synthetic test adapters are implemented in [test_model_gateway.py](tests/test_model_gateway.py) and [test_tool_gateway.py](tests/test_tool_gateway.py); they operate on in-memory fixture values and make no network calls.

Both gateways revalidate requests at entry, resolve only registered IDs, return bounded failure codes/messages, and do not retry. Adapter exception text is not included in results. Successful calls hash the canonical invocation bytes passed to the adapter (including the resolved model payload in its canonical UTF-8 representation) and the exact adapter output bytes. `BoundaryEnvelope` stores references and digests, not payload bodies, credentials, or tool arguments. Valid-but-denied calls receive a failure boundary with no response reference/digest. Malformed requests fail before a boundary can be safely formed. Boundary sequence numbers are volatile per registry/run; there is no persistence, replay engine, signed audit chain, or complete audit guarantee.

Gateway results explicitly report `authorization=NOT_EVALUATED` and `external_effect=False`. This is not a policy decision or an authorization grant. The registry trusts application adapter code and does not sandbox a malicious adapter; only the included synthetic tests were reviewed for in-memory behavior. There is no live adapter or policy path in CR0-D. Future provider and tool adapters must remain behind these wrappers and require separate policy, privacy, approval, credential-isolation, and release-gate work. This slice does not prove P00-P03, provider egress safety, or F21/F29/F33/F34 completion.

## CR0-E structured diagnostics

`sentinel.observability` exports `DiagnosticEvent`, `DiagnosticEventCode`, `DiagnosticSeverity`, `DiagnosticOutcome`, `DiagnosticComponent`, `DiagnosticErrorCode`, `JsonLinesDiagnosticLogger`, `encode_event`, and `stderr_logger`. A diagnostic event contains only registered codes, a UTC timestamp, and bounded optional metadata: `run_id` and `boundary_id` UUIDs, a fixed component, a `SensitivityLabel`, and a registered error code. The timestamp defaults to the current UTC time; supplied aware timestamps are normalized to UTC.

The fixed event codes are `cli.operation_result`, `storage.operation_result`, `gateway.operation_result`, `boundary.operation_result`, and `diagnostic.failure`. Outcomes are `SUCCESS`, `DENIED`, `FAILURE`, or `UNAVAILABLE`; severities are `DEBUG`, `INFO`, `WARNING`, or `ERROR`. No free-form message, dictionary, path, URL, exception object, source body, prompt, model response, or tool argument is part of the event schema. Sensitivity has no default to `PUBLIC`; absent classification serializes as JSON `null`. An event outcome is diagnostic information and does not represent authorization, owner intent, trust authentication, or approval.

Use an explicitly selected diagnostic sink. The convenience factory selects stderr, and the logger rejects the process's stdout stream so MCP protocol output cannot be polluted:

```python
from uuid import uuid4

from sentinel.observability import (
    DiagnosticComponent,
    DiagnosticEvent,
    DiagnosticEventCode,
    DiagnosticOutcome,
    DiagnosticSeverity,
    stderr_logger,
)

stderr_logger().emit(
    DiagnosticEvent(
        event_code=DiagnosticEventCode.CLI_OPERATION_RESULT,
        severity=DiagnosticSeverity.INFO,
        outcome=DiagnosticOutcome.SUCCESS,
        run_id=uuid4(),
        boundary_id=None,
        component=DiagnosticComponent.CLI,
        sensitivity=None,
        error_code=None,
    )
)
```

Each event becomes one deterministic JSON Lines record. Validation rejects unknown codes, enum values, and fields with a fixed non-sensitive `DiagnosticValidationError`. Unchecked Pydantic instances are revalidated before encoding. Failure diagnostics carry a registered `DiagnosticErrorCode`; exception text and tracebacks are never inspected or serialized automatically. Sink failures raise a fixed `DiagnosticSinkError` instead of being treated as success. Since a text stream can accept record text before reporting a write/flush error, this API does not claim atomic or durable evidence.

The event contract is allowlist-based; it does not depend on regex masking of arbitrary content. It configures no global Python logger and does not capture or redact unrelated Python or third-party logging calls. No existing CLI, gateway, or storage operation is automatically instrumented in CR0-E. Future integrations must emit only safe registered fields and keep MCP stdout protocol-only. Diagnostics are ephemeral and unsigned: there is no persistent trace database, audit receipt, hash chain, signing, or authorization function.

## CR0-F bundled configuration

`sentinel.config` exports `load_bundled_defaults()`, `validate_bundled_config(value)`, `canonical_config_bytes(value)`, `config_sha256(value)`, the immutable nested models, `CONFIG_SCHEMA_VERSION`, and `ConfigValidationError`. The schema version is `sentinel.config.v1`. The default profile is `local-only` with timezone `UTC`; `data.storage_path` is `null`; `sources.enabled` and `sources.host_allowlist` are empty; `models.egress.internal_cloud_consent` is `false`; all four supported write gates (`gmail_draft`, `gmail_send`, `github_comment`, `github_label`) are `false`; approved email recipients and allowlisted GitHub repositories are empty.

The API validates a complete Python dictionary, JSON text/bytes, or a `SentinelConfig` instance. Unknown keys, missing required fields, wrong Python types, invalid field values, nonempty source/recipient/repository lists, cloud consent, enabled write gates, and unsafe Pydantic copies fail with `ConfigValidationError`. Errors have a fixed message and do not echo rejected values. JSON documents with duplicate keys are rejected. Default loading creates no files and performs no network calls.

```python
from sentinel.config import (
    canonical_config_bytes,
    config_sha256,
    load_bundled_defaults,
)

config = load_bundled_defaults()
canonical = canonical_config_bytes(config)
fingerprint = config_sha256(config)
print(config.profile.name, config.profile.timezone)
print(canonical.decode("utf-8"), fingerprint)
```

Canonical bytes use UTF-8 JSON with sorted keys, compact `,` / `:` separators, no NaN values, and every field including `schema_version`. The fingerprint is lowercase SHA-256 over those exact bytes. The serializer accepts only the typed config model and revalidates it recursively; it does not serialize arbitrary Python objects. A matching fingerprint identifies bytes only: it does not prove owner authorization, trusted provenance, policy approval, or activation.

This CR0-F schema represents only `schema_version`, `profile.name/timezone`, `data.storage_path`, `sources.enabled/host_allowlist`, `models.egress.internal_cloud_consent`, and `security.external_writes`, `security.allowed_email_recipients`, and `security.github_allowlisted_repos`. The schema accepts only `UTC` for timezone in this slice; other IANA timezones require separately verified timezone data. It has no model provider/profile IDs, credentials, plugin registry, policy rules/unsafe overrides, approval grants, retention, prompt/briefing/scheduler/notification/UI settings, or evaluation manifest. Such keys are rejected, not ignored. There is no config file loader, user/profile/project/CLI merge, persistence, activation state machine, owner-admin provenance, quick-evaluation receipt, or config hash authorization check in gateways. The configuration is data, not authority; trusted policy ceilings and P00-P03 enforcement remain future work.

## CR0-G credential references and broker

`sentinel.credentials.SecretRef` is a frozen, strict metadata record matching the §10 `secret_refs` fields: `secret_ref_id`, `provider`, `keychain_locator`, `scope_manifest_sha256`, `os_owner_binding`, `created_at`, and optional `revoked_at`. Identifiers and opaque references are bounded, the scope hash must be lowercase SHA-256 hex, timestamps must be timezone-aware and normalize to UTC, and a revocation timestamp cannot precede creation. Unknown fields are rejected. A reference contains no token, password, passkey, or signing private-key bytes. Its locator and owner-binding fields are excluded from `repr`, and these values are not part of model, tool, boundary, or diagnostic event DTOs.

The production `CredentialBroker()` uses `UnavailableCredentialBackend`. Its `status(reference)` method reports `backend=UNAVAILABLE` and `reference=UNKNOWN`; the production broker has no value-retrieval, write, delete, environment fallback, or plaintext-file operation. Public `CredentialStatus` and `CredentialBrokerError` contain only bounded enums and fixed messages. A secret reference is a locator, not authorization or evidence that the caller may retrieve its value.

```python
from datetime import UTC, datetime

from sentinel.credentials import CredentialBroker, SecretRef

reference = SecretRef(
    secret_ref_id="secret.synthetic.calendar-read",
    provider="calendar",
    keychain_locator="sentinel:calendar/read",
    scope_manifest_sha256="a" * 64,
    os_owner_binding="windows-owner:local-profile",
    created_at=datetime.now(UTC),
)
status = CredentialBroker().status(reference)
assert status.backend.value == "UNAVAILABLE"
```

`CredentialBroker.for_tests()` explicitly constructs an `InMemoryTestBackend` for synthetic automated tests. That path has `put_for_test`, `status`, `resolve_for_test`, and `revoke_for_test`; repeated identical registration and revocation are idempotent, missing and revoked references have separate failure codes, and conflicting registration fails. `resolve_for_test` returns a redacted `SyntheticCredentialAccess` handle whose value is available only through the test-named `reveal_for_test()` method. This is a contract-test facility, not a secure store; Python memory is not zeroized or isolated from a compromised process. It must not be used by the application, gateways, CLI, or production adapters.

There is no verified OS keychain backend or isolated worker in CR0-G, and no keyring dependency was added. No OS credentials are read or written. The reference record is suitable as a future metadata contract only: a later §10 `secret_refs` table would hold reference metadata, never raw secrets. Signing private keys remain outside SQLite; a reference to one must remain unavailable to models and external tools. No trusted internal credential-operation principal, authenticated owner, OS-protected IPC, or owner verification is implemented here. P17 and credential isolation remain unimplemented, and this slice does not establish F23 or production C6 behavior.

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

These guarantees cover the migration foundation, not application-wide ownership by themselves. At CR0-C, WAL and migration-time `BEGIN IMMEDIATE` did not implement the §3 process-wide writer lease; CR1-D now adds the cooperative Windows writer lease described below. Backup/restore, checkpoint workflows, encryption, application tables, and application workflows remain unavailable. Do not store secrets or raw private source bodies in this database. The migration registry is trusted code and is not an interface for model output, CLI SQL, or external migration files.

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
.\.venv\Scripts\sentinel.exe init --help
.\.venv\Scripts\sentinel.exe doctor --help
.\.venv\Scripts\sentinel.exe version
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src/sentinel
.\.venv\Scripts\python.exe -m build --wheel
```

The initial development install is registry-resolved and not yet hash-locked. See ADR-0001 and the ledger for the actual selected versions and the remaining clean offline installation gate.

## Security limitations

This bootstrap is not a security certification and does not implement the blueprint's P00-P17 policy rules or AB01-AB18 bypass tests. It has no credentials or personal-data fixtures. All consequential external capabilities remain unavailable pending their release gates. Use synthetic fixtures only in future tests.

## CR0-H explicit database initialization

Create a new local database by supplying an absolute path whose parent directory already exists:

```powershell
.\.venv\Scripts\sentinel.exe init --database "$env:TEMP\sentinel-cr0-h-disposable.sqlite3"
```

Use a fresh, disposable path for this example. The command refuses every existing target, including a previously initialized Sentinel database; choose another new path if it reports that the target already exists. There is no default database location, no automatic parent-directory creation, and no command in this slice to open or upgrade an existing installation.

The CLI reserves the exact target with the operating system's exclusive-create operation, then calls the trusted storage migration API. The 0.2.0 release applies the registered foundation migration `cr0-c-0001-schema-migrations` followed by `cr1-e-0002-source-registry`, verifies each artifact and the complete expected schema checkpoint, and runs SQLite integrity and foreign-key checks. File-backed connection setup retains the existing `foreign_keys=ON`, WAL, and bounded busy timeout behavior. Success output is fixed and does not disclose the path. Invalid paths and initialization failures exit unsuccessfully with bounded messages that omit exception text and path values. The historical CR0 0.1.0 wheel and lock remain unchanged.

If initialization fails after exclusive creation, the newly reserved file and any SQLite-owned sidecars are left for inspection. The command does not attempt path-based cleanup because a concurrent path replacement could make deletion unsafe. Resolve the cause before manually removing that exact disposable path.

Exclusive creation uses `O_CREAT|O_EXCL`, which refuses an already present final-component path, and adds `O_NOFOLLOW` where the host exposes it. The symlink test could not run here because Windows denied symlink creation without elevated support. This does not establish full race-free filesystem protection: directory junctions/reparse points are not comprehensively defended against, and a process able to replace directory entries concurrently may race subsequent SQLite path opens. The implementation checks the reserved file identity before and after storage operations, but does not claim protection from a hostile process with directory write access.

CR0-H adds only the `init` command. CR0-I adds read-only `doctor`; CR0-J adds a synthetic in-memory `demo`. CR1-D adds a cooperative Windows writer lease, but the authenticated daemon/IPC ownership protocol remains unavailable. Configuration activation, durable source ingestion, content-blob storage, backup/restore, credential retrieval, providers, external tools, and external writes remain unavailable. Initialization is an explicit local filesystem effect, not owner authorization or a policy decision.

## CR0-I read-only diagnostics

Inspect an existing, disposable CR0-H database with an explicit absolute path:

```powershell
$database = Join-Path $env:TEMP ("sentinel-cr0-i-" + [guid]::NewGuid().ToString("N") + ".sqlite3")
.\.venv\Scripts\sentinel.exe init --database $database
.\.venv\Scripts\sentinel.exe doctor --database $database
```

`doctor` never selects a default database, creates a database, initializes it, migrates it, repairs it, or runs application SQL writes. It requires an existing absolute path. It opens the file with SQLite URI `mode=ro`, enables `PRAGMA query_only=ON`, enables and verifies connection-local foreign-key enforcement, and closes the connection deterministically. Invalid, missing, relative, or corrupted database paths produce bounded `FAIL` output without echoing the path or SQLite exception text and exit nonzero.

Supported checks report separate results for read-only opening, WAL mode, SQLite integrity, foreign-key enforcement and integrity, registered migration IDs/order/artifact digests, the trusted schema checkpoint, bundled config validation and deterministic fingerprinting, the default credential broker state, and actual synthetic ModelGateway/ToolGateway success and denial probes. The gateway probes use only fixed in-memory PUBLIC fixtures: they verify typed boundary metadata and hashes, reject an unknown model/tool and SECRET model input, and deny write and approval capabilities. They do not invoke a provider, network, MCP process, credential retrieval, or external effect.

`UNAVAILABLE` is expected for the production credential backend and OS keychain. `NOT_IMPLEMENTED` is reported for authenticated owner verification, policy enforcement, live model/provider routing, MCP smoke testing, backup verification, and signed audit roots. These states are never displayed as `PASS`. The command exits 0 when every currently supported required check passes; expected unavailable or not-implemented capabilities do not make this partial CR0 diagnostic fail. A passing report is not production readiness, authorization, or proof that P00-P17 or AB01-AB18 have passed.

Doctor validates the database's applied migration prefix and its matching trusted schema checkpoint; it never upgrades the database. A passing checkpoint on an older registered prefix establishes integrity at that version, not that all current migrations have been applied. Use `inspect_migration_state_readonly()` from `sentinel.storage.migrations` to read `applied_migration_ids`, `schema_version`, `pending_migration_ids`, and `is_current` separately.

The database connection itself is opened with SQLite `mode=ro`, and tests verify writes fail even after temporarily turning `query_only` off. Doctor does not issue application data writes or change journal mode. SQLite may still create or update its own WAL/SHM sidecars to read a WAL database. On the current Windows/SQLite 3.43.1 environment, inspecting a clean initialized database left the main database at the same 16,384-byte size and created `-wal` and `-shm` sidecars. This filesystem-side effect is SQLite-managed and is not an application-data write; the database directory must permit SQLite's WAL coordination. A mode=ro connection may fail if the needed WAL state cannot be read safely. Doctor does not use `immutable=1` to skip locking or uncheckpointed WAL data. This slice does not guarantee zero filesystem changes, defend against all directory junction/reparse-point races, or perform backups/checkpointing.

## CR0-J deterministic synthetic demo

Run the packaged synthetic flow without a database, provider configuration, credentials, network access, or external tool:

```powershell
.\.venv\Scripts\sentinel.exe demo
```

The trusted package contains one UTF-8 fixture, `sentinel.demo-fixture.v1`, representing a fictional public note and a fixed read-only lookup. Its exact bytes are checked against SHA-256 `365c9f02f1375c3e784138b7cdb3c2fd3ed1a0f4cf64cfec6fdef2fe5d9ecbb8` before strict schema validation. The versioned schema rejects unknown keys, malformed data, duplicate JSON keys, invalid UTF-8, inconsistent expected output, and unsupported versions. Fixture data contains no handler, plugin, destination, URL, path, or capability instruction. Application code registers the only model and read-only tool adapters; fixture data cannot install or select executable code.

`sentinel demo` uses `importlib.resources` to load the wheel resource, validates and fingerprints bundled `sentinel.config.v1` defaults, creates a PUBLIC `SourceEnvelope`, and calls the actual `ModelGateway.generate()` and `ToolGateway.call()` APIs. The adapters transform or look up fixture data in memory only. It also probes an unknown model, SECRET and PRIVATE model inputs, an unknown tool, and write/approval capabilities; the demo fails if any probe is not denied or if a denied handler runs. Gateway boundary digests are checked against the exact invocation and response bytes.

Stdout is exactly one sorted, compact JSON document with schema `sentinel.demo.v1`. It includes fixture/config hashes, `execution_mode`, `profile`, model/tool success statuses and boundary hashes, denial statuses, and fixed `credentials_used`, `external_effects`, and `production_readiness` booleans. It does not include source bodies, generated model/tool text, paths, timestamps, or random boundary IDs. Re-running the same installed package produces byte-identical output. A failure exits nonzero, emits no partial JSON, and prints only a fixed bounded message to stderr.

Example output from this fixture version (hashes are stable for the packaged inputs):

```json
{"config_sha256":"9ba0e71e6026ecc93149cfe2052d75082528732a82c2556ce10de893e97c4256","credentials_used":false,"execution_mode":"DEMO","external_effects":false,"fixture_sha256":"365c9f02f1375c3e784138b7cdb3c2fd3ed1a0f4cf64cfec6fdef2fe5d9ecbb8","fixture_version":"sentinel.demo-fixture.v1","model":{"request_sha256":"e2fc9fc18fa242c3352399a7f896d22ad08edcfcf98756ba87c7f6549ed82c2e","response_sha256":"42fa19a1ee558e9cc6c6d983db3ab0f4366fc255f0a0d621435ce0ad1b7f1667","status":"SUCCESS"},"negative_probes":{"approval_tool":"DENIED","external_write_tool":"DENIED","private_model":"DENIED","secret_model":"DENIED","unknown_model":"DENIED","unknown_tool":"DENIED"},"production_readiness":false,"profile":"local-only","schema_version":"sentinel.demo.v1","tool":{"request_sha256":"c79832341a39653868ef4d9356091fd76cb3d04417e3b35cde9d54d20293ed00","response_sha256":"06ba4f94d418f201177452ffb6ae0e861a013f2dbc0548c56fa8316054f344f3","status":"SUCCESS"}}
```

To build and confirm the fixture is in the wheel:

```powershell
.\.venv\Scripts\python.exe -m build --wheel
.\.venv\Scripts\python.exe -c "import glob, zipfile; wheel = zipfile.ZipFile(glob.glob('dist/*.whl')[0]); assert 'sentinel/demo/fixtures/demo-v1.json' in wheel.namelist(); print('fixture included')"
```

A successful demo proves that this fixed packaged fixture validates and that the current synthetic gateway success/denial contracts and content hashes behave as expected. It does not demonstrate LLM inference, production model/tool adapters, network or credential isolation for future code, policy authorization, human approval, production readiness, or P00-P17/AB01-AB18 compliance. The demo's source labels and gateway contract checks are not security certification. At CR0-J, the clean offline install remained the final §16 exit gate; CR0-K records that installation evidence below.

## CR0-K pinned Windows offline installation

`requirements/cr0-windows-py311.lock` pins the complete Sentinel 0.1.0 runtime dependency closure for **CPython 3.11.7 on Windows x64**. Every installed distribution, including the Sentinel wheel, has an exact version and SHA-256 listed in the lock. The lock is an installation manifest, not a general source-build lock: setuptools' build dependency is not pinned in this file. The staging recipe fixes `SOURCE_DATE_EPOCH=1793687886` for wheel timestamps. Two builds using `build==1.6.1` and isolated `setuptools==84.2.1` produced identical wheel bytes in this environment; this does not establish cross-toolchain or cross-platform build reproducibility. The development extra remains separately resolved for local linting and tests.

The selected runtime versions were resolved against the live package registry with binary-only downloads on the target interpreter. The lock contains Sentinel 0.1.0, Pydantic 2.14.2, Typer 0.27.3, and all 11 transitive runtime distributions. The Blueprint §15 lists nearby candidates Pydantic 2.14.0 and Typer 0.27.1; this lock uses later registry releases that satisfy the existing project constraints and whose full Windows wheel closure installed and passed `pip check`. `pydantic-core` is pinned to its CPython 3.11 Windows AMD64 wheel. The exact inventory and hashes are in the lock and build ledger.

Stage the artifacts outside the repository. Run the commands from the repository root in Windows PowerShell:

```powershell
$stage = Join-Path $env:TEMP ("sentinel-cr0k-stage-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $stage | Out-Null
$wheelhouse = Join-Path $stage "wheelhouse"
New-Item -ItemType Directory -Path $wheelhouse | Out-Null
$env:SOURCE_DATE_EPOCH = "1793687886"
.\.venv\Scripts\python.exe -m build --wheel
Copy-Item .\dist\sentinel-0.1.0-py3-none-any.whl $wheelhouse
Get-Content .\requirements\cr0-windows-py311.lock | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#")) {
        $spec = ($line -split "\s+")[0]
        if (-not $spec.StartsWith("sentinel==")) {
            .\.venv\Scripts\python.exe -m pip download --no-cache-dir --only-binary=:all: --no-deps --dest $wheelhouse $spec
            if ($LASTEXITCODE -ne 0) { throw "Wheel download failed for $spec" }
        }
    }
}
```

The command shown above uses the project-local environment only for build and download tooling. Keep the resulting wheelhouse disposable and untracked. The offline verifier checks that its wheels exactly match the lock before pip runs. To install and execute the installed wheel from a fresh environment, pass the pyenv-managed base interpreter and new external install root:

```powershell
$basePython = (pyenv which python).Trim()
$installRoot = Join-Path $env:TEMP ("sentinel-cr0k-install-" + [guid]::NewGuid().ToString("N"))
.\.venv\Scripts\python.exe .\tools\verify_cr0_offline.py `
    --python-exe $basePython `
    --wheelhouse $wheelhouse `
    --requirements .\requirements\cr0-windows-py311.lock `
    --install-root $installRoot
if ($LASTEXITCODE -ne 0) { throw "CR0-K offline verification failed" }
```

The installer creates a new venv with system site packages disabled, bootstraps pip only with that Python installation's bundled `ensurepip`, removes inherited Python/pip configuration and credential-like environment variables for its child processes, and runs pip with:

```powershell
python -m pip install --no-index --find-links <wheelhouse> --require-hashes --no-cache-dir --only-binary=:all: -r requirements/cr0-windows-py311.lock
```

The verifier runs from a working directory outside the checkout. It checks package imports resolve only from the new venv, rejects editable/source-path links, runs `pip check`, verifies the wheel's CLI entry point and packaged modules, and executes `version`, `--help`, `demo`, `init`, and `doctor`. The demo must produce one deterministic JSON document twice; the disposable database is checked for the unchanged foundation migration/hash and exact foundation schema. Missing and malformed database diagnostics must fail without creating/replacing data. It also validates fixture/config fingerprints, the six documented denials, expected credential/keychain `UNAVAILABLE` states, and future-component `NOT_IMPLEMENTED` states.

For a manual hash-checked pip install into an already-created fresh venv, the offline command is:

```powershell
& "$installRoot\venv\Scripts\python.exe" -m pip install `
    --no-index --find-links $wheelhouse --require-hashes --no-cache-dir `
    --only-binary=:all: -r .\requirements\cr0-windows-py311.lock
```

Pip's hash-checking mode requires every requirement and transitive dependency to be pinned and hashed, and `--only-binary=:all:` excludes source distributions. `--no-index` limits pip to the local wheelhouse. The verifier additionally compares each wheel's metadata version and SHA-256 with the lock before installation. Missing or changed wheels fail; the verifier does not retry against an index. This does not disable networking at the operating-system level or sandbox package code. The fixed wheel artifacts are integrity-pinned relative to the committed lock, not independently authenticated by that lock alone.

The wheelhouse is not committed. It is staged under a disposable directory outside the checkout so its binary artifacts and temporary venv do not enter Git. Preserve the printed wheel inventory and command output with the release evidence. The verified platform is only Windows x64 with CPython 3.11.7; no other Python patch, architecture, or OS is established by this gate. Local `ensurepip` supplies the installer pip; the requirements lock covers Sentinel's runtime, not pip itself or build/dev tooling. The build backend is isolated and resolved by `build` under `setuptools>=68`; the observed build used `setuptools==84.2.1`. That build-tool range is not hash-locked.

This offline gate completes only the CR0 installation evidence. A clean pinned install does not prove cross-toolchain or cross-platform source-build reproducibility, network sandboxing, policy enforcement, credential isolation for future code, or production readiness. The existing Windows symlink test remains skipped/unverified. The technical lead subsequently accepted CR0 for the recorded Windows x64 / CPython 3.11.7 scope; the ledger records that bounded acceptance. Later-release capabilities remain out of scope.

## CR1-A strict plain-text normalization and citations

`sentinel.normalization` exports `PlainTextSourceDescriptor`, `NormalizedPlainTextSource`, `normalize_plain_text`, `add_citation`, `verify_citation`, and `NormalizationError`. The descriptor is a frozen, strict Pydantic model containing the trusted caller's `source_id`, `provider_id`, aware `observed_at`, `TrustLabel`, and `SensitivityLabel`. The resulting immutable value contains the existing `SourceEnvelope`, the exact decoded `text` for explicit internal use, original bytes, the original-byte `payload_sha256`, normalized MIME information, and the envelope's tuple of `ByteSpan` citations. It deliberately has no JSON/model dump helper that emits source content, and its default representation omits the body.

The accepted MIME forms are `text/plain` and `text/plain; charset=utf-8`. MIME tokens and charset are matched case-insensitively; surrounding ASCII spaces/tabs are accepted. No other MIME parameters or repeated charset parameters are accepted. A missing charset is interpreted as UTF-8. Input is at most **1 MiB (1,048,576 bytes)** and must be a real `bytes` object that strictly decodes as UTF-8. There is no content sniffing or fallback decoder. The normalizer preserves the original bytes and exact decoded code points, including a UTF-8 BOM, NUL/control characters, CRLF versus LF, and NFC versus NFD distinctions. It does not alter whitespace, line endings, case, or Unicode normalization.

```python
from datetime import UTC, datetime
from uuid import UUID

from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.normalization import (
    PlainTextSourceDescriptor,
    add_citation,
    normalize_plain_text,
    verify_citation,
)

content = b"synthetic fact\n"
source = normalize_plain_text(
    PlainTextSourceDescriptor(
        source_id=UUID("f3d9e8b2-6f52-45a1-850d-76b9df02dc7c"),
        provider_id="synthetic-reader",
        observed_at=datetime(2026, 11, 3, tzinfo=UTC),
        trust=TrustLabel.T4_EXTERNAL,
        sensitivity=SensitivityLabel.PUBLIC,
    ),
    content,
    "text/plain; charset=utf-8",
)
cited = add_citation(
    source,
    span_id=UUID("9f371f63-8180-4ef3-85ef-56a8c018a652"),
    start_byte=10,
    end_byte=14,
    expected_text="fact",
)
assert verify_citation(cited, cited.citations[0], expected_text="fact") == "fact"
assert cited.envelope.content_sha256 == cited.payload_sha256
```

Citation offsets are half-open UTF-8 byte coordinates `[start_byte, end_byte)`, never Python character indexes. `add_citation` requires explicit offsets and a UUID; it returns a new normalized value with the validated `ByteSpan` in `SourceEnvelope.byte_spans`. It does not search text for a phrase. `verify_citation` revalidates the source envelope, re-hashes the complete original bytes, confirms that the span belongs to that envelope, checks both UTF-8 boundaries, re-hashes the exact selected bytes, and optionally compares exact cited text. Errors use fixed `NormalizationErrorCode` categories and never include raw source text or filesystem paths.

For a reference that must retain its source association, use the immutable `SourceBoundCitation` and `bind_citation(source, citation)` / `verify_bound_citation(source, bound_citation, *, original_bytes=None, expected_text=None)` APIs. A bound value contains only the source UUID, the full content SHA-256, and the existing `ByteSpan`; it never contains source text. Binding revalidates the normalized value and span, checks span membership and source/slice hashes. Verification rechecks those facts against the supplied source and bytes, including UTF-8 boundaries, and returns only the exact cited text. Cross-source and persisted citation consumers should use this source-bound representation.

The older `verify_citation(source, citation)` remains available for CR1-A compatibility. It proves that the unbound span is a member of the supplied normalized source and that the supplied source bytes and slice match their digests. A standalone `ByteSpan` has no source UUID or full-source digest, however, so it cannot preserve the identity of the source from which it was originally obtained. Two sources with identical bytes and an identical reused span can therefore have interchangeable unbound spans. `SourceBoundCitation` closes that internal association gap; it does not authenticate a provider, prove that a caller's source ID or trust label is truthful, or establish that content remains unchanged at an external origin.

Caller-supplied trust and sensitivity labels are retained exactly. These labels describe asserted provenance and classification; they do not authenticate the descriptor's caller or grant authority. Literal instructions inside a source remain untrusted content. PRIVATE and SECRET data may be normalized in memory, but this slice does not send content to `ModelGateway`, persist it, or authorize its use. Authentication of reader metadata and future source ingestion belong to later CR1 boundaries.

Only plain UTF-8 text is supported. HTML, Markdown transformation, multipart MIME, attachments, OCR/PDF extraction, providers/readers, deduplication, persistence, and citations generated by models are not implemented. The operation is in-memory and introduces no network, process, model, tool, or database access. The CR0 release lock, CR0 wheel hash, and `cr0-v0.1.0` tag remain historical artifacts and are not changed for CR1 development.

## CR1-B synthetic GitHub-style issue fixture reader

`sentinel.readers.read_packaged_github_fixture()` loads the one fixed package resource `sentinel/readers/fixtures/github-issues-v1.json`. Its schema is `sentinel.github-issues-fixture.v1`; the complete 1,829-byte UTF-8 JSON file is pinned to SHA-256 `7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1`. It is stored as a compact, newline-free JSON document so Git's Windows line-ending conversion cannot alter the digest. The schema rejects duplicate JSON keys, non-standard JSON constants, unknown fields, unsupported versions, invalid IDs/timestamps/ranges, duplicate issue/span identities, coercions and oversize content. Bounds are 64 KiB per fixture, 16 issues, 1 KiB per title, 32 KiB per body, 32 evidence spans per issue and 4 KiB per expected citation text.

The packaged records are fictional and use `example-owner/fixture-project`. Reader code assigns `provider_id="github.fixture"`, `trust=T4_EXTERNAL`, and `sensitivity=PUBLIC`; those labels are fixed in trusted reader code and cannot be set by fixture fields. PUBLIC is suitable only for this synthetic fixture and must not be inferred for real GitHub content. Issue text that looks like an instruction remains ordinary external content. No GitHub API, account, token, network, provider, database, model, tool, or subprocess is used. This fixture adapter does not implement or verify F03's production GitHub API reader.

Issue identity uses UUIDv5 with the standard URL namespace and the name `sentinel:github.fixture:<canonical-repository>#<issue-number>`. The stable ID therefore survives body revisions; the `SourceEnvelope.content_sha256` changes with the exact body bytes. `updated_at` is fictional provider-like metadata and is not evidence of when Sentinel observed or authenticated the issue. The source envelope uses a fixed trusted observation time, `2026-11-03T12:00:00Z`.

The raw fixture hash covers the complete JSON file. Each issue's body is decoded from JSON, then encoded as UTF-8 without Unicode, whitespace, or newline normalization. Its source digest covers exactly `issue.body.encode("utf-8")`. Evidence offsets are half-open byte offsets into those body bytes, not positions within JSON's escaped wire representation. The reader passes each explicit range and `expected_text` through the existing `normalize_plain_text`, `add_citation`, `bind_citation`, and `verify_bound_citation` APIs. It returns immutable records with provider metadata separate from the normalized source; body access is explicit through `issue.body_text` or `issue.normalized_source.text`. The records do not provide a convenience dump that serializes the bodies.

```python
from sentinel.normalization import verify_bound_citation
from sentinel.readers import read_packaged_github_fixture

fixture = read_packaged_github_fixture()
issue = fixture.issues[0]
citation = issue.citations[0]
assert verify_bound_citation(issue.normalized_source, citation) == "parser reports"
```

The reader returns a complete collection or raises a fixed, body-free `GithubFixtureError`; it never drops invalid issues and returns partial success. The resource is available through `importlib.resources` from an installed package. Setuptools package data includes the JSON file in the built wheel; `python -m build --wheel` followed by inspection of the wheel archive verifies the actual packaged bytes and pinned digest.

This is a local fixture/format adapter only. It does not authenticate GitHub, source IDs, timestamps, or labels; inspect Markdown/HTML; synchronize live repositories; persist source items; or make CR1 complete. CR0's `0.1.0` tag and runtime lock are unchanged.

## CR1-C synthetic Gmail message fixture reader

`sentinel.readers.read_packaged_gmail_fixture()` loads only the fixed packaged resource `sentinel/readers/fixtures/gmail-messages-v1.json`. The wrapper schema is `sentinel.gmail-messages-fixture.v1`; the fictional package file is pinned to SHA-256 `781112d5b62439e833f33040f0e4f67c4adafa86d2f94e1b137fa09d52fa8b57`. The returned immutable `GmailFixtureRead` contains fictional mailbox metadata and `GmailFixtureMessage` records. A message exposes `message_id`, `thread_id`, parsed `internal_date`, its `SourceEnvelope` through `normalized_source`, verified `citations`, and explicit internal `subject`, `body_text`, and `body_bytes` access. Subject and normalized source fields are omitted from the default message representation; no generic body dump is provided. Errors use fixed `GmailFixtureErrorCode` categories and do not include mail content.

This models a deliberately small Gmail `users.messages.get(format=full)` subset: `id`, `threadId`, `internalDate`, and `payload` with `mimeType`, `filename`, `headers`, and `body.size`/`body.data`. The fixture wrapper keeps `fixture_version`, `mailbox_alias`, and the test-only `evidence_spans` annotations outside each Gmail-style `message` object. The selected fields follow the official [Gmail Message resource](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages), [MessagePartBody resource](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages.attachments), and [Gmail Format enum](https://developers.google.com/workspace/gmail/api/reference/rest/v1/Format); this reader does not implement their complete schemas or API methods.

The fixture accepts only a plain `text/plain` payload, an empty filename, and one in-memory body. Multipart `parts`, HTML, non-empty filenames, `attachmentId`, `raw` RFC 822 data, unsupported headers, and unknown fields are rejected. A `Content-Type` header is optional; when present, this subset requires `text/plain; charset=utf-8`. Body `data` must use the fixture's canonical unpadded base64url form: URL-safe alphabet only, no whitespace or padding, and re-encoding must reproduce the same characters. This is a strict fixture convention, not a claim that every valid Gmail response uses this exact canonical spelling. `body.size` is checked against the decoded byte count.

Three byte representations are kept distinct: SHA-256 of the full JSON fixture file; ASCII base64url characters in `body.data`; and the decoded message body bytes. The `SourceEnvelope.content_sha256` hashes only those decoded bytes, and citation offsets address those bytes. The body is strictly decoded as UTF-8 and passed unchanged to `normalize_plain_text(..., "text/plain; charset=utf-8")`; CRLF/LF, whitespace, and Unicode code points are preserved. Fixture citations give explicit half-open byte ranges and expected text, then use the existing `add_citation`, `bind_citation`, and `verify_bound_citation` functions.

Source IDs use UUIDv5 with `NAMESPACE_URL` and the name `sentinel:gmail.fixture:<mailbox-alias>#<message-id>`. The message ID, not `threadId`, identifies the source; the stable identity is unchanged by a body revision, while its content digest changes. Reader code assigns `provider_id="gmail.fixture"`, `trust=T4_EXTERNAL`, and `sensitivity=PRIVATE`. The fixed observation timestamp is `2026-11-03T12:00:00Z`; `internalDate` is parsed as bounded epoch milliseconds and remains untrusted provider-like metadata. Neither the timestamp, source ID, headers, nor email body authenticate a sender or convey owner intent. PRIVATE is intentionally conservative for mail-like data even though this fixture is entirely fictional.

```python
from sentinel.normalization import verify_bound_citation
from sentinel.readers import read_packaged_gmail_fixture

fixture = read_packaged_gmail_fixture()
message = fixture.messages[0]
citation = message.citations[0]
assert verify_bound_citation(message.normalized_source, citation) == "parser flagged"
```

The reader makes no Gmail API, OAuth, keychain, SMTP, IMAP, network, subprocess, database, gateway, or provider calls. It does not read a real mailbox, implement attachments or general MIME support, or enable message modifications. F01's production OAuth reader, source authentication, credentials, cursor/sync state, and persistence remain unimplemented. CR1 remains in progress.

## CR1-D cooperative SQLite writer lease

`sentinel.storage.acquire_writer_lease(database)` provides a Windows-only cooperative writer-ownership context for one already initialized Sentinel database. It requires an explicit absolute path to an existing regular database file on a fixed, removable, or RAM disk. UNC paths, mapped remote drives, and unknown/no-root drive types are rejected before resolving or opening the database. The registered migration history, artifact hashes, schema checkpoint, SQLite integrity, foreign-key integrity, foreign-key setting, and existing WAL mode are checked before a lease is returned. The API never creates a database, applies a migration, or changes journal mode.

```python
from pathlib import Path

from sentinel.storage import acquire_writer_lease

database = Path(r"C:\SentinelData\sentinel.sqlite3")
with acquire_writer_lease(database) as lease:
    with lease.transaction() as connection:
        row = connection.execute(
            "SELECT migration_id FROM schema_migrations ORDER BY migration_id"
        ).fetchone()
```

The current CR1 development schema contains source-registry metadata tables, so the example reads a verified migration record. No source ingestion or persistence API is implemented. Later application writers should keep their SQL static and application-controlled, and execute DML only inside `lease.transaction()`. Each transaction uses SQLite `BEGIN IMMEDIATE`, explicit commit, and rollback on failure. A connection authorizer denies transaction control outside the context, writes outside the context, schema DDL, and database attachment. Nested acquisition and nested transactions are rejected. Connections and the mutex are closed on normal and exceptional exits. The lease is bound to the thread that acquired it.

On Windows, ownership uses a named mutex in the `Global\` namespace, named from a SHA-256 of the selected database's available volume/file ID (with a canonical-path fallback). A zero-millisecond mutex wait fails fast with `lock_contended`; SQLite's transaction busy timeout is 500 ms. The kernel releases mutex ownership when its owning process/thread terminates, and SQLite rolls back an uncommitted transaction when the connection closes. The named mutex is not a persistent lockfile and is not removed as a filesystem entry. Windows documents named mutex creation, global/session namespaces, and abandoned ownership in the [CreateMutexW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw), [kernel object namespace](https://learn.microsoft.com/en-us/windows/win32/termserv/kernel-object-names), and [mutex object](https://learn.microsoft.com/en-us/windows/win32/sync/mutex-objects) references.

`WriterLeaseError` exposes a fixed category in `WriterLeaseError.code`: `unsupported_platform`, `invalid_path`, `database_missing`, `database_unavailable`, `database_invalid`, `migration_invalid`, `lock_unavailable`, `lock_contended`, `reentrant`, `lease_inactive`, `thread_mismatch`, `transaction_active`, `transaction_busy`, `transaction_failed`, or `lease_release_failed`. Public exception messages omit paths and SQLite details.

This is cooperative arbitration for application code that follows the API. It does not authenticate the Windows user, prevent a noncooperating process from writing SQLite directly, protect a directory against a same-user process that can replace its files, or isolate keychain credentials. Default Windows mutex ACLs may limit which user identities can share the named object. File identity and reparse-point checks reduce ordinary path aliasing, but Windows directory replacement/reparse races and filesystems without a usable file ID are not comprehensively defended. The lock and SQLite integrity checks are not a security boundary against malicious same-user code. The daemon/PID ownership protocol and authenticated local IPC described by the wider architecture are not implemented here. This slice adds no persistence tables, source ingestion, credentials, network access, or external effect; CR1 remains in progress.

CR1-D alone adds no schema. CR1-E adds the source-registry metadata schema below; it does not add ingestion APIs, credentials, network access, or external effects. CR1 remains in progress.

## CR1-E registered source metadata schema

Migration `cr1-e-0002-source-registry` adds five metadata tables to the current development schema. The canonical migration artifact SHA-256 is `7ef613bdb646d9b98bc18bb20dd7bba3467d4de12b2cb5c4802e4d1dd8d1c0c7`; the complete post-migration schema checkpoint SHA-256 is `38eb2f69500aa21df1002691c40759ba5acbc58b09c97de4a8ab7bfdd9c40d6a`. The unchanged CR0 foundation artifact remains `b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217`, and its historical schema checkpoint remains `1f4d935bf45b5c09f68b4f6e3deb18846aa6d9ee14510eed89b3ab4a71139d30`.

The tables are `principals`, `plugin_manifests`, `sources`, `sync_cursors`, and `source_items`. Their dependency graph is `plugin_manifests` and `principals` → `sources` → `sync_cursors` and `source_items`. The migration also creates the §10 secondary indexes: principals `(kind, revoked_at)`, plugin manifests `(enabled, trust)`, sources `(enabled, source_type)`, sync cursors `(status)`, and source items `(source_id, observed_at)` and `(content_sha256)`. Table-level primary, unique, foreign-key, and check constraints are included in the exact DDL checkpoint.

The blueprint gives `plugin_manifests` a composite primary key `(plugin_id, plugin_version)`, but its `sources` relationship names only `plugin_id`. SQLite cannot use that single child column as a foreign key to a composite parent key. The implemented schema adds required `sources.plugin_version` and references the exact pair. Multiple manifest versions remain valid; `sources` also retains the blueprint's `UNIQUE(plugin_id, account_alias)`, so one plugin ID cannot register the same account alias twice across its versions. See [ADR-0002](docs/adr/0002-plugin-version-bound-source-fk.md) for the explicit deviation and compatibility consequences.

At the CR1-E historical checkpoint, `source_spans` was deferred because its `derived_by_boundary_id` relation depends on `boundary_envelopes`, which depends on `runs` and related tables. CR1-F now adds that parent graph and `source_spans` as schema only. No fake parent table is created. The existing in-memory `SourceBoundCitation` remains available; the new table does not add a persistence API or validate stored offsets against source bytes.

`content_ref` and `value_cipher_ref` are opaque references only. This migration does not provide an encrypted blob store, cursor advancement, source ingestion, sync APIs, or task workflows; the references do not prove encryption, availability, or authorization. No plaintext source bodies, OAuth tokens, or passwords are inserted by initialization.

At the CR1-E checkpoint, explicit initialization applied the foundation and source-registry migrations. Current fresh initialization applies all registered migrations through CR1-F. A CR0-only database upgrades through CR1-E and CR1-F in order, and a valid CR1-E database remains a historical prefix with CR1-F pending. `initialize_storage(existing_path)` validates the applied history and schema prefix, then applies pending registered migrations in order; it is a maintenance operation, not used by `doctor` or the writer lease. The read-only `inspect_migration_state_readonly(connection)` reports schema integrity/version separately from pending migrations without changing the database. Each migration uses an atomic SQLite `BEGIN IMMEDIATE`; an active SQLite writer transaction makes the migration fail within the bounded busy timeout and leaves no partial DDL/history record.

Migrations do not acquire the CR1-D application writer mutex: the writer lease's authorizer correctly denies DDL. Therefore callers must stop and coordinate all application writer sessions before running maintenance migrations. There is no maintenance lease or daemon arbitration yet, and an idle active lease is not detected by `BEGIN IMMEDIATE`. A file-identity mutex also does not make hard-link aliases' distinct WAL/SHM sidecars coherent. Concurrent maintenance across aliases or during an application writer session is not claimed safe.

## CR1-F configuration/run/boundary/source-span schema

Migration `cr1-f-0003-source-spans` adds `config_revisions`, `run_manifests`, `runs`, `boundary_envelopes`, and `source_spans` to the registered schema. Its canonical artifact SHA-256 is `6e6b98e60cff17f0eac94b942533964588344fdd0d8342567962ac4a1c3304b7`; the independently pinned complete post-CR1-F schema checkpoint SHA-256 is `26f31fe4601c67cb60c6faa324eba83ff59c611b1fa283e514f0a77e3acf44ad`. This checkpoint contains 11 tables and 13 indexes, including the unchanged foundation and CR1-E objects.

The new FK graph is:

- `config_revisions.parent_config_id` → `config_revisions.config_id` (nullable self-reference).
- `run_manifests.config_id` → `config_revisions.config_id`.
- `runs.principal_id` → `principals.principal_id`; `runs.manifest_id` → `run_manifests.manifest_id`.
- `boundary_envelopes.run_id` → `runs.run_id`.
- `source_spans.item_id` → `source_items.item_id`; nullable `source_spans.derived_by_boundary_id` → `boundary_envelopes.boundary_id`.

The migration also registers the §10 indexes for activation/creation time, manifest creation time, run thread/status timelines, boundary kind/adapter, and source item/start-byte lookup. It enforces required SHA-256 formats, `replay_injected IN (0,1)`, integer half-open span bounds `0 <= start_byte < end_byte`, primary/unique keys, and declared foreign keys. Exact trusted DDL comparison rejects missing, altered, or extra schema objects.

`SourceBoundCitation.source_id` is an in-memory normalization identity; persisted `source_spans.item_id` refers to one exact `source_items` revision. They are not interchangeable. Future persistence code must map them explicitly and verify the source content digest. The database can store byte offsets and a span digest, but it cannot prove those offsets against bytes that are not stored or available. `content_ref`, `effective_config_ref`, request/response refs, and context refs are opaque locators, not proof of encryption, availability, activation, authorization, or source provenance.

The Blueprint's `runs.briefing_id` is retained as a nullable field. The related `briefings` table is outside CR1-F, so this migration does not invent a placeholder table or a dangling FK. §10 also names `run_source_items` and `run_memory_uses` join tables; they remain outside this explicitly bounded five-table migration (`run_memory_uses` additionally depends on the not-yet-registered memory schema). Their omission is documented for a later schema slice, not treated as implemented. See [ADR-0003](docs/adr/0003-cr1-f-schema-scope.md). This is not a full §10 application schema.

Fresh storage initialization applies all three registered migrations. Existing CR0 and CR1-E databases can be explicitly upgraded without rewriting their prior migration records; doctor and `acquire_writer_lease()` remain read-only with respect to schema and report/accept valid historical prefixes without migration. The new schema creates no rows containing source bodies, credentials, configs, run execution, or boundary payloads. No source ingestion, durable citation API, content-addressed blob store, config activation, run execution, provider invocation, or audit behavior is implemented.

Migration maintenance remains separate from CR1-D's writer lease. Tests show an active SQLite write transaction blocks the bounded `BEGIN IMMEDIATE` migration and leaves no partial DDL. They also demonstrate the unresolved hazard: an idle lease holds no SQLite write transaction, so `initialize_storage()` can migrate while that lease is open because it does not acquire the Windows writer mutex. A production daemon must quiesce writers before maintenance. Hard-link aliases may produce distinct SQLite WAL/SHM sidecars and mutex identities; arbitrary concurrent upgrades or alias coherence are not claimed safe. CR1 remains in progress.

## CR1-G synthetic GitHub fixture persistence

`sentinel.ingestion` exports `ingest_packaged_github_fixture(database)`, `read_persisted_github_fixture(database)`, and `verify_persisted_github_citation(database, *, item_id, span_id)`. Ingestion accepts only an explicit absolute path to an existing Sentinel database at the current registered CR1-F schema checkpoint. It never initializes or migrates a database. It reads only the fixed `sentinel.github-issues-fixture.v1` package resource (SHA-256 `7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1`), with the existing reader enforcing its pin.

```python
from pathlib import Path

from sentinel.ingestion import (
    ingest_packaged_github_fixture,
    read_persisted_github_fixture,
    verify_persisted_github_citation,
)

database = Path(r"C:\Temp\sentinel-cr1-g.sqlite3")  # must already be initialized
report = ingest_packaged_github_fixture(database)
assert (report.inserted_items, report.inserted_spans) == (3, 9)

persisted = read_persisted_github_fixture(database)  # mode=ro; no application writes
item = persisted.items[0]
span = item.spans[0]
cited_text = verify_persisted_github_citation(
    database, item_id=item.item_id, span_id=span.span_id
)
```

The rows use separate deterministic identities. The registry `source_id` is UUIDv5 over `NAMESPACE_URL` and `sentinel:github.fixture:source:example-owner/fixture-project`. The provider item ID is `example-owner/fixture-project#<issue-number>`. `SourceEnvelope.source_id` remains the in-memory issue identity assigned by the fixture reader. Persisted `source_items.item_id` is UUIDv5 over `NAMESPACE_URL` and `sentinel:github.fixture:item:<registry-source-uuid>:<provider-item-id>:<body-sha256>`, so a changed body digest maps to a different revision ID rather than replacing the earlier row. The original in-memory `ByteSpan.span_id` remains distinct from persisted `source_spans.span_id`, which is UUIDv5 over `NAMESPACE_URL` and `sentinel:github.fixture:span:<persisted-item-uuid>:<in-memory-span-uuid>`. The reader verifies each source-bound citation and persists its exact half-open byte offsets, slice digest, and item relationship; `derived_by_boundary_id` and `context_ref` are NULL because this fixture was not produced by a recorded model/tool boundary.

Only the synthetic PUBLIC GitHub fixture is accepted. Trusted application code assigns the fixed source/plugin/principal metadata and retains `T4_EXTERNAL` and `PUBLIC`; the fixture cannot select identities, labels, content references, paths, hosts, capabilities, or SQL. The plugin manifest is registered disabled (`enabled=0`) and is not a production plugin approval; the fixed source registration is enabled (`enabled=1`) only for this fixture reader path. `source_at` and canonical `metadata_json` retain provider-like update time and fixture/source identifiers without issue body or title. The `content_ref` is a strict allowlisted fixture-and-issue identifier. It is never opened as a file, fetched as a URL, or treated as a credential/encryption reference.

The batch registers one synthetic principal, plugin manifest and source, then inserts or matches the 3 item revisions and 9 spans in one `acquire_writer_lease()` scope and one SQLite `BEGIN IMMEDIATE` transaction. Before `COMMIT`, while that same write transaction is still active, ingestion reruns exact comparisons for the fixed registration, complete expected item set, and complete span set for every expected fixture item. An unexpected extra item under this fixture's registry source, an extra span on an expected fixture item, a missing row, or an altered row fails with a bounded conflict and rolls back the entire current batch. The check is scoped to this fixed fixture source; unrelated registered sources and their items are not treated as fixture records. First import reports 3 new items and 9 new spans; identical replays report 3 existing items and 9 existing spans and do not change rows. The immutable report omits body text and titles.

`read_persisted_github_fixture()` opens the selected DB read-only, validates the complete current migration/checkpoint and SQLite/FK integrity, reads the pinned packaged fixture again, and compares every expected registry, item, content digest, and citation row with the database. It reconstructs body bytes from that package fixture only; SQLite does not independently preserve those bytes. The explicit citation verifier returns a cited text slice only after the complete database/fixture/source-bound digest and offset checks succeed. Missing or altered fixture content, registration, items, or spans fails with a fixed, path-free category. SQLite integrity alone is not application-row provenance verification. This completeness rule is specific to the pinned three-issue collection: it is not a general revision-aware synchronization policy and does not authorize deleting or reconciling arbitrary future source revisions.

CR1-G does not add a general blob store, private Gmail persistence, ingestion for arbitrary sources, content encryption, live GitHub access, cursor advancement, deletion/tombstone handling, or provider authentication. The packaged fictional fixture is not evidence that GitHub issued a record. It does not elevate content to owner intent or authorize any action. No PRIVATE/SECRET content is persisted.

The writer API rejects detectable hard-linked database files, UNC paths, and Windows remote/unknown drive types; it checks visible path components for symlinks/reparse points before opening. Windows directory-entry replacement and reparse-point races, same-user direct database access, and maintenance arbitration remain limitations. The CR1-D lease arbitrates cooperating application writers, but `initialize_storage()` does not acquire it; callers must not run migration maintenance concurrently with ingestion. Current-schema and integrity checks occur under the lease before the write transaction, migration identity and exact registered schema DDL are rechecked inside `BEGIN IMMEDIATE`, and the batch has SQLite transaction atomicity. This is not a guarantee against noncooperating database writers or hostile same-user filesystem changes. CR1 and F12 remain IN_PROGRESS; live readers, source authentication, broader persistence and product workflows remain open.

## CR1-H PUBLIC fixture content store

`sentinel.content` provides three APIs for one fixed data set:

- `initialize_public_fixture_store(root)` creates the explicitly selected store root and its fixed subdirectories. The root path must be absolute, on an existing Windows fixed local drive, and its parent must already exist. No implicit/default path or parent tree is selected. An existing unknown or partial nonempty directory is rejected.
- `store_packaged_github_public_bodies(root)` accepts no caller-supplied body or fixture path. It reads the existing hash-pinned `sentinel.github-issues-fixture.v1` package resource and stores only the three fictional PUBLIC issue-body byte strings.
- `read_public_fixture_blob(root, *, content_sha256)` returns exact verified bytes for one of the three allowlisted body SHA-256 identities. It validates the store and blob files and does not call the fixture reader or reconstruct bytes from the JSON resource.

```python
from pathlib import Path

from sentinel.content import (
    initialize_public_fixture_store,
    read_public_fixture_blob,
    store_packaged_github_public_bodies,
)

store_root = Path(r"C:\Temp\sentinel-public-fixture-store")
initialize_public_fixture_store(store_root)
report = store_packaged_github_public_bodies(store_root)
blob = report.blobs[0]
body_bytes = read_public_fixture_blob(
    store_root, content_sha256=blob.content_sha256
)
assert len(body_bytes) == blob.payload_byte_length
```

The store format is `sentinel.public-fixture-store.v1`; blobs use `sentinel.public-fixture-blob.v1` at `public-v1/sha256/<lowercase-content-sha256>.blob`. Each blob contains a fixed magic value, a four-byte big-endian metadata length, canonical sorted compact UTF-8 JSON, then the exact original body bytes. The bounded header records format version, fixture version/hash, content SHA-256, payload byte length, `sensitivity=PUBLIC`, `retention_class=fixture_public`, and `trust_provenance=T4 EXTERNAL`. It contains no issue title or body. The payload hash covers the raw UTF-8 body bytes, not the fixture JSON or its encoded string. The reader accepts only the three pinned body digests:

| Issue | Body SHA-256 |
|---|---|
| 101 | `4ed9123596eda8d6095d288d39f3ee267faef342e515da10d22cd2013a9509b2` |
| 102 | `58485f7f640572778e5938f992eb20b4ae23481b35dcb7b94c714856727876d3` |
| 103 | `0d8f518b261850fb65ac0ec792b60e3abb3407659410a84fd390196c978e2ef2` |

Each payload is limited to 32 KiB, matching the existing fixture reader's body limit; metadata is limited to 1 KiB, and the selected root path to 160 characters. Files are created as unique temporary entries, written in bounded chunks, flushed and `fsync()`ed, then published with Windows `os.rename()` in the same directory. On Windows, Python documents that `os.rename()` raises `FileExistsError` when the destination exists, unlike `os.replace()`; CR1-H tests this on the host's NTFS volume. A valid existing blob is fully verified and reused without overwrite; a corrupt existing blob fails without repair. Each blob is individually published and read back. The three-file collection is not one atomic batch: a failure can leave earlier complete blobs, and a retry verifies and reuses them. The [Python 3.11 `os.rename` documentation](https://docs.python.org/3.11/library/os.html#os.rename) describes the Windows destination-exists behavior used here.

A process exit before rename can leave a uniquely named `.tmp-<random>.part` file, but not a partial `.blob` at the digest path. Unknown temporary files are not garbage-collected. After rename, the final file is complete and is verified on read. File `fsync()` and rename do not establish survival across abrupt power loss; this code does not flush directory metadata or claim power-loss atomicity. A same-user process able to replace directory entries can still race path checks; detectable reparse components and hard-linked final blobs are rejected, but this is not protection against a malicious same-user filesystem actor. On this Windows host, C: is a fixed NTFS volume; actual symlink creation is unavailable in the existing test environment, so new reparse tests also exercise the detection boundary with a controlled mock. Other fixed Windows filesystems are not independently certified.

This store is unencrypted and is scoped to synthetic PUBLIC fixture data. SHA-256 verifies payload integrity relative to the requested trusted digest; it does not authenticate GitHub, provide confidentiality, prove authorization, or prevent a same-user process from replacing both blob and trusted references. It does not store PRIVATE Gmail bodies, use OS credentials, or integrate with SQLite `source_items.content_ref`. CR1-G continues to reconstruct its content from the pinned fixture; this new store is an independent primitive, not a cross-filesystem SQLite transaction or general content store.

## CR1-H1 SQLite reference promotion

CR1-H1 explicitly connects the existing fixed CR1-G rows to the separate CR1-H store. It does not add a schema migration or change the blob format. The public APIs are:

```python
from pathlib import Path

from sentinel.ingestion import (
    promote_github_fixture_to_public_blobs,
    read_blob_backed_github_fixture,
    read_blob_backed_github_body,
    verify_blob_backed_github_citation,
)

database = Path(r"C:\Temp\sentinel-cr1-g.sqlite3")  # existing, current CR1-F database
store_root = Path(r"C:\Temp\sentinel-public-fixture-store")  # initialized explicitly

promotion = promote_github_fixture_to_public_blobs(database, store_root=store_root)
snapshot = read_blob_backed_github_fixture(database, store_root=store_root)
body = read_blob_backed_github_body(
    database, store_root=store_root, item_id=snapshot.items[0].item_id
)
cited_text = verify_blob_backed_github_citation(
    database,
    store_root=store_root,
    item_id=snapshot.items[0].item_id,
    span_id=snapshot.items[0].spans[0].span_id,
)
```

Promotion accepts only an existing database at the exact current registered schema, the complete verified CR1-G fixture state, and an explicitly initialized CR1-H store root. It promotes exactly the three pinned fixture items and nine spans. The reference changes from `fixture:sentinel.github-issues-fixture.v1:<repository>#<issue>` to the closed grammar `sentinel-public-blob-v1:sha256:<lowercase-body-sha256>`. The digest is checked against the expected item revision before it is passed to the fixed content-store API; a value from SQLite is never opened as a path, URL, or generic resource. No body bytes are written to SQLite.

The promotion order is validate the complete old or fully promoted state, publish and read back all three blobs, then acquire the CR1-D writer lease and update all three `content_ref` fields in one `BEGIN IMMEDIATE` transaction. The transaction rechecks current migration identity, registrations, exact item and span sets, and all three blob payloads before updating. It compares the complete promoted state again before commit. A database error or failed postcondition rolls back all three reference changes. If a process stops after blob publication but before commit, the old references remain and complete orphan blobs are harmless; no automatic orphan cleanup is performed. A retry verifies and reuses them. A crash after commit leaves references to blobs that were already published. This is not one atomic transaction across SQLite and the filesystem, and no sudden power-loss guarantee is claimed.

The blob-backed read APIs use the fixed, metadata-only expectation manifest `sentinel.github-fixture-persistence-manifest.v1`, pinned at SHA-256 `645aecaedd14d8e6c6071b9d8c32a5d91f664c715799191303eac315d6f9c08f`. It records expected registration and item metadata, stable in-memory source IDs, content digests, persisted span IDs, original span IDs, byte ranges, and slice digests; it contains no issue titles or bodies. The reader validates SQLite rows against that manifest, resolves only the exact blob-reference grammar through the explicitly selected store, reconstructs normalized sources under fixed `github.fixture` / `T4_EXTERNAL` / `PUBLIC` labels, and revalidates all nine citation associations against exact blob bytes. It does not load the packaged GitHub JSON fixture and fails if a blob is missing or corrupted. `read_blob_backed_github_body()` and `verify_blob_backed_github_citation()` are explicit internal byte/text access APIs; the default report omits source bodies and titles.

The original CR1-G fixture-backed APIs remain for unpromoted databases and reject promoted refs. There is no implicit mode switch or fixture fallback. This fixed-fixture check requires exactly the pinned three revisions, so additional revisions under this one synthetic registry source are conflicts; it is not a general revision-aware synchronizer. Other unrelated registered sources are left outside its comparison. Only fictional PUBLIC GitHub fixture content is eligible; PRIVATE Gmail and SECRET data are rejected by scope. The plugin remains a disabled synthetic manifest, and labels do not authenticate GitHub or grant authority.

SQLite writes use the existing cooperative writer lease. It does not coordinate schema maintenance while an idle lease is held; maintenance and promotion must not be run concurrently. The lease does not prevent a noncooperating same-user process from changing database or blob files. Windows directory-entry/reparse-point replacement races and filesystem-to-SQLite atomicity remain limitations. The CR1-H store is unencrypted and protects content integrity only relative to the trusted digest; it does not provide confidentiality, provider authentication, authorization, or malicious-same-user protection. CR1-H1 is not general content storage and does not implement live GitHub/Gmail, cursor updates, or CR1 completion.

## CR1-I synthetic GitHub evidence brief

Once the fixed GitHub fixture has been ingested and promoted, the installed CLI can display its complete verified evidence after restart:

```powershell
sentinel brief github-fixture `
  --database C:\Temp\sentinel-cr1-current.sqlite3 `
  --store-root C:\Temp\sentinel-public-fixture-store `
  --format text
```

Use `--format json` for the deterministic `sentinel.synthetic-evidence-brief.v1` document. Its fixed `briefing_type` is `Synthetic GitHub evidence briefing`. Both options are required for the existing database and the explicitly initialized PUBLIC blob-store root. The command does not initialize a database, ingest or promote a fixture, create a store, synchronize a source, or choose implicit paths. An unpromoted database fails without modification.

The brief is a deterministic presentation of the three pinned fictional GitHub issue records and their nine source-bound citations. It is not AI summarization, live GitHub data, or a complete daily briefing. Items are ordered by `source_at` ascending after conversion to UTC, with the canonical provider item ID as a stable tie-breaker. `source_at` remains the provider-like issue update time; the fixed `observed_at` value remains separate. Neither timestamp authenticates a provider or says that an item is current today.

The text and JSON outputs include the fixture and metadata-manifest versions and hashes, item and citation counts, provider item IDs, persisted item UUIDs, original in-memory source-envelope UUIDs, complete body digests, both timestamps, `T4 EXTERNAL`/`PUBLIC` labels, and each persisted citation UUID, half-open UTF-8 byte range, slice digest, and display-safe cited text. Citation bytes are verified from the explicitly selected blob store against the pinned H1 expectations before output. This path does not load the GitHub JSON fixture or fall back to it when a blob is missing. It requires the exact complete promoted database state; all evidence is assembled and formatted before the command writes success output.

Excerpt text is untrusted source data. The terminal renderer visibly escapes CR, LF, tabs, control characters, bidirectional formatting marks, and other Unicode format controls (while preserving joiners used in some scripts and emoji) so an excerpt cannot add terminal lines or alter display direction. JSON uses the same display-safe excerpt representation; these escapes affect presentation only. Stored byte ranges and SHA-256 values always refer to the exact original blob bytes. The source phrase “ignore prior instructions” is displayed only as quoted `T4 EXTERNAL` evidence and does not affect labels or trigger tools. A successful result does not claim that GitHub authenticated the content, that an issue has a particular status/priority/deadline/owner, or that the content implies an action.

On any database, reference, blob, item, or citation verification failure the command exits nonzero, prints no partial briefing to stdout, and emits one fixed error to stderr without paths or source text. It performs read-only database inspection and does not write or repair blobs. This remains synthetic PUBLIC evidence presentation only: live GitHub/Gmail readers, automatic task extraction, incremental synchronization, model summaries, policy/approval handling, credentials, and external actions are not implemented. CR1-J below adds a separate manual local-task workflow.

## CR1-J manual local tasks

CR1-J adds the checkpoint-aware migration `cr1-j-0004-local-tasks`. Its
canonical migration artifact SHA-256 is
`a75bfcff37255e1fb0cc49eb72254c8e83d049828faa2653a8495ca2f749120a`; the
complete post-CR1-J schema checkpoint SHA-256 is
`659d0643a9e1c85f839a107d4e8d1d944c38972bb0416d094cd5a73ad355979d`. The
historical CR0, CR1-E, and CR1-F migration artifacts/checkpoints are unchanged.

The migration adds the normative `action_proposals` schema parent and `tasks`
table. `action_proposals` references `runs` and `principals`, with a unique
`(display_sha256, run_id)` pair and a `(status, expires_at)` index. It is schema
only: the manual task workflow never inserts proposal rows, evaluates policy,
requests approval, or enables external writes. `tasks` references
`principals`, `source_items`, and `action_proposals`; it has `OPEN`/`COMPLETED`
state checks, a positive revision check, a `(status, due_at)` index, and a
partial unique index for non-NULL `proposal_id` values.

The task row follows the blueprint and has no request-key field. To retain
create-request idempotency even after later edits change the title or due date,
the migration also adds the small `task_creation_requests` receipt table. It
binds one request UUID to one task UUID and a digest of the original canonical
arguments. See [ADR-0004](docs/adr/0004-cr1-j-task-request-receipts.md). The
receipt stores no duplicate title/body. Its digest is an integrity value, not
authentication or protection against direct database modification.

### Explicit schema maintenance

Task commands and `sentinel doctor` never apply migrations. A database at the
CR1-F schema must be upgraded explicitly during a quiescent maintenance window.
For example, after stopping all Sentinel writers and confirming no task or
other application writer is active:

```powershell
.\.venv\Scripts\python.exe -c "from sentinel.storage.migrations import initialize_storage; initialize_storage(r'C:\Temp\sentinel.sqlite3')"
```

For a new database, `sentinel init --database <absolute-path>` applies all
currently registered migrations. The existing writer lease coordinates
cooperating application writers, but migration maintenance does not acquire
that writer-session mutex. An active SQLite write transaction blocks a DDL
migration and the migration rolls back; an idle lease does not block it. Do not
run maintenance concurrently with the CLI or another application writer.

### Manual commands

Initialize the dedicated task operator once, then add, list, edit, complete,
and reopen tasks. Every command requires the existing database path explicitly:

```powershell
sentinel task setup --database C:\Temp\sentinel.sqlite3
sentinel task add --database C:\Temp\sentinel.sqlite3 --title "Review release notes" --request-id 7cb7306e-77d8-4762-84cb-3af481d485c8 --due-at 2027-05-01T12:00:00+05:30
sentinel task list --database C:\Temp\sentinel.sqlite3
sentinel task edit --database C:\Temp\sentinel.sqlite3 --task-id <task-uuid> --expected-revision 1 --title "Review revised notes"
sentinel task complete --database C:\Temp\sentinel.sqlite3 --task-id <task-uuid> --expected-revision 2
sentinel task reopen --database C:\Temp\sentinel.sqlite3 --task-id <task-uuid> --expected-revision 3
```

`setup` registers a deterministic `local-task-operator` principal. It is an
unauthenticated local CLI identity, not a Windows logon proof, cryptographic
owner identity, or approval actor. Repeating setup reuses the exact row;
conflicting metadata fails closed. It is separate from the synthetic GitHub
fixture principal.

The Python API is `setup_local_task_operator(database)`,
`create_local_task(database, *, request_id, title, due_at=None)`,
`list_local_tasks(database, *, status=None)`, `edit_local_task(...)`,
`complete_local_task(...)`, and `reopen_local_task(...)` in
`sentinel.tasks`. It returns frozen `LocalTaskOperator`, `LocalTask`, and
`TaskCreateResult` values; it never exposes a SQLite connection. Writes use one
CR1-D writer-lease transaction each; reads use the existing read-only database
connection and do not run DML. All APIs require the exact current registered
schema and refuse a missing database, historical prefix, or schema drift.

Task titles are supplied directly by the caller; no GitHub/Gmail text or CR1-I
evidence is converted into a task. Titles must contain 1-200 Unicode code
points and at most 800 UTF-8 bytes. NUL, terminal controls, ANSI escape, line
separators, unpaired surrogates, and bidirectional controls are rejected
without silently rewriting the title. International text is preserved. Due
dates require an explicit ISO-8601 UTC offset and are stored in UTC. Creation
and update timestamps come from the local aware UTC clock, never a source
timestamp or caller-supplied creation time.

If `--request-id` is omitted, `sentinel task add` generates and prints a UUIDv4
for that new intent. Repeating the command with a new automatic ID creates a
new request; it does not deduplicate a manually repeated command. Reuse the
same request ID to retry: the identical normalized title/due date returns the
same task, while changed arguments fail. The task UUID is stable UUIDv5 over
the fixed application namespace, the local operator principal, and request ID.

Every task mutation requires `--task-id` and `--expected-revision`. Successful
edits and transitions increment the revision exactly once and preserve
`created_at`. Editing with no changed fields, setting the same value, or
repeating a completion/reopen transition is rejected without incrementing the
revision. The only transitions are `OPEN -> COMPLETED` and
`COMPLETED -> OPEN`; completion sets `completed_at` and reopening clears it.
There is no deletion. Lists sort by due date ascending with undated tasks last,
then creation time and task UUID.

Manual rows always use `source_item_id=NULL`, `proposal_id=NULL`, and
`body_ref=NULL`; CR1-J creates no `action_proposals` rows. Task titles are
stored as ordinary unencrypted SQLite text. Do not put passwords, credentials,
or confidential records in them. This is a single local CLI workflow, not
authenticated owner intent, multi-user isolation, encrypted private storage,
AI planning, a source-derived task mechanism, or a full personal task manager.
The writer lease is cooperative and does not prevent a noncooperating same-user
process from modifying SQLite. CR1-J does not implement source ingestion,
incremental sync, policy, approvals, external actions, a daemon, or CR1 release
completion.

## CR1-K synthetic incremental fixture replay

CR1-K exercises a persistent cursor transition against the existing
`sentinel.github-issues-fixture.v1` package resource. Its fixed resource hash is
`7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1`; no new
fixture collection or migration is added. The isolated registry source has
UUID `28d81af7-dac5-58c1-9dbe-dbad88440cb5`, distinct from CR1-G's source
`9338577b-4f6d-5507-9422-598c6ffc16bd`. Its account alias is
`example-owner/fixture-project::incremental-fixture-v1`, and its trusted code
scope marks it as a **synthetic incremental fixture replay**. It is not a
second real GitHub account. The source remains `T4_EXTERNAL` and `PUBLIC` and
reuses the disabled `github.fixture` manifest and fictional fixture principal.

An explicit setup requires an existing current CR1-J database, the complete
promoted CR1-H1 source, and the initialized PUBLIC fixture store:

```powershell
sentinel fixture-sync setup `
  --database C:\Temp\sentinel.sqlite3 `
  --store-root C:\Temp\sentinel-public-fixture-store
```

Each call to `advance` processes at most one fixed page, in fixture order
`#101`, `#102`, `#103` (not provider timestamp order):

```powershell
sentinel fixture-sync advance --database C:\Temp\sentinel.sqlite3 `
  --store-root C:\Temp\sentinel-public-fixture-store --expected-generation 0
sentinel fixture-sync status --database C:\Temp\sentinel.sqlite3 `
  --store-root C:\Temp\sentinel-public-fixture-store
```

The corresponding Python APIs in `sentinel.sync` are
`setup_incremental_github_fixture(database, *, store_root)`,
`advance_incremental_github_fixture(database, *, store_root,
expected_generation)`, and `read_incremental_github_fixture_state(database, *,
store_root)`. All paths are explicit. There is no implicit database/store
creation, migration, URL, fixture path, cursor token, body, or label input. The
status API is read-only and verifies the entire committed prefix against the
body-free pinned H1 expectation manifest and existing blobs; it does not load
the packaged GitHub JSON fixture. Advancement uses that pinned package
resource and rejects any invalid fixture, citation, source, blob, cursor, or
row state.

The UUID mappings use `uuid5(NAMESPACE_URL, name)`. The incremental registry
source name is
`sentinel:github.fixture:incremental-fixture:v1:example-owner/fixture-project`,
which yields `28d81af7-dac5-58c1-9dbe-dbad88440cb5`. Provider items use
canonical `example-owner/fixture-project#<number>` values. The persisted item
name is
`sentinel:github.fixture:incremental-item:v1:<registry-source-uuid>:<provider-item-id>:<body-sha256>`.
The in-memory source UUID comes from the fixture reader. The persisted span
name is
`sentinel:github.fixture:incremental-span:v1:<persisted-item-uuid>:<in-memory-span-uuid>`.
The cursor ID name is
`sentinel:github.fixture:incremental-cursor:v1:<registry-source-uuid>:github_fixture_page_v1`,
which yields `7860e3f9-7b4a-5b7d-9efd-aa04a08b9598`. Cursor kind is
`github_fixture_page_v1`. Cursor references use the closed grammar
`sentinel-github-fixture-cursor-v1:sha256:<lowercase-digest>`. The digest pins
canonical JSON containing the fixture version/hash, incremental source UUID,
cursor schema, and sequence number 0 through 3. These are synthetic page
checkpoints, not encrypted provider tokens; future sensitive live cursors need
a separate protected design.

One `BEGIN IMMEDIATE` transaction inserts the expected item revision and all
of its verified spans, advances the cursor exactly once, and checks the full
post-transition state before commit. Replays do not insert duplicates:
generation progresses 0→1→2→3 with item/span counts 0/0→1/3→2/8→3/9. A replay
of the immediately previous generation returns `ALREADY_APPLIED`; an older
request returns `STALE`, a future generation returns `OUT_OF_ORDER`, and
generation 3 returns `COMPLETE` without another advance. Setup verifies and
reuses an existing registration without rewinding it. `last_commit_at` is a
local UTC timestamp assigned to the cursor transition; `last_full_sync_at` and
`etag` remain NULL because this is not a provider full sync and the fixture has
no ETag.
`source_at` remains the fixture's untrusted provider-like timestamp, while
`observed_at` is the fixture reader's fixed local observation value. Neither
one authenticates a provider event.

The synthetic body phrase “ignore prior instructions” remains
`T4_EXTERNAL` source data. Only the explicit local API/CLI call processes a
page; this does not create a task, approve an action, or invoke a model, tool,
provider, credential broker, network, or MCP process. Page advancement does not
change the original CR1-G/H1 rows or manual tasks. It reuses the three existing
PUBLIC blobs and stores no PRIVATE Gmail material.

Real child-process termination tests cover death before item insertion, after
item insertion, during span insertion, after all spans before cursor update,
after cursor update before commit, and immediately after commit. Before commit,
SQLite recovery presents the prior complete page prefix; after commit it
presents the next complete prefix. A retry then applies or verifies the page
without duplication. This is process-crash/SQLite transaction evidence, not a
sudden power-loss guarantee or cross-file atomicity. The Windows writer lease
coordinates cooperating app writers only. A noncooperating same-user process
can still modify SQLite/files, and migration maintenance does not share the
writer-session mutex; do not run schema maintenance concurrently. This is a
fixed synthetic replay, not live GitHub pagination, OAuth, Gmail sync, cursor
encryption, scheduling, deletion/tombstones, automatic task creation, or full
F18 implementation. CR1 release verification is limited to the bounded offline scope described at the top of this README; live synchronization remains unavailable.

## CR1-L explicit local overview

`sentinel brief local-overview` displays three separately labeled sections:
manually entered local tasks, the existing verified three-item/nine-citation
synthetic GitHub evidence briefing, and the CR1-K synthetic cursor status. It
does not combine them into source claims, repeat the three issues as if they
were new observations, create tasks from source text, or generate an AI summary.
The selected date is explicit; this is not an automatically scheduled daily
briefing.

The command requires an existing current CR1-J database, a fully promoted and
valid CR1-H1 GitHub fixture source, an initialized unauthenticated local task
operator, an initialized CR1-K fixture cursor at generation 0 through 3, and an
initialized PUBLIC blob store containing all three verified bodies. It does
not initialize or repair state, apply migrations, ingest or promote source
data, publish blobs, create tasks, or advance a cursor. Prepare the H1 database
and PUBLIC blobs through their existing explicit APIs first; the overview has
no setup path. The separate local operator and cursor setup commands are:

```powershell
sentinel task setup --database C:\Data\sentinel.sqlite3
sentinel fixture-sync setup --database C:\Data\sentinel.sqlite3 `
  --store-root C:\Data\sentinel-public-fixture-store
```

Then run the overview:

```powershell
sentinel brief local-overview `
  --database C:\Data\sentinel.sqlite3 `
  --store-root C:\Data\sentinel-public-fixture-store `
  --as-of 2026-11-04T18:00:00+05:30 `
  --format text
```

`--database`, `--store-root`, and `--as-of` have no defaults. `--as-of` must be
an ISO-8601 timestamp with an explicit offset (UTC `Z` is accepted). Sentinel
reports its UTC instant, the supplied offset, and the resulting local calendar
day. This slice treats that offset as fixed for the whole day; it does not
provide IANA timezone or daylight-saving transitions. The day uses the
half-open interval `[local midnight, next local midnight)`. Thus an OPEN task
whose due time has already passed earlier on the selected day remains
`DUE_TODAY`; it becomes `OVERDUE` only before that day's beginning.

OPEN tasks appear in `OVERDUE`, `DUE_TODAY`, `UPCOMING`, or `NO_DUE_DATE`;
completed tasks appear in their own `COMPLETED` section. Dated OPEN tasks sort
by due instant ascending, then creation time and task UUID. Undated tasks sort
by creation time and UUID; completed tasks sort by completion time and UUID.
Displayed due times use the selected fixed offset. These are calendar buckets,
not inferred urgency or task-title analysis. Task entries are manual local
data owned by an unauthenticated CLI identity; they are not verified owner
intent. SQLite task titles are unencrypted, so do not store credentials or
confidential information in them.

The synthetic GitHub section reuses CR1-I's complete verified briefing and
preserves its three item identities, nine byte-accurate citations, source
digests, manifest pin, timestamps, and `T4 EXTERNAL` / `PUBLIC` labels. Its body
bytes are verified from the PUBLIC blob store, independently of the original
GitHub JSON fixture. The fixture text, including instruction-like excerpts,
remains untrusted evidence. It creates no tasks, deadline, priority,
recommendation, resolution, or project status. The separate sync section
reports the synthetic source/cursor UUIDs, fixture pin, generation, page/item/
span counts, and `READY`/`COMPLETE` fixture replay state. It is not live GitHub
freshness and does not duplicate incremental items into the original evidence
count. In JSON the version is `sentinel.local-overview.v1`; `synthetic_data`
describes the fixture evidence and replay only, while manual tasks have their
own provenance label.

The text formatter reuses CR1-I's terminal escaping. It renders control,
newline, and bidi characters visibly without changing the verified citation
bytes, offsets, or digests. JSON output is deterministic and path-free; it is
not digitally signed. Sentinel completes every read, check, and render before
writing success output. A missing task operator, cursor, promoted source,
blob, or citation, or any corrupt stored record, fails the whole command with
no partial stdout and a bounded stderr message.

The overview reads tasks and cursor state, builds the verified evidence, then
rereads tasks and cursor state and compares their complete returned records.
A detectable change rejects the output. These existing readers use separate
SQLite connections, so this check is not a single atomic cross-component
snapshot and cannot rule out every race by a noncooperating process. The
overview itself is read-only: it does not acquire the writer lease, issue DML,
write or repair blobs, migrate schema, change cursor state, or modify tasks.
There is no network, live GitHub/Gmail integration, credential access, model,
tool, MCP, task extraction, or scheduling in this slice. CR1 remains
IN_PROGRESS; the broader source readers, authorization, privacy, policy,
daemon, and release requirements remain open.

## CR1-M read one allowlisted local text file

The read-only command accepts one explicit file and one explicit allowlisted
directory on a local Windows fixed drive:

```powershell
sentinel source inspect-file `
  --allow-root C:\Notes `
  --file C:\Notes\meeting-notes.md `
  --format text
```

It accepts only existing `.txt` and `.md` files, treats Markdown as plain text,
and reads at most 1,048,576 bytes. The root and target must be absolute paths on
the same fixed drive. UNC and device paths, ADS, glob characters, traversal,
reserved device names, trailing-dot/space aliases, directories, reparse points,
and detectable hard-linked targets are rejected. It does not search for files,
expand environment variables, parse Markdown, render HTML, follow links, or
read referenced files.

The reader preserves the exact original UTF-8 byte sequence, including BOM,
line endings, whitespace and Unicode, and uses the existing normalizer and
source-bound citation verifier. Its deterministic source identity is
`UUIDv5(NAMESPACE_URL, "sentinel:local-text:v1:<canonical-relative-identity>:<content_sha256>")`;
the relative identity is taken from the opened final target path beneath the
opened final root, with `/` separators. A span identity is
`UUIDv5(NAMESPACE_URL, "sentinel:local-text:span:v1:<source_uuid>:<start_byte>:<end_byte>")`.
These identifiers do not authenticate file ownership and can correlate
repeated reads of the same relative file and content, including across roots
with the same relative file identity. Observation time comes from the local
UTC clock; file modification time is retained only as untrusted metadata and
is not displayed by default.

All selected content is labeled `T4 EXTERNAL` and conservatively `PRIVATE`.
The PRIVATE label does not prove that a file contains no SECRET content, and it
does not enable persistence. The result keeps raw bytes behind the existing
explicit in-memory normalization object; its default representation omits
body, path and file metadata. Without offsets, CLI output contains only reader
metadata and a warning that file placement does not authenticate the author
or establish owner intent. To display one excerpt, provide both byte offsets:

```powershell
sentinel source inspect-file `
  --allow-root C:\Notes `
  --file C:\Notes\meeting-notes.md `
  --start-byte 18 --end-byte 42 `
  --format json
```

The byte range and SHA-256 always refer to the original bytes. Text/JSON
presentation escapes control, line-separator and bidi characters without
rewriting the source or its citation digest. Output schema is
`sentinel.local-file-inspection.v1`; it omits absolute paths and source text
unless the caller explicitly requests one verified span. Errors are bounded,
and a failed read or citation produces no success output.

Trusted in-process callers can use the typed API directly:

```python
from sentinel.readers import read_allowlisted_local_text, verify_local_text_span

source = read_allowlisted_local_text(allowed_root=r"C:\Notes", file_path=r"C:\Notes\meeting-notes.md")
citation = verify_local_text_span(source, start_byte=18, end_byte=42)
```

The returned `LocalTextRead` contains the existing immutable normalized source;
only an explicit internal caller can access its decoded text or original bytes
through that normalization contract. The CLI never serializes that object.

On Windows, the reader checks every path component for reparse attributes,
holds directory handles opened without write/delete sharing, opens the target
with `CreateFileW` and `FILE_FLAG_OPEN_REPARSE_POINT`, disables handle
inheritance, checks the opened file ID and final path beneath the opened root,
reads through that stable handle, and rechecks identity/metadata afterward.
`GetDriveTypeW` must report `DRIVE_FIXED`; handle-reported hard-link count must
be one. These are tested local-filesystem checks, not a sandbox against a
malicious same-user process with directory permissions. Windows reparse-point
and directory-entry replacement races remain possible outside the held-handle
window; the environment also cannot create symlinks, so live symlink behavior
remains unverified (the controlled reparse rejection test passes). File
`fsync` or storage durability is not relevant here because this reader writes
nothing.

CR1-M is a single-file in-memory adapter, not a directory watcher or sync
engine. It makes no SQLite or PUBLIC-blob-store changes and does not preserve
PRIVATE bytes across process restarts. It makes no network request, credential
access, model call, tool invocation, task write, or external action. This
differs from the packaged synthetic GitHub reader: the selected local file is
real external data supplied explicitly by the operator and is always PRIVATE.
F10 is IN_PROGRESS only for this bounded reader; directory sync, secure
PRIVATE persistence, authorization, and the remaining CR1 requirements are
not implemented.

## CR1-N search explicitly selected local text files

Search is a read-only literal search over files named directly by the caller;
it does not crawl directories, glob, watch, index, follow Markdown links, or
search the network. Example:

```powershell
sentinel source search-files `
  --allow-root C:\Notes `
  --file C:\Notes\meeting.md `
  --file C:\Notes\research.txt `
  --query "deadline" `
  --format text
```

The command requires an absolute allowlisted root, one to eight repeated
absolute `--file` paths, a literal `--query`, and `--format text|json`. Each
file is independently passed through the CR1-M Windows path and file reader:
only `.txt` and `.md` files are accepted, Markdown remains plain text, and each
source is capped at 1 MiB. The selected bytes are capped at 8 MiB total. Files
must be beneath the selected root; case aliases and repeated canonical file
identities are rejected. There are no defaults, environment-variable
expansion, directory discovery, database reads, caches, or persistence.

Matching compares the exact UTF-8 bytes, with case sensitivity and no Unicode
normalization, regular expressions, fuzzy matching, locale conversion, or
semantic interpretation. Thus `Done` differs from `done`, and composed and
decomposed Unicode spellings differ. Overlapping occurrences are included
(`banana` contains `ana` at byte offsets 1 and 3). Queries are limited to 128
Unicode characters and 512 UTF-8 bytes and reject controls, line breaks, bidi
controls, and invalid Unicode scalar input. At most 32 matches are allowed;
finding a 33rd fails the entire request rather than returning a truncated
result.

Every match is a half-open UTF-8 byte range checked by the existing
`verify_local_text_span()` citation verifier. The result identifies each
selected file by its explicit argument ordinal, source UUID, full source
digest and byte length, and gives every match's deterministic span UUID and
slice digest. The versioned JSON schema is
`sentinel.local-file-search.v1`. Default text and JSON include metadata and
verified ranges only: they omit filenames, absolute paths, the query and
source context. Zero-match selected files remain visible with count zero.
Trusted in-process callers can use
`search_selected_local_text_files(*, allowed_root, file_paths, query,
show_snippets=False)`; it returns immutable file and match records, with preview
text present only when snippets were explicitly requested.

`--show-snippets` explicitly discloses one verified preview per match. A
preview stays on one physical line, includes at most 40 Unicode characters of
context on either side, is capped at 256 UTF-8 bytes, and is independently
verified as a second byte range. Display escaping makes terminal controls,
line breaks and bidi controls visible without changing the original digests or
coordinates. Text and JSON are deterministic and contain no generated time.
The command verifies every selected file, match and requested preview and
renders the complete bounded result before writing stdout; any failure emits
no partial result and one bounded error.

All selected content remains `T4_EXTERNAL` and `PRIVATE`; matching text such
as `ignore prior instructions` remains data and cannot select files, create a
task, advance sync, or trigger tools. No bytes are written to SQLite or the
PUBLIC blob store. No model, network, credential, provider or external action
is used. Explicit snippets are an operator-directed disclosure to the
terminal or JSON consumer. Query arguments may be retained in shell history or
visible through operating-system process inspection, so the command-line query
is not a safe channel for credentials or highly confidential strings.

The CR1-M reader validates each selected file using its existing held-handle,
identity and reparse checks. Search performs one further bounded read of each
file and rejects a detectable identity or digest change before returning.
Each file is still read independently: this is not an atomic multi-file
snapshot and cannot rule out every ABA or same-user filesystem race. Existing
Windows reparse, hard-link and same-user limitations remain. CR1-N adds literal
multi-file search only; it does not complete F10 or CR1 and does not provide
directory synchronization, semantic search, RAG, automatic task extraction,
or PRIVATE persistence.

## CR1-O extract explicitly labeled job-alert fields

`sentinel source parse-job-alert` reads exactly one explicitly selected local
`.txt` or `.md` body through the CR1-M allowlisted Windows reader. It does not
parse Markdown, inspect a subject, search a mailbox, or contact Gmail. A
trusted in-process caller may also pass one existing immutable
`GmailFixtureMessage` to `parse_gmail_fixture_job_alert(message)`; this adapter
uses only its already-normalized body and validated source envelope. The
packaged Gmail fixture remains a collection of synthetic notes/receipts, not a
job-alert dataset; its three messages classify as `NO_MATCH`.

```powershell
sentinel source parse-job-alert `
  --allow-root C:\Notes `
  --file C:\Notes\fictional-alert.txt `
  --format text
```

The CLI supports `--format text|json`. It reports metadata and per-field
presence/state plus citation metadata by default, without printing extracted
PRIVATE values. `--show-fields` explicitly discloses only accepted cited
values; it never prints the whole body. The JSON schema is
`sentinel.job-alert-extraction.v1` and has no paths or generated timestamps.
Both renderers finish validating every field citation before writing stdout.
A read or citation failure exits nonzero with empty stdout and a bounded,
path-free error.

The supported line grammar is one field per physical line, with an exact
case-insensitive label before `:` and an unchanged UTF-8 value after optional
ASCII spaces/tabs. Accepted labels are `Company`/`Employer`, `Role`/`Position`,
`Location`, `Apply URL`/`Application URL`, and `Deadline`. Values are not
case-folded, stripped, Unicode-normalized, inferred from prose, subject text,
quoted content, or other fields. A blank or ordinary prose line separates
field blocks. Multiple blocks, repeated labels (including aliases with the
same value), or multiple `Job opportunity` markers yield `AMBIGUOUS`; the
parser never takes the first listing or merges its fields. No recognized
labels yields `NO_MATCH`; recognized structure missing company or role, or
containing an invalid value, yields `INCOMPLETE`. `CANDIDATE` means only that
one company and one role were explicitly labeled and byte-cited. It does not
verify an employer, live opening, job legitimacy, user eligibility,
application readiness, or that a URL works.

The adapter accepts at most 64 KiB, 256 physical lines, 1 KiB per line and 12
recognized fields. UTF-8 bytes and CRLF/LF line endings are retained exactly.
Company is limited to 160 UTF-8 bytes, role/location to 200 each, application
URL to 1,024, and deadline to 64. Each present field has a deterministic
source-bound citation over its exact value bytes (the label and delimiter are
excluded), including the source UUID, full-body digest, half-open byte range,
span UUID and slice digest. The local source UUID reuses CR1-M's UUIDv5 rule
over the canonical root-relative identity and complete body digest; Gmail
reuses the fixture message UUID. Field span UUIDv5 values bind source UUID,
field kind and byte range. These identifiers are deterministic and
correlatable, not authentication or anonymity proofs. Invalid optional URLs
or dates make the result `INCOMPLETE`; their text is not returned as an
extracted value. Dates accept only real `YYYY-MM-DD` calendar dates and remain
date-only. URLs are inert
strings: only syntactically bounded HTTPS URLs with ordinary DNS-style hosts
are accepted; userinfo, fragments, whitespace, malformed ports, localhost,
local suffixes, numeric/IP hosts and non-HTTPS schemes are rejected. There is
no DNS lookup, URL fetch, redirect, or application action.

All inputs remain `T4 EXTERNAL` / `PRIVATE`. These labels are assigned by
trusted reader code; file placement, Gmail-like metadata and source text do
not authenticate an author or establish owner intent. PRIVATE is conservative
and does not prove the absence of SECRET information. Extracted values and
citations are in memory only; no SQLite row, task, proposal, run, blob, cache,
log, or telemetry record is created. Instruction-like text remains cited
untrusted data. No model, tool, provider, network, credential or task API is
called.

The separate tests-only fictional corpus has 35 labeled cases. The current
observed run classifies its 31 in-bound cases exactly (12 candidates, 10
incomplete, 5 ambiguous, 4 non-matches; 100% classification accuracy on those
31), with 48/48 expected field values exact, 48 verified present-field
citations, and zero candidate false positives or false negatives. Four cases
are correctly rejected by fixed source/line/field-count bounds. This is a
contract test, not a real-world job-alert accuracy estimate. The parser
deliberately cannot resolve prose, forwarded quotation semantics, multiple
listing templates, relative deadlines, eligibility, or unmodeled job details;
such content is ignored, incomplete, or ambiguous rather than guessed. F05
and CR1 remain IN_PROGRESS; live Gmail access, task creation, application
submission, and broader extraction remain unimplemented.

## CR1-P review a bounded set of local job alerts

`sentinel source review-job-alerts` applies the existing CR1-O labeled-field
parser to one through eight files explicitly selected with repeated `--file`
options beneath one explicit CR1-M allowlisted root:

```powershell
sentinel source review-job-alerts `
  --allow-root C:\Notes `
  --file C:\Notes\alert-one.md `
  --file C:\Notes\alert-two.txt `
  --format text
```

The command also accepts `--format json`. Its deterministic schema is
`sentinel.job-alert-batch-review.v1`. `--show-fields` is the only opt-in for
displaying accepted `PRESENT` field values; those values retain their
CR1-O-verified citations and pass through its display escaping. The default
output includes file ordinals, source identities and digests, classifications,
field states, citation metadata and correlation group identifiers, but no
filenames, paths, source bodies, company/role/location values, URLs, or
deadlines. Metadata hashes and UUIDs remain correlatable and are not
confidentiality proofs.

Every selected file remains a separate record in the supplied order. The
batch reports exact counts for `CANDIDATE`, `INCOMPLETE`, `AMBIGUOUS`, and
`NO_MATCH`; unreadable, invalid, oversized, or changed input rejects the whole
operation instead of being omitted. A `CANDIDATE` is only the CR1-O bounded
classification, not a verified vacancy, legitimate employer, open role,
eligibility result, salary, application readiness, or ranking. Incomplete,
ambiguous, and non-matching files remain visible. No fields are copied from
one alert to another.

Two non-authoritative correlation signals are reported without deduplication.
`EXACT_SOURCE_CONTENT` groups separately selected files only when both their
body SHA-256 and bytes match; each file keeps its own root-relative source
UUID and citations. `SHARED_APPLICATION_URL` groups only `CANDIDATE` records
with a `PRESENT` application URL whose original strings are exactly equal.
The URL is not fetched, opened, normalized, or treated as evidence that the
records describe one vacancy; employer, role, similarity, and hostname are not
deduplication keys. Group membership lists selected file ordinals and source
UUIDs, not filenames or URL values.

CR1-P reuses CR1-M's explicit local Windows `.txt`/`.md` reader and CR1-O's
64 KiB source, 256-line, 1 KiB-per-line, 12-field, and per-field limits. It
does no crawling, globbing, mailbox access, Markdown-link following, network
lookup, model call, application action, task creation, database write, blob
write, or PRIVATE-content persistence. All local source material is
`T4_EXTERNAL` / `PRIVATE`; a note or alert on the local disk is not authenticated
owner intent. Instruction-like text remains source data. Optional displayed
values are an explicit disclosure to the terminal or JSON consumer.

The output is fully parsed, citation-checked, correlation-checked, and
formatted under a fixed 128 KiB output cap before stdout is written. One
bounded CR1-M reread of every selected source rejects detectable source-ID,
root-relative identity, digest, length, or byte changes during assembly. This
does not provide an atomic snapshot across files and cannot rule out every ABA
or malicious same-user filesystem race. CR1-M's Windows reparse/hard-link
limitations still apply; live symlink creation remains unavailable on the
recorded host. `--show-fields` can disclose personal data, and metadata can be
correlatable. F05 and F10 remain IN_PROGRESS only for their bounded parser and
selected-file workflows; this is not model triage, live email review, vacancy
verification, automatic task extraction, or full F10/CR1 functionality.

## CR1-Q inspect the pinned Calendar fixture

`sentinel source calendar-fixture --format text` reads one packaged fictional
Calendar-style collection. Use `--format json` for deterministic
`sentinel.calendar-fixture-inspection.v1` output. `--show-details` is an
explicit disclosure of the fixture's PRIVATE summaries, date/time metadata,
and verified description excerpts:

```powershell
sentinel source calendar-fixture --format text
sentinel source calendar-fixture --show-details --format json
```

The only resource is `sentinel/readers/fixtures/calendar-events-v1.json`,
schema `sentinel.calendar-events-fixture.v1`, pinned at SHA-256
`e879838ea32430497160bacbdedde1c4ffd98b1906bcdddc1c77c776f756575a`. It
contains four fictional event records in package order: three `confirmed` and
one `cancelled`, with two timed events, one date-only all-day interval, and a
cancelled timed event. The event shape is a deliberately small Calendar-style
subset; descriptions use canonical unpadded base64url of exact UTF-8 bytes.
Unknown fields, duplicate JSON keys and IDs, invalid shapes, oversized values,
unsupported statuses, and malformed citations fail closed. Each citation
records its span UUID, half-open byte range, exact expected text, and SHA-256
of the original cited bytes.

Timed endpoints must be strict ISO-8601 values with explicit `Z` or numeric
UTC offsets. The reader normalizes timed values to aware UTC instants for
comparison while retaining the original timestamp strings. It does not infer
a timezone or interpret an arbitrary `timeZone` field. All-day events remain
date intervals: the start date is included and the end date is exclusive; an
all-day range is never converted to UTC. There is no recurrence expansion,
exception handling, attendee/RSVP data, DST database, timezone inference,
provider pagination, or live Calendar synchronization.

Event IDs, status, summaries, and start/end values are validated fixture
metadata, not description-body citations. UUIDv5 event source identities bind
the trusted synthetic calendar alias and event ID; span identities bind the
same event identity and exact byte range. Descriptions are normalized with
`provider_id=calendar.fixture`, `T4_EXTERNAL`, and `PRIVATE`. The instruction-
like text in the cancelled event is ordinary external source data. Event
metadata and descriptions do not establish a real Calendar account, event,
owner action, or provider-authenticated cancellation.

Default output shows fixture identity, event IDs, status/type, digest and
citation counts, and the `T4_EXTERNAL` / `PRIVATE` labels. It omits summaries,
descriptions and cited text. `--show-details` displays escaped summaries,
original timed strings plus normalized UTC instants, explicit exclusive
all-day end dates, and only the verified cited excerpts with byte ranges and
slice digests. Escaping changes display only, not source bytes or provenance.
Identifiers and hashes can be correlatable; neither the pin nor a digest is a
confidentiality or real-provider authenticity guarantee.

The reader uses no database, blob store, credential, Google client, network,
model, tool, task or scheduling path. It does not modify events and does not
persist the PRIVATE descriptions. The installed wheel includes the pinned
resource. CR1-Q verifies this bounded fixture reader only; live F09 Calendar
OAuth/read remains NOT_STARTED for CR4. CR1 does not imply live Calendar access.

## CR1-R prepare or verify the offline fixture workspace

For a new disposable synthetic demo, first initialize an explicit database,
then prepare its explicitly selected PUBLIC blob store:

```powershell
sentinel init --database C:\SentinelDemo\workspace.sqlite3
sentinel fixture-workspace prepare `
  --database C:\SentinelDemo\workspace.sqlite3 `
  --store-root C:\SentinelDemo\public-store
sentinel fixture-workspace verify `
  --database C:\SentinelDemo\workspace.sqlite3 `
  --store-root C:\SentinelDemo\public-store
```

Both paths are required and absolute. `init` is separate and refuses an
existing database. The store API requires its parent directory to exist.
Workspace preparation never initializes a database, migrates a schema,
chooses a default location, or repairs unknown/corrupt state.

Preparation validates the current CR1-J migration history and checkpoint,
then recognizes only an absent original fixture source, a complete legacy
fixture state, or a complete H1 blob-backed state. It uses the existing
CR1-H store, CR1-G ingestion, CR1-H1 promotion/readback, CR1-J operator,
CR1-K cursor, and CR1-L overview APIs. Legacy rows are verified completely
before promotion; a promoted source is never passed back through legacy
ingestion. The fixed precondition is three PUBLIC synthetic GitHub items,
nine cited spans, and three verified PUBLIC blobs. No Calendar or Gmail data
is persisted.

The explicit stages are store initialization, verified blob publication,
legacy item/span ingestion if absent, atomic three-reference promotion,
local task-operator setup, and incremental cursor setup. Existing committed
stages survive process termination. Retry recognizes completed stages and
continues; it does not delete files, overwrite corrupt blobs, duplicate items
or spans, recreate a valid operator, create tasks, or rewind cursor progress.
For example, a crash after publishing blobs can leave harmless verified
files; a crash during H1 reference promotion leaves SQLite's all-three-ref
transaction rolled back; a crash after promotion leaves the promoted rows
available for later setup. This workflow spans filesystem publication and
separate SQLite transactions, so it is not one cross-resource atomic commit
and does not claim power-loss durability.

`prepare` reports `Fixture workspace prepared` or, on a complete repeat,
`Fixture workspace already prepared`, with counts and the actual cursor
generation/status. A progressed cursor at generations 1, 2, or 3 is retained.
`verify` is read-only: it checks the current schema, blob-backed fixture and
all nine citations, operator/task readability, full incremental state and
the local overview at a fixed internal timestamp. It does not repair missing
blobs, register an operator/cursor, run migrations, or create tasks. A valid
result says `synthetic workspace ready`; this means only that the bounded
offline local overview can be assembled. It says nothing about production
readiness, an authenticated owner, live integrations, or release-gate
completion.

The operator is unauthenticated. Tasks remain manual local text in SQLite;
preparation creates none. The incremental cursor is a deterministic
synthetic fixture checkpoint, not an encrypted provider cursor. GitHub bodies
remain PUBLIC / T4_EXTERNAL. This workflow never stores PRIVATE Gmail or
Calendar content, action proposals, approvals, credentials, run traces, or
external effects. Store and SQLite operations keep their existing separate
locking and durability limits; maintenance migrations still require a
quiescent window. Workspace preparation adds no cross-component lock:
simultaneous prepare invocations can observe each other's committed stages
and may fail closed if an observation is inconsistent. Retry after a competing
invocation finishes. Direct same-user SQLite or filesystem changes are outside
this cooperation boundary. CR1-R does not implement live providers, task
extraction, models, schedulers, external writes, or complete CR1 release
functionality.

## CR1-S source capability status and release audit

Run the source diagnostic without selecting a database or store:

```powershell
sentinel source status --format text
sentinel source status --format json
```

It reads the three fixed packaged Gmail, GitHub, and Calendar fixtures using
their existing pinned readers. `FIXTURE_READY` means that the packaged
resource hash and that reader's strict content/citation validation passed in
this process. It does not mean a real provider account is linked. Explicit
local text read, literal search, job-alert parsing, and batch review are
reported as `EXPLICIT_LOCAL_ONLY`; those APIs require the caller to select a
file/root and do not enable directory discovery, background scanning,
automatic polling, PRIVATE persistence, or source-to-task actions.

Live Gmail, GitHub, and Calendar adapters are `NOT_IMPLEMENTED` and disabled.
The status command does not check for account credentials: the live account
and per-provider credential states are `NOT_CHECKED`. The production
credential backend is `UNAVAILABLE`; this describes the broker implementation
without constructing a fake provider reference or inspecting Windows
Credential Manager, environment variables, or user secrets. No account is
connected or probed.

Greenhouse and Lever feed readers are not implemented. Both remain
`TERMS_REVIEW_REQUIRED`, with source-specific review incomplete. A public GET
endpoint is not an approval for aggregation or caching. No employer board is
approved by this status record, and source text cannot approve its own host,
terms, or capability. LinkedIn owner-export import remains unimplemented and
source-review-gated. These are closed gates, not successful feed readiness.

The command checks the immutable bundled defaults in memory: no live source is
enabled, external writes are disabled, and there is no implicit credential
access. It does not modify configuration, enumerate local files, access a
database, or use a network. JSON uses the deterministic
`sentinel.source-capability-status.v1` schema and includes implementation,
activation, credential-check, backend, account-check, and review-gate states
separately. It contains no fixture body, title, path, account name, secret, or
generated timestamp. Repeated output is byte-stable when package contents are
unchanged.

The typed read API is
`build_source_status_report() -> SourceStatusReport`, with
`format_text_source_status(report) -> str`,
`format_json_source_status(report) -> str`, and
`is_source_status_healthy(report) -> bool` in
`sentinel.readers.source_status`. Its immutable capability rows are defined in
`sentinel.readers.source_status_types`.

An invalid fixture or invalid bundled defaults produce the complete inventory
with `validation=FAILED` and a nonzero exit code; this is deliberate so the
operator sees which fixed checks failed without a false success. An unexpected
status/rendering failure produces no stdout and one fixed stderr message. The
command never reports production readiness. The detailed CR1 audit and the
remaining blockers are recorded in
[`docs/audit/cr1-release-exit-matrix.md`](docs/audit/cr1-release-exit-matrix.md).
The matrix records the independently reviewed §16 exit evidence; the current
bounded release status and remaining product gates are summarized above.

## CR1-T build and verify a local notes registry

Build a baseline from one to eight notes selected explicitly beneath one
allowlisted Windows local root:

```powershell
sentinel source notes-registry build `
  --allow-root C:\Notes `
  --file C:\Notes\meeting.md `
  --file C:\Notes\research.txt
```

`build` writes one deterministic UTF-8 JSON document to stdout and never saves
it. The operator may deliberately save those bytes as a `.txt` registry under
the same root, encoded as UTF-8 without a byte-order mark. For example, native
`cmd.exe` stdout redirection can save the CLI output:

```text
cmd.exe /d /c "sentinel source notes-registry build --allow-root C:\Notes --file C:\Notes\meeting.md --file C:\Notes\research.txt > C:\Notes\registered-notes.txt"
```

Sentinel itself does not create or modify the registry file. The registry uses the closed
`sentinel.local-notes-registry.v1` schema with only `schema_version` and
`entries`; each entry contains a canonical root-relative path, exact byte
length, and SHA-256 of the original UTF-8 bytes. Selected order is preserved.

Verify a saved baseline in a later process:

```powershell
sentinel source notes-registry verify `
  --allow-root C:\Notes `
  --registry C:\Notes\registered-notes.txt `
  --format text
```

Use `--format json` for the deterministic
`sentinel.local-notes-verification.v1` report. Verification returns only
ordinal/status records, counts, `T4_EXTERNAL` / `PRIVATE` labels, and the
explicit statement that hashes do not authenticate file authors. It does not
show registered names, current hashes, excerpts, or note bodies. A complete
valid registry with changed notes produces a complete `CHANGED` report and a
nonzero exit; missing, malformed, oversized, or unsafe input fails before
stdout. Verification never updates the baseline.

Registry generation explicitly discloses relative filenames and content
digests. This metadata can be sensitive or correlatable; it is not encrypted,
signed, anonymous, or tamperproof. A digest checks bytes against the saved
baseline, not who authored them. The notes remain untrusted `T4_EXTERNAL` and
`PRIVATE`. Sentinel does not persist their bodies in SQLite or the PUBLIC blob
store, and it does not create tasks or proposals.

Both commands reuse CR1-M's allowlisted reader for each file, including the
existing `.txt` / `.md`, strict UTF-8, one-MiB, local fixed-volume, reparse,
hard-link, and path-boundary checks. The registry is itself selected and
validated through that reader, must be `.txt`, and is capped at 16 KiB. The
closed schema rejects duplicate JSON keys, unknown fields, duplicate/case-alias
entries, traversal, absolute paths, device names, alternate streams, and a
registry that references itself. Verification resolves only validated
root-relative components and asks CR1-M to validate each resulting file; it
does not use a string-prefix check as a containment boundary.

Build rereads the selected metadata before rendering. Verify reads the
registry and all notes, then rereads them once to reject detectable ordinary
changes. These independent filesystem handles do not form one atomic snapshot
and cannot rule out every ABA or malicious same-user replacement race. The two
existing Windows symlink-creation tests remain skipped on hosts where the OS
denies their creation; CR1-M's controlled boundary tests and existing reader
checks remain in force. No watcher, directory discovery, network, provider,
database, blob write, or private-content storage is added. Broader F10 remains
`IN_PROGRESS`; the registered-notes behavior is one bounded explicit-file
workflow in the verified offline CR1 core.

## CR1-U deterministic job-alert triage

Use `sentinel source triage-job-alerts` to create a deterministic, typed
projection from one to eight explicitly selected local `.txt` or `.md` files:

```powershell
sentinel source triage-job-alerts `
  --allow-root C:\Notes `
  --file C:\Notes\alert-one.txt `
  --file C:\Notes\alert-two.md `
  --format json
```

The command reuses CR1-P's explicit Windows allowlist checks, CR1-O's labeled
field parser and byte-citation validation, and CR1-P's whole-batch source
stability checks. It does not add a parser or infer facts from prose. Its
closed signal vocabulary is `JOB_ALERT_CANDIDATE`,
`APPLICATION_URL_DECLARED`, and `DEADLINE_DATE_DECLARED`. A candidate signal
requires verified `company` and `role` field citations; URL and date signals
appear only when those accepted fields are present. `INCOMPLETE` and
`AMBIGUOUS` records remain `REVIEW_REQUIRED`; `NO_MATCH` remains `NO_SIGNAL`.
No fields are joined across files, and duplicate bodies or shared URLs never
merge records.

The output schema is `sentinel.job-alert-triage.v1`. Items follow the explicit
file order; signals follow the registered kind order. Each signal ID is a
domain-separated deterministic UUID derived from the source identity, signal
kind, and supporting field span IDs. Positive signal evidence preserves source
UUID, source SHA-256, field ID, source-bound span UUID, half-open UTF-8 byte range,
and exact slice SHA-256. Original source material remains `T4_EXTERNAL` /
`PRIVATE`; projected signals are `T3_DERIVED` / `PRIVATE`. These labels and
citations do not authenticate the source, employer, vacancy, owner intent,
eligibility, application status, or deadline validity.

By default, output contains field states and citations but hides company,
role, URL, and deadline values. `--show-fields` deliberately discloses only
the already accepted `PRESENT` field values, escaped by the existing
terminal-safe formatter. Neither mode displays the source body. Errors produce
no partial stdout and use fixed messages; rendered output is capped at 128
KiB.

This implementation is deliberately local and deterministic. CR1-O/P PRIVATE
source bodies are never sent to ModelGateway: CR0-D currently admits synthetic
PUBLIC demo traffic only, and its gate is unchanged. Triage performs no model,
network, credential, tool, SQLite, blob, task, or application operation. It
does not create summaries, rankings, priorities, tasks, or recommendations.
The narrow labeled-field parser misses prose-only candidate examples; this
slice does not improve extraction recall and is not general F13 completion.

### CR1-U reproducible fictional evaluation

The tests-only evaluation inputs and expected-label manifest are separately
versioned and SHA-256 pinned in `tests/cr1_u_corpus.py`:

- Development: 24 cases; corpus SHA-256
  `13e4374e7cee04a1d08d9987376dc6d764eb737b63f1965ca756964fa0e820b5`.
- Holdout: 30 cases; corpus SHA-256
  `645bdaf8a2725e4228de49490b568ef92bcc37b4352b73e8ff3d439d026d47ba`.
- Expected-label manifest SHA-256
  `482008fb933808175d4ab1847d6c055b772dcb7a13abc388b2f941dabcbc2e79`.

All cases are fictional. The corpus exercises required and optional fields,
incomplete and ambiguous records, duplicate bytes, shared URLs, Unicode,
CRLF, repeated listings, unsupported prose, injection-like text, invalid
bytes, and parser limits. It is authored contract data, not an independently
collected real-world benchmark. The evaluator reports parser classification
confusion separately from exact typed-signal precision/recall/F1 and counts
verified evidence references, missing evidence, invalid citations, and
cross-source evidence. A signal matches only when both its kind and ordered
required field IDs match exactly. A zero denominator yields zero.

Measured holdout results: classification accuracy is 26/28 (92.86%) over
in-bound cases; candidate-signal precision is 1.00, recall is 12/14 (85.71%),
and F1 is 12/13 (92.31%). Application-URL and deadline signal F1 are each
1.00; micro signal F1 is 25/26 (96.15%); macro signal F1 is 97.44%. There are
zero candidate false positives, two candidate false negatives, zero missing
or invalid citations, and zero cross-source evidence errors. The two missed
holdout candidates are natural-language descriptions that CR1-O classifies as
`NO_MATCH`; deterministic triage does not guess beyond that parser contract.
Development results and full confusion matrices are recorded in
`docs/audit/cr1-u-evaluation.md`.

F13 remains IN_PROGRESS: CR1-U/V provide bounded deterministic cited-field
signals and fictional evaluation, while model-mediated PRIVATE triage remains
gated. The independent CR1-W scope review finds that §16 does not make full
model-mediated F13 a CR1 exit test; its row D passes only for the bounded CR1
criterion. This is not F13 completion or CR1 release approval. The separate
release scope is accepted for the bounded offline CR1 core. Full F13 remains
IN_PROGRESS, and model-mediated PRIVATE triage remains gated.
