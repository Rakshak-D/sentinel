# Sentinel

Sentinel is a planned local-first personal automation application. Its authoritative design is [the Sentinel Master Blueprint](docs/spec/Sentinel%20Master%20Blueprint.pdf); [the build ledger](docs/BUILD_LEDGER.md) tracks implementation evidence and remaining gates. The architecture separates untrusted source content, model access through `ModelGateway`, tool effects through `ToolGateway`, and a deterministic policy reference monitor.

## Implemented bootstrap slices

CR0-A establishes repository governance, a Python package, and an installable CLI. CR0-B adds immutable typed source and model/tool boundary envelopes. CR0-C adds an explicit SQLite connection API and a versioned migration foundation. CR0-D adds centralized, demo-only `ModelGateway.generate()` and `ToolGateway.call()` wrappers. CR0-E adds an allowlisted structured diagnostic event and JSON Lines sink API. CR0-F adds strictly validated, immutable bundled configuration defaults and a deterministic SHA-256 fingerprint. CR0-G adds a fail-closed credential broker contract; CR0-H adds explicit new-database initialization; CR0-I adds read-only diagnostics; CR0-J adds one deterministic synthetic `demo` flow through the existing gateway methods. CR1-A adds an in-memory UTF-8 plain-text normalizer and verified byte-span citations. CR0 is accepted only for the recorded Windows x64 / CPython 3.11.7 / Sentinel 0.1.0 scope; CR1-A does not complete F12, F43, F46, or CR1.

There is no agent, live provider adapter, MCP worker, policy engine, approval system, provider integration, daemon, or frontend. CR0-H adds `sentinel init` for one explicitly selected new database; CR0-I adds read-only diagnostics for an existing database; CR0-J adds a fixed-fixture `sentinel demo` that uses only in-memory synthetic adapters. CR0-C's only schema is `schema_migrations`; no task, source, approval, audit, or user-data table is included. No live model, HTTP provider, MCP, or external-tool calls are wired. External writes are unavailable. These bootstrap slices do not demonstrate later security invariants.

The project metadata now identifies ongoing CR1 development as `0.2.0.dev0`. The immutable CR0 tag and the historical `requirements/cr0-windows-py311.lock` retain the accepted `0.1.0` release identity and hashes.

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

The CLI reserves the exact target with the operating system's exclusive-create operation, then calls the trusted storage migration API. In the CR1 development build it applies the registered foundation migration `cr0-c-0001-schema-migrations` followed by `cr1-e-0002-source-registry`, verifies each artifact and the complete expected schema checkpoint, and runs SQLite integrity and foreign-key checks. File-backed connection setup retains the existing `foreign_keys=ON`, WAL, and bounded busy timeout behavior. Success output is fixed and does not disclose the path. Invalid paths and initialization failures exit unsuccessfully with bounded messages that omit exception text and path values. The historical CR0 0.1.0 wheel and lock remain unchanged; this description is for the current 0.2.0.dev0 source build.

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
