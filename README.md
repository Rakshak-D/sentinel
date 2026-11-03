# Sentinel

Sentinel is a planned local-first personal automation application. Its authoritative design is [the Sentinel Master Blueprint](docs/spec/Sentinel%20Master%20Blueprint.pdf); [the build ledger](docs/BUILD_LEDGER.md) tracks implementation evidence and remaining gates. The architecture separates untrusted source content, model access through `ModelGateway`, tool effects through `ToolGateway`, and a deterministic policy reference monitor.

## Implemented bootstrap slices

CR0-A establishes repository governance, a Python package, and an installable CLI. CR0-B adds immutable typed source and model/tool boundary envelopes. CR0-C adds an explicit SQLite connection API and a versioned migration foundation. CR0-D adds centralized, demo-only `ModelGateway.generate()` and `ToolGateway.call()` wrappers. CR0-E adds an allowlisted structured diagnostic event and JSON Lines sink API. CR0-F adds strictly validated, immutable bundled configuration defaults and a deterministic SHA-256 fingerprint. CR0-G adds a fail-closed credential broker contract; CR0-H adds explicit new-database initialization; CR0-I adds read-only diagnostics; CR0-J adds one deterministic synthetic `demo` flow through the existing gateway methods. These slices do not complete F38, F43, F46, or CR0.

There is no agent, live provider adapter, MCP worker, policy engine, approval system, provider integration, daemon, or frontend. CR0-H adds `sentinel init` for one explicitly selected new database; CR0-I adds read-only diagnostics for an existing database; CR0-J adds a fixed-fixture `sentinel demo` that uses only in-memory synthetic adapters. CR0-C's only schema is `schema_migrations`; no task, source, approval, audit, or user-data table is included. No live model, HTTP provider, MCP, or external-tool calls are wired. External writes are unavailable. These bootstrap slices do not demonstrate later security invariants.

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

The CLI reserves the exact target with the operating system's exclusive-create operation, then calls the existing trusted storage migration API. It applies the currently registered foundation migration `cr0-c-0001-schema-migrations`, verifies the registered artifact digest and expected schema, and runs SQLite integrity and foreign-key checks. File-backed connection setup retains the existing `foreign_keys=ON`, WAL, and bounded busy timeout behavior. Success output is fixed and does not disclose the path. Invalid paths and initialization failures exit unsuccessfully with bounded messages that omit exception text and path values.

If initialization fails after exclusive creation, the newly reserved file and any SQLite-owned sidecars are left for inspection. The command does not attempt path-based cleanup because a concurrent path replacement could make deletion unsafe. Resolve the cause before manually removing that exact disposable path.

Exclusive creation uses `O_CREAT|O_EXCL`, which refuses an already present final-component path, and adds `O_NOFOLLOW` where the host exposes it. The symlink test could not run here because Windows denied symlink creation without elevated support. This does not establish full race-free filesystem protection: directory junctions/reparse points are not comprehensively defended against, and a process able to replace directory entries concurrently may race subsequent SQLite path opens. The implementation checks the reserved file identity before and after storage operations, but does not claim protection from a hostile process with directory write access.

CR0-H adds only the `init` command. CR0-I adds read-only `doctor`; CR0-J adds a synthetic in-memory `demo`. Configuration activation, application tables, writer leases, backup/restore, credential retrieval, providers, external tools, and external writes remain unavailable. Initialization is an explicit local filesystem effect, not owner authorization or a policy decision.

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

A successful demo proves that this fixed packaged fixture validates and that the current synthetic gateway success/denial contracts and content hashes behave as expected. It does not demonstrate LLM inference, production model/tool adapters, network or credential isolation for future code, policy authorization, human approval, production readiness, or P00-P17/AB01-AB18 compliance. The demo's source labels and gateway contract checks are not security certification. The clean offline install from locally cached pinned artifacts remains an outstanding CR0 exit gate; CR0 stays IN_PROGRESS.
