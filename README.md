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
