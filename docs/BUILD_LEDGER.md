# Sentinel build ledger

Canonical project status. Statuses describe implementation evidence, not the blueprint's intended product scope. The authoritative source is the Master Blueprint dated 2026-11-01.

## A. Project metadata

| Field | Value |
|---|---|
| Authoritative blueprint | `docs/spec/Sentinel Master Blueprint.pdf` |
| Blueprint SHA-256 | `92911A27CDA2AACE41616E5A45F07E228C3D21838E8EB93A30BF71CF228701E7` |
| Current release / active slice | CR0 / CR0-E — redacted structured diagnostic logging |
| Previous accepted slice | CR0-D implementation; correction starting HEAD `f294b8dafc2323ade712a90365aa80ae4ac2684f` |
| CR0-B slice status | VERIFIED (contract slice only; CR0 remains IN_PROGRESS) |
| CR0-B implementation commit | `f5833df063807c0fe383d5a10109cd5e2657ac31` |
| CR0-C slice status | VERIFIED (migration foundation and trusted schema-checkpoint extension; CR0 remains IN_PROGRESS) |
| CR0-C implementation commit | `784707ab813c4e974655fc50c03a131f468d69e4` |
| CR0-C correction commit | `97d163cc5e2f4cfae86b4c516a117267ab97c1ca` |
| CR0-D slice status | VERIFIED (synthetic demo gateways only; no real provider, policy, or approval capability; CR0 remains IN_PROGRESS) |
| CR0-D implementation commit | `ef1808981c19b9a28ef451487a1a30a878212ece` |
| CR0-D model-ID correction status | VERIFIED (consistent provider model-ID contract; CR0 remains IN_PROGRESS) |
| CR0-D model-ID correction commit | `a6bf06a2883174bdca597119d28dee8af6fe240b` |
| CR0-E slice status | VERIFIED (allowlisted ephemeral diagnostic event/logger foundation only; CR0 remains IN_PROGRESS) |
| CR0-E implementation commit | `3bd30c4688180d0f215fac928622f0c503391c9e` |
| Branch | `main` |
| Initial implementation commit | `61c218f7f0ebb5185a15cb2ce86e82b7918adac3` (root commit; author email uses GitHub noreply) |
| GitHub remote | `https://github.com/Rakshak-D/sentinel` (`origin`, `main`; visibility PUBLIC as of 2026-11-02) |
| Environment | Windows, pyenv-win 3.11.7, project-local `.venv` |
| Selected interpreter | Python 3.11.7 (`.venv\Scripts\python.exe`) |
| Dependency management | `pyproject.toml`, setuptools build backend, pip through explicit venv interpreter; no lockfile yet |
| Environment inspection | Git 2.53.0.windows.2; Python initially resolved to 3.14.2; pyenv 3.14.2; installed versions 3.10.11, 3.11.7, 3.14.2; Node v24.14.0; npm 11.12.1. Python 3.11.7 was selected and verified. |
| Installed runtime/dev packages | sentinel 0.1.0; typer 0.27.3; rich 15.0.0; pytest 8.4.2; ruff 0.17.3; mypy 1.20.2; build 1.6.1; packaging 26.3; pluggy 1.7.0; setuptools in isolated wheel build 84.2.1. Full resolved environment: annotated-doc 0.0.5, colorama 0.4.6, iniconfig 2.3.1, librt 0.16.0, markdown-it-py 4.2.0, mdurl 0.1.2, mypy_extensions 1.1.0, pathspec 1.1.1, pyproject_hooks 1.3.3, Pygments 2.21.0, shellingham 1.5.4, typing_extensions 4.16.0. Local pip 23.2.1 and setuptools 65.5.0 are present in the venv; build isolation selected setuptools 84.2.1. |
| CR0-B dependency | Pydantic 2.14.2; pydantic-core 2.50.2; annotated-types 0.8.0; typing-inspection 0.4.4. Registry checked via PyPI through the local pip index; constrained as `pydantic>=2,<3`. No lockfile claimed. |
| CR0-C SQLite runtime | SQLite 3.43.1, observed via `.venv\Scripts\python.exe -c "import sqlite3; print(sqlite3.sqlite_version)"` |
| CR0-C migration artifact | `cr0-c-0001-schema-migrations`; canonical-artifact SHA-256 `b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217` |
| CR0-C foundation schema checkpoint | SHA-256 `1f4d935bf45b5c09f68b4f6e3deb18846aa6d9ee14510eed89b3ab4a71139d30`; separately pinned to preserve historical migration artifact validation |

The Master Blueprint does not define a one-to-one release assignment for every feature ID. The assignment column below is the ledger's dependency-based planning map; it does not claim a verbatim per-feature assignment from the blueprint. Names and scope states come from section 2.

## B. Feature catalogue F01-F46

| ID | Exact blueprint feature name | Blueprint target scope | Implementation status | Release assignment | Evidence reference | Open blocker |
|---|---|---|---|---|---|---|
| F01 | Gmail read-only OAuth | ACTIVE TARGET | NOT_STARTED | CR4 | Master Blueprint §2 | OAuth/read worker not implemented |
| F02 | IMAP app-password alternative | GATED: owner choice | GATED | CR4 | Master Blueprint §2 | Owner decision and scope review |
| F03 | GitHub selected repositories | ACTIVE TARGET | NOT_STARTED | CR4 | Master Blueprint §2 | Read worker and credential scope |
| F04 | GitHub notification mail | ACTIVE TARGET | NOT_STARTED | CR4 | Master Blueprint §2 | Depends on F01 and GitHub reader |
| F05 | Job-alert email parser | ACTIVE TARGET | NOT_STARTED | CR1 | Master Blueprint §2 | Parser and synthetic accuracy suite |
| F06 | Public Greenhouse feeds | GATED: per-board legal check | GATED | CR1 | Master Blueprint §2 | Per-board terms review |
| F07 | Public Lever feeds | GATED: per-site legal check | GATED | CR1 | Master Blueprint §2 | Per-site terms review |
| F08 | LinkedIn owner-export import | GATED: verify specific archive | GATED | CR1 | Master Blueprint §2 | Archive schema verification |
| F09 | Google Calendar read | ACTIVE TARGET | NOT_STARTED | CR4 | Master Blueprint §2 | OAuth/read worker not implemented |
| F10 | Allowlisted notes/files | ACTIVE TARGET | NOT_STARTED | CR1 | Master Blueprint §2 | Path and symlink controls not implemented |
| F11 | Local task store | ACTIVE TARGET | NOT_STARTED | CR1 | Master Blueprint §2 | Durable store and idempotency absent |
| F12 | Source normalization | ACTIVE TARGET | IN_PROGRESS | CR1 | `sentinel.contracts.SourceEnvelope`; CR0-B contract tests | Normalization, deduplication, readers, and source behavior remain absent |
| F13 | Triage and extraction | ACTIVE TARGET | NOT_STARTED | CR1 | Master Blueprint §2 | No triage/extraction workflow, production prompt set, or evaluation exists; CR0-D is only a synthetic wrapper |
| F14 | Job/profile matching | ACTIVE TARGET | NOT_STARTED | CR1 | Master Blueprint §2 | Retriever and ranking evaluation absent |
| F15 | Structured daily briefing | ACTIVE TARGET | NOT_STARTED | CR1 | Master Blueprint §2 | Citation-backed product flow absent |
| F16 | Scheduler and daemon | ACTIVE TARGET | NOT_STARTED | CR4 | Master Blueprint §2 | Durable scheduler absent |
| F17 | Desktop/terminal notifications | ACTIVE TARGET | NOT_STARTED | CR4 | Master Blueprint §2 | Notification adapters absent |
| F18 | Persistent incremental sync | ACTIVE TARGET | NOT_STARTED | CR1 | Master Blueprint §2 | Cursor persistence/recovery absent |
| F19 | Rate-limit/backoff | ACTIVE TARGET | NOT_STARTED | CR1 | Master Blueprint §2 | Production tool adapters, rate limits, backoff, and provider controls absent; CR0-D makes no retries |
| F20 | Provenance envelopes | ACTIVE TARGET | IN_PROGRESS | CR2 | `sentinel.contracts.SourceEnvelope`; CR0-B contract tests | Structure only; provenance production, enforcement, and causal completeness are absent |
| F21 | Deterministic policy gate | ACTIVE TARGET | NOT_STARTED | CR2 | Master Blueprint §2 | Policy engine absent |
| F22 | Human-verified approval inbox | GATED: valid human channel | GATED | CR2/CR7 | Master Blueprint §2, §6 | User-verifying channel not implemented |
| F23 | Credential isolation | GATED: OS isolation verified | GATED | CR7 | Master Blueprint §2 | OS isolation evidence absent |
| F24 | Gmail draft writer | GATED/OFF | GATED | CR7 | Master Blueprint §2 | Isolated credential, approval, and tests absent |
| F25 | Gmail send writer | GATED/OFF | GATED | CR7 | Master Blueprint §2 | Send capability must remain OFF |
| F26 | GitHub comments | GATED/OFF | GATED | CR7 | Master Blueprint §2 | Writer, isolated token, and approval absent |
| F27 | GitHub labels | GATED/OFF | GATED | CR7 | Master Blueprint §2 | Writer, isolated token, and approval absent |
| F28 | Idempotency/reconciliation | ACTIVE TARGET | NOT_STARTED | CR2 | Master Blueprint §2 | Transactional effect ledger absent |
| F29 | Boundary record/replay | ACTIVE TARGET | IN_PROGRESS | CR3 | `sentinel.contracts.BoundaryEnvelope`; CR0-B contract tests | Envelope only; recording, storage, replay, and no-network guarantees are absent |
| F30 | Policy/prompt mutation suite | ACTIVE TARGET | NOT_STARTED | CR3 | Master Blueprint §2 | Mutation suite absent |
| F31 | Audit hash chain | ACTIVE TARGET | NOT_STARTED | CR8 | Master Blueprint §2 | Audit chain/verifier absent |
| F32 | Signed audit roots | ACTIVE TARGET | NOT_STARTED | CR8 | Master Blueprint §2 | Independent signing/root export absent |
| F33 | Static privacy selector | ACTIVE TARGET | NOT_STARTED | CR5 | Master Blueprint §2 | CR0-D only refuses non-PUBLIC model inputs; CR5 profile selection and egress policy absent |
| F34 | Ollama/Gemini/OpenAI/OpenRouter | ACTIVE TARGET | NOT_STARTED | CR5 | Master Blueprint §2 | No provider SDKs or live adapters; CR0-D permits only trusted synthetic demo code |
| F35 | Learned routing gate | GATED; negative result acceptable | GATED | CR9 | Master Blueprint §2 | CR5 baseline and paired evaluation absent |
| F36 | Governed memory | ACTIVE TARGET | NOT_STARTED | CR6 | Master Blueprint §2 | Memory lifecycle absent |
| F37 | Pluggable hybrid RAG | ACTIVE TARGET; opt-in default | NOT_STARTED | CR6 | Master Blueprint §2 | Retriever and ablation absent |
| F38 | Layered validated config | ACTIVE TARGET | NOT_STARTED | CR4 | Master Blueprint §2 | Config schema/evaluation absent |
| F39 | Signed/reviewed plugin registry | ACTIVE TARGET | NOT_STARTED | CR3 | Master Blueprint §2 | Manifest and sandbox absent |
| F40 | Versioned prompt store | ACTIVE TARGET | NOT_STARTED | CR5 | Master Blueprint §2 | Prompt inventory/store absent |
| F41 | Briefing/theme/schedule customization | ACTIVE TARGET | NOT_STARTED | CR4 | Master Blueprint §2 | Config/UI absent |
| F42 | Config-change quick eval | ACTIVE TARGET | NOT_STARTED | CR2 | Master Blueprint §2 | Evaluation gate absent |
| F43 | CLI + optional Textual | ACTIVE TARGET | IN_PROGRESS | CR0 bootstrap; later CR1-CR4 surfaces | `src/sentinel/cli.py`; `tests/test_cli.py`; CR0-A acceptance output | Only `--help` and `version` bootstrap; full command tree, golden output, approval negative tests remain |
| F44 | React web control plane | ACTIVE TARGET | NOT_STARTED | CR4 | Master Blueprint §2 | Frontend/API absent |
| F45 | Sentinel-as-MCP server | ACTIVE TARGET | NOT_STARTED | CR3 | Master Blueprint §2 | MCP adapter absent; approval must never be exposed |
| F46 | Diagnostic/backup/restore/migrations | ACTIVE TARGET | IN_PROGRESS | CR0 bootstrap; CR4/CR8 capability | `sentinel.storage`; `sentinel.observability`; `tests/test_storage_connection.py`; `tests/test_storage_migrations.py`; `tests/test_observability_events.py`; `tests/test_observability_logging.py`; CR0-C/CR0-E acceptance evidence | Only an ephemeral allowlisted event/log writer is implemented; CLI/storage/gateway integration, production application tables, backup/restore, and clean offline install remain unavailable |

## C. Release table CR0-CR9

| Release | Dependency | Status | Exit criteria | Verified evidence |
|---|---|---|---|---|
| CR0 — Package and trust skeleton | Initial foundation | IN_PROGRESS (CR0-A through CR0-E foundations only) | Offline pinned install; wheel/CLI (`init`, `doctor`, `demo`); typed envelopes, SQLite migrations, redacted logs, keychain abstraction, default config, demo fixtures | CR0-A CLI, CR0-B contracts, CR0-C migration foundation/checkpoints, CR0-D synthetic gateway tests, and CR0-E diagnostic event/logger tests; offline install and remaining CR0 deliverables not verified |
| CR1 — Daily read/product core | CR0 | NOT_STARTED | Source normalization/citation tests; missing credentials clear; one-shot CLI restart behavior | None |
| CR2 — Deterministic authorization | CR1 | NOT_STARTED | P00-P17 hard cases, no direct tool bypass, task idempotency/outbox crash matrix | None |
| CR3 — MCP and regression platform | CR2 | NOT_STARTED | MCP conformance, no approve tools, replay without network, seeded mutations caught, manifest hashing | None |
| CR4 — Continuous operation + all local UX | CR3 | NOT_STARTED | Daemon restart/cursor repair, six keyboard scripts, restore/import/export, scope review, localhost CSRF/session tests | None |
| CR5 — Four-model privacy gateway | CR4 | NOT_STARTED | Sensitivity egress oracles, provider contract/unsupported state, sealed paired report | None |
| CR6 — Governed memory and retrieval | CR5 | NOT_STARTED | Longitudinal suite, BM25/hybrid comparison, negative ablation if needed | None |
| CR7 — Optional credential-isolated writes | CR2-CR6 plus verified OS user channel | GATED | AB01-AB18, eval quick, isolation, reconciled throwaway effects; failure leaves writes OFF; live activation after CR8 | None; writes remain unavailable |
| CR8 — Signed audit and operational assurance | CR2-CR7 | NOT_STARTED | Adversarial alteration suite, independent root verifies after restore, no unsigned privileged effect | None |
| CR9 — Learned-router evidence gate | CR5 + full static baseline | NOT_STARTED | Activate only with pre-registered paired benefit; otherwise preserve static routing and report negative result | None |

## D. Policy P00-P17

Initial status for every rule is NOT_STARTED. Blueprint wording below is a short identifier, not an implementation claim.

| Rule | Blueprint rule | Status | Test/evidence reference |
|---|---|---|---|
| P00 | Hard malformed/unregistered/mismatch/invalid principal/engine error deny | NOT_STARTED | None |
| P01 | Hard replay/live effect and gateway bypass deny | NOT_STARTED | None |
| P02 | Hard C4/C5 disabled or missing isolated worker/scope deny | NOT_STARTED | None |
| P03 | Hard SECRET/raw PRIVATE/unknown sensitivity model egress deny | NOT_STARTED | None |
| P04 | Scoped C0 allowlisted GET | NOT_STARTED | None |
| P05 | Owner-authorized C1 private read | NOT_STARTED | None |
| P06 | Bounded sanitized C2 suggestion to proposal only | NOT_STARTED | None |
| P07 | Exact pre-authorized C3 local task action | NOT_STARTED | None |
| P08 | Derived/external C3 task action pending human | NOT_STARTED | None |
| P09 | Missing/forged lineage, stale intent/config/hash, unsafe target deny | NOT_STARTED | None |
| P10 | Pending action with verified one-use owner proof | NOT_STARTED | None |
| P11 | Rejected/expired/revoked/consumed/wrong approval deny | NOT_STARTED | None |
| P12 | Catch-all deny | NOT_STARTED | None |
| P13 | Gmail draft always pending with isolated write credential | NOT_STARTED | None |
| P14 | Gmail send always pending with isolated credential and recipient allowlist | NOT_STARTED | None |
| P15 | GitHub comments/labels always pending with isolated credential | NOT_STARTED | None |
| P16 | CLI flag/stdin/PTY/session token alone cannot approve | NOT_STARTED | None |
| P17 | Model/front end/external source secret retrieval deny | NOT_STARTED | None |

## E. Bypass suite AB01-AB18

Every case remains NOT_STARTED; the CLI bootstrap is not bypass-test evidence.

| Test | Status | Evidence reference |
|---|---|---|
| AB01 | NOT_STARTED | None |
| AB02 | NOT_STARTED | None |
| AB03 | NOT_STARTED | None |
| AB04 | NOT_STARTED | None |
| AB05 | NOT_STARTED | None |
| AB06 | NOT_STARTED | None |
| AB07 | NOT_STARTED | None |
| AB08 | NOT_STARTED | None |
| AB09 | NOT_STARTED | None |
| AB10 | NOT_STARTED | None |
| AB11 | NOT_STARTED | None |
| AB12 | NOT_STARTED | None |
| AB13 | NOT_STARTED | None |
| AB14 | NOT_STARTED | None |
| AB15 | NOT_STARTED | None |
| AB16 | NOT_STARTED | None |
| AB17 | NOT_STARTED | None |
| AB18 | NOT_STARTED | None |

## F. Decisions and ADR index

| ADR | Decision | Status |
|---|---|---|
| [ADR-0001](adr/0001-python-environment-and-packaging.md) | pyenv-win + pip + local venv; pip/setuptools package bootstrap without requiring uv in CR0-A | Accepted |

## G. Deviations and unresolved ambiguities

- The Master Blueprint presents uv as a candidate tool for installation/locking, with its exact pin unverified. CR0-A uses the owner's requested pyenv + pip workflow and records the deviation from the table's `SQLite/uv tools` alternative for F46 in ADR-0001. Locking/offline requirements remain CR0 exit gates.
- The blueprint assigns capability dependencies and release exits but does not give a one-to-one release label for every F01-F46 row. The feature release column is a dependency-based planning map, not a quoted blueprint assignment.
- The blueprint requests the broader CR0 skeleton. CR0-A implements only package governance and two real CLI commands; remaining CR0 work is intentionally incomplete.
- CR0-C interprets the first migration as the minimum legitimate slice: it creates only `schema_migrations` and its required `applied_at` index. The broader §10 application schema is deliberately not synthesized in this slice.
- CR0-C correction root cause: the first storage implementation compared every database to a single foundation-only `EXPECTED_SCHEMA_OBJECTS` set after every migration, so a trusted migration adding application tables or indexes was rolled back. The correction selects a complete trusted schema checkpoint from the validated applied migration prefix; it does not learn allowed objects from SQLite contents.
- CR0-D correction root cause: `ModelRequest` and `ModelAdapterRegistration` allowed slash-containing provider model IDs, while `ModelInvocation` and `ModelResponse.provider_model_id` used the narrower `GatewayIdentifier`. The correction uses the existing `ModelIdentifier` type alias for every provider model-ID field and validates registration values through that same Pydantic type definition.
- CR0-E event-schema interpretation: the blueprint requires sanitized small metadata and redaction of Authorization, cookies, email bodies, and access-token data but does not define a diagnostic DTO. This slice uses a fixed event-code/severity/outcome vocabulary, UTC timestamp, optional UUID correlations, a fixed component enum, optional existing sensitivity enum, and optional registered error code. It has no free-form message or metadata map. No material blueprint deviation was required.

## H. Open issues and verification blockers

- Verify the selected dependency graph in a fresh clean install; capture exact dependency versions and solver output.
- Create and verify a deterministic hash-pinned lock and local wheelhouse; pass an offline clean install before CR0 exit.
- Complete CR0 clean offline install, remaining schema/migration inventory, keychain abstraction, default config, demo fixtures, and `init`, `doctor`, `demo` commands. CR0-E supplies a reusable diagnostic API only; later CLI/doctor/storage/gateway integration and unrelated-library log review remain open.
- Decide supported Python/OS matrix and verify each selected interpreter/platform combination.
- Later policy, authenticated provenance authority, approval, credential isolation, live model/tool adapters, application-wide SQLite writer lease, and external-write gates are entirely unimplemented. Keep external writes disabled.
- CR0-C correction regression evidence: a trusted test-only migration creates a real table with a CHECK constraint and an index; separate test-only migrations cover index-only and data-only schema checkpoints. Legacy foundation rows and application records remain preserved during upgrade/reopen. Extra/missing objects and changed checkpoint digests fail closed. No production application table was registered.
- Credential-pattern scan of the proposed tracked files and supplied reference text found no matches; email-address scan of the references found no matches; Master Blueprint PDF metadata contains title/creator/producer only and no author field. References are preserved and safe for this initial commit review.
- Package metadata is intentionally restricted to Python 3.11 (`>=3.11,<3.12`); Python 3.12 support is not claimed because it was not verified in this slice.

Dependency resolution used the live PyPI registry through the project venv and completed without a solver error. No lockfile, hash pinning, wheelhouse, clean-environment installation, or offline installation has been verified. The selected package versions are current install evidence only, not a reproducible lock.

CR0-B schema decisions: trust values preserve the literal §6 labels (`T0 POLICY` through `T5 UNKNOWN`); sensitivity accepts only `PUBLIC`, `INTERNAL`, `PRIVATE`, and `SECRET`; all envelope collections are tuples and models reject extras and field assignment. Timestamps must be timezone-aware and normalize to UTC. Digest strings are lowercase 64-character hex; content references use `sha256:<hex>` and must match their corresponding digest. Boundary `seq` is interpreted as 1-based and positive. Nullable response fields and `error_code` remain nullable, but their fields must be supplied. A ByteSpan enforces `0 <= start_byte < end_byte`; the blueprint does not put source byte length in SourceEnvelope, so an upper-bound check against source body length is out of scope. These are ordinary schema interpretations, not a material blueprint deviation. A T1 value is only a label, never authenticated authority.

CR0-B defines data structures only. CR0-D adds demo-only `ModelGateway.generate()` and `ToolGateway.call()` wrappers with in-memory test adapters. Policy, approval, source ingestion, boundary persistence/replay, live provider/model execution, and external effects remain unimplemented. Canonical JSON for CR0-B contracts and CR0-D adapter-call bytes is not the future approval-digest or audit-chain algorithm.

The canonical helpers accept only the exact two contract classes and revalidate `model_dump(mode="python")` before canonical JSON/hash generation, protecting against invalid state introduced through Pydantic's unchecked copy/construct escape hatches. This still validates structure only and is not an adversarial authority boundary.

CR0-C schema decisions: the first transaction creates only the normative `schema_migrations` table (`migration_id`, `applied_at`, `artifact_sha256`, `app_build`, `success`) and its `applied_at` index; no application table is inferred from the broader §10 inventory. The registered artifact `cr0-c-0001-schema-migrations` hashes canonical UTF-8 JSON containing the migration ID and ordered SQL statements. Successful rows record `success=1`; a failed migration rolls back its effects and row together rather than persisting a failed row. Applied timestamps are UTC ISO-8601 with microseconds, and histories must form the registry's ordered prefix. Missing DB files are refused by default; file creation requires `create=True`. Foreign-key enforcement is set and checked per connection; file databases must successfully enable WAL; the default busy timeout is 5 seconds, bounded to 60 seconds. SQLite integrity and foreign-key checks run before each migration commit and on initialized storage. WAL and `BEGIN IMMEDIATE` are not the §3 application-wide process writer lease. No migration bootstrap occurs outside a transaction.

CR0-C correction design: each trusted migration registers a complete `SchemaDefinition` checkpoint for its post-migration schema. The verifier compares the exact set of table/index/view/trigger objects and their DDL, plus the normative `schema_migrations` columns/index and SQLite integrity checks. It selects the checkpoint associated with the last ID in the validated applied migration prefix. New artifact v2 digests include both ordered SQL and checkpoint content; data-only migrations carry the full unchanged object inventory at a new checkpoint version. The foundation remains artifact v1 with its original canonical bytes and SHA-256, and its checkpoint has an independent pinned SHA-256. Test-only migrations cover real table/index/constraint expansion, index-only and data-only changes, legacy database upgrade, preservation, repeat initialization, altered checkpoint digest, unregistered schema objects, and rollback. No production application schema migration is added.

No material blueprint deviation was required, so no CR0-C ADR was created. This slice does not implement the full §10 schema, application writer lease, backup/restore, checkpointing, encryption, redacted logs, keychain abstraction, diagnostics, or application workflows. The repository visibility is currently PUBLIC; this metadata is not a security certification.

CR0-D gateway decisions: ModelRequest follows the §7 field set with adapter/model IDs resolved only against exact static registrations. Its trust labels are not caller fields; source IDs resolve to revalidated SourceEnvelope values held in the trusted registry. ModelRequest carries only `payload_ref`; bounded UTF-8 bytes are held separately in a trusted `DemoPayload` tuple on `GatewayRegistry`. Registry construction revalidates each payload digest and requires it to match a registered source digest. The gateway resolves those bytes only after request, source, profile, locality, and sensitivity checks pass. Request sensitivity must equal the maximum registered source sensitivity; only PUBLIC, `local-only`, loopback, `sentinel.text.v1` calls execute. Other sensitivities, cloud-classified routes, hybrid/cloud profiles, live mode, replay, and unsupported schemas are refused. Provider model IDs share the `ModelIdentifier` grammar across request, registration, invocation, and response types, including registered slash-separated IDs. The demo uses plain text output; raw and parsed references are the same content hash. Token counts and billing are unknown (`None`), not fabricated zeroes.

ToolRequest permits only sorted immutable scalar string arguments. A static ToolAdapterRegistration supplies the exact argument-name allowlist and capability. Only DEMO + READ_ONLY registrations can execute; WRITE_LOCAL, WRITE_EXTERNAL, SEND, APPROVAL, and EXECUTE are denied. No approval data is accepted or evaluated. Both gateways return `authorization=NOT_EVALUATED`, do not retry, and use bounded error codes/messages. Their built-in data contracts set `external_effect=False`, but registry adapters are trusted application code and are not sandboxed; the included test adapters were reviewed as in-memory only. Source trust labels remain declarations rather than authentication. Only Pydantic validation, registry membership, sensitivity propagation, and this test-only demo path are evidenced; P00-P03, provider egress safety, and authorization are not established.

CR0-D BoundaryEnvelope decisions: request digests cover deterministic canonical UTF-8 JSON bytes in `ModelInvocation.request_bytes` or `ToolInvocation.request_bytes`. Model invocation serialization includes the resolved UTF-8 payload; the adapter also receives those exact payload bytes separately. Response digests cover the exact returned output bytes. Envelopes contain only references, hashes, labels, and metadata. Failed attempts contain an error code and no response digest. Sequence numbers are volatile per GatewayRegistry/run and are not a persistent trace or replay facility. No cryptographic audit completeness is claimed. No material blueprint deviation was required; no CR0-D ADR was created.

CR0-E diagnostic decisions: `DiagnosticEvent` requires an event code, severity, and outcome; its timestamp is UTC-aware (generated in UTC by default and normalized when explicitly supplied). Optional metadata is limited to `run_id`/`boundary_id` UUIDs, a fixed component enum, `SensitivityLabel | None`, and `DiagnosticErrorCode | None`. Missing sensitivity remains `null`, never PUBLIC. Registered event codes are `cli.operation_result`, `storage.operation_result`, `gateway.operation_result`, `boundary.operation_result`, and `diagnostic.failure`. No raw message, URL/path, exception object/text, traceback, dictionary, source/model/tool content, credential, authorization decision, trust assignment, or approval is accepted. `JsonLinesDiagnosticLogger.emit()` revalidates an exact event instance and emits sorted compact JSON with one terminal newline to an explicitly configured text stream; the current stdout object is rejected. `stderr_logger()` selects stderr. Validation and sink errors have fixed non-sensitive messages; sink failures are raised and never converted to success, although the text stream may have accepted a partial record before failure. No global logging configuration, persistence, audit signing, policy meaning, or automatic integration into existing modules was added. Test-first red command: `pytest -q --tb=line tests/test_observability_events.py tests/test_observability_logging.py`; before implementation it reported 27 failed because `sentinel.observability` did not yet exist. The raw first-failure line was `ModuleNotFoundError: No module named 'sentinel.observability'`; all failures occurred inside test bodies, not test collection. After implementation, the focused tests exercise event validation, immutable and unchecked-instance handling, stderr/stdout behavior, deterministic JSON, newline safety, unknown/payload/credential field rejection, and exception-text exclusion. Diagnostics remain distinct from policy authorization and CR8 audit receipts.

## I. Step history

| Step | Commit | Tests/checks | Outcome |
|---|---|---|---|
| CR0-A implementation and acceptance | `61c218f7f0ebb5185a15cb2ce86e82b7918adac3` | `pip install -e ".[dev]"`: success; `pip check`: “No broken requirements found.”; `pytest -q`: 6 passed; `ruff check .`: “All checks passed!”; `mypy src/sentinel`: “Success: no issues found in 2 source files”; `build --wheel`: built `sentinel-0.1.0-py3-none-any.whl`; `sentinel --help`: exit 0 and lists `version`; `sentinel version`: exit 0 and prints `0.1.0`. | All mandatory local acceptance commands passed after fixing the first test run's real Typer/test assertion failures. Build and registry install succeeded. No later security capability claimed. |
| Governance/data review and publication | `61c218f7f0ebb5185a15cb2ce86e82b7918adac3` | Governance test confirms required IDs/files; credential-pattern scan returned no matches; email-address scan of references returned no matches; `.venv`, caches, build, dist, and egg-info are ignored; no runtime DB exists. `gh auth status` passed. The repository was initially created private; initial push was rejected for private commit email, unpublished local root commit was amended to noreply, then push of `main` succeeded. | Reference documents were reviewed and included. Current repository visibility is PUBLIC as of 2026-11-02. |
| CR0-B tests-first | Pending implementation commit | Before contract implementation: targeted contract pytest collection failed with three `ModuleNotFoundError: No module named 'sentinel.contracts'` errors; exit 1. | Expected red phase: tests were present before contract modules/classes. |
| CR0-B implementation and acceptance | `f5833df063807c0fe383d5a10109cd5e2657ac31` | `pip install -e ".[dev]"`: success; selected Pydantic 2.14.2 / pydantic-core 2.50.2; `pip check`: no broken requirements; full pytest: 87 passed; contract-only tests: 81 passed; original CR0-A tests: 6 passed; Ruff: all checks passed; mypy: no issues in 6 source files; wheel: built successfully; CLI help/version exited 0 and version printed 0.1.0. | First Ruff pass reported style errors and a mypy pass reported one canonical serializer annotation error; both were corrected. Final acceptance passed. CR0, F12, F20, and F29 remain incomplete. |
| CR0-C tests-first | `784707ab813c4e974655fc50c03a131f468d69e4` | Before storage modules were created: `pytest -q tests/test_storage_connection.py tests/test_storage_migrations.py` failed collection with 2 `ModuleNotFoundError: No module named 'sentinel.storage'` errors; exit 1. | Expected red phase: storage behavior tests were authored before implementation. |
| CR0-C implementation and acceptance | `784707ab813c4e974655fc50c03a131f468d69e4` | SQLite 3.43.1; migration `cr0-c-0001-schema-migrations`, artifact SHA-256 `b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217`; storage-focused tests: 20 passed; full pytest: 107 passed; editable install succeeded; `pip check`: no broken requirements; Ruff: all checks passed; mypy: no issues in 10 source files; wheel `sentinel-0.1.0-py3-none-any.whl` built; CLI help/version exited 0 and version printed 0.1.0. | During implementation, early storage tests found index-validation and test expectation defects; a first Ruff run found import/line formatting issues. These were corrected without removing negative assertions. Final acceptance passed. Application tables and process writer lease remain unimplemented. CR0 and F46 remain IN_PROGRESS. |
| CR0-C correction tests-first | `97d163cc5e2f4cfae86b4c516a117267ab97c1ca` | Before changing `schema.py` or `migrations.py`, the new migration regressions reported 3 failed and 20 passed. The failing cases were real table/index schema expansion, legacy database upgrade, and upgraded-database reopen; each was rejected with `MigrationIntegrityError: registered migration produced schema drift (test-0002-schema-expansion)` by the foundation-only verifier. | Expected red phase reproduced the reported defect. The three regressions passed after the checkpoint correction. |
| CR0-C migration-aware schema correction | `97d163cc5e2f4cfae86b4c516a117267ab97c1ca` | Editable install succeeded; pip check: no broken requirements; focused storage tests: 35 passed; full suite: 122 passed; Ruff: all checks passed; mypy: no issues in 10 source files; wheel `sentinel-0.1.0-py3-none-any.whl` built; CLI help/version exited 0 and version printed 0.1.0. Foundation artifact digest remains `b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217`; checkpoint digest is `1f4d935bf45b5c09f68b4f6e3deb18846aa6d9ee14510eed89b3ab4a71139d30`. | Test-only table/index, index-only, and data-only expansions pass. Legacy history/data survives upgrade and repeat initialization. Missing/extra objects, altered constraints, altered checkpoint hashes, unknown migrations, and partial failures are rejected or rolled back. No production schema was added. CR0/F46 remain IN_PROGRESS; P00-P17 and AB01-AB18 remain NOT_STARTED. |
| CR0-D tests-first | `ef18089` | Before gateway modules were created, `pytest -q tests/test_model_gateway.py tests/test_tool_gateway.py tests/test_gateway_boundaries.py` failed collection: each test module reported `ModuleNotFoundError: No module named 'sentinel.gateways'`; exit 1. | The tests existed before gateway implementation, but the red run stopped during collection; it did not execute behavioral assertions. No skipped or xfailed tests were used. This is the exact limit of the test-first evidence. |
| CR0-D gateway implementation and acceptance | `ef18089` | Editable install succeeded with the existing dependency set; pip check: no broken requirements; gateway-focused tests: 42 passed; full pytest: 164 passed; Ruff: all checks passed; mypy: no issues in 15 source files; wheel `sentinel-0.1.0-py3-none-any.whl` built; CLI help/version exited 0 and version printed 0.1.0; `git diff --check` exited 0 with only Git LF-to-CRLF notices for README/ledger. | Synthetic model and read-only tool paths passed. Unknown IDs, missing/invalid sensitivity and provenance, SECRET, raw PRIVATE cloud, cloud profiles/routes, writes, approval flags, raw model payload fields, invalid requests, and adapter exceptions were denied before unsafe invocation. The model's body was resolved only from trusted DEMO registry state. ModelRequest and ToolRequest are frozen; boundary digests matched canonical adapter request bytes and exact output bytes. No providers/integrations or external writes were added. CR0-D is verified only as a wrapper/test foundation; CR0 remains IN_PROGRESS; F21/F29/F33/F34 remain incomplete; P00-P17 and AB01-AB18 remain NOT_STARTED. |
| CR0-D model-ID correction tests-first | `a6bf06a2883174bdca597119d28dee8af6fe240b` | Before implementation changes, `pytest -q tests/test_model_gateway.py tests/test_gateway_boundaries.py` reported 2 failed and 33 passed. Both failures reached `ModelGateway.generate()` with `synthetic/example-v1` and raised Pydantic `ValidationError` at `ModelInvocation.model_id`, whose narrower pattern rejected `/`; exit 1. | This red phase executed behavioral assertions and reproduced the contract mismatch, rather than failing collection. The raw failure showed `String should match pattern '^[a-z][a-z0-9_.:-]{0,127}$'` for `synthetic/example-v1`. |
| CR0-D model-ID correction validation | `a6bf06a2883174bdca597119d28dee8af6fe240b` | Editable install succeeded with the existing dependency set; pip check: no broken requirements; focused model/tool/boundary tests: 47 passed; full pytest: 169 passed; Ruff: all checks passed; mypy: no issues in 15 source files; wheel `sentinel-0.1.0-py3-none-any.whl` built; CLI help/version exited 0 and version printed 0.1.0; `git diff --check` exited 0 (Git emitted only LF-to-CRLF notices). | `ModelIdentifier` is now shared by request, registration, invocation, response, and model registry lookup. Tests prove `synthetic/example-v1` passes registration, request validation, invocation, response, and boundary-digest checks. Unregistered slash IDs fail before adapter calls; malformed IDs remain rejected. The prior SECRET, PRIVATE/cloud, DEMO-only, approval, write, and schema-denial tests remain passing. No provider, integration, migration, schema, dependency, policy, or release-scope change was made. CR0 remains IN_PROGRESS; F21/F29/F33/F34 remain incomplete; P00-P17 and AB01-AB18 remain NOT_STARTED. |
| CR0-E tests-first | Pending acceptance commit | Before the event/logger modules existed, `pytest -q --tb=line tests/test_observability_events.py tests/test_observability_logging.py` executed 27 tests and reported 27 failed; representative raw failure: `ModuleNotFoundError: No module named 'sentinel.observability'`. | Tests were authored first and ran in test bodies. The initial red phase was blocked at API import because this package did not exist; it did not yet exercise behavior. Final focused tests exercise the behavioral assertions after implementation. |
| CR0-E structured diagnostic implementation and acceptance | `3bd30c4688180d0f215fac928622f0c503391c9e` | Editable install succeeded; Pydantic 2.14.2 remained installed and no dependency changed; `pip check`: no broken requirements; focused observability tests: 33 passed; full pytest: 202 passed; original suite excluding the two new files: 169 passed; Ruff: all checks passed; mypy: no issues in 18 source files; wheel `sentinel-0.1.0-py3-none-any.whl` built; CLI help/version exited 0 and version printed 0.1.0; `git diff --check` exited 0 with only Git LF-to-CRLF notices. | Fixed-schema JSON Lines diagnostics only. Tests cover stable event codes, UTC formatting/normalization, enum and field rejection, UUID metadata, deterministic output, one-record-per-line behavior, safe sink routing, stdout rejection, sink failure signaling, exception/credential/payload canary exclusion, CR/LF injection rejection, and unchecked-instance revalidation. No provider/tool execution, schema/migration changes, external writes, automatic integration, persistence, audit receipt, signed chain, policy engine, or CR8 functionality was added. CR0/F46 remain IN_PROGRESS; P00-P17 and AB01-AB18 remain NOT_STARTED. |
