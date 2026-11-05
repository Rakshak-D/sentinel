# CR1 release-exit evidence matrix

**Audit slices:** CR1-S; row C refreshed by CR1-T; row D refreshed by CR1-U and scorer correction CR1-V
**Audited starting revision:** `ce44c433df2f7ffd114337841ea11de0f91dfeb0`
**Authoritative definition:** Master Blueprint §16 (Blueprint SHA-256
`92911A27CDA2AACE41616E5A45F07E228C3D21838E8EB93A30BF71CF228701E7`), with
feature scope cross-checked against §2.
**Package:** `0.2.0.dev0`

This matrix classifies the 18 requested row-level criteria. `PASS` means the
bounded criterion named in that row has concrete code and test evidence; it
does not mean the broader feature is complete. `PARTIAL` records an active
CR1 feature with an identified missing deliverable. `DEFERRED` is reserved for
work the Blueprint assigns to a later release. A test result does not upgrade
an unimplemented capability. The matrix is not a release approval.

| ID | Blueprint requirement | Code entrypoint | Tests and acceptance command | Verified evidence | Known limitation | State | Blocks CR1 exit? Reason |
|---|---|---|---|---|---|---|---|
| A | §16 prerequisite: CR0 accepted before CR1. | `sentinel.bootstrap`; `sentinel version`; CR0 tag and historical runtime lock. | `python -m pytest -q tests/test_bootstrap_doctor.py tests/test_cli_doctor.py`; `git show cr0-v0.1.0`; `Get-FileHash requirements/cr0-windows-py311.lock -Algorithm SHA256`. | Starting verification retained CR0 `VERIFIED`, tag object `e5aa8bb2e280a2fc78804d74d576afdfaf544559` peeling to `b446e1b934eb2be71853f9b6eab9e0238eade211`, and lock digest `319ec67ddf87b44690eda03d47675975c806d5cc16242166dbf109ed5c4005ec`. | CR0 acceptance is bounded to its recorded Windows / CPython scope; it is not production security certification. | PASS | No. CR0 prerequisite evidence is preserved. |
| B | §2 F11: durable local task create/list/edit/complete/reopen and restart behavior. | `sentinel.tasks.store`; `sentinel task`. | `python -m pytest -q tests/test_cr1_j_tasks.py tests/test_cr1_j_transitions.py tests/test_cr1_j_idempotency.py tests/test_cr1_j_restart.py tests/test_cr1_j_cli.py`. | Manual task state, request receipts, optimistic revisions, and process restart are covered by CR1-J tests; CR1-L presents tasks read-only. | Operator identity is unauthenticated; task titles are unencrypted and must not hold secrets. No source-derived tasks or approval semantics. | PASS | No for this bounded manual workflow. F11 remains `IN_PROGRESS` for the wider product. |
| C | §2 F10: allowlisted local evidence, path registry/read worker, traversal and symlink denial, byte limits, and edit detection. | `sentinel.readers.local_text.read_allowlisted_local_text`; `sentinel.readers.notes_registry.build_local_notes_registry`; `verify_local_notes_registry`; `sentinel source notes-registry build|verify`. | `python -m pytest -q tests/test_cr1_m_local_reader.py tests/test_cr1_m_path_security.py tests/test_cr1_m_races.py tests/test_cr1_n_search.py tests/test_cr1_n_boundaries.py tests/test_cr1_o_job_alert.py tests/test_cr1_p_batch.py tests/test_cr1_t_registry.py tests/test_cr1_t_changes.py tests/test_cr1_t_boundaries.py tests/test_cr1_t_cli.py tests/test_cr1_t_restart.py`. | CR1-T builds a deterministic metadata-only registry from 1–8 explicit files, preserving canonical relative identity, exact byte length, and SHA-256. It saves nothing; a later process validates the `.txt` registry and each listed file through CR1-M, rereads once, and reports `UNCHANGED`/`CHANGED` without names or bodies. Cross-process same-length content change, restoration, path boundaries, malformed metadata, and no-stdout failures are covered. | Registry filenames and hashes are an explicit metadata disclosure, not encrypted, signed, or author-authenticating. Notes remain PRIVATE and are not persisted. Multi-file reads are not an atomic snapshot; malicious same-user/ABA replacement is not ruled out. Two existing live Windows symlink-creation tests are skipped because creation is unavailable on the host. F10 remains `IN_PROGRESS` as a broader feature. | PASS | No for the bounded explicit allowlisted read/registry/edit-detection criterion. This does not complete the overall CR1 release; row D remains PARTIAL and blocks exit. |
| D | Blueprint Sections 2 F05/F13: job-alert extraction/review and source facts to typed signals. | sentinel.extraction; sentinel.triage.job_alert.triage_selected_job_alerts; sentinel.triage.evaluation.evaluate_job_alert_triage. | pytest -q tests/test_cr1_o_job_alert.py tests/test_cr1_o_citations.py tests/test_cr1_p_batch.py tests/test_cr1_p_groups.py tests/test_cr1_p_citations.py tests/test_cr1_u_triage.py tests/test_cr1_u_citations.py tests/test_cr1_u_evaluation.py tests/test_cr1_v_evaluation_matching.py. | CR1-U provides deterministic cited field projection, abstention, and fictional dev/holdout evaluation. CR1-V fixes case-local signal matching; adversarial candidate/URL/deadline swaps now score TP/FP/FN per case. Frozen corpus metrics remain unchanged and are compared in docs/audit/cr1-u-evaluation.md. | This remains deterministic projection, not a ModelGateway run. PRIVATE source bodies cannot use the current CR0-D synthetic-PUBLIC-only gateway; prose-only candidate examples remain parser misses. No live inbox, legitimacy, ranking, or application action. | PARTIAL | Yes. The active CR1 F13 requirement is not complete until its remaining gateway/execution and release-scope requirements are separately resolved. |
| E | §2 F06/F07: public job feeds must remain behind explicit per-board/per-site terms gates. | Bundled source-status inventory; `sentinel.readers.source_status`. | `python -m pytest -q tests/test_cr1_s_terms_gates.py tests/test_cr1_s_status.py`. | Greenhouse and Lever report `TERMS_REVIEW_REQUIRED`, `TERMS_GATED`, and `REQUIRED_NOT_COMPLETED`; no host is enabled. The status operation does not interpret source text as review authority. | No feed adapter or trusted per-board review artifact exists. A public GET endpoint is not an aggregation/cache permission. The gate is closed; no feed is approved. | PASS | No. The requested gate is enforced by leaving both readers unimplemented and activation closed. |
| F | §2 / §16: packaged Gmail fixture reader. | `read_packaged_gmail_fixture()`. | `python -m pytest -q tests/test_gmail_fixture_reader.py tests/test_gmail_fixture_packaging.py tests/test_gmail_fixture_decoding.py tests/test_gmail_fixture_citations.py tests/test_gmail_fixture_boundaries.py tests/test_cr1_s_fixtures.py`. | Existing strict reader validates its fixed package hash, schema, body encoding, and citations; CR1-S invokes it before reporting `FIXTURE_READY`. | This is synthetic fixture support only. Live F01 Gmail OAuth/read remains later-release work and account state is `NOT_CHECKED`. | PASS | No for the fixture criterion. Live Gmail access is explicitly deferred to CR4. |
| G | §2 / §16: packaged GitHub fixture reader. | `read_packaged_github_fixture()`. | `python -m pytest -q tests/test_github_fixture_reader.py tests/test_github_fixture_packaging.py tests/test_github_fixture_citations.py tests/test_github_fixture_boundaries.py tests/test_cr1_s_fixtures.py`. | Existing fixed hash/schema/citation reader runs offline; source status independently invokes it and reports only fixture readiness. | Does not authenticate a GitHub account or provide live F03 selected-repository access. | PASS | No for the fixture criterion. Live GitHub access is explicitly deferred to CR4. |
| H | §2: packaged Calendar fixture reader. | `read_packaged_calendar_fixture()`; `sentinel source calendar-fixture`. | `python -m pytest -q tests/test_cr1_q_calendar_reader.py tests/test_cr1_q_timestamps.py tests/test_cr1_q_all_day.py tests/test_cr1_q_citations.py tests/test_cr1_q_cli.py tests/test_cr1_s_fixtures.py`. | Four fixed fictional events, explicit-offset instants, exclusive all-day dates, and description citations validate offline; source status re-runs the reader. | No Google Calendar account access, recurrence/DST expansion, scheduling, or persistence. F09 live access is scheduled for CR4. | PASS | No for the fixture criterion. Live Calendar access is explicitly deferred to CR4. |
| I | §2 F12: normalized source envelopes with declared trust/sensitivity. | `sentinel.normalization`; fixture and local readers. | `python -m pytest -q tests/test_plain_text_normalization.py tests/test_normalization_boundaries.py tests/test_source_citations.py tests/test_cr1_m_local_reader.py tests/test_cr1_q_calendar_reader.py`. | UTF-8 plain-text normalization, original-byte preservation, trust/sensitivity labels, and bounded source identities are tested across fixture and local readers. | Declared trust labels and digests do not authenticate an external author or provider. Full F12 remains `IN_PROGRESS`. | PASS | No for this bounded contract. It is not production provenance authentication. |
| J | §16: exact source-bound citations. | `add_citation()`, `bind_citation()`, `verify_bound_citation()` and CR1-G/H1/local/Calendar consumers. | `python -m pytest -q tests/test_source_citations.py tests/test_cr1_g_citations.py tests/test_cr1_h1_citations.py tests/test_cr1_m_citations.py tests/test_cr1_o_citations.py tests/test_cr1_p_citations.py tests/test_cr1_q_citations.py`. | Persisted and in-memory citations are checked against exact UTF-8 half-open byte slices and source digests, including tamper cases. | Correct bytes prove integrity relative to the expected digest, not provider authenticity or truth. | PASS | No. The bounded citation contract has direct tests. |
| K | §2: persistent incremental synthetic source state. | `sentinel.sync.github_fixture`; CR1-G/H1 ingestion and blob readback; `fixture-workspace`. | `python -m pytest -q tests/test_cr1_g_complete_state.py tests/test_cr1_h1_restart.py tests/test_cr1_k_progress.py tests/test_cr1_k_crash.py tests/test_cr1_r_verify.py tests/test_cr1_r_crash.py`. | Three fixed GitHub revisions/nine spans, three verified PUBLIC bodies, promoted refs, and cursor 0–3 are transactionally validated and restart-tested. | Persistence is fixture-specific; no general blob store integration, live cursor, private storage, or cross-resource transaction is claimed. | PASS | No for synthetic state. General source persistence remains outside this criterion. |
| L | §2: terminal evidence briefing. | `sentinel brief github-fixture`; `build_github_fixture_brief()`. | `python -m pytest -q tests/test_cr1_i_briefing.py tests/test_cr1_i_formatters.py tests/test_cr1_i_cli.py tests/test_cr1_i_restart.py`. | Three source items and nine citations are read from promoted rows and verified PUBLIC blobs without requiring packaged fixture fallback. | Deterministic evidence presentation only; no model-generated summary or live GitHub claim. | PASS | No for this synthetic evidence brief. |
| M | §2: local task/evidence overview. | `sentinel brief local-overview`; `build_local_overview()`. | `python -m pytest -q tests/test_cr1_l_overview.py tests/test_cr1_l_task_buckets.py tests/test_cr1_l_formatters.py tests/test_cr1_l_boundaries.py tests/test_cr1_l_restart.py`. | Fixed-as-of task day buckets, original verified evidence once, separate synthetic cursor status, and detectable read-stability changes are tested. | Separate readers do not form one atomic SQLite snapshot; no automatic source-to-task conversion or freshness claim. | PASS | No for the bounded local overview. |
| N | §16: missing-credential/capability status is clear without false account claims. | `sentinel source status`; `CredentialBroker.backend_availability`. | `python -m pytest -q tests/test_cr1_s_status.py tests/test_cr1_s_credentials.py tests/test_cr1_s_terms_gates.py tests/test_bootstrap_doctor.py`. | Reports fixture checks separately from live adapter implementation, activation, backend availability, credential-check and account-check state; account and credential state are `NOT_CHECKED`, production backend `UNAVAILABLE`. | No real credential or account presence is inspected. Status is not production readiness. | PASS | No. The bounded §16 status assertion is satisfied without probing user secrets. |
| O | §16: one-shot CLI behavior after restart. | Installed `sentinel` entry point; `fixture-workspace`, `brief`, `task`, `fixture-sync`, `source status`. | `python -m pytest -q tests/test_cr1_r_restart.py`; disposable installed-wheel workflow recorded below. | A fresh installed process initializes/prepares/verifies the synthetic workspace, reads evidence and Calendar fixture, performs manual task transitions and one cursor advance, then verifies state and repeats prepare. | Synthetic local restart only; no live integrations or power-loss guarantee. | PASS | No for the one-shot offline CLI criterion. |
| P | §16: installed-wheel functionality. | Built `sentinel-0.2.0.dev0` wheel and console entry point. | `python -m build --wheel`; install the resulting wheel into the disposable verification environment; invoke from outside the checkout. | The complete prepare/verify/brief/calendar/overview/task/cursor/restart sequence is run from the installed wheel outside the source tree. | Covers this fixed offline workflow and packaged fixtures, not every platform or future adapter. | PASS | No for the bounded installed-wheel requirement. |
| Q | Read-only source-status and evidence paths; no provider side effects. | `sentinel source status`; existing read-only brief/readback APIs. | `python -m pytest -q tests/test_cr1_s_status.py tests/test_cr1_s_cli.py tests/test_cr1_s_credentials.py tests/test_bootstrap_doctor.py tests/test_cr1_i_restart.py`. | Status takes no database/root/credential options; source-status tests prohibit reference checks/network sockets; existing brief tests preserve read-only DB/blob behavior. | A code review/test cannot prove absence of all malicious same-user interference; status still reads its packaged resources. | PASS | No for the bounded read-only/no-external-effects criterion. |
| R | §3/§6/§16: unresolved security/privacy limitations must remain visible. | README, this matrix, `docs/BUILD_LEDGER.md`, source-status explanations. | `git diff --check`; `python -m pytest -q tests/test_cr1_s_status.py tests/test_cr1_s_terms_gates.py`; final ledger/diff review. | Explicitly records unauthenticated task operator, unencrypted task titles, no private persistence, no live credential/account checks, closed feed terms gates, local filesystem limitations, and no production-readiness claim. | Disclosure does not resolve the limitations; CR1 remains open while active target work is incomplete. | PASS | No as a disclosure criterion; row D's F13 work remains PARTIAL and blocks release. F10 remains IN_PROGRESS at the wider product level. |

## Row-level classification count

| Classification | Count |
|---|---:|
| PASS | 17 |
| PARTIAL | 1 |
| FAIL | 0 |
| UNVERIFIED | 0 |
| DEFERRED | 0 |

The `DEFERRED` count is zero because the 18 requested rows are CR1-facing
criteria. Live Gmail, GitHub, and Calendar adapters are noted as later-release
limitations within the fixture rows rather than counted as CR1 row failures.

## CR1 §16 decision evidence and open blockers

The three §16 mechanical checks have evidence: source normalization and exact
citations pass; the CLI reports the unavailable production credential backend
and leaves real account credentials `NOT_CHECKED`; and the one-shot installed
CLI workflow succeeds after process restart. The README and source-status
output explicitly state that fixtures are not linked accounts and that this is
not a production-readiness result.

This does **not** close CR1. The bounded F10 allowlisted-notes criterion in row
C now has explicit registry generation, cross-process comparison, and
edit-detection evidence. F10 remains `IN_PROGRESS` as a wider capability; this
row does not establish encrypted storage or broader discovery/synchronization.
The active-target F13 criterion in row D remains PARTIAL: CR1-U adds
deterministic cited-field projection and frozen fictional dev/holdout
evaluation, and CR1-V corrects cross-case metric matching. Two prose-only
candidate misses remain. PRIVATE inputs cannot pass the current CR0-D
synthetic-PUBLIC-only ModelGateway gate; a separately reviewed execution path
and broader F13 acceptance remain open.

F01/F03/F09 live provider access remains explicitly assigned to later work and
is not required to make fixture status appear healthy. F06/F07 remain disabled
until source-specific terms review and implementation; no review approval is
claimed. CR0 remains `VERIFIED`; CR1 remains `IN_PROGRESS`. The release decision
must be made separately from CR1-S/CR1-T/CR1-U/CR1-V bounded acceptance.

## Bounded audit limitations

This is a source-code, test, package, and local-process audit. It does not
authenticate a user, inspect credentials, approve terms, establish provider
truth, certify Windows isolation, prove sudden-power-loss durability, or
establish production readiness. See the build ledger for exact test and
acceptance outputs, commit IDs, and preserved artifact digests.

## CR1-S execution evidence

The requested implementation and tests were committed as
`0aa2a95` (`Add read-only source capability status`). The CR1-S focused
selection, including the existing doctor regression tests, reported
`38 passed in 2.43s`. The full run used
`.\.venv\Scripts\python.exe -m pytest -q` and reported
`1251 passed, 2 skipped in 274.53s`; both skips are the same existing
Windows final-component symlink-creation limitations at
`tests/test_bootstrap_init.py:125` and
`tests/test_storage_writer_lease.py:251`. No new skip or xfail was added.

Acceptance commands completed successfully: editable installation;
`pip check` (`No broken requirements found.`); Ruff (`All checks passed!`);
mypy (`Success: no issues found in 84 source files`); wheel build for
`sentinel-0.2.0.dev0-py3-none-any.whl`; root, source, and source-status help;
and `sentinel version` (`0.2.0.dev0`). The built wheel was installed into the
selected virtual environment and invoked from a fresh temporary working
directory outside the checkout. Its import origin was
`.venv\Lib\site-packages\sentinel`.

The installed-wheel restart workflow used a disposable database and store:
`init`; `fixture-workspace prepare`; `fixture-workspace verify`; source
status; GitHub evidence brief; Calendar fixture inspection; a fixed-as-of
local overview; task add/edit/complete/reopen; one synthetic cursor advance;
new-process verification; repeated prepare; and a rebuilt overview. Results
were three original GitHub items/nine citations, four Calendar fixture events,
one retained task at revision 4, cursor generation 1, and final overview
counts of one task/three evidence items/nine citations/generation 1. The
database held two synthetic source rows, two principals, four items, twelve
spans, one task, one cursor, and zero action proposals. Source-status JSON
was byte-identical across processes. Complete SQLite row snapshots and PUBLIC
blob hashes were unchanged across read-only checks and the repeated
`ALREADY_PREPARED` call. Successful CLI calls had empty stderr. This is
process-restart evidence for the bounded local fixture workflow, not a
power-loss, production, or live-provider guarantee.

The deterministic JSON diagnostic had 14 capability rows and
`validation=VALID`: the three packaged fixtures were `FIXTURE_READY`; four
explicit local workflows were `EXPLICIT_LOCAL_ONLY`; the three live adapters
were `NOT_IMPLEMENTED`, disabled, with credentials and account state
`NOT_CHECKED`; Greenhouse and Lever remained `TERMS_REVIEW_REQUIRED` and
`TERMS_GATED`; LinkedIn owner-export remained unimplemented and source-review
gated; and the production credential backend was `UNAVAILABLE`. The text
view makes the same distinctions and says it is not a production-readiness
result.

No database schema, migration, checkpoint, fixture, H1 manifest, package
version, dependency, CR0 lock, or CR0 tag was changed. The implementation
commit is `0aa2a95`; README, audit-matrix, and detailed ledger evidence are
recorded in the separate documentation commit reported with this slice.

## CR1-U deterministic triage evidence

CR1-U adds source-bound deterministic typed signals and an evaluator over
24 development and 30 holdout fictional cases. The separate report
docs/audit/cr1-u-evaluation.md records corpus/label hashes, exact confusion
matrices, signal metrics, citation counts, and the two natural-language
candidate misses. The evaluator reports zero candidate false positives,
zero missing/invalid citation references, and zero cross-source evidence
errors on both splits. The implementation never calls ModelGateway; the
current PRIVATE-to-model path remains gated. Row D therefore remains
PARTIAL; the row-level matrix count remains 17 PASS and 1 PARTIAL.

CR1-V did not alter the frozen evaluation corpus or expected-label manifest.
The corrected evaluator matches signal kind and required field IDs within each
case before adding TP/FP/FN counts; the release blocker and row-level
classification remain unchanged.
