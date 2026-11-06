# CR1-X final release verification

## 1. Executive decision

**Recommendation: READY_FOR_OWNER_APPROVAL** for the bounded offline CR1 daily-read/product core defined by Blueprint §16.

This is an audit recommendation, not a release approval or promotion. The scope interpretation is **PROPOSED** and owner approval is **ABSENT**. CR0 remains VERIFIED; CR1 remains IN_PROGRESS; F13 remains IN_PROGRESS. No tag, release promotion, stable version, or package publication is made by this audit. An owner must accept or reject the staged scope, and release engineering must separately prepare the final versioned artifact.

The recommendation is based on the §16 deliverable and its explicit mechanical exits, independently rerun acceptance, a separate installed-wheel workflow, and the failure/security evidence below. It does not rely on the prior 18-PASS matrix. The new independent crosswalk is docs/audit/cr1-release-exit-matrix.md.

## 2. Audited revision and authoritative sources

- Repository: C:\RAKSHAK\MY CODE\Sentinel, branch main.
- Audited implementation revision: b5f31dd990f6d12ff301cc21456ad364dd66de5e.
- Starting worktree: clean; HEAD exactly matched the expected revision and origin/main. No untracked or modified repository files were present before this documentation-only audit.
- Master Blueprint: docs/spec/Sentinel Master Blueprint.pdf, SHA-256 92911A27CDA2AACE41616E5A45F07E228C3D21838E8EB93A30BF71CF228701E7.
- The current package version is 0.2.0.dev0.

The review read Blueprint §§2, 3, 6, 7 and 16; README.md; docs/BUILD_LEDGER.md; the CR1-W scope review and current CR1-U evaluation report; source, extraction, triage, gateway, workspace, overview, task, sync and doctor implementations; and their direct regression tests. The Blueprint text was extracted from the pinned PDF for the section comparison. No product code, tests, fixtures, dependencies, schema or version were changed.

## 3. Exact Blueprint interpretation

Blueprint §2 is the feature catalogue. It identifies F13 as an active target that turns source facts into typed signals, depends on ModelGateway, and expects held-out structured-field evaluation and span citations. It also marks F06 Greenhouse and F07 Lever as gated for per-board/per-site legal or terms review. §2 status describes complete feature scope; it is not by itself a release checklist.

Blueprint §16 separately defines CR1 as the “Daily read/product core.” Its stated deliverable is CR0 plus local tasks, notes, job feeds with explicit terms gates, Gmail/GitHub/Calendar fixture readers, incremental source state and terminal briefings. Its mechanical exits are source-normalization and citation tests, clear missing-credential status, and one-shot CLI behavior after restart. It does not list completion of every §2 ACTIVE TARGET feature or model-mediated F13 as a CR1 mechanical exit.

Blueprint §16 places the four-model privacy gateway in CR5 after CR4. §7 describes the intended sensitivity-aware routing constraints, including no SECRET model input and raw PRIVATE restricted to an eligible local-only route. Therefore the current absence of PRIVATE model execution is a real F13 limitation, but it is not evidence that CR1 may weaken CR0-D or skip the future CR5 privacy and egress tests.

This audit accepts the staged dependency as a defensible interpretation of the written §16 boundary: CR1 ships an offline cited deterministic subset; full F13 remains IN_PROGRESS and model-mediated PRIVATE processing remains gated for a separately reviewed gateway stage. This is an architectural interpretation, not a sentence that the Blueprint explicitly assigns “F13 to CR5.” Owner approval remains outstanding. If the owner interprets §2 F13 as a mandatory CR1 completion condition despite §16's narrower deliverable and exit list, the appropriate decision would change to BLOCKED pending an authorized scope decision and safe implementation; this audit does not disguise that interpretive choice.

## 4. Independent requirement matrix

The complete A-R crosswalk is in docs/audit/cr1-release-exit-matrix.md. It lists each bounded criterion, source entrypoint, direct tests, executed acceptance, limitation, state and blocking effect. It was rebuilt against §16 and the implementation rather than copied from CR1-W.

Independent classifications: **18 PASS, 0 PARTIAL, 0 FAIL, 0 UNVERIFIED** for bounded CR1 exit rows. These states do not mark the broader F-features complete and do not promote CR1. The table records two skipped Windows symlink-creation tests as unexecuted, not as passing; they are known baseline limitations.

## 5. F13 coverage and ModelGateway boundary

| F13 aspect | Audit state | Evidence and limit |
|---|---|---|
| Structured field extraction | BOUNDED | CR1-O parses only its narrow, line-labeled grammar from explicitly selected local files; it is not natural-language extraction. |
| Typed signal projection | BOUNDED | CR1-U emits a closed deterministic signal set from accepted parser fields. |
| Source-bound citations | IMPLEMENTED for this grammar | Signal references retain source ID/digest, field ID, span ID, half-open byte range and slice digest; CR1-O/P/U/V tests validate them. |
| Ambiguity and missing-data abstention | BOUNDED | INCOMPLETE and AMBIGUOUS remain REVIEW_REQUIRED; NO_MATCH yields NO_SIGNAL; no fields are borrowed across sources. |
| Source trust retention | IMPLEMENTED for local job alerts | Source stays T4_EXTERNAL; no owner authority is inferred. |
| PRIVATE sensitivity retention | IMPLEMENTED for local job alerts/signals | Input remains PRIVATE; derived signal is T3_DERIVED/PRIVATE. |
| Deterministic output and identity | IMPLEMENTED for the bounded API | Fixed ordering, domain-separated signal identity and deterministic text/JSON; no generated timestamp. |
| Source-to-signal evaluation | BOUNDED | Frozen fictional CR1-U development and holdout sets; actual parser and evaluator are exercised. |
| Case-local TP/FP/FN | IMPLEMENTED | CR1-V matches within each case; the cross-case URL swap is 0/1/1. |
| Real-world generalization | NOT_IMPLEMENTED | Corpus is developer-authored synthetic contract data, not real mail or job-site data. |
| Natural-language extraction | NOT_IMPLEMENTED | Three prose-only candidate cases remain missed by the narrow parser. |
| Model-mediated F13 extraction | GATED | Triage has no ModelGateway route; no fake output is substituted. |
| F13 model output schema validation | NOT_IMPLEMENTED | No F13 model request/response schema is executed. |
| Local-only PRIVATE model execution | GATED | CR0-D denies PRIVATE; the Blueprint's intended future route requires a separately reviewed implementation. |
| Cloud privacy routing/evaluation | GATED for CR5 | Current code fails closed for non-PUBLIC traffic; CR5 egress oracles and provider contracts are absent. |

CR0-D source inspection confirms ModelGateway is the sole model call surface in the current implementation and only registered synthetic PUBLIC demo requests execute. It rejects PRIVATE and SECRET; CR1-U/V did not change the gateway. Current local alert sources are T4_EXTERNAL/PRIVATE, and derived signals are T3_DERIVED/PRIVATE. Triage imports no ModelGateway and no authorized route sends those bytes to it. Tests test_model_gateway.py and test_cr1_u_privacy.py cover PRIVATE/SECRET denial and no model route from triage.

No source label is downgraded. A cited signal is a derived record, not a verified employer, legitimate vacancy, live opening, eligibility determination, owner instruction or application status.

## 6. CR1-V evaluation independently recomputed

The current tests.cr1_u_corpus loader verified the frozen resources before evaluation. SHA-256 values remained:

| Resource | SHA-256 |
|---|---|
| Development corpus | 13e4374e7cee04a1d08d9987376dc6d764eb737b63f1965ca756964fa0e820b5 |
| Holdout corpus | 645bdaf8a2725e4228de49490b568ef92bcc37b4352b73e8ff3d439d026d47ba |
| Expected-label manifest | 482008fb933808175d4ab1847d6c055b772dcb7a13abc388b2f941dabcbc2e79 |

The audit independently decoded all 24 development and 30 holdout cases, ran triage on the actual temporary local-file observations, and passed those observations and frozen labels to the current evaluator.

| Metric | Development (24 total) | Holdout (30 total) |
|---|---:|---:|
| In-bound classifications | 22 | 28 |
| Classification accuracy | 21/22 = 0.9545 | 26/28 = 0.9286 |
| Confusion rows: expected CANDIDATE | 12, 0, 0, 1, 0 | 12, 0, 0, 2, 0 |
| Confusion rows: expected INCOMPLETE | 0, 4, 0, 0, 0 | 0, 5, 0, 0, 0 |
| Confusion rows: expected AMBIGUOUS | 0, 0, 3, 0, 0 | 0, 0, 5, 0, 0 |
| Confusion rows: expected NO_MATCH | 0, 0, 0, 2, 0 | 0, 0, 0, 4, 0 |
| Candidate TP/FP/FN; F1 | 12/0/1; 0.9600 | 12/0/2; 0.9231 |
| URL TP/FP/FN; F1 | 9/0/0; 1.0000 | 10/0/0; 1.0000 |
| Deadline TP/FP/FN; F1 | 2/0/0; 1.0000 | 3/0/0; 1.0000 |
| Micro TP/FP/FN; F1 | 23/0/1; 0.9787 | 25/0/2; 0.9615 |
| Macro signal F1 | 0.9867 | 0.9744 |
| Incorrect abstentions | 1 | 2 |
| Unexpected failures | 0 | 0 |
| Verified/missing/invalid/cross-source evidence references | 35/0/0/0 | 37/0/0/0 |

The confusion vector order is CANDIDATE, INCOMPLETE, AMBIGUOUS, NO_MATCH, INPUT_REJECTED. The final component is zero in each in-bound row; the two expected invalid inputs in each dataset are excluded from the in-bound classification-accuracy denominator and counted as expected rejections. Citation reference totals count signal evidence references and can count a source span more than once if it supports multiple signals.

The evaluator's exact rule is case_local_kind_and_required_field_ids. Direct execution of tests/test_cr1_v_evaluation_matching.py returned 17 passed in 3.60s. In the URL-swap regression, case A's missing expected URL and case B's extra URL produce TP=0, FP=1, FN=1; no cross-case match is credited. Candidate and deadline swaps, correct/partial matches, rejected/accepted cases, and arithmetic are also covered by that test file.

One development and two holdout candidate examples written as prose rather than labeled fields are missed and classified NO_MATCH. These are parser limitations, not model errors. The measurements apply only to these fixed, fictional contract inputs; they are neither model evaluation nor evidence of real-world recall.

## 7. Terms-gate finding

The installed status JSON and tests/test_cr1_s_terms_gates.py show Greenhouse and Lever as implementation NOT_IMPLEMENTED, activation TERMS_GATED, source review NOT_ASSESSED, terms review REQUIRED_NOT_COMPLETED, and readiness TERMS_REVIEW_REQUIRED. No employer board is approved, no terms review is represented as completed, and no HTTP reader exists to activate. Source-status code uses fixed registered capability metadata; source text is not a review authority. The end-to-end process guard observed no socket or subprocess attempt.

The literal §16 phrase “job feeds with explicit terms gates” is satisfied here as an explicit, closed gate for the absent integrations. This is not live feed support, not an approval of aggregation, and not a claim that a future reader can be enabled without source-specific review.

## 8. Full acceptance commands

Using the repository's Windows .venv:

| Command | Observed result |
|---|---|
| .\.venv\Scripts\python.exe -m pip install -e ".[dev]" | Succeeded; imports resolved to the checkout for source tests. |
| .\.venv\Scripts\python.exe -m pip check | No broken requirements found. |
| .\.venv\Scripts\python.exe -m pytest -q | 1326 passed, 2 skipped in 620.01s. |
| .\.venv\Scripts\python.exe -m ruff check . | All checks passed! |
| .\.venv\Scripts\python.exe -m mypy src/sentinel | Success: no issues found in 91 source files. |
| .\.venv\Scripts\python.exe -m build --wheel | Successfully built sentinel-0.2.0.dev0-py3-none-any.whl. |
| Installed sentinel --help, doctor --help, source status --format json, source triage-job-alerts --help, source notes-registry --help, version | Help/status/version invocations succeeded; version printed 0.2.0.dev0. |

The only skips were the existing final-component symlink creation cases at tests/test_bootstrap_init.py:125 and tests/test_storage_writer_lease.py:251. This Windows host denied the symlink-creation operation. No new skip or xfail appeared. The skipped real-symlink cases are disclosed as unverified; controlled path/reparse boundary and race tests passed.

## 9. Installed-wheel and restart evidence

The wheel SHA-256 is b8380fb655c90d3715424a15fee3fcd9fbcc5e7a1e074ab9670bae8579f3c56d. It was installed without index access into a separate clean Python 3.11.7 verification environment using locally available runtime dependencies. The interpreter resolved sentinel and its reader modules from that venv's site-packages, not the repository. pip check in the verification environment reported no broken requirements. The wheel includes the packaged Gmail, GitHub and Calendar fixture JSON resources; the installed readers returned their pinned hashes.

The installed console script ran with its working directory outside the checkout. Each invocation was a separate process. A child-process audit guard patched socket creation/connect/DNS, subprocess.Popen, os.system and os.startfile to record and reject use. Across 36 guarded CLI processes there were zero blocked network or process calls.

| Workflow step | Executed result |
|---|---|
| init; fixture-workspace prepare; verify | New explicit database initialized; three GitHub items/nine citations and three PUBLIC blobs verified; task operator ready; synthetic cursor 0/3 READY. |
| source status; GitHub brief; Calendar inspection | Stable status JSON; 3 original GitHub items/9 citations; 4 synthetic Calendar events (3 confirmed, 1 cancelled). |
| fixed-as-of local overview | Zero tasks at generation 0; after task/cursor changes, 1 manual task, 3 original items, 9 citations, generation 1. Repeated JSON bytes matched. |
| task add/list/edit/complete/reopen | CLI showed revisions 1 → 2 → 3 → 4; a later process listed revision 4. |
| fixture-sync setup/status/advance; restart | Cursor advanced 0 → 1 once; state after restart was generation 1, 1 replay item, 3 replay spans. |
| workspace verify; repeat prepare | Verified progressed state; repeat reported Fixture workspace already prepared at 1/3 READY without state changes. |
| notes registry | Built and deliberately saved the exact emitted registry bytes. Three notes verified UNCHANGED, one valid edit yielded 1 CHANGED/2 UNCHANGED with exit 1, restore returned 3 UNCHANGED; verification did not change the saved registry SHA-256. |
| job-alert parse/review/triage | One fictional candidate parsed and reviewed; default triage omitted values; opt-in showed cited fields only; instruction-like prose did not become a signal or action. |
| failure paths | Missing late batch file and malformed registry each returned nonzero with empty stdout and bounded path-free stderr. |

Before/after snapshots taken around read-only status, verify, brief, Calendar, overview, sync-status and task-list calls matched for every SQLite table row and every PUBLIC store file hash. Repeated prepare also left those snapshots equal. Final disposable database checks were integrity_check=ok and zero foreign-key violations. It contained 4 source_items (3 original fixture items plus one incremental replay item), 12 spans (9 original plus 3 replay), one manual task and zero action_proposals. The evidence brief continued to report only the original 3 issues/9 citations; replay rows were not counted as unique issues.

The three PUBLIC store blobs contained none of the synthetic PRIVATE notes/job-alert canaries. A query-only SQLite scan likewise found no such canaries. Notes-registry metadata intentionally contains relative filenames and whole-file digests because the operator explicitly saves it; that metadata is not encrypted, signed or anonymous.

## 10. Negative and privacy evidence

The full 1326-test suite includes direct denial and failure cases. The focused independent security/evaluation regression selection returned 149 passed in 208.10s, covering CR1-V case-local evaluation, frozen evaluation/citations/privacy, ModelGateway, ToolGateway, source capability and terms status, fixture validation, local path/race boundaries, notes registry, and workspace verification/crash behavior. The separate cross-case evaluator file returned 17 passed.

Observed safeguards include:

- malformed/tampered citations and source digests do not receive signal credit;
- corrupt or missing synthetic blobs, invalid schema/cursor state, unsafe or missing selected files, and malformed registry input fail closed in direct tests or the installed CLI smoke;
- late selected-file and malformed-registry failures produced empty stdout and bounded stderr;
- PRIVATE and SECRET model requests are denied; unauthorized tool capabilities are denied;
- live provider adapters remain NOT_IMPLEMENTED and disabled; account and real credential status remain NOT_CHECKED, and the production credential backend is UNAVAILABLE;
- no PRIVATE source text entered the PUBLIC blob store or SQLite in the disposable workflow;
- no source-derived tasks, action proposals, approvals, external writes, or provider requests occurred.

These checks establish the exercised code paths and synthetic boundaries. They do not prove safety against a compromised operating system, malicious same-user process, all filesystem ABA races, sudden power loss, or untested environments.

## 11. Pin and preservation verification

| Artifact | Observed SHA-256 or identity |
|---|---|
| CR0 annotated tag object | e5aa8bb2e280a2fc78804d74d576afdfaf544559 |
| CR0 peeled commit | b446e1b934eb2be71853f9b6eab9e0238eade211 |
| requirements/cr0-windows-py311.lock | 319ec67ddf87b44690eda03d47675975c806d5cc16242166dbf109ed5c4005ec |
| GitHub fixture | 7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1 |
| Gmail fixture | 781112d5b62439e833f33040f0e4f67c4adafa86d2f94e1b137fa09d52fa8b57 |
| Calendar fixture | e879838ea32430497160bacbdedde1c4ffd98b1906bcdddc1c77c776f756575a |
| H1 expectation manifest | 645aecaedd14d8e6c6071b9d8c32a5d91f664c715799191303eac315d6f9c08f |
| CR1-U development / holdout / labels | 13e4374e7cee04a1d08d9987376dc6d764eb737b63f1965ca756964fa0e820b5 / 645bdaf8a2725e4228de49490b568ef92bcc37b4352b73e8ff3d439d026d47ba / 482008fb933808175d4ab1847d6c055b772dcb7a13abc388b2f941dabcbc2e79 |

The four registered migration artifact and complete schema checkpoint pairs were independently recomputed from MIGRATIONS and matched the code pins:

| Migration | Artifact SHA-256 | Schema checkpoint SHA-256 |
|---|---|---|
| cr0-c-0001-schema-migrations | b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217 | 1f4d935bf45b5c09f68b4f6e3deb18846aa6d9ee14510eed89b3ab4a71139d30 |
| cr1-e-0002-source-registry | 7ef613bdb646d9b98bc18bb20dd7bba3467d4de12b2cb5c4802e4d1dd8d1c0c7 | 38eb2f69500aa21df1002691c40759ba5acbc58b09c97de4a8ab7bfdd9c40d6a |
| cr1-f-0003-source-spans | 6e6b98e60cff17f0eac94b942533964588344fdd0d8342567962ac4a1c3304b7 | 26f31fe4601c67cb60c6faa324eba83ff59c611b1fa283e514f0a77e3acf44ad |
| cr1-j-0004-local-tasks | a75bfcff37255e1fb0cc49eb72254c8e83d049828faa2653a8495ca2f749120a | 659d0643a9e1c85f839a107d4e8d1d944c38972bb0416d094cd5a73ad355979d |

No new migration, schema checkpoint, fixture, manifest, dependency, CLI behavior, security default or version was introduced. No new release tag exists.

## 12. Version and owner decision

Project metadata and the built wheel both identify 0.2.0.dev0. This is appropriate for the audited development build but is not a stable CR1 release version. If the owner approves the bounded scope, a separate release-engineering step must select and apply a stable version, rebuild and revalidate the final artifact, and follow the repository's release-tag procedure. This audit does not guess a stable version.

- Scope interpretation: PROPOSED.
- Owner approval evidence: ABSENT.
- Release promotion: not performed.
- Tag creation or movement: not performed.
- CR1 status: IN_PROGRESS.

## 13. Remaining limitations and risks

- F13 remains IN_PROGRESS: narrow labeled grammar only, three prose-only missed candidate cases, no natural-language extraction, no model-mediated extraction, no F13 model-output validation, and no real-world evaluation.
- CR0-D ModelGateway is demo-only and PUBLIC-only. No PRIVATE model route is available; the broader sensitivity-aware privacy gateway and egress evaluation remain for CR5.
- F10 remains IN_PROGRESS; explicit file selection and registry comparison do not implement directory discovery/indexing. The two Windows symlink-creation tests were skipped on this host. Same-user path replacement/ABA limits remain.
- The local task operator is unauthenticated; task titles are unencrypted. There is no general encrypted PRIVATE persistence.
- No live Gmail, GitHub, Calendar, Greenhouse or Lever access; no real account authentication or credential inspection. Greenhouse and Lever remain explicitly closed pending source-specific terms review.
- No automatic task extraction, external application, external writes, CR2 policy/approval workflow, production scheduler, general provider sync, production backup/restore assurance or sudden-power-loss guarantee.
- A passing bounded offline audit is not production readiness and does not prove resistance to a compromised OS.

## 14. Final recommendation

**READY_FOR_OWNER_APPROVAL** for the bounded CR1 scope stated in Blueprint §16, subject to the owner's explicit decision on the staged F13 interpretation and separate release engineering for a stable version and final artifact.

The finding “CR1 EXIT VERIFIED FOR OWNER REVIEW” describes this audit's technical evidence only. It is not the top-level CR1 status, which remains IN_PROGRESS. No release is approved, promoted, tagged or published here.