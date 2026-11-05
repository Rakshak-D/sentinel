# CR1-W — Independent CR1 release-scope and architecture review

**Review starting revision:** 2c044aaf3fd8fe334bbf6875a51dfc0843a58084
**Blueprint SHA-256:** 92911A27CDA2AACE41616E5A45F07E228C3D21838E8EB93A30BF71CF228701E7
**Package:** 0.2.0.dev0
**Review type:** documentation-only and advisory; no release promotion.

## 1. Executive decision

**Recommendation: CR1 EXIT CANDIDATE**, subject to a separate release decision. This is not a declaration that CR1 is verified, production-ready, or that F13 is complete.

The §16 CR1 deliverable is the offline daily-read/product core: explicit local tasks and notes, job-feed terms gates, packaged Gmail/GitHub/Calendar fixture readers, persistent incremental source state, and terminal briefings. Its mechanical exit tests name source normalization/citations, a clear capability/credential status, and one-shot CLI operation after restart. §16 does not state that every §2 feature marked ACTIVE TARGET must be complete before CR1 exits, and it does not name model-mediated F13 as a CR1 mechanical exit test.

F13 remains an active, incomplete feature. Its §2 definition depends on ModelGateway and expects broader extraction/triage evaluation. CR1-U/V supply a narrow deterministic, source-cited projection with abstentions and a fixed fictional evaluation; they do not deliver general model-mediated F13. The CR0-D ModelGateway cannot accept the PRIVATE job-alert sources. The later §16 CR5 deliverable is the four-model privacy gateway, including routing and sensitivity egress evaluation, and depends on CR4. A private-model route added now would pull CR5-class privacy and provider work into CR1 and would change the gateway's accepted demo-only contract.

I recommend the explicit staged dependency in Option C: keep the bounded deterministic signals in the CR1 offline core, keep F13 IN_PROGRESS, keep PRIVATE model execution gated, and place any model-mediated PRIVATE F13 route behind the separately accepted privacy gateway work scheduled at CR5 (or a future explicit blueprint decision). This does not erase F13; it identifies its remaining work and destination. No code or privacy policy was changed.

On that interpretation, the CR1 matrix's row D is **PASS for the bounded CR1 criterion only**. That conclusion follows from §16's listed CR1 deliverable and exit tests, not from treating deterministic triage as full F13. The previously recorded “row D PARTIAL blocks CR1” conclusion applied a feature-level dependency as a release-level gate without support in §16. This review changes that blocker semantics explicitly. The release remains IN_PROGRESS until a separate review accepts or rejects this scope interpretation.

## 2. Exact blueprint interpretation

### Verified blueprint requirements

- **§2 feature catalogue:** F05 and F13 are ACTIVE TARGETs. F13 describes turning source facts into typed signals and lists ModelGateway as a dependency; its acceptance notes held-out structured-field precision/recall and span citations. F06 Greenhouse and F07 Lever are explicitly gated by per-board/per-site legal or terms review. §2 describes feature scope; the ledger itself notes that the blueprint does not assign every feature ID one-to-one to a release.
- **§3 trust boundaries:** external mail, web posts, GitHub bodies and notes are T4 external content, not memory or owner authority. Trust labels do not establish factual accuracy or authenticated owner intent.
- **§6 provenance and policy:** untrusted source facts require provenance and do not become trusted intent merely by being quoted, parsed, or emitted by a model. SECRET is excluded from model use; raw PRIVATE content is not eligible for cloud egress.
- **§7 model architecture:** the blueprint describes ModelGateway as the sole model route and prescribes a privacy filter before model selection. Its target design permits raw PRIVATE only through a known loopback model; it does not make that route an implementation fact.
- **§16 CR1:** the release deliverable lists local tasks, notes, job feeds with explicit terms gates, Gmail/GitHub/Calendar fixture readers, incremental source state, and terminal briefings. The explicit exit criteria are passing source-normalization/citation tests, clear missing-credential status, and one-shot CLI operation after restart.
- **§16 CR5:** the four-model privacy gateway is a later deliverable after CR4. Its tests include PUBLIC/INTERNAL/PRIVATE/SECRET egress oracles, provider/profile contracts or explicit unsupported states, and a sealed paired report.

### Interpretation

The Blueprint has two levels of scope. §2 describes complete capability targets; §16 defines release deliverables and their exit criteria. It does not say “all ACTIVE TARGET features are complete before CR1.” Treating F13's ModelGateway dependency as a CR1 release blocker would also conflict with §16's explicit placement of the four-model privacy gateway in CR5. This review therefore treats CR1-U/V as a bounded CR1 deterministic extraction/briefing contribution and leaves broader F13 work open. This is an architectural interpretation, not a verbatim per-feature release assignment.

The terms phrase is read together with §2: F06/F07 are gated, and §16 requires feeds “with explicit terms gates.” Current status explicitly reports the readers absent, the gates closed, and source-specific reviews incomplete. That satisfies the **gate** deliverable; it does not satisfy or claim Greenhouse/Lever feed integration or legal approval. If §16 was intended to require active feeds despite §2's GATED states, the Blueprint should be clarified before enabling any feed. No feed was fetched or approved here.

## 3. Independently rebuilt CR1 requirement crosswalk

The following crosswalk was built from §16's CR1 deliverable and exit assertions, then checked against §2 feature scope. It is not copied from the prior matrix. PASS means only that the bounded CR1 criterion named here has evidence. It does not complete the feature catalogue entry.

| ID | CR1 criterion and source | Code, tests, CLI and installed behavior | Data class and limitation | State / blocks CR1 |
|---|---|---|---|---|
| A | Local task usability (§16 local tasks; §2 F11) | sentinel.tasks.store; CR1-J task/transition/idempotency/restart/CLI tests; sentinel task setup/add/list/edit/complete/reopen. Wheel workflow retained a task through revision 4. | Manual, unauthenticated operator; unencrypted title. No source-derived tasks or approvals. | PASS for bounded workflow; no. F11 remains IN_PROGRESS. |
| B | Explicit allowlisted notes and edit detection (§16 notes; §2 F10) | read_allowlisted_local_text and notes_registry APIs; CR1-M/T path/change/restart tests; source inspect-file and notes-registry build/verify. Installed-wheel smoke built and verified a one-note registry. | T4_EXTERNAL / PRIVATE. Explicit files only. Two existing Windows final-component symlink-creation tests skip on this host; same-user and ABA races remain. | PASS for bounded workflow; no. F10 remains IN_PROGRESS. |
| C | Job feeds with explicit terms gates (§16; §2 F06/F07 are GATED) | source_status; CR1-S terms-gate/status tests. Greenhouse and Lever each report NOT_IMPLEMENTED, TERMS_GATED, TERMS_REVIEW_REQUIRED, and REQUIRED_NOT_COMPLETED. No host enabled. | No HTTP readers or trusted source-specific approval artifacts; no feed is approved. | PASS for gate only; no. F06/F07 remain gated. |
| D | Bounded job-alert extraction/review and cited typed signals as part of the CR1 offline read core (§16 terminal briefing/normalization/citations; §2 F05/F13 broader targets) | sentinel.extraction, sentinel.triage.job_alert, sentinel.triage.evaluation; CR1-O/P/U/V tests including test_cr1_v_evaluation_matching.py. CLI parse-job-alert, review-job-alerts, triage-job-alerts. Installed-wheel smoke ran all three on a fictional local alert. | Source T4_EXTERNAL / PRIVATE; signals T3_DERIVED / PRIVATE. Cited deterministic projection and abstentions. Not full F13: prose-only misses remain, no model runs or real-world generalization. | PASS for bounded CR1 criterion; no. F13 remains IN_PROGRESS and model-mediated PRIVATE triage gated. |
| E | Packaged Gmail fixture reader (§16 fixture readers; §2 F01/F05 context) | read_packaged_gmail_fixture; fixture-reader and CR1-S integrity tests; source status validates it offline. | Synthetic, T4_EXTERNAL / PRIVATE. No live account, OAuth, mailbox, or credential check. | PASS for fixture reader; no. Live F01 remains unimplemented. |
| F | Packaged GitHub fixture reader (§16 fixture readers; §2 F03 context) | read_packaged_github_fixture; fixture/ingestion/CR1-S tests; brief github-fixture. Installed workflow verified 3 original items / 9 citations. | Fictional, PUBLIC / T4_EXTERNAL. No live repository or authenticated account. | PASS for fixture reader; no. |
| G | Packaged Calendar fixture reader (§16 fixture readers; §2 F09 context) | read_packaged_calendar_fixture; CR1-Q reader/time/all-day/citation tests; source calendar-fixture. Installed workflow verified 4 events. | Synthetic descriptions are PRIVATE / T4_EXTERNAL. No live Calendar, OAuth, recurrence, timezone database, or scheduling. | PASS for fixture reader; no. Live F09 remains NOT_STARTED for CR4. |
| H | Source normalization and typed provenance (§16 exit; §2 F12) | sentinel.normalization; reader and plain-text normalization/boundary tests. | Preserves original UTF-8 bytes and declared trust/sensitivity. Labels and hashes do not authenticate source authors. | PASS for bounded normalization; no. F12 remains IN_PROGRESS. |
| I | Exact source-bound citations (§16 exit) | add_citation, bind_citation, verify_bound_citation; CR1-G/H1/M/O/P/Q/U/V citation tests. | Exact half-open UTF-8 byte spans and slice digests. Integrity against expected bytes is not provider authenticity or truth. | PASS for tested contract; no. |
| J | Persistent incremental source state (§16; §2 F18) | sentinel.sync.github_fixture; CR1-K/R progress, tampering, rollback, and restart tests; fixture-sync. Installed workflow advanced generation 0→1 and verified after restart. | Synthetic cursor and fixture items only; no live pagination, provider token, tombstones, scheduling, or general sync. | PASS for bounded persistent state; no. F18 remains IN_PROGRESS. |
| K | Terminal briefings (§16; §2 F15) | build_github_fixture_brief and build_local_overview; CR1-I/L tests; brief commands. Installed workflow read 3 items / 9 citations and kept cursor status separate. | Deterministic offline presentation; no AI narrative, live freshness, or complete personal briefing. | PASS for bounded briefing; no. F15 remains IN_PROGRESS. |
| L | Clear capability/credential status (§16 missing-credential status) | build_source_status_report and CredentialBroker.backend_availability; CR1-S status/credential tests; source status --format json. | Live adapters NOT_IMPLEMENTED; account and credential checks NOT_CHECKED; production credential backend UNAVAILABLE. No credential store is queried. | PASS for honest offline status; no. It does not claim a user's credential is missing. |
| M | One-shot CLI after restart (§16 exit) | CR1-R restart tests and component restart suites; the installed workflow used distinct CLI processes. | Task and cursor state recovered on later invocations; no daemon or power-loss guarantee. | PASS for offline workflow; no. |
| N | Installed-wheel functionality (§16 wheel/CLI core and restart assertion) | python -m build --wheel; installed console script. Import resolved from .venv/Lib/site-packages/sentinel; 17 process calls ran with working directory outside checkout. | Tested Windows wheel and packaged fixtures; no cross-platform claim. | PASS for tested wheel workflow; no. |
| O | PRIVATE containment (§3/§6/§7) | Local reader/triage labels and tests/test_cr1_u_privacy.py plus CR1-M/P/Q boundaries. | Sources remain T4_EXTERNAL / PRIVATE; signals T3_DERIVED / PRIVATE. No PRIVATE body enters PUBLIC blob storage or ModelGateway. Not encryption or general same-user isolation. | PASS for tested paths; no. |
| P | No unauthorized external effects (§3/§6; offline CR1 boundary) | CR1-S/U privacy tests and code review of reader/status/triage paths. | Installed workflow did not request providers, open URLs, create proposals, or invoke model/tool paths. Defaults keep live sources and external writes disabled. | PASS for bounded commands; no. Not a certification of future adapters. |
| Q | Windows limits disclosed (§2 F10 failure modes; current host) | CR1-M path/race tests and ledger skip records. | Two existing live symlink-creation tests skipped because creation is unavailable. No claim those cases ran. | PASS as disclosure criterion; no. Host limitation remains. |
| R | Documentation and reproducible demo | README, ledger, fixture-workspace APIs and this review; actual disposable wheel workflow. | No private user data, credentials, or live source content used. | PASS for current evidence; no. Separate release owner still decides. |

**Crosswalk result:** 18 PASS for the bounded CR1 criteria above; 0 PARTIAL, 0 FAIL, 0 UNVERIFIED, 0 DEFERRED as CR1 exit rows. Deferred F13/CR5 work below is not being counted as a CR1 exit row. This does not change feature status or promote the release.

## 4. F13 capability versus CR1 scope

| F13 capability | Status | Evidence and limitation |
|---|---|---|
| Structured field extraction | BOUNDED | CR1-O accepts a closed line-labeled grammar from selected local files or the fixed Gmail fixture. Not general email understanding. |
| Typed signal projection | BOUNDED | CR1-U emits candidate, declared URL, and declared date signals only from CR1-O present fields. |
| Verified source citations | IMPLEMENTED | Positive field references check source identity, digest, span UUID, byte range, and slice digest. |
| Ambiguity handling | IMPLEMENTED | Ambiguous cases remain visible as AMBIGUOUS / REVIEW_REQUIRED; no cross-record merge. |
| Missing-data abstention | IMPLEMENTED | Incomplete records remain REVIEW_REQUIRED; absent URL/deadline produces no optional signal. |
| Source trust retention | IMPLEMENTED | Original source T4_EXTERNAL; derived signal T3_DERIVED. |
| PRIVATE sensitivity retention | IMPLEMENTED | Source and signal stay PRIVATE; no downgrade. |
| Deterministic output | IMPLEMENTED | Closed signal grammar, deterministic IDs/order, stable JSON/text. |
| Source-to-signal evaluation | BOUNDED | Actual triage outputs scored against pinned fictional labels. |
| Held-out scoring | BOUNDED | Fixed 30-case holdout; authored with the development corpus, not independent sampling. |
| Case-local TP/FP/FN | IMPLEMENTED | CR1-V matches within case ID before aggregate scoring; adversarial swaps receive no cross-case TP. |
| Real-world generalization | NOT_IMPLEMENTED | No real Gmail, board, or user-alert corpus. |
| Natural-language extraction | NOT_IMPLEMENTED | Three prose-only expected candidates are missed across development and holdout. |
| Model-mediated extraction | GATED | No F13 route sends PRIVATE content to a model; CR0-D rejects it. |
| F13 model-output schema validation | NOT_IMPLEMENTED | CR0-D supports its synthetic text contract; no model-generated typed triage response exists. |
| Local-only PRIVATE model execution | GATED | Current CR0-D rejects PRIVATE even for loopback. §7 target architecture is not current code. |
| Cloud privacy routing / egress evaluation | DEFERRED | No cloud route is active; fuller provider/profile and egress-oracle work is §16 CR5. SECRET remains excluded. |

This is deterministic extraction/projection evaluation, **not model evaluation**. The 24 development cases produced 21/22 in-bound classifications correct, candidate F1 0.9600, and micro signal F1 0.9787. The 30 holdout cases produced 26/28 in-bound classifications correct, candidate F1 0.9231, and micro signal F1 0.9615. One development and two holdout candidates expressed only in natural language and were classified NO_MATCH. These are observations about a synthetic contract corpus, not real-world recall estimates.

## 5. ModelGateway and privacy constraints

### Verified implementation facts

- src/sentinel/gateways/model.py accepts only explicit DEMO registrations and the supported sentinel.text.v1 input/output schema. It checks registered source sensitivity against the request and rejects SECRET; it then permits only PUBLIC. Cloud-classified adapters are denied. It does not provide the §7 raw-PRIVATE local execution target.
- tests/test_model_gateway.py includes test_secret_content_never_reaches_any_model_adapter, test_private_content_cannot_reach_cloud_classified_adapter, test_cloud_profile_and_cloud_adapter_are_unavailable_even_for_public_data, and sensitivity-downgrade denial. Denied adapters do not run.
- src/sentinel/extraction/job_alert.py labels local source data T4_EXTERNAL / PRIVATE. src/sentinel/triage/types.py carries source evidence as T4_EXTERNAL / PRIVATE and signals as T3_DERIVED / PRIVATE. src/sentinel/triage/job_alert.py rejects different source labels.
- Triage does not import or call ModelGateway. CR1-U/V did not modify gateway, extraction, readers, or privacy labels. CR1-U privacy tests and the full suite pass.
- Source status does not inspect a real credential/account. It reports live credential/account checks NOT_CHECKED, absent live adapters NOT_IMPLEMENTED, and the production credential backend UNAVAILABLE.
- Bundled defaults have no enabled sources or host allowlist, internal-cloud consent is false, and external writes are false. Greenhouse/Lever remain terms-gated. SECRET is never gateway-callable. Source content cannot approve its own terms or become T1_OWNER_INTENT.

### Architectural consequence

There is no authorized route from PRIVATE local alerts to the current ModelGateway. A valid route requires a separately reviewed local PRIVATE execution path with verified loopback/provider identity, schema and prompt contracts, route policy, egress measurement, and adversarial privacy tests. A second model path bypassing ModelGateway would violate repository governance; changing CR0-D to accept PRIVATE would invalidate its accepted contract. §16 CR5 is the later destination for fuller sensitivity-aware routing. No CR5 work is claimed here.

## 6. Architecture options

| Option | Blueprint fidelity | Utility and truthfulness | Privacy / gateway effect | Work and release risk |
|---|---|---|---|---|
| A — Accept deterministic F13 subset; keep rest open | Consistent with the CR1 offline core, but does not formally explain why §2's ModelGateway dependency remains open. | Useful and honest if called bounded deterministic projection, never complete F13. | Preserves PRIVATE and CR0-D restrictions. | Low work; leaves ambiguity that caused row D to be marked blocking. |
| B — Block CR1 until PRIVATE-safe ModelGateway inference exists | Treats §2 feature dependency as a release gate not stated in §16; conflicts with CR5's later placement unless the Blueprint is amended. | More inference, but not required to make the documented offline core usable. | Requires local PRIVATE routing/security work; cannot relabel PRIVATE or bypass ModelGateway. | Pulls CR5 work forward and changes accepted gateway scope. |
| C — Formal staged dependency (recommended) | Reads §2 as complete F13 feature scope and §16 as the CR1 release test; places full PRIVATE model route with the later privacy gateway. | Preserves useful cited deterministic outputs and exposes absent capabilities. | Keeps current hard boundaries; no PRIVATE/SECRET model egress. | Decision now; privacy-gateway work later; no product-code change. |

### Recommended staged dependency

1. **CR1:** deterministic narrow extraction, batch review, typed source-cited projections with abstention, offline fixture/local workflows and restart evidence. A bounded product contribution, not full F13.
2. **CR5 (proposed feature staging consistent with §16):** model-mediated PRIVATE triage only after the four-model privacy gateway, local route verification, schema validation, and privacy/egress evaluations pass. The Blueprint does not explicitly assign F13 to CR5; this is a dependency-based recommendation, not a quoted release requirement.
3. Keep F13 IN_PROGRESS; keep CR0-D synthetic-PUBLIC-only; do not enable provider SDKs, cloud routes, task creation from signals, or source-derived owner intent.

## 7. Release blockers versus later limitations

**No unverified mechanical §16 CR1 blocker was found in this review.** The current evidence covers the listed offline deliverables and exit tests. This supports the advisory CR1 EXIT CANDIDATE recommendation, not release approval.

The following remain real and must not be recast as completed CR1 capabilities:

- Full F13 natural-language/model-mediated extraction; the model path is gated and F13 stays IN_PROGRESS.
- Live Gmail, GitHub, Calendar, Greenhouse, and Lever access; provider credentials and terms are not checked/approved. Greenhouse/Lever have no readers and remain closed.
- General sync, daemon/scheduler, desktop/web UI, model privacy routing, CR2 authorization/approvals, CR5 egress evaluation, general encrypted PRIVATE persistence, RAG/memory, and external writes.
- F10's broader folder workflow, actual Windows symlink creation tests skipped on this host, and malicious same-user/ABA race protection.
- CR1 evaluation corpora are synthetic and developer-authored; three prose-only misses show the parser boundary. They do not establish production accuracy.
- Manual task operator identity is unauthenticated; task titles are unencrypted. Notes and Calendar descriptions are PRIVATE and are not persisted by these slices. No general private storage or production security claim.
- SQLite writer coordination does not protect against noncooperating same-user access; no power-loss or production backup/restore assurance.
- Source-status checks package fixtures and bundled state; they do not inspect actual user credentials or accounts.

A future release owner may disagree and require full F13 in CR1. If so, the Blueprint/release definition should be amended explicitly before scheduling a private model path; the safe technical consequence is a CR1 blocker pending reviewed gateway design, not a PRIVATE-to-PUBLIC downgrade or direct SDK call.

## 8. Actual evaluation and corpus verification

The pinned resources were hash-checked and the evaluator rerun by building labels from the frozen expected-label manifest, running triage_selected_job_alerts on each decoded local case, and passing those actual observations to evaluate_job_alert_triage.

| Metric | Development | Holdout |
|---|---:|---:|
| Cases; in-bound | 24; 22 | 30; 28 |
| Classification accuracy | 21/22 (95.45%) | 26/28 (92.86%) |
| Candidate TP/FP/FN; P/R/F1 | 12/0/1; 1.0000/0.9231/0.9600 | 12/0/2; 1.0000/0.8571/0.9231 |
| URL TP/FP/FN/F1 | 9/0/0/1.0000 | 10/0/0/1.0000 |
| Deadline TP/FP/FN/F1 | 2/0/0/1.0000 | 3/0/0/1.0000 |
| Micro TP/FP/FN/F1 | 23/0/1/0.9787 | 25/0/2/0.9615 |
| Macro F1 | 0.9867 | 0.9744 |
| Incorrect abstentions; unexpected failures | 1; 0 | 2; 0 |
| Citation references verified/missing/invalid/cross-source | 35/0/0/0 | 37/0/0/0 |

CR1-V case-local matching is confirmed in src/sentinel/triage/evaluation.py: each label/observation pair is checked for aligned unique case ID, exact signal counters are matched inside that pair, and per-kind counts are summed afterward. An expected URL in case A and unexpected URL in case B therefore produce TP/FP/FN 0/1/1. Confusion rows remain actual per-case class predictions; expected invalid inputs remain separate from in-bound accuracy. A zero denominator yields zero.

Frozen SHA-256 values:

- Development, 24 cases: 13e4374e7cee04a1d08d9987376dc6d764eb737b63f1965ca756964fa0e820b5
- Holdout, 30 cases: 645bdaf8a2725e4228de49490b568ef92bcc37b4352b73e8ff3d439d026d47ba
- Expected labels, 54 cases: 482008fb933808175d4ab1847d6c055b772dcb7a13abc388b2f941dabcbc2e79

These are not model metrics or an independent real-world benchmark.

## 9. One-shot installed-wheel / restart evidence

The wheel was built and installed into the project virtual environment; sentinel.__file__ resolved from .venv/Lib/site-packages/sentinel/__init__.py. A disposable workflow launched **17 separate console-script processes** with their working directory outside the repository. Every successful command returned code 0 and empty stderr.

Verified sequence:

1. sentinel init --database <temporary-db>
2. sentinel fixture-workspace prepare --database <temporary-db> --store-root <temporary-public-store>
3. fixture-workspace verify reported synthetic workspace ready, 3 original GitHub items / 9 citations, cursor 0/3 READY.
4. source status --format json reported fixtures ready, live sources disabled/not implemented, terms gates closed, and no account/credential inspection.
5. brief github-fixture reported exactly 3 items and 9 citations.
6. source calendar-fixture --show-details --format json reported 4 events; no live Calendar request.
7. brief local-overview with fixed as-of 2026-11-05T18:00:00+05:30 reported zero tasks, three evidence items/nine citations, and cursor generation 0.
8. Separate task add, edit, complete, and reopen invocations; a later task list saw one OPEN task at revision 4.
9. fixture-sync advance with expected generation 0 returned APPLIED at generation 1; a later workspace verify saw generation 1/3 READY.
10. Repeated workspace prepare reported ALREADY_PREPARED and preserved generation 1.
11. A later local overview saw one manual task, three original evidence items/nine citations, and incremental generation 1 in a separate section. The replay item was not counted as another unique original issue.

A second outside-checkout wheel smoke built and verified a metadata-only notes registry and ran CR1-O parse, CR1-P review, and CR1-U triage on a fictional local alert. It verified default triage output hid values and explicit show-fields enabled cited-field disclosure. No user note, mailbox, credential, provider URL, or personal data was used. Separate CLI processes establish process-restart behavior, not a daemon or power-loss guarantee.

## 10. Acceptance, preservation, and security boundaries

Observed in this review:

- Starting main was exactly 2c044aaf3fd8fe334bbf6875a51dfc0843a58084, clean and equal to origin/main.
- Full suite: **1326 passed, 2 skipped in 441.04s**. The only skips were tests/test_bootstrap_init.py:125 and tests/test_storage_writer_lease.py:251 because final-component symlink creation was unavailable on this Windows host.
- pip install -e .[dev] succeeded; pip check reported no broken requirements; Ruff passed; mypy found no issues in 91 source files; wheel build succeeded as sentinel-0.2.0.dev0-py3-none-any.whl.
- CLI root/source/doctor/workspace/triage/notes-registry help checks and version succeeded; version remained 0.2.0.dev0.
- CR0 tag object e5aa8bb2e280a2fc78804d74d576afdfaf544559 still peels to b446e1b934eb2be71853f9b6eab9e0238eade211. Runtime-lock SHA-256 remains 319ec67ddf87b44690eda03d47675975c806d5cc16242166dbf109ed5c4005ec.
- Four migration IDs and artifact/checkpoint pins are unchanged. GitHub/Gmail/Calendar resource bytes remain pinned; H1 manifest and CR1-U corpora/labels match recorded pins.
- Source status reports live_sources_enabled=false, external_writes_enabled=false, and safe_defaults_state=VERIFIED. No live credentials were read. This audit added no model, provider, gateway, task, proposal, migration, or storage behavior.
- CR2 P00-P17 and AB01-AB18 remain NOT_STARTED; CR5 privacy gateway is not implemented. No release tag was created.

## 11. Unresolved decisions and remaining risks

**Resolved by this review, subject to the separate release owner:** whether full model-mediated F13 is a CR1 mechanical exit test. This review finds no such test in §16 and recommends staging the privacy-dependent remainder as above.

**Not a completed capability:** live providers, feed terms, and accounts are not enabled; no credentials were checked or terms approved.

**Residual interpretation risk:** §2's F13 dependency does not assign F13 to a release, and §16 does not explicitly say “F13 may remain incomplete.” The staged reading best fits the release table and CR5 dependency, but the release owner should approve it before changing CR1's top-level state. If the owner requires complete F13 in CR1, the outcome is CR1 STILL BLOCKED and implementation must be separately scoped.

## 12. Proposed next engineering action

Have the independent release owner accept or reject the staged CR1/CR5 dependency. If accepted, conduct the separate CR1 release-promotion review with this crosswalk as evidence. Keep F13 in progress and create a future CR5-bound design/task for PRIVATE local model routing and F13 output validation. If rejected, revise the authoritative release requirement explicitly and plan a reviewed gateway change; do not implement a direct model path.

## 13. No production-readiness statement

This recommendation describes a reproducible synthetic/offline Windows CLI core with bounded local workflows. It is not production readiness, live-provider readiness, a complete daily briefing, a complete F13 implementation, a general PRIVATE-data store, a security certification, or CR1 release approval.
