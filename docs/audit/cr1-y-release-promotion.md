# CR1-Y — release promotion record

## Approved scope and authorization

The release owner, through the supervising conversation, accepted staged Option C and authorized preparation of the bounded offline CR1 release, conditional on every mandatory technical gate passing. The accepted scope is the offline daily-read/product core and mechanical exit criteria in Master Blueprint §16. This authorization covers stable version preparation, final acceptance, the annotated `cr1-v0.2.0` tag, and non-force promotion of `main` plus that tag. It does not authorize PyPI publication, a GitHub Release, provider calls, model egress, external writes, or CR2 implementation.

CR1 release verification applies only to this bounded offline scope. Full F13 remains IN_PROGRESS; model-mediated PRIVATE triage remains gated. The ModelGateway remains synthetic PUBLIC-only. CR5 privacy-gateway requirements, live Gmail/GitHub/Calendar access, live job feeds, general source synchronization, CR2 authorization, and external writes remain unimplemented, gated, or deferred as recorded in the ledger. This release is not production-ready.

## Revision and version

- Original CR1-X audited source and ledger revision: `335b3e53c81ed98e783edf663cc0bcc7df7043d6`.
- Stable-version implementation commit: `1b6245707da1149f912947dc1a26889e9051d572`.
- Release README/audit commit: `6156e3d29bc6e274654fa73d6db553569c1ba146`.
- Version sources: `pyproject.toml` and the source-checkout fallback in `src/sentinel/__init__.py`; both now identify `0.2.0`. The installed metadata, `sentinel.__version__`, and `sentinel version` were checked in an isolated Python 3.11.7 environment.
- Target annotated tag: `cr1-v0.2.0`, intended to point to the final committed release record. Its message will identify “Sentinel CR1 — bounded offline daily-read/product core.” No tag is created until final-candidate acceptance succeeds.

Earlier CR1 slices and the independent CR1-X audit intentionally retain their historical `0.2.0.dev0` observations. No historical test or audit evidence was rewritten.

## Acceptance evidence gathered during preparation

The clean pre-change baseline run at `335b3e5` completed with `1326 passed, 2 skipped in 494.46s`. After the version alignment at `1b62457`, editable installation succeeded and the full suite completed with `1326 passed, 2 skipped in 383.32s`. Both runs skipped only the same Windows symlink-creation tests:

- `tests/test_bootstrap_init.py:125`
- `tests/test_storage_writer_lease.py:251`

Windows denied creation of those final-component symlinks. No new skip or xfail was reported. On the version-aligned source, `pip check` reported no broken requirements, Ruff passed, and mypy reported no issues in 91 source files. The wheel build produced `sentinel-0.2.0-py3-none-any.whl`.

The first version-only wheel was SHA-256 `9c7097922e61150b183e5c2cb22b5b2d1e7d8eea97531180f88d0b55ab37add0`. It predates the release README update and is explicitly superseded. With the final README content, the stable wheel is `sentinel-0.2.0-py3-none-any.whl`, SHA-256 `ff4ca51223d8d176cdabf8f2c135d7f2da20532be896413cff845df8e4daa80a`. Its wheel metadata says `Version: 0.2.0`; the three packaged fixture resources were rehashed from inside the wheel and matched their existing pins. The final post-ledger commit build is required to reproduce this digest before tagging.

The first separate clean Python 3.11.7 venv was populated without an index from wheel artifacts downloaded against the existing CR0 runtime lock using `--require-hashes`; Sentinel itself was installed from the version-aligned local wheel with `--no-deps`. `pip check` passed. Imports resolved under that venv's `Lib/site-packages`, not the source checkout. The CLI reported version `0.2.0`; root help, doctor help, source status, fixture-workspace help, notes-registry help, and triage help succeeded. The status report validated all three packaged fixtures and reported live providers NOT_IMPLEMENTED, actual account/credential checks NOT_CHECKED, Greenhouse/Lever TERMS_GATED, and external writes disabled.

The independently launched process workflow was rerun with the wheel built from the final README content. It exercised init, workspace prepare/verify, source status, the GitHub briefing (3 original items / 9 citations), Calendar inspection (4 synthetic events), fixed-as-of overview, manual task setup/add/edit/complete/reopen, incremental cursor advancement, registry build/verify/edit-detect/restore, and fictional alert parse/review/triage. A same-length note edit yielded one CHANGED result, then restoration returned all three notes to UNCHANGED. After separate CLI processes restarted, the task was revision 4 and OPEN, the cursor was generation 1, and repeat preparation reported ALREADY_PREPARED. The fixture workspace contained 4 source items / 12 spans including one incremental item, with no duplicate original evidence. SQLite integrity was `ok`, foreign-key violations were zero, and action proposals were zero. PRIVATE test canaries were absent from SQLite and PUBLIC blobs. A child-process guard observed zero network, process, shell, or Windows credential calls. Read-only DB row and PUBLIC blob-hash snapshots were unchanged across read commands and repeat preparation. The exact final ledger commit is rebuilt and rechecked before tag creation; no result from this preparation stage is substituted for that final check.

## Preserved integrity pins

| Artifact | Verified value |
|---|---|
| Master Blueprint | SHA-256 `92911a27cda2aace41616e5a45f07e228c3d21838e8eb93a30bf71cf228701e7` |
| CR0 annotated tag object / peeled commit | `e5aa8bb2e280a2fc78804d74d576afdfaf544559` / `b446e1b934eb2be71853f9b6eab9e0238eade211` |
| CR0 runtime lock | SHA-256 `319ec67ddf87b44690eda03d47675975c806d5cc16242166dbf109ed5c4005ec` |
| CR0-C migration / checkpoint | `b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217` / `1f4d935bf45b5c09f68b4f6e3deb18846aa6d9ee14510eed89b3ab4a71139d30` |
| CR1-E migration / checkpoint | `7ef613bdb646d9b98bc18bb20dd7bba3467d4de12b2cb5c4802e4d1dd8d1c0c7` / `38eb2f69500aa21df1002691c40759ba5acbc58b09c97de4a8ab7bfdd9c40d6a` |
| CR1-F migration / checkpoint | `6e6b98e60cff17f0eac94b942533964588344fdd0d8342567962ac4a1c3304b7` / `26f31fe4601c67cb60c6faa324eba83ff59c611b1fa283e514f0a77e3acf44ad` |
| CR1-J migration / checkpoint | `a75bfcff37255e1fb0cc49eb72254c8e83d049828faa2653a8495ca2f749120a` / `659d0643a9e1c85f839a107d4e8d1d944c38972bb0416d094cd5a73ad355979d` |
| GitHub / Gmail / Calendar fixtures | `7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1` / `781112d5b62439e833f33040f0e4f67c4adafa86d2f94e1b137fa09d52fa8b57` / `e879838ea32430497160bacbdedde1c4ffd98b1906bcdddc1c77c776f756575a` |
| H1 manifest | SHA-256 `645aecaedd14d8e6c6071b9d8c32a5d91f664c715799191303eac315d6f9c08f` |
| CR1-U development / holdout / labels | `13e4374e7cee04a1d08d9987376dc6d764eb737b63f1965ca756964fa0e820b5` / `645bdaf8a2725e4228de49490b568ef92bcc37b4352b73e8ff3d439d026d47ba` / `482008fb933808175d4ab1847d6c055b772dcb7a13abc388b2f941dabcbc2e79` |

The registered migration set was independently checked as four entries with the recorded artifact and checkpoint hashes. CR0's annotated tag and lock were not changed. The fixture and evaluation resources were hashed from their current bytes. The status, doctor, gateway, and source-reader contracts retain their existing offline/privacy boundaries.

## Scope limitations and release boundary

- F13's complete ModelGateway-dependent feature, natural-language extraction, and real-world generalization are incomplete; the three prose-only parser misses remain documented. No PRIVATE bytes are sent to the current PUBLIC-only demo gateway.
- F10's broader capability is incomplete. The release includes only bounded explicit local-file read/search and registered-note workflows; no directory discovery or watcher exists.
- Gmail, GitHub, and Calendar support is fixture-only. Greenhouse and Lever remain unimplemented and terms-gated. No account or credential check is performed by source status.
- Local task operation is unauthenticated; task titles are unencrypted. General PRIVATE persistence, CR2 authorization/approval, CR5 privacy routing, live synchronization, scheduling, and external writes are not included.
- Two Windows symlink-creation tests remain skipped on this host. Same-user filesystem replacement/ABA races, sudden power-loss durability, and production operational assurances are not established.

CR0 remains VERIFIED. CR1 is VERIFIED only for the bounded §16 offline scope after the documented acceptance. The final committed ledger candidate must reproduce the full test, wheel, and restart results before tag creation. This promotion does not complete F13, broader F10, or the Sentinel product.
