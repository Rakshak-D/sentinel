# ADR-0005: CR2-G-A owner-authentication trust root and channel feasibility

- Status: Proposed architecture; production owner authentication remains unavailable
- Date: 2026-11-08
- Scope: Documentation-only CR2-G-A review on `feat/cr2-g-a-owner-trust-feasibility`
- Reviewed source revision: `bd420b94f1a64ff0b2f534102e135856150436fe`
- Master Blueprint SHA-256: `92911A27CDA2AACE41616E5A45F07E228C3D21838E8EB93A30BF71CF228701E7`

This record proposes a future trust architecture. It does not authorize enrollment, production authentication, approval, task acceptance, grants, policy changes, or effects. No application code or schema is changed by CR2-G-A.

## 1. Decision summary

Use **Option C, a separately protected Windows service/broker boundary, as the required trust and storage boundary**. If a future service needs a WebAuthn ceremony, evaluate **Option B, the Windows WebAuthn Win32 API**, as its platform interface through a narrowly scoped user-session component. Do not treat either the browser path or native authenticator API as the owner trust root. Do not use the current `https://sentinel.test` origin for production credentials.

Protected enrollment is **conditionally feasible at the platform level but unavailable in the current product**. It becomes eligible for implementation only after an explicit bootstrap authority is selected, the service-owned credential state is protected and tested against a non-admin same-user process, and an exact-action trusted display path is demonstrated. If those gates cannot be established, production owner verification and all consequential capabilities must remain unavailable/OFF.

The current architecture has no independent root that can decide which first credential belongs to the owner. A WebAuthn assertion is a signature produced by an authenticator for a relying-party request, under its registered credential and checked RP/challenge context. The WebAuthn specification describes the ceremony as consent to a specific transaction, but the relying party cannot infer from signature verification alone that Sentinel's exact proposal was accurately presented and understood. The assertion does not prove who enrolled the public key, that enrollment metadata is truthful, or that the credential's user is a particular natural person.

## 2. Blueprint requirements used

The local, hash-pinned Master Blueprint is authoritative. The following requirements govern this decision:

| Blueprint section | Requirement applied here |
|---|---|
| §2 F21 | The deterministic policy gate authorizes exact capability and arguments, consumes validated labels/registry/provenance, and must be tested for bypass and overblocking. |
| §2 F22 | Human-verified approval is a one-use decision for an exact proposal; it is gated on a valid human channel and replay/expiry denial. |
| §2 F23 | Write credentials must be isolated from read/MCP surfaces; the feature is gated on verified OS process isolation. |
| §3, TB1/TB4/TB6/TB8 | Browser/CLI mutation boundaries need origin/session controls; external text stays T4 and cannot mint memory authority; storage needs OS controls; a writer process needs a distinct OS identity or OS-protected secret and request-mediated worker. |
| §3 deployment and failure posture | Loopback is not an exposed public listener; one policy core serves all surfaces; failed policy/approval verification denies writes. The writer lease arbitrates cooperating code and is not protection against privileged same-UID access. |
| §4 | Approval is a durable state transition, revalidated after resume. The approved action is frozen and canonical; a changed field requires fresh proof. |
| §6 trust model | T1 is independently authenticated owner intent. T2 authentication metadata is not content authority; T3 derived and T4 external content cannot become T1; T5/missing information denies. P00-P03 are hard denials, P11 denies rejected/expired/revoked/consumed/wrong-proposal approvals, P16 rejects CLI/stdin/PTY/session-token substitutes, and P12 is catch-all DENY. |
| §6 proposal confirmation | The challenge is random, one-use, short-lived, and bound to proposal, policy, account, capability, expiry, and nonce; the verifier checks RP ID/origin, UV, signature, challenge, and atomic consumption. |
| §7 | User verification is an authenticator-local check. Model privacy routing is separate; no change to PRIVATE/SECRET restrictions is justified by WebAuthn. |
| §16 | CR2 ultimately includes P00-P17, an approval queue, local task writes, and durable interrupts, with hard-policy, bypass, idempotency, and crash gates. CR7 external writes remain gated on a verified OS user channel and credential isolation; CR8 adds independently anchored signed audit. |

F22 and F23 are explicitly gated in the feature catalogue; that is a security condition, not permission to omit them from a future approval/write release. The CR2-G-A decision only defines a defensible prerequisite architecture and does not claim CR2's §16 exit criteria pass.

## 3. Trust model and verified repository facts

These identities and decisions are separate:

| Concept | Meaning | What establishes it |
|---|---|---|
| Windows account/local operator | A process security context identified by Windows access-token SIDs and privileges. Multiple processes can run under the same account and token. | Windows logon and token state; this identifies an OS account/session, not a natural person or intent for a specific proposal. |
| Human owner | The person designated by the product owner as controlling a Sentinel profile. | An explicit trusted bootstrap and recovery process is required; none exists today. |
| Enrolled WebAuthn credential | A registered credential ID and public key the verifier trusts for that owner. | A protected enrollment record and authenticated owner-to-key association are required. CR2-F has neither for production. |
| Authenticator UP/UV | Evidence that an authenticator reported presence and, when required, its local user-verification flag for a signed assertion. | Authenticator response checked by a verifier. UV does not identify the owner to the RP. |
| T1 owner intent | An instruction attributed to the independently authenticated owner. | A trusted owner-intent resolver must create it from an authenticated, scoped channel. Source text, model output, account name, or a request flag cannot mint it. |
| Proposal approval | Consent to one immutable proposal snapshot and an explicit action. | A future one-use verification receipt bound to that exact snapshot and displayed through a trusted channel. Authentication by itself is not approval. |
| Effect permission | Policy authorization for one capability, arguments, target, and runtime context. | A separate current policy decision plus mandatory reference-monitor enforcement. An assertion, T1 intent, proposal status, or approval receipt alone is not a grant to execute. |

Verified implementation facts at the reviewed revision:

- `src/sentinel/owner_proof/service.py` exports only `issue_synthetic_assertion_options()`, `verify_synthetic_assertion()`, and read-only `build_owner_proof_status()`. The issue/verify APIs state and enforce synthetic-only scope. No production registration/enrollment API or owner-intent resolver exists.
- `src/sentinel/owner_proof/types.py` fixes verification to `credential_classification="SYNTHETIC_TEST_ONLY"`, `owner_verified=False`, and `executable=False`. Status fixes `production_owner_verification="UNAVAILABLE"`, `owner_verified=False`, and `executable=False`.
- `src/sentinel/storage/schema.py` marks credential rows `SYNTHETIC_TEST_ONLY` and `synthetic-test-owner`; there is no private-key column. The CR2-F tests insert their synthetic credential public-key rows directly for test setup. They do not demonstrate a protected enrollment procedure.
- `sentinel auth status` is read-only and reports synthetic counts/backend state. It does not inspect Windows Credential Manager or claim a linked production credential.
- The production `CredentialBroker()` uses `UnavailableCredentialBackend`; its explicit in-memory operations are test-named and not used as an application backend.
- SQLite schema guards and the Windows writer lease protect expected application operations and cooperating writers. They do not prevent another process with write access to the same database file from changing the file, dropping/replacing triggers through a separate connection, or replacing rows. The repository's `README.md` and CR2-F ledger already state that same-user database tampering is not defeated.
- The native authentication result is never consumed by policy, proposal status, task creation, grant, or effect code. P11, an approval queue, trusted owner identity, and a privileged effect worker remain unimplemented.

**Trust-root finding:** Under the current same-user-writable SQLite layout, an arbitrary process under the same interactive account can add, replace, or alter the stored public key/owner association if it can write the database file. SQLite triggers and a cooperative mutex are not an OS access-control boundary. A signature against such a replacement key only proves possession of the attacker's corresponding private key. WebAuthn verification alone does not solve enrollment substitution.

## 4. Same-user threat model

### In scope for future consequential actions

- Untrusted email, notes, issues, postings, model output, tool descriptions, and caller JSON attempting to claim T1, change an action, or select a handler.
- A non-admin malicious process or agent running in the owner's interactive account, including direct SQLite/file access, shell/PTY automation, same-user browser automation, service IPC attempts, session-handle theft, challenge replay, and attempts to trigger a ceremony for substituted proposal data.
- Wrong origin/RP ID, missing UV, stale/expired challenge, credential loss/revocation, recovery misuse, interrupted enrollment, process crash, and inconsistent durable challenge/counter/approval state.
- Cross-user access to service-owned files, pipes, and stored owner state.

### Explicit exclusions and assumptions

- A compromised Windows kernel, administrator/SYSTEM actor, malware with an already elevated service/administrator token, compromised authenticator implementation, or OS-level ability to subvert the display/input stack is not prevented by this architecture. The Blueprint itself does not claim protection against a fully compromised owner OS.
- A correct SID or successful Windows logon is an account/session identity, not proof that the user understood or approved a particular action. Shared Windows accounts/authenticators further prevent a natural-person identity claim.
- Current environment probing does not validate an actual Hello PIN/biometric configuration, external key, firmware state, revocation/recovery behavior, or user-visible transaction display.

A service DACL can protect data from processes whose tokens lack the service identity/administrative rights. It does **not** distinguish two ordinary processes that have the same permitted user SID on a named pipe. If that user may call the broker, any such process can attempt the same IPC operation unless the service performs its own action-specific verification and the trusted display path is separately established.

## 5. Feasibility of the three channels

| Option | Trust root and local/offline fit | Feasibility and limitations | Decision |
|---|---|---|---|
| **A — Browser-mediated local WebAuthn** | WebAuthn can bind a credential to RP ID and browser origin and can request UV. A loopback service can operate offline. | Browsers expose WebAuthn only in secure contexts. W3C Secure Contexts allows user agents to treat localhost names as potentially trustworthy only when localhost-resolution requirements are met; behavior still needs a supported-browser test. A predictable `https://localhost:<fixed-port>` would need a trusted local TLS/certificate story, strict Host/Origin checks, CSRF defenses, SameSite/HttpOnly session handling, loopback-only binding, short one-use server challenges, and no wildcard CORS. RP ID and origin are distinct; the server must check both exactly. `sentinel.test` is a reserved testing name, not a production DNS/origin choice. A compromised frontend/browser can replace display text or steal a session. Plain WebAuthn does not define a transaction display for challenge data. Browser path does not protect the same-user SQLite database. | **Not selected as primary approval channel.** Viable as a UI transport only after an independently protected broker, fixed origin bootstrap, browser matrix, CSRF/session tests, and trusted-display solution. |
| **B — Native Windows WebAuthn** | Uses Windows platform APIs for Windows Hello and external FIDO2 security keys; no browser listener or web origin/cookie session is required. RP ID, challenge, UV requirement, and response still require a trusted relying party. | Microsoft documents Win32 WebAuthn on Windows 10 version 1903+ and Windows 11. `WebAuthNAuthenticatorMakeCredential` and `WebAuthNAuthenticatorGetAssertion` take a window handle and client-data/RP parameters; option structures expose platform/cross-platform attachment selection, allowed credential lists, UV requirement, timeout, and cancellation/authenticator selection. These are request controls, not evidence that a particular authenticator is installed or supports the requested policy. Correct integration also needs API-version checks, HRESULT/cancellation handling, and freeing returned buffers. `WEBAUTHN_CLIENT_DATA` contains caller-supplied UTF-8 JSON and hash algorithm, so Sentinel must construct fixed client data and validate the signed response; the API does not choose or protect an enrollment trust root. The documented API targets C/C++; a Python `ctypes` binding must correctly model versioned structs, pointer ownership, and allocated return buffers. A small reviewed native shim is lower risk than handwritten FFI or an unmaintained authentication wrapper, but still requires tests. A service in Session 0 cannot simply own an interactive ceremony; Windows documents a separate user-session GUI communicating over IPC. That GUI is itself part of the display boundary. | **Preferred ceremony mechanism only inside Option C.** Host DLL/header/API symbols are present, but no Hello prompt, credential enrollment, authenticator selection, cancellation path, or trusted display was exercised. |
| **C — Protected service boundary first** | A dedicated Windows service under a distinct service SID/restricted account can own the credential registry and approval state; an explicit DACL can deny direct writes by the interactive account. This is the only option that addresses direct same-user database replacement at the storage layer, assuming the attacker is non-admin and the ACL/service installation are intact. | Requires an administrator-controlled installation/update path; service-owned data directory ACL; protected service configuration/binary; named-pipe DACL scoped to expected logon/account/session; strict request grammar; caller token inspection/impersonation; service-side revalidation; and no generic enrollment or execution RPC. Windows service/session isolation means a separate interactive client is needed for a user ceremony. Pipe ACLs authenticate security principals, not a particular human or trusted GUI binary. A malicious same-user client can still call permitted IPC. Recovery/re-enrollment needs a separately trusted bootstrap. Complexity, service lifecycle, signing/installer maintenance, and FFI/display verification are material. | **Recommended trust architecture.** Pair with B only after the protected enrollment root and action display pass their gates. No service is implemented or installed in this slice. |

### Required adversarial scenario comparison

`A` is browser-local, `B` is native WebAuthn from an application process, and `C` is a protected service/broker. These are design assessments, not executed security tests.

| Scenario | A — browser local | B — native API | C — protected broker |
|---|---|---|---|
| Same-user database edit/key replacement | No defense; app SQLite remains user-writable. | No defense by API choice alone. | Service-owned ACL can deny direct writes to a non-admin same-user process; verify with a second process. Admin/service compromise remains out of scope. |
| Malicious client enrolls attacker key | Local endpoint can be called unless enrollment requires a separate trusted bootstrap. | Native API creates a credential but does not decide which owner was entitled to register it. | Do not expose first-enrollment IPC to ordinary clients. Require admin/out-of-band bootstrap and service-side registration verification. |
| Forged “enrollment succeeded” metadata | Client JSON is untrusted; server must verify registration response and persist only after validation. | Caller response/metadata remains untrusted; verifier must check exact challenge, RP context, attestation policy, and public key. | Service must derive the record from verified ceremony output; never accept client-supplied success flags/keys as proof. |
| Replayed registration/assertion challenge | Server-side random, expiring, single-use challenge and atomic consumption; browser session storage is not sufficient. | Same relying-party checks; Win32 invocation is not replay protection. | Store/consume nonce and counter transactionally in protected state; deny replay after restart. |
| Proposal swapped after display | Compromised page/session can replace displayed proposal; challenge binding alone does not prove what was seen. | Caller UI can substitute content; OS authenticator prompt is not proven to show the proposal. | Bind the exact immutable snapshot, but still require a verified trusted display process before accepting consent. |
| Prompt injection attempts T1 | Deny; content remains T4/T3. | Deny; source text cannot affect registration or policy. | Broker accepts no authority claims from source/request payload; service-generated identity/provenance only. |
| Wrong origin/RP ID | Browser validates secure-context/origin scope; server must compare exact expected origin and RP ID. | Fixed RP ID and origin must be constructed/checked by trusted relying-party code; do not infer an app origin from Windows identity. | Service owns fixed RP/origin policy and validates client-data/authenticator result before state change. |
| Missing user verification | Set `userVerification=required`; reject absent UV flag. | Request UV required in options and reject returned UV=false. Actual authenticator support must be tested. | Enforce verifier-side UV and fail closed; service state cannot turn missing UV into success. |
| Authenticator loss, revocation, recovery, re-enrollment | Requires protected server-side revocation and a recovery authority; frontend reset is unsafe. | Same requirement; device UI is not a recovery trust root. | Maintain protected revocation/credential registry; recovery requires separately established bootstrap and invalidates old credentials/sessions. No current procedure exists. |
| Interrupted registration/process crash | Persist challenge/credential atomically; orphan registration cannot become trusted. | Same; native modal cancellation must map to denial, no partial enrollment. | `BEGIN IMMEDIATE` transaction for record and challenge state; crash matrix and orphan handling required. Filesystem ACL changes are not part of SQLite atomicity. |
| Compromised browser/frontend/IPC client | Can alter UI, issue calls, steal sessions, or attempt CSRF; origin/CSRF controls reduce web attacks, not same-user compromise. | Can request ceremonies and present deceptive text unless the trusted display is independent. | Narrow authenticated IPC limits data access, not intent: any authorized same-user client may send requests. Broker-side exact action and trusted display remain mandatory. |
| Stolen session handle/stale state | Revoke session; challenge binds snapshot and is one-use/short-lived; CSRF alone is insufficient. | Avoid browser session authority; challenge still needs single-use expiry and proposal snapshot. | Server owns one-use challenge/receipt; handle is not a grant, revalidate proposal and current policy at use. |
| Cross-user access | Browser profiles/cookies and filesystem ACLs need tests; no service isolation is added. | Windows account/profile and key availability differ; no protected app data is added. | ACL data/pipes to service SID plus intended logon/user SID; test with two OS accounts and reject remote/other-session access. |
| Malicious same-user program controls unlocked session | Can automate browser and induce a WebAuthn prompt; user can be deceived about the proposal. | Can call APIs and may induce system UI; UV may resist unattended use but does not prove the person saw the transaction. | Cannot directly edit protected state if ACLs pass, but can request allowed IPC and manipulate same-user UI. Keep approval unavailable until display/call-path attacks are tested; do not claim protection against OS compromise. |

## 6. Exact future confirmation binding

A later approval design must freeze one canonical proposal snapshot before any authenticator call. The digest input should include, at minimum:

1. Schema/domain version and explicit action type (for example, `APPROVE_PENDING_PROPOSAL` for the exact proposed effect; reject/withdraw must be distinct actions).
2. Proposal ID and immutable canonical proposal/display digest, including the exact operation, capability, arguments, target/account, and effect class.
3. Selected source item/envelope IDs, content digests, exact citation span IDs, half-open byte offsets, cited-slice digests, and source trust/sensitivity labels.
4. Policy, capability-registry, configuration, and verifier-version identities.
5. Expiry, fresh cryptographically random challenge, challenge ID, owner/credential association, and one-use semantics.

The protected verifier must create the challenge, bind it to the stored proposal, atomically consume it once, and recheck current proposal/status/expiry/policy/credential state before recording proof. Editing any material proposal field means a new snapshot and new challenge. A hash provides identity binding, not a signature or trusted registrar identity.

**Display is a separate invariant.** The user must see the exact operation, destination, body/arguments, source evidence, capability, and consequences through an independently protected display path before signing. The displayed digest must match the immutable snapshot submitted to the verifier; clipping or omitted fields deny. WebAuthn signs the client-data hash and authenticator data; the authenticator is not required to parse Sentinel's client-data JSON or display its transaction fields. The generic challenge provides freshness and cryptographic request binding, but is not itself proof of the exact Sentinel content shown. An authenticator UV flag or native “WebAuthn” dialog alone is not evidence that the person saw or understood Sentinel's complete proposal. The service/client boundary must not silently claim that a matching signature is informed approval.

## 7. Windows and Python feasibility evidence

### Official platform facts consulted

- W3C WebAuthn Level 3 restricts browser exposure to secure contexts, separates RP ID from origin, requires challenge/origin/RP verification, and defines UV as local authenticator verification rather than concrete RP identification of a natural person.
- W3C Secure Contexts treats localhost as potentially trustworthy only when user-agent localhost-resolution conditions are met. IANA marks `.test` as special-use/reserved for testing; `sentinel.test` is suitable for synthetic tests only.
- Microsoft documents the Windows WebAuthn API for Windows 10 version 1903 and later and Windows 11, supporting Windows Hello and external FIDO2 keys. Its option structures expose authenticator attachment, credential selection, UV, timeout and cancellation settings; API presence does not establish authenticator availability or owner identity. The caller supplies client data and owns exact relying-party policy.
- Microsoft says services do not directly interact with users on current Windows; the documented pattern is a separate user-session GUI communicating over IPC. The service must not place privileged UI on the interactive desktop. Named-pipe security descriptors/DACLs control access through caller tokens; impersonation can scope filesystem/database access but does not identify the person or distinguish processes with the same token.
- Duo Labs `webauthn==3.0.1`, the exact optional package installed in this repository's Python 3.11 environment, is a server-side verifier. `verify_authentication_response()` requires expected challenge, RP ID, origin, stored credential public key and current counter; UV enforcement is opt-in at the function contract (`require_user_verification=True`). It does not enroll a trusted owner or supply a protected key registry.

### Read-only environment probes

On the current Windows development host, without opening an authenticator dialog or changing settings:

- `Win32_OperatingSystem` reported Windows 11 Home Single Language, 64-bit, version `10.0.26300`, build `26300`; the registry `ProductName` still said Windows 10 while `DisplayVersion` said `26H2`. This inconsistent labeling is recorded rather than used as a precise supported-build certification.
- `C:\Windows\System32\webauthn.dll` exists (file version `10.0.26100.9278`). The Windows SDK `webauthn.h` exists under the installed `10.0.26100.0` include tree.
- CPython `3.11.7` x64 loaded the DLL, called only `WebAuthNGetApiVersionNumber()` and observed `9`, and found exports for make credential, get assertion, cancellation ID/cancel, and result-free functions.
- The project environment contains `webauthn 3.0.1`. No make-credential/get-assertion API, biometric/PIN prompt, hardware authenticator, credential enrollment, or real assertion was invoked for this feasibility review. Actual Windows Hello policy, FIDO key availability, native UI presentation, and end-to-end native/Python integration remain unverified.

The local probe establishes library/API presence only. It does not establish that a usable authenticator is provisioned, that UV succeeds, that the UI is trustworthy, or that a service DACL works on this device. No OS security setting, credential store, account, or service was changed.

## 8. Recommendation and conditions

**Recommend Option C as the required trust root, with Option B as a conditional ceremony adapter.** Keep A as a possible local web UX only after the root and display gates pass; it does not solve protected enrollment or same-user database tampering. This staged architecture best matches the Blueprint's distinct F22 valid-human-channel and F23 OS-isolation gates, while preserving the native Windows-first deployment and avoiding a new listener/cookie/origin surface as the primary security boundary.

Protected enrollment is **conditionally feasible**, not implemented or currently enabled. Before any production enrollment implementation, the owner must explicitly choose and approve:

- Who is the bootstrap authority: an administrator-managed installation/operator, an independently delivered recovery secret/key, or another specifically reviewed external trust anchor. Windows username/session alone is not that decision.
- Which Windows account/service SID owns the protected registry, proposal state, and challenge state; whether the expected attacker is a non-admin same-user process; and how service update, ACL recovery, credential revoke, authenticator loss, and account migration work.
- Which supported native/browser client and exact origin/RP ID are supported. `sentinel.test` is test-only.
- Which protected interactive presentation path shows and locks the complete proposal snapshot. If a compromised same-user client can replace the displayed action while still obtaining an accepted assertion, P11/approval remains blocked.
- What backup/recovery guarantees are required. Do not copy the database key or trust root into the same user-writable backup location and call it protected.

Until those decisions are accepted and their tests pass: `production_owner_verification=UNAVAILABLE`; no `owner_verified=true`; no T1 from WebAuthn verification alone; P11 remains NOT_STARTED; F22/F23 remain GATED; C4/C5/C6 and external effects remain OFF. The existing CR0-D ModelGateway and its PRIVATE/SECRET restrictions do not change.

## 9. Proposed bounded CR2-G-B implementation slice

CR2-G-B should be a **non-authorizing Windows broker/storage isolation prototype**, not enrollment or approval:

1. In a disposable Windows environment, install a minimal service under a dedicated restricted service identity/SID. Store only synthetic canary metadata in a service-owned directory protected by explicit ACLs; do not use LocalSystem unless separately justified.
2. Add one narrow named-pipe status/read request and a deliberately denied registration/approval request. Set an explicit pipe DACL and session boundary; inspect the client token. Do not treat a client-supplied PID, executable path, username, owner flag, or success boolean as authentication.
3. From a second ordinary same-user process, prove direct reads/writes/replacement of the service database and service configuration are denied. Prove the same-user client can reach only the explicitly permitted IPC operation, and that an attempted enrollment/approval operation is denied without changing state. From a second Windows account/session, prove pipe/file access is denied. Record that same-user code may still issue allowed IPC.
4. Exercise service restart, process termination at transaction cut points, migration/checkpoint validation, ACL verification, malformed IPC, replayed nonce, and clean uninstall/recovery against disposable synthetic state. No OS authenticator call, owner flag, T1 record, approval, task, grant, provider action, or production credential is created.
5. Return a concrete trusted-display and bootstrap decision. If Windows cannot provide a separately protected user-session display/client for the exact action and service-bound assertion, leave production owner verification unavailable and stop before enrollment.

Acceptance is binary: verified service SID and ACLs; non-admin direct-database tamper denied; cross-user/session access denied; malformed or unauthorized IPC denied with zero state change; all crash cases are either consistent committed state or no new state; no approval/owner authority is emitted; and documented residual same-user IPC/UI limitations. This prototype would validate OS isolation mechanics, not complete F22, P11, or production owner authentication.

## 10. Consequences and unresolved items

- No production owner can be recognized until a trusted bootstrap is chosen and protected enrollment is built.
- A dedicated service can make direct database replacement by a standard same-user process harder, but it cannot turn a user SID, pipe connection, or assertion into informed consent.
- Native WebAuthn API presence on one Windows host does not prove Windows Hello availability, real user verification, supported authenticator policy, cross-version compatibility, or trusted proposal display.
- A local browser may be technically operable with loopback/HTTPS, but browser/session/origin protections do not solve the missing trust root and do not provide general transaction display.
- Full CR2 remains IN_PROGRESS. CR2-G-A is architecture evidence only; it does not verify F21/F22/F23, P11, CR2, or CR7.
- This document is not a production-readiness or security-certification claim.

## 11. Sources

### Local authoritative evidence

- `docs/spec/Sentinel Master Blueprint.pdf` (SHA-256 above), §§2–7, 16–17.
- `docs/BUILD_LEDGER.md`, CR2-A through CR2-F-01 records; F21/F22/F23 and P11 statuses.
- `src/sentinel/owner_proof/service.py`, `types.py`, `src/sentinel/storage/schema.py`, `src/sentinel/storage/writer.py`, `src/sentinel/credentials/`, `src/sentinel/policy/`, `src/sentinel/proposals/`, and `tests/test_cr2_f_webauthn.py`.

### Official external references consulted 2026-11-08

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [W3C Secure Contexts](https://www.w3.org/TR/secure-contexts/)
- [W3C Secure Payment Confirmation draft — plain WebAuthn does not specify transaction display](https://www.w3.org/TR/2026/CRD-secure-payment-confirmation-20260604/)
- [IANA `.test` reserved special-use TLD](https://www.iana.org/domains/root/db/test)
- [Microsoft Windows WebAuthn API overview](https://learn.microsoft.com/en-us/windows/win32/webauthn/-webauthn-portal)
- Microsoft [`WebAuthNAuthenticatorGetAssertion`](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatorgetassertion), [GetAssertion options](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/ns-webauthn-webauthn_authenticator_get_assertion_options), [MakeCredential](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthnauthenticatormakecredential), [MakeCredential options](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/ns-webauthn-webauthn_authenticator_make_credential_options), [client-data structure](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/ns-webauthn-webauthn_client_data), [API-version query](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthngetapiversionnumber), and [cancellation API](https://learn.microsoft.com/en-us/windows/win32/api/webauthn/nf-webauthn-webauthncancelcurrentoperation)
- [Microsoft service accounts](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts), [service SID](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info), [named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [named-pipe client impersonation](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client), [access tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens), and [services and user interaction](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services)
- [Duo Labs `webauthn` 3.0.1 PyPI release](https://pypi.org/project/webauthn/3.0.1/), [project repository](https://github.com/duo-labs/py_webauthn), and [authentication verification implementation](https://github.com/duo-labs/py_webauthn/blob/master/webauthn/authentication/verify_authentication_response.py)
