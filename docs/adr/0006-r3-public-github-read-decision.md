# ADR-0006: R3 Public GitHub Read Decision

- **Status:** Proposed — owner approval required
- **Date:** 2026-11-17
- **Decision scope:** Documentation only. No live GitHub request or runtime capability is approved here.
- **Reviewed base:** `66f0f54cfaccf27fee32be3901655d97da8ace66`
- **Authoritative Blueprint:** [`Sentinel Master Blueprint.pdf`](../spec/Sentinel%20Master%20Blueprint.pdf), SHA-256 `92911A27CDA2AACE41616E5A45F07E228C3D21838E8EB93A30BF71CF228701E7`

## 1. Decision context

R3-A asks whether Sentinel should add one live, unauthenticated, read-only GitHub issue read before the Blueprint's scheduled GitHub integration work. This ADR evaluates feasibility and sequencing. It does not authorize implementation, change a capability, or treat an existing synthetic `ALLOW` as permission to access a provider.

The local Blueprint fingerprint was recomputed and matches the ledger. This review used Blueprint §§2, 3, 5, 6, 7, 16, and 17, including feature IDs F03, F20–F23, F26–F27, trust boundaries TB1–TB6, the P00–P17 rule table, and the CR1–CR4 release sequence. The Blueprint's verification notice distinguishes proposed design from verified platform facts and implementation evidence; this ADR does the same.

## 2. Current implementation and Blueprint constraints

### Blueprint requirements

- **§2, Feature catalogue:** F03 is selected-repository GitHub issue/PR state with a fine-grained read credential and tests for allowed and blocked repositories, pagination omission, cursor recovery, and denial. F20 and F21 require provenance and deterministic policy. F22 is gated on a valid human channel; F23 is gated on verified OS isolation. GitHub comments and labels (F26/F27) are gated/off.
- **§3, TB2/TB4/TB5 and deployment:** the policy boundary uses fixed registrations and typed arguments; issue bodies and other external content remain T4 and cannot create owner authority. Outbound HTTPS may be limited to allowlisted GitHub and other configured hosts, but local-first is not offline, and arbitrary upstream URLs or exposed listeners are excluded.
- **§5, MCP roles:** the read role lists GitHub issue/PR reads and calls for selected-repository read credentials; it separately identifies public feeds as credential-free. The section requires strict host/repository allowlists and rejects arbitrary generic REST calls. This does not make the current fixture route a live reader.
- **§6, trust and policy:** T0 is trusted bundled policy, T1 is independently authenticated owner intent, T2 is provider identity metadata, T3 is derived output, T4 is external content, and T5 is missing or unverifiable. Sensitivity is a separate classification; unlabeled data is not PUBLIC by default. C0 is `READ_PUBLIC`. Hard rules precede P09 provenance and the narrow P04/P06 routes; P12 is catch-all DENY. P11 concerns review/approval outcomes. An `ALLOW` is not an executable grant.
- **§7, ModelGateway:** model egress must pass the ModelGateway's sensitivity and locality rules. Public content being eligible for a model under a future profile does not authorize sending retrieved content to a model now.
- **§16, release dependency order:** CR1 is the daily read/product core; CR2 adds deterministic authorization; CR3 adds the MCP and regression platform; CR4 adds continuous operation and optional OAuth source-read connections. A pre-CR3 live reader would be a sequencing deviation. The ledger's feature-to-release table is explicitly a dependency-based planning map, not a verbatim Blueprint assignment.
- **§17, risks:** prompt injection, incomplete provenance, provider terms, rate limits, and same-UID access have explicit tripwires. A passing synthetic test is not live-provider or field-security evidence.

### Repository state at the reviewed base

Sentinel currently has a packaged fictional GitHub fixture, promoted blob-backed readback, resolver-created source binding, citations, and a deterministic local briefing. The fixture adapter reads local packaged/SQLite/blob state. [`resolve_github_fixture_public_read`](../../src/sentinel/policy/source_binding.py#L289) resolves a complete pinned fixture and [`build_github_fixture_brief`](../../src/sentinel/briefing/evidence.py#L74) verifies P09/P04 before returning the briefing. The existing binding contract is fixture-version and manifest pinned, contains three PUBLIC/T4 sources and nine citations, and is validated by the CR2-B source-binding tests.

The current P04 registration is `sentinel.synthetic.read.public`, takes only `resource_id=github.fixture`, and is `POLICY_ONLY`; see [`policy/registry.py`](../../src/sentinel/policy/registry.py#L172). [`build_verified_public_read_policy_input`](../../src/sentinel/policy/evaluator.py#L86) constructs that exact synthetic request. The evaluator accepts only the resolver-created `VerifiedGithubPublicRead` binding for the bounded route and returns `executable=false`; see [`policy/evaluator.py`](../../src/sentinel/policy/evaluator.py#L757) and [`policy/source_binding.py`](../../src/sentinel/policy/source_binding.py#L323). This is one tested route, not authorization for a network call or proof of a system-wide reference monitor.

The existing [`ToolGateway`](../../src/sentinel/gateways/tool.py#L37) accepts one registered read-only demo adapter. Its [`GatewayRegistry`](../../src/sentinel/gateways/registry.py#L109) is explicitly DEMO-only and does not open URLs or load request-supplied handlers. The ModelGateway similarly rejects live/replay/cloud execution. Source inspection found no HTTP client or public-network reader under `src/sentinel`; the GitHub integration in the runtime is fixture-backed. The current code therefore has no live GitHub authorization path, no credential-free live provider request, and no reusable P04 network grant.

The ledger continues to mark CR2 IN_PROGRESS. Production owner verification is UNAVAILABLE; P11 is NOT_STARTED; F22/F23 remain gated. The archived Windows service-isolation lab failed twice and remains parked with ROOT CAUSE UNRESOLVED. It is not evidence that protected service isolation is ready.

## 3. Problem and user value

A single selected public issue could make the briefing useful against changing GitHub data instead of only fictional fixtures. A successful unauthenticated read could demonstrate a bounded source adapter without storing a token or enabling a write. It would also introduce real network egress and public content into Sentinel's data path. GitHub describes its issue endpoint as usable without authentication when only public resources are requested; this is endpoint feasibility, not Sentinel authorization or a promise of availability. The unauthenticated REST API limit is IP-based and currently documented as 60 requests per hour, subject to provider changes.

Public visibility is not a confidentiality or safety guarantee. A public issue can contain personal information, accidentally disclosed secrets, malicious instructions, hostile links, or false claims. The selected source remains T4 external content. Choosing an issue does not establish T1 owner intent, approve a proposal, authorize an effect, or prove the issue is authentic outside GitHub's response.

## 4. Options considered

| Option | Blueprint fit and prerequisites | User value, cost, privacy, testing, and reversibility | Decision |
|---|---|---|---|
| **A — Defer** | Preserves the CR2 → CR3 → CR4 order and leaves F03 and the existing fixture-only P04 boundary intact. | No live issue updates yet. No new egress, credential, cache, or content-retention surface. Easy to reverse because no runtime change is made. Synthetic fixture work remains deterministic and testable. | **Recommended.** Wait for the planned integration sequence and its release gates. |
| **B — Narrow public read** | A fixed unauthenticated `GET /repos/{owner}/{repo}/issues/{issue_number}` for one explicitly selected public issue is technically possible. It would still require a separately approved operation, source resolver/binding, gateway route, and policy contract. Reusing current synthetic P04 would be incorrect. Before CR3/CR4 it changes the release sequence. | Provides current issue data without a token, but adds outbound networking, hostile T4 text, rate-limit and API-version handling, privacy review, and new failure modes. A fixed request and synthetic transport tests can make it bounded and reversible; only a real provider run can verify the selected endpoint and observed API behavior. | Not recommended for immediate R3. Consider only after an explicit owner-approved sequencing deviation and separate implementation task. |
| **C — Broader authenticated integration** | Moves toward F03's selected-repository credential path and later CR4 source-read connections, but requires credential enrollment/storage, account and repository scope, token revocation, and protected execution boundaries. | Could support private or account-connected resources, but expands identity, credential, and privacy risk. Requires F22/F23/CR7-related gates and live credential/OS isolation evidence. It is not a small read-only slice and is difficult to reverse after credentials or durable account state exist. | Reject for this proposed slice. Keep credentials and private repositories out of scope. |

## 5. Threat model

| Threat | Required boundary if a later Option B task is approved | Synthetic tests can establish | Evidence still needed |
|---|---|---|---|
| Prompt injection, false owner claims, malicious links | Treat all returned strings as T4 data. No instruction execution, source-to-T1 promotion, user discovery, or effect proposal. Do not follow links. | Parser/rendering tests with instruction-like strings; assert trust labels remain T4 and no model/tool/effect is invoked. | Review of any later transformation/display path; tests do not prove an operator will interpret content safely. |
| Public content containing sensitive material | Do not infer sensitivity solely from a public repository. Keep the initial path local and model-free; minimize fields and avoid logging bodies. If classification is unsupported or uncertain, fail closed or retain a more restrictive label. | Known synthetic PII/secret-like values remain out of logs, model calls, and unapproved fields; reject malformed/unknown labels. | Human review of the selected source and a clear privacy/display decision. No scanner can prove a public issue contains no sensitive information. |
| SSRF, hostile URL parsing, DNS rebinding | Build the URL from fixed `https://api.github.com` plus validated owner/repo/issue components; accept no URL, scheme, host, port, query, or path from source content. Require TLS hostname verification and an explicit destination policy. Domain allowlisting alone is insufficient; bind the connection to validated public addresses or stop if the chosen client cannot enforce the check. | Fake transport and local test server reject arbitrary hosts, IP literals, private/loopback/link-local resolution, userinfo, malformed path components, and changed destinations. | Actual network stack, resolver, proxy environment, TLS peer, and egress behavior on supported Windows configurations. |
| Redirects and response-provided API URLs | Do not blindly follow redirects or response links. A later client must validate each redirect and keep HTTPS, exact API host, method, request identity, and a small hop limit; any cross-host or scope-changing redirect denies. Never fetch URL fields from the response. | Redirect chains to another host, local address, changed path, or non-HTTPS are denied; no second request occurs. | GitHub's real canonicalization/redirect behavior for the chosen resource and whether a reviewed same-host redirect policy is sufficient. GitHub documents that REST redirects occur; this security boundary must be tested explicitly. |
| Unexpected method, pagination, or request fan-out | Exactly one GET to the one issue endpoint; no search, comments, events, PR review comments, pagination, web pages, retry loop, or background poll. | Transport records exactly one method/URL; unknown endpoint or `Link` pagination is not followed. | Future scope expansion requires separate review; do not silently increase calls. |
| Oversized, malformed, partial, or changing response | Fixed connect/read/overall deadlines; fixed response and field byte limits; strict UTF-8/JSON/schema validation; reject duplicate keys and unexpected fields where the parser contract requires it; no partial briefing. Hash the exact response bytes and derive citations from the same immutable parsed snapshot. Do not claim a fetched snapshot remains current after retrieval. | Exact byte limits, invalid encodings, duplicate keys, missing/extra identity fields, wrong repository/issue, PR-shaped response, body mutations, partial reads, timeout, and disconnect all fail with empty success output. | Real endpoint response shape and evolution under a pinned API version. GitHub API versions and response fields can change; a selected version must be reviewed at implementation time. |
| Rate limiting and retries | One request per invocation; do not retry a 403/429 or ambiguous transport failure automatically in the first slice. Return bounded unavailable status; a later explicit invocation is a new request. | 403/429, `Retry-After`, exhausted rate state, timeout, and 5xx produce bounded failure with no fallback to fixtures or another issue. | Actual unauthenticated rate behavior depends on shared originating IP and provider controls. |
| Credentials, models, and external effects | No `Authorization` header, token lookup, credential broker, ModelGateway call, ToolGateway generic dispatch, write method, proposal/task/approval, or external action. Logs contain bounded codes and digests, not response bodies or credentials. | Assert zero credential access, model/tool calls, writes, and sockets outside the single fake transport; scan rendered output/logs for canaries. | Platform-level egress observation for an eventual live test. |

The GitHub documentation consulted for this decision confirms public issue GET availability, versioned REST requests, rate-limit behavior, pagination headers, and redirects. It does not establish the correctness of a Sentinel transport, public-source sensitivity, or the security of the local process.

## 6. Recommended decision

Recommend **Option A — defer**. The Blueprint does contain public-read concepts and C0, so a narrowly constrained unauthenticated GET can be compatible with the overall model in principle. It is not compatible with reusing the current fixture-only P04 decision, and placing a live reader before CR3/CR4 would be a release-sequence change. CR2 is still IN_PROGRESS, the evaluator and gateway are not system-wide live-network enforcement, and the current ToolGateway intentionally accepts demo adapters only.

If the owner wants the user value earlier, Option B should return as a separately authorized implementation task with an explicit sequence deviation. No policy or capability contract is changed by this ADR. Any registry/policy change, new HTTP dependency, or gateway change needs its own review and updated hashes/tests before implementation.

## 7. Proposed capability boundaries

The following is a **conditional design sketch**, not an approved feature contract or current behavior. It may be refined only in a later owner-authorized task.

- **Resource:** one plain GitHub issue from a configured public repository using `GET /repos/{owner}/{repo}/issues/{issue_number}`. Reject responses identifying a pull request. No repository search, list, comments, events, files, clone, private resource, or GitHub web-page scraping.
- **Scope:** one explicitly selected issue and exactly one request per invocation. No pagination, scheduling, background polling, automatic retries, or request fan-out.
- **Configuration:** require an explicit operator-selected `owner/repo` and issue number, validated as separate path components and matched against an explicit local allowlist. Do not accept a full URL. Do not perform account or repository discovery. Selection is configuration, not T1 authority. The configuration and policy identities must be part of the request digest.
- **Request:** fixed HTTPS API base, exact path template, GET only, no Authorization header, fixed Accept and reviewed API-version headers, bounded User-Agent, finite connect/read/total deadline. Do not inherit arbitrary proxy settings without an explicit reviewed proxy policy.
- **Response:** allowlist only the fields required for a single issue briefing; verify repository URL/identity, issue number, stable issue identity and non-PR shape. Use a strict schema and byte limits. Candidate implementation limits such as response size and deadline must be selected and pinned by the future task; they are not Blueprint constants.
- **Provenance:** a trusted resolver, not caller-created `SourceEnvelope`, constructs T4 evidence from the exact HTTP response bytes. Bind the request method/path, configured repository identity, issue number, stable provider IDs, API version, exact response SHA-256, extracted title/body digests, fetch time, and citation span IDs/ranges/slice digests. The output must be assembled from that same in-memory snapshot; no read-after-authorization refetch or fixture fallback.
- **Policy/gateway:** a separately registered static operation may use C0 only after P00–P03/P17 hard checks and P09 verified provenance. P04 may be considered only after a distinct reviewed rule contract; the present synthetic `ALLOW` must never authorize the HTTP request. The gateway must validate the exact local decision and exact operation before it sends one request. Unknown routes deny. No capability becomes executable; decision remains metadata with `executable=false`.
- **Sensitivity and outputs:** preserve T4. Do not infer that content is harmless or suitable for a model merely because GitHub marks the repository public. Return only a bounded local briefing with explicit source/citation identity and a retrieval timestamp; escape terminal control characters. Do not store raw response/body by default, log it, send it to a model, or promote its content to owner intent.
- **Failure behavior:** validation, DNS, TLS, redirect, rate-limit, timeout, response-size, schema, provenance, policy, or rendering failure returns no partial briefing, no raw body/path/credential, and no fallback source. A new explicit invocation is required after failure.
- **Prohibited:** tokens, OAuth/GitHub App installation, private repositories, user discovery, arbitrary URLs, write methods, comments/labels, automatic task/proposal creation, owner verification, approval, model inference, external effects, and background execution.

## 8. Required verification and negative tests

If implementation is later authorized, synthetic tests must cover:

1. One exact GET and success response; no auth header or credential lookup; asserted one-request maximum.
2. Wrong operation, capability, effect class, policy/registry/config hash, missing resolver seal, fabricated binding, wrong repo/issue/provider ID, malformed source, wrong body digest, citation ID/range/slice mismatch, and P09 denial.
3. Prompt-injection and false-authority content remains T4; no T1, P11, task, proposal, grant, model call, or effect is created.
4. URL/path injection, alternative schemes/ports, userinfo, IP literals, DNS results in private/loopback/link-local/reserved space, DNS rebinding between validation and connection, proxy redirection, and off-host redirects deny.
5. PR-shaped payload, repository/issue identity mismatch, duplicate JSON keys, unsupported API version, malformed UTF-8/JSON, unexpected schema, oversized headers/body/fields, and invalid timestamps deny.
6. 301/302/307/308, `Link` pagination, 403/404/410/422/429/5xx, `Retry-After`, socket timeout, partial response, disconnect, and rendering failure produce bounded failure, empty stdout, no retry, no fallback, and no state mutation.
7. Changed issue content between independent invocations produces a new content digest and citations; one invocation never combines bytes from two responses.
8. Existing synthetic P04 briefing, policy hash/registry tests, CLI output, no-network tests, and all P00–P03/P09/P12/P17 denial behavior remain unchanged.

All transport tests should use a fake transport or a disposable local server; they must not contact GitHub. A later live smoke test would require separate approval and must use a public test issue, no credentials, a recorded request/response identity, real TLS/DNS/redirect/egress evidence, and no writes. Live tests would establish only the measured endpoint/platform behavior, not general SSRF immunity or correct interpretation by a human.

Implementation must stop before networking if a static policy/gateway route cannot be added without weakening P00–P03, treating declared provenance as proof, or reusing fixture P04; if destination validation cannot bind the connection to its checked address; if redirects cannot be constrained; if any credential or model route is reached; if public content cannot remain T4; or if the required change would bypass the Blueprint sequence without explicit owner approval.

## 9. Approval and sequencing implications

This ADR is proposed and requires an owner decision. The recommended path is to keep the fixture-backed GitHub briefing and defer a live public read until the originally planned CR3/CR4 prerequisites and release review. Approving a later Option B task would be an explicit sequencing deviation, not blanket approval of live GitHub integration.

No production owner verification, P11 outcome, P04 live route, C0 registry expansion, credential access, model route, approval, task, grant, or external write is authorized. CR2 remains IN_PROGRESS; F22/F23 remain gated; the parked Windows isolation lab remains unresolved.

## 10. Unresolved questions and explicit non-goals

- Which public repository and issue would provide useful, legally appropriate, non-sensitive test material? No target was contacted in this review.
- What exact response fields, retention rules, response/deadline limits, and sensitivity treatment should the owner accept?
- Can the chosen Windows HTTP transport validate resolved addresses and connect to the validated address while preserving TLS hostname verification, including any approved proxy environment?
- What redirect behavior does the selected endpoint require, and can it be restricted to the fixed API origin without breaking the use case?
- Which supported GitHub API version and response schema should a future implementation pin, and what upgrade process will keep it supported?
- What acceptance evidence should be required before a small live smoke test, and who can authorize that external network access?

Non-goals: private repositories, OAuth/PAT/GitHub App credentials, account discovery, writes, MCP server exposure, model use, proposal/approval/task creation, T1 owner intent, a general HTTP client, arbitrary URL fetching, or a claim of system-wide reference monitoring.

### Evidence and references

**Repository evidence at base `66f0f54cfaccf27fee32be3901655d97da8ace66`:**

- [Master Blueprint](../spec/Sentinel%20Master%20Blueprint.pdf), fingerprint above, §§2, 3, 5, 6, 7, 16, 17.
- [Build ledger](../BUILD_LEDGER.md), current CR1/CR2 scope, fixture-only P04, CR2-G-B2 parked status, and release planning caveat.
- [ADR-0005: owner authentication trust root](0005-cr2-g-a-owner-authentication-trust-root.md), especially its distinction between provider/session identity, trusted enrollment, T1 intent, transaction display, and approval.
- [`policy/registry.py`](../../src/sentinel/policy/registry.py), [`policy/evaluator.py`](../../src/sentinel/policy/evaluator.py), and [`policy/source_binding.py`](../../src/sentinel/policy/source_binding.py), bounded synthetic P04/P06 paths.
- [`ingestion/github_fixture.py`](../../src/sentinel/ingestion/github_fixture.py), [`ingestion/blob_readback.py`](../../src/sentinel/ingestion/blob_readback.py), and [`briefing/evidence.py`](../../src/sentinel/briefing/evidence.py), fixture readback and briefing construction.
- [`gateways/registry.py`](../../src/sentinel/gateways/registry.py), [`gateways/tool.py`](../../src/sentinel/gateways/tool.py), and [`gateways/model.py`](../../src/sentinel/gateways/model.py), demo-only tool/model constraints.
- [`test_cr2_b_source_binding.py`](../../tests/test_cr2_b_source_binding.py), [`test_cr2_b_briefing_gate.py`](../../tests/test_cr2_b_briefing_gate.py), [`test_tool_gateway.py`](../../tests/test_tool_gateway.py), and [`test_cr2_a_hard_denials.py`](../../tests/test_cr2_a_hard_denials.py), synthetic evidence, denial, and no-network regression contracts.

**Official external documentation consulted 2026-11-17:**

- GitHub REST [Get an issue](https://docs.github.com/en/rest/issues/issues#get-an-issue) documents the issue endpoint and states that public resources may be read without authentication.
- GitHub REST [rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) documents unauthenticated public-data access, IP-based accounting, and current limits.
- GitHub REST [API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions) documents the version header and support lifecycle.
- GitHub REST [pagination](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api) documents `Link` pagination behavior.
- GitHub REST [redirect best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#follow-redirects) documents that redirects occur and describes their handling.
- OWASP [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) warns that host allowlists alone do not prevent DNS rebinding and recommends validating and binding the actual destination.

These sources establish that a public unauthenticated issue GET exists and describe API behavior. They do not establish Sentinel's implementation security, suitability of any issue content, or owner approval.
