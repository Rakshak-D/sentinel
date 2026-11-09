# CR2-G-B1 isolated broker prototype

This is a standalone engineering experiment under `tools/`. It is not wired
into Sentinel's credential broker, owner-proof, policy, proposal, task, or
effect paths. It provides no owner identity, T1 intent, enrollment, approval,
P11 decision, task, grant, receipt, or external action. `enroll` and `approve`
are permanently denied by this prototype.

## Protocol

Each request is one four-byte unsigned big-endian payload length followed by
UTF-8 JSON. The request body is at most 4096 bytes, has nesting depth at most
8, and must have exactly these fields:

```json
{
  "schema_version": "sentinel.cr2-g-b1-request.v1",
  "request_id": "lab-1",
  "command": "health",
  "arguments": {}
}
```

Duplicate keys at every JSON object level, non-finite numbers, invalid UTF-8,
trailing frame bytes, unsupported schema versions, unknown fields, nonempty
arguments, and invalid field types fail closed. `health` returns fixed
non-sensitive non-authorizing status. `canary_status` returns only the fixed
synthetic canary identifier and classification. The known `enroll` and
`approve` commands return `DENIED`; any other syntactically valid command
returns `DENIED` as unknown. Invalid protocol frames raise fixed-code errors
and are not reflected to a client.

No caller-controlled path, SQL, executable name, import path, authority flag,
provider request, or tool/model invocation exists in the protocol.

## Synthetic store

`CanaryStore.initialize()` creates a new database with its own SQLite
`application_id`, `user_version`, and strict schema. The schema consists only
of `lab_metadata` and `canary_record`; it contains no Sentinel tables or user
data. Initialization refuses an existing file. `open_existing()` uses
read-only/query-only access and checks the application identity, schema,
integrity, exact fixed rows, and absence of unexpected views/triggers. No
Sentinel migration is added or reused. A failed seed transaction may leave an
empty database file, but it must not leave trusted-looking partial schema or
canary rows; reopening that file fails closed.

This SQLite file is disposable test state, not protected storage. It is not
encrypted, authenticated, or safe from a same-user process that can modify
the file.

## Windows named-pipe host

`windows_pipe.serve_one_request()` is an uninstalled, one-request process host
using `CreateNamedPipeW`, a protected explicit DACL, `FILE_FLAG_FIRST_PIPE_INSTANCE`,
`PIPE_REJECT_REMOTE_CLIENTS`, overlapped I/O with a bounded timeout, and an
explicit impersonated-thread-token SID check before protocol dispatch. It
accepts one exact pipe-name form and one caller SID supplied by the trusted
lab harness. The server reads at most one bounded frame before examining the
client token, then validates the token before dispatch. The one-byte transport
acknowledgment prevents disconnecting the pipe before the client has read the
complete response. No service is installed or started.

The ordinary client's DACL ACE and `CreateFileW` request use the specific
access mask `0x00100083`: `FILE_READ_DATA` (`0x1`), `FILE_WRITE_DATA` (`0x2`),
`FILE_READ_ATTRIBUTES` (`0x80`), and `SYNCHRONIZE` (`0x00100000`). A live
Windows test reads the security descriptor from the actual pipe handle with
`GetSecurityInfo(SE_FILE_OBJECT)`, locates the configured client's access
allowed ACE with `GetAce`, and requires that exact mask. It therefore rejects
`FILE_CREATE_PIPE_INSTANCE` (`0x4`), `GENERIC_READ`, `GENERIC_WRITE`,
`GENERIC_ALL`, `WRITE_DAC`, and `WRITE_OWNER` in the client ACE. Real local
pipe tests also show a permitted current-process SID can exchange a health
request and a SID absent from the DACL is denied by Windows. A separate live
mask probe checked all 16 combinations of those four specific rights; only
`0x00100083` supported the complete duplex exchange on this host. This is
local API evidence, not a service-identity or protected-storage result.

`request_pipe(timeout_ms=...)` now uses a single monotonic deadline for
connection retries, frame transmission, response header and body reads, and
the final acknowledgment. The client handle is opened with
`FILE_FLAG_OVERLAPPED`; reads and writes loop on short transfers. On timeout,
the client calls `CancelIoEx` and waits for `GetOverlappedResult` to report
completion/cancellation before releasing the event, `OVERLAPPED`, buffer, or
pipe handle. This safe reaping step depends on the local Windows I/O stack
completing cancellation; it is not a wall-clock guarantee against OS stalls.
Tests use real disposable local pipe endpoints stalled before the response
header, during a partial header, and during a partial body, plus absent-server
and disconnect cases. The earlier synchronous client exceeded its 140 ms
deadline in each stalled-response case; the overlapped client reports the
bounded `PIPE_TIMEOUT` result before the test releases the peer.

The focused Windows test exercises a real local named pipe and a real
Windows-enforced named-pipe DACL denial when the current process SID is not in
the DACL. This is a test of the local pipe API boundary only. It is not proof
of a service SID, service-owned filesystem ACL, protected database, cross-user
or cross-session boundary, or isolation from a hostile same-user process.

## Lab procedure and status

1. Use a disposable Windows VM separate from the developer workstation.
   Do not use a host service, host account, host ACL change, real credential,
   browser profile, or existing Sentinel database.
2. Confirm that guest-to-host writable shares containing repositories,
   credentials, or personal data are disabled; prefer a disabled guest network.
3. Create a fresh synthetic canary store and run the deterministic protocol
   tests. If separately authorized and reviewed, a later lab slice can install
   a test-only service with a dedicated identity and service SID, then inspect
   the effective service, pipe, binary, configuration, and data ACLs.
4. Record direct-read/write/replace/delete/ACL-denial results separately from
   pipe access, account/session separation, and restart/crash results. Do not
   infer one boundary from another.
5. Remove only the disposable guest service and guest canary state, and record
   cleanup evidence.

The available development host is Windows 11 Home, and no isolated disposable
Windows guest was found. Therefore service identity/SID, service-owned storage
ACLs, cross-user/session denial, remote-client rejection on a networked peer,
service crash recovery, and deterministic service uninstall are **UNVERIFIED**.
The local pipe code/test and portable protocol/store tests do not substitute
for that lab evidence. Windows Sandbox was not enabled or bypassed, and no
virtualization software, guest, Windows service, account, credential, network,
or host security setting was created or changed.

## Platform references

- [CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew) documents the pipe name, security attributes, `FILE_FLAG_FIRST_PIPE_INSTANCE`, overlapped I/O, and `PIPE_REJECT_REMOTE_CLIENTS`.
- [Named-pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights) explains why `FILE_GENERIC_WRITE` includes the `FILE_APPEND_DATA`/`FILE_CREATE_PIPE_INSTANCE` bit and recommends individual rights.
- [Named pipe open modes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-open-modes) documents client access compatibility and `FILE_FLAG_OVERLAPPED`.
- [ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile) specifies `NULL` for `lpNumberOfBytesRead` on overlapped operations and requires the `OVERLAPPED` and buffer to remain valid until completion.
- [Canceling pending I/O operations](https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations) documents `CancelIoEx` and waiting for completion before cleanup.
- [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo) and [securable objects](https://learn.microsoft.com/en-us/windows/win32/secauthz/securable-objects) document retrieving a named pipe's actual security descriptor from its handle.
- [Named pipe server using overlapped I/O](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-overlapped-i-o) and [synchronous and overlapped pipe I/O](https://learn.microsoft.com/en-us/windows/desktop/ipc/synchronous-and-overlapped-input-and-output) document bounded asynchronous connect/read/write patterns.
- [Named-pipe client impersonation](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client) describes using a client token for server-side access checks; a SID is an OS account boundary, not proof of a particular person's intent.
- [Named-pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights) describes pipe DACLs. No service or protected data directory was installed or configured by this slice.

## CR2-G-B2 ephemeral service-isolation laboratory

CR2-G-B2 adds a standalone SCM-compatible service host and a disposable
GitHub Actions laboratory. It remains outside the `sentinel` runtime package
and does not connect to owner proof, policy, proposals, tasks, credentials,
models, tools, or external effects. The service protocol has only `health`,
`canary_status`, `enroll` (deny), and `approve` (deny); unknown or malformed
requests fail closed. The canary remains the fixed B1 synthetic-only SQLite
record and is opened query-only by the service.

The proposed guest configuration uses `NT AUTHORITY\LocalService` plus
`SERVICE_SID_TYPE_RESTRICTED` for the fixed service name
`SentinelCR2GB2Lab`. The service verifies that its process token user is
LocalService and that its service SID appears in both enabled groups and
restricted SIDs. SYSTEM owns the disposable root and receives full control;
Administrators receive full control for lab setup/inspection; the service SID
receives read/execute only on its binary, configuration, and canary storage.
The ordinary permitted pipe client receives exactly `0x00100083`
(`FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE`);
the protocol has no storage-write operation. A separate disposable standard
local account is expected to be denied by the pipe DACL and filesystem ACLs.
The service does not use LocalSystem. These are the intended lab ACLs; they
are **not yet measured Windows service or storage results**.

The reviewable workflow is
`.github/workflows/cr2-g-b2-ephemeral-windows-lab.yml`. It is limited to
`pull_request` targeting `main`, then requires the same repository, exact
feature branch `feat/cr2-g-b2-windows-ephemeral-lab`, and base `main` both in
the job condition and in the guest script. It requests only
`permissions: contents: read`, checks out with credentials not persisted,
uses immutable SHA-pinned checkout/setup-python actions, has a 45-minute job
timeout, and does not reference repository secrets, upload artifacts, or publish
anything. Branch push alone does not start this job. **Do not open the first
pull request until an independent reviewer has reviewed this workflow and the
privileged harness.** The workflow executes the reviewed branch's lab code on
an administrator-capable hosted runner, so review of the exact PR revision is
part of the safety boundary. The workflow does not disable the hosted runner's
network; its scripts make no provider/model/credential requests, and there
are no repository secrets or write-capable token permissions.

The guest script creates two random disposable standard local accounts,
configures the test service and its restricted service SID, inspects effective
SCM/token/storage/pipe descriptors, and probes direct read/write/delete/
rename/replace/ACL/service-configuration denial from an unprivileged process.
The probe checks actual Win32 error codes and before/after synthetic file
hashes. It exercises allowed health/canary IPC, a second account's denied
pipe access, malformed and authority-claim frames, pre-creation, concurrent
requests, timeouts, stop/restart, in-flight process termination, recovery, and
guest-only cleanup. The unprivileged probe is staged with a read-only copy of
the Python runtime and synthetic helper under a random `C:\Users\Public`
directory. Its DACL is checked as SYSTEM/Admin full control plus `Users`
read/execute, and the directory is removed in the cleanup block; it contains
no configuration or canary data. ACL inspection rejects non-allow ACE types, duplicate ACEs,
unexpected SIDs, or masks other than the exact expected entries. The runner's
administrator token is used only for service setup and inspection, never as
evidence of an unprivileged access denial. The two local accounts are separate
Windows accounts, but the lab does not claim distinct interactive sessions.

**Execution state:** GitHub Actions is enabled for the repository and
`windows-2025` is a documented hosted-runner label. No lab workflow run has
been triggered, so actual runner allocation and every service/ACL/token/pipe/
restart/cleanup result remain **UNVERIFIED**. The development host is Windows
11 Home; the local guard invocation returned
`GITHUB_WINDOWS_RUNNER_REQUIRED`, and the guest root did not exist afterward.
No host service, account, ACL, VM, network setting, credential, or Windows
security configuration was changed. Pure service-config/lifecycle and ACL
validation tests are deterministic code tests, not OS isolation evidence.
Cross-session denial, remote-peer denial, and resistance to a privileged or
compromised hosted runner also remain **UNVERIFIED**. A later successful job
would demonstrate only the specific ephemeral Windows service/storage
behavior that it actually measures—not trusted owner enrollment, trusted
display, owner intent, approval, or production security.
