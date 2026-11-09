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
