# ADR-0004: CR1-J task creation request receipts

- Status: Accepted for the bounded CR1-J manual task workflow
- Date: 2026-11-04

## Context

Blueprint §10 defines `tasks` without a creation request ID or immutable
creation-argument digest. CR1-J must still make a caller-supplied request UUID
idempotent and reject reuse of that UUID with different arguments. Task titles
and due dates are editable, so comparing a replay only with the current task row
would lose the original creation arguments after an edit.

## Decision

Keep the normative `tasks` columns and add `task_creation_requests` in the same
checkpoint-aware migration. The table stores the request UUID, deterministic
task UUID, and SHA-256 of canonical JSON containing the original title and
normalized UTC due date. One request maps to one task and one task maps to one
creation request. The receipt and task row are inserted in the same writer
transaction and the task API does not update or delete receipts.

The task UUID is UUIDv5 under the fixed `sentinel:manual-task-id:v1` namespace,
using the dedicated local operator UUID and request UUID. Reusing a request UUID
with an identical canonical argument digest returns the existing current task;
reusing it with different arguments fails without changing rows.

## Consequences

- The additional table is an explicit schema deviation needed to preserve the
  F11 retry contract after task edits; the normative `tasks` row stays intact.
- The receipt stores no duplicate title or due-date plaintext. The task title
  itself remains ordinary, unencrypted SQLite text.
- The digest is not a MAC and does not resist direct same-user database edits.
- `action_proposals` remains schema-only. Manual task APIs create no proposal,
  source link, body reference, approval, or external effect.
- Existing CR0/CR1-E/F migrations and their checkpoints are unchanged. Databases
  must use the explicit current-schema maintenance path before task commands;
  maintenance must run while application writers are quiescent.
