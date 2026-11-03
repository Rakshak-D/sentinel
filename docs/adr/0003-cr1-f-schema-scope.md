# ADR-0003: Bound CR1-F to the five requested schema tables

- Status: Recorded for CR1-F; full §10 schema remains incomplete
- Date: 2026-11-03

## Context

The CR1-F slice explicitly requests one migration adding `config_revisions`,
`run_manifests`, `runs`, `boundary_envelopes`, and `source_spans`. The Blueprint
§10 relational-schema prose also names `run_source_items` and `run_memory_uses`
as normative join tables. The latter depends on a memory schema that is not
registered. The same §10 prose describes intentional cyclic references such as
`runs.briefing_id`, while the selected table inventory omits the `briefings`
parent.

## Decision

Keep `cr1-f-0003-source-spans` limited to the five tables explicitly requested
for this slice and their direct parent graph. Do not create either join table or
a placeholder `memories`/`briefings` table. Preserve `runs.briefing_id` as a
nullable field without an FK because the task explicitly requires deferring its
parent. Record `run_source_items` and `run_memory_uses` as deferred normative
schema work. The CR1-F checkpoint is complete for the objects registered by
this migration; it is not the complete Blueprint §10 application schema.

## Rationale

`run_source_items` is not a direct dependency of `source_spans` or of the
requested five-table closure. Adding it would broaden the authorized migration
scope. `run_memory_uses` cannot be registered with valid foreign keys until
its memory parent exists. Creating a placeholder parent would give an
incomplete schema a misleading appearance of integrity. A later schema slice
must add these relationships with their real parent definitions and a new
versioned checkpoint.

## Consequences

- This migration creates no `run_source_items`, `run_memory_uses`,
  `briefings`, or memory table.
- Durable run-to-source-item association and run-to-memory-use history remain
  unavailable.
- `briefing_id` has no database-enforced reference until its parent is
  introduced in a later migration.
- The existing CR0 and CR1-E migration artifacts and checkpoints remain
  unchanged; no automatic repair or schema inference is added.
- This is an explicit bounded-slice deferral from the full §10 schema, not a
  claim that those normative relationships are implemented.
