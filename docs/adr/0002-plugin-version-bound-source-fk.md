# ADR-0002: Version-bound plugin references from sources

- Status: Accepted for CR1-E
- Date: 2026-11-03
- Decision owners: Sentinel project

## Context

The Master Blueprint §10 defines `plugin_manifests` with primary key `(plugin_id, plugin_version)`, allowing multiple registered versions of a plugin. In the same schema inventory, `sources.plugin_id` is described as a foreign key to `plugin_manifests` without a version column. A single child column cannot reference the two-column parent primary key in SQLite. Attempting the declared relation causes a foreign-key mismatch; making only `plugin_id` unique instead would contradict the specified composite key and disallow multiple versions.

## Decision

Add `sources.plugin_version TEXT NOT NULL` and declare:

```sql
FOREIGN KEY (plugin_id, plugin_version)
    REFERENCES plugin_manifests(plugin_id, plugin_version)
```

The blueprint does not specify the additional source column. This is a documented schema deviation. It ensures each source row names the exact registered manifest version it uses while preserving multiple versions per plugin ID. The normative `UNIQUE(plugin_id, account_alias)` remains unchanged.

## Compatibility and migration impact

The change is introduced only in the additive CR1 migration `cr1-e-0002-source-registry`. It does not alter the CR0 foundation migration artifact or its schema checkpoint. An existing CR0-only database remains a valid historical prefix; applying CR1-E adds the new tables and records the second migration without rewriting the old row. There is no source data to backfill in this migration. Any future table referencing a source's plugin registration must use both columns. Removing or changing the version binding after this migration would require a separate migration and explicit data compatibility handling.

## Consequences and limitations

The schema can validate that a source references an existing plugin/version pair and principal. It does not validate plugin policy, approve a manifest, authenticate a principal, fetch source content, or authorize ingestion. `content_ref` and `value_cipher_ref` remain references, not evidence of encryption. Migrations use SQLite transaction locking but do not acquire an application maintenance lease; the application must quiesce writers before an upgrade. Hard-link aliases and their WAL sidecars remain a separate unresolved concurrency/coherence risk.

## Revisit conditions

Revisit only if an authoritative blueprint revision changes the plugin key model or a later migration introduces a separately validated plugin-registration identity. Preserve this migration's artifact bytes and historical schema checkpoint.
