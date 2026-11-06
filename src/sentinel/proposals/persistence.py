"""One source-bound, transactional pending-proposal persistence operation."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from sentinel.config import canonical_config_bytes, config_sha256, load_bundled_defaults
from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.policy import (
    BUILTIN_REGISTRY,
    Capability,
    PolicyDecision,
    PolicyOutcome,
    PolicyReasonCode,
    PolicyRuleId,
    build_policy_context,
    build_proposal_persistence_policy_request,
    evaluate_policy,
)
from sentinel.policy.canonical import policy_sha256, registry_sha256, request_sha256
from sentinel.policy.identities import proposal_preview_identity
from sentinel.policy.source_binding import (
    PublicCitationBinding,
    PublicSourceBinding,
    VerifiedGithubPublicRead,
    VerifiedPublicSourceSet,
    resolve_github_fixture_public_read,
    source_binding_sha256,
    validate_verified_github_public_read,
)
from sentinel.policy.types import PolicyRequest
from sentinel.proposals.persistence_types import (
    ProposalListReport,
    ProposalSaveReport,
    SyntheticPendingProposal,
)
from sentinel.proposals.preview import _build_preview_from_verified_read
from sentinel.proposals.types import _verified_preview_snapshot
from sentinel.storage.connection import DatabaseOpenError, readonly_database_connection
from sentinel.storage.migrations import (
    MIGRATIONS,
    MigrationIntegrityError,
    inspect_migration_state_readonly,
    verify_integrity,
)
from sentinel.storage.schema import CURRENT_SCHEMA
from sentinel.storage.writer import WriterLeaseError, acquire_writer_lease

_PROPOSAL_SCHEMA = "sentinel.synthetic-pending-proposal.v1"
_ARGUMENT_SCHEMA = "sentinel.synthetic-pending-proposal-arguments.v1"
_LIST_SCHEMA = "sentinel.synthetic-pending-proposal-list.v1"
_SAVE_SCHEMA = "sentinel.synthetic-pending-proposal-save.v1"
_PROPOSAL_TTL = timedelta(days=30)
_MAX_ARGUMENT_BYTES = 16_384
_MAX_PROPOSALS = 1000
_PUBLIC_BLOB_REF_PREFIX = "sentinel-public-blob-v1:sha256:"
_PROPOSER_PRINCIPAL_ID = uuid5(NAMESPACE_URL, "sentinel:cr2-d:synthetic-proposal-proposer:v1")
_PROPOSER_KIND = "synthetic-proposal-workflow"
_PROPOSER_DISPLAY_NAME = "Sentinel synthetic proposal workflow (not an owner)"
_PROPOSER_OS_BINDING = "application-defined-synthetic"
_TOOL_ID: Literal["sentinel.synthetic.proposal.persist"] = (
    "sentinel.synthetic.proposal.persist"
)
_CAPABILITY = Capability.C2_WRITE_LOCAL_PROPOSAL.value
_GRAPH_BUILD = "sentinel.cr2d.proposal-save.v1"
_CONFIG_LAYER_SET_JSON = '["bundled-defaults"]'
_CONFIG_ACTIVATION_STATE = "BUNDLED_DEFAULT_SNAPSHOT"
_RUN_STATUS = "PROPOSAL_PERSISTED"
_RUN_MODE = "LOCAL"
_RUN_TRIGGER = "cli-proposal-save"
_ATTRIBUTION = "SOURCE_CITATION"


class ProposalPersistenceErrorCode(StrEnum):
    INVALID_SELECTION = "invalid_selection"
    SOURCE_UNAVAILABLE = "source_unavailable"
    POLICY_DENIED = "policy_denied"
    SCHEMA_INVALID = "schema_invalid"
    RECORD_INVALID = "record_invalid"
    WRITE_FAILED = "write_failed"
    DATABASE_UNAVAILABLE = "database_unavailable"


_ERROR_MESSAGES = {
    ProposalPersistenceErrorCode.INVALID_SELECTION: "Select one supported synthetic issue number.",
    ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE: (
        "Verified synthetic GitHub evidence is unavailable."
    ),
    ProposalPersistenceErrorCode.POLICY_DENIED: (
        "Pending proposal persistence was denied by policy."
    ),
    ProposalPersistenceErrorCode.SCHEMA_INVALID: (
        "The selected database schema is not current and valid."
    ),
    ProposalPersistenceErrorCode.RECORD_INVALID: "Stored pending proposal metadata is invalid.",
    ProposalPersistenceErrorCode.WRITE_FAILED: (
        "Pending proposal transaction failed without a committed result."
    ),
    ProposalPersistenceErrorCode.DATABASE_UNAVAILABLE: "The selected database is unavailable.",
}


class ProposalPersistenceError(RuntimeError):
    """Registered bounded failure category; never carries source text or paths."""

    def __init__(self, code: ProposalPersistenceErrorCode) -> None:
        if type(code) is not ProposalPersistenceErrorCode:
            raise TypeError("proposal persistence error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class _Lineage:
    config_id: str
    config_sha256: str
    config_ref: str
    config_schema: str
    manifest_id: str
    manifest_sha256: str
    plugin_set_sha256: str
    prompt_set_sha256: str
    model_profile_sha256: str


@dataclass(frozen=True, slots=True)
class _Materials:
    issue_number: int
    source: PublicSourceBinding
    preview_id: str
    source_binding_sha256: str
    request_sha256: str
    policy_sha256: str
    registry_sha256: str
    config_sha256: str
    source_manifest_sha256: str
    canonical_args_json: str
    canonical_args_sha256: str
    display_sha256: str
    proposal_id: str
    request: PolicyRequest
    lineage: _Lineage
    run_id: UUID
    thread_id: UUID


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _domain_sha256(domain: str, payload: bytes) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + payload).hexdigest()


def _runtime_lineage() -> _Lineage:
    config = load_bundled_defaults()
    config_bytes = canonical_config_bytes(config)
    config_digest = config_sha256(config)
    if hashlib.sha256(config_bytes).hexdigest() != config_digest:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.SCHEMA_INVALID)
    config_id = f"sentinel.bundled-config.{config_digest}"
    plugin_hash = _domain_sha256(
        "sentinel.cr2d.plugin-set.v1",
        _canonical_json(list(EXPECTED_MANIFEST.plugin_row)).encode("utf-8", errors="strict"),
    )
    prompt_hash = _domain_sha256(
        "sentinel.cr2d.prompt-set.v1",
        _canonical_json({"schema_version": "sentinel.cr2d.prompt-set.v1", "items": []}).encode(
            "utf-8", errors="strict"
        ),
    )
    model_hash = _domain_sha256(
        "sentinel.cr2d.model-profile.v1",
        _canonical_json(
            {
                "schema_version": "sentinel.cr2d.model-profile.v1",
                "model_calls": False,
                "gateway": "none",
            }
        ).encode("utf-8", errors="strict"),
    )
    manifest_payload = {
        "schema_version": "sentinel.cr2d.proposal-run-manifest.v1",
        "config_id": config_id,
        "config_sha256": config_digest,
        "policy_sha256": policy_sha256(),
        "registry_sha256": registry_sha256(BUILTIN_REGISTRY),
        "graph_build": _GRAPH_BUILD,
        "plugin_set_sha256": plugin_hash,
        "prompt_set_sha256": prompt_hash,
        "model_profile_sha256": model_hash,
        "unsafe_overrides": [],
        "fixture_manifest_sha256": EXPECTED_MANIFEST.sha256,
    }
    manifest_digest = _domain_sha256(
        "sentinel.cr2d.proposal-run-manifest.v1",
        _canonical_json(manifest_payload).encode("utf-8", errors="strict"),
    )
    return _Lineage(
        config_id=config_id,
        config_sha256=config_digest,
        config_ref=f"sha256:{config_digest}",
        config_schema=config.schema_version,
        manifest_id=f"sentinel.cr2d.run-manifest.{manifest_digest}",
        manifest_sha256=manifest_digest,
        plugin_set_sha256=plugin_hash,
        prompt_set_sha256=prompt_hash,
        model_profile_sha256=model_hash,
    )


def _pinned_binding() -> VerifiedPublicSourceSet:
    sources: list[PublicSourceBinding] = []
    for expected in EXPECTED_MANIFEST.items:
        values = expected.values
        citations_list: list[PublicCitationBinding] = []
        for span in expected.spans:
            start_byte = span.values[2]
            end_byte = span.values[3]
            if type(start_byte) is not int or type(end_byte) is not int:
                raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
            citations_list.append(
                PublicCitationBinding(
                    span_id=UUID(str(span.values[0])),
                    start_byte=start_byte,
                    end_byte=end_byte,
                    text_sha256=str(span.values[4]),
                )
            )
        citations = tuple(citations_list)
        sources.append(
            PublicSourceBinding(
                source_id=expected.source_envelope_id,
                item_id=UUID(str(values[0])),
                provider_item_id=str(values[2]),
                content_sha256=str(values[6]),
                trust=TrustLabel.T4_EXTERNAL,
                sensitivity=SensitivityLabel.PUBLIC,
                citations=citations,
            )
        )
    unsigned = VerifiedPublicSourceSet(
        fixture_version="sentinel.github-issues-fixture.v1",
        fixture_sha256=EXPECTED_MANIFEST.fixture_sha256,
        manifest_sha256=EXPECTED_MANIFEST.sha256,
        registry_source_id=UUID(str(EXPECTED_MANIFEST.source_row[0])),
        sources=tuple(sources),
        source_set_sha256="0" * 64,
    )
    raw = unsigned.model_dump(mode="python")
    raw["source_set_sha256"] = source_binding_sha256(unsigned)
    return VerifiedPublicSourceSet.model_validate(raw, strict=True)


def _selected_source(binding: VerifiedPublicSourceSet, issue_number: int) -> PublicSourceBinding:
    provider_item_id = f"example-owner/fixture-project#{issue_number}"
    matches = tuple(item for item in binding.sources if item.provider_item_id == provider_item_id)
    if len(matches) != 1:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE)
    return matches[0]


def _materials(
    *,
    binding: VerifiedPublicSourceSet,
    issue_number: int,
    preview_id: str | None = None,
) -> _Materials:
    source = _selected_source(binding, issue_number)
    expected_preview_id = proposal_preview_identity(source.item_id, binding.source_set_sha256)
    if preview_id is not None and preview_id != expected_preview_id:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    preview_digest = expected_preview_id
    request = build_proposal_persistence_policy_request(
        binding=binding,
        issue_number=issue_number,
        preview_id=preview_digest,
    )
    policy_digest = policy_sha256()
    registry_digest = registry_sha256(BUILTIN_REGISTRY)
    config_digest = config_sha256(load_bundled_defaults())
    display_text = (
        f"Review synthetic GitHub issue #{issue_number}\n\n"
        "Possible review only; not an actual task assignment."
    )
    display_digest = hashlib.sha256(display_text.encode("utf-8", errors="strict")).hexdigest()
    args = {
        "schema_version": _ARGUMENT_SCHEMA,
        "proposal_kind": "REVIEW_SOURCE",
        "issue_number": issue_number,
        "preview_id": preview_digest,
        "selected_source_item_id": str(source.item_id),
        "selected_source_envelope_id": str(source.source_id),
        "provider_item_id": source.provider_item_id,
        "source_content_sha256": source.content_sha256,
        "source_binding_sha256": binding.source_set_sha256,
        "source_manifest_sha256": binding.manifest_sha256,
        "evidence_span_ids": [str(citation.span_id) for citation in source.citations],
        "policy_request_sha256": request_sha256(request),
        "policy_sha256": policy_digest,
        "registry_sha256": registry_digest,
        "config_sha256": config_digest,
        "display_sha256": display_digest,
    }
    args_json = _canonical_json(args)
    args_bytes = args_json.encode("utf-8", errors="strict")
    if len(args_bytes) > _MAX_ARGUMENT_BYTES:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    args_digest = _domain_sha256("sentinel.synthetic-pending-proposal-arguments.v1", args_bytes)
    identity = {
        "schema_version": "sentinel.synthetic-pending-proposal.identity.v1",
        "proposal_kind": "REVIEW_SOURCE",
        "selected_source_item_id": str(source.item_id),
        "source_content_sha256": source.content_sha256,
        "source_binding_sha256": binding.source_set_sha256,
        "source_manifest_sha256": binding.manifest_sha256,
        "canonical_args_sha256": args_digest,
        "policy_sha256": policy_digest,
        "registry_sha256": registry_digest,
    }
    proposal_id = _domain_sha256(
        "sentinel.synthetic-pending-proposal.identity.v1",
        _canonical_json(identity).encode("utf-8", errors="strict"),
    )
    lineage = _runtime_lineage()
    run_id = uuid5(NAMESPACE_URL, "sentinel.cr2d.proposal-run.v1:" + proposal_id)
    thread_id = uuid5(NAMESPACE_URL, "sentinel.cr2d.proposal-thread.v1:" + proposal_id)
    return _Materials(
        issue_number=issue_number,
        source=source,
        preview_id=preview_digest,
        source_binding_sha256=binding.source_set_sha256,
        request_sha256=request_sha256(request),
        policy_sha256=policy_digest,
        registry_sha256=registry_digest,
        config_sha256=config_digest,
        source_manifest_sha256=binding.manifest_sha256,
        canonical_args_json=args_json,
        canonical_args_sha256=args_digest,
        display_sha256=display_digest,
        proposal_id=proposal_id,
        request=request,
        lineage=lineage,
        run_id=run_id,
        thread_id=thread_id,
    )


def _evaluate_persistence(read: VerifiedGithubPublicRead, materials: _Materials) -> PolicyDecision:
    if not validate_verified_github_public_read(read):
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE)
    if read.binding.source_set_sha256 != materials.source_binding_sha256:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE)
    context = build_policy_context(
        sources=read.source_envelopes,
        source_binding_sha256=read.binding.source_set_sha256,
    )
    decision = evaluate_policy(
        request=materials.request,
        context=context,
        registry=BUILTIN_REGISTRY,
        evidence_binding=read,
    )
    if not _decision_matches_persistence(decision, materials):
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.POLICY_DENIED)
    return decision


def _decision_matches_persistence(decision: object, materials: _Materials) -> bool:
    if type(decision) is not PolicyDecision:
        return False
    try:
        checked = PolicyDecision.model_validate(decision.model_dump(mode="python"), strict=True)
        expected = (
            materials.request.request_id,
            materials.source.source_id,
            *(citation.span_id for citation in materials.source.citations),
        )
        return (
            checked.outcome is PolicyOutcome.ALLOW
            and checked.rule_id is PolicyRuleId.P06
            and checked.reason_code is PolicyReasonCode.PROPOSAL_PERSISTENCE_ALLOWED
            and checked.request_sha256 == materials.request_sha256
            and checked.policy_sha256 == materials.policy_sha256
            and checked.registry_sha256 == materials.registry_sha256
            and checked.evidence_binding_sha256 == materials.source_binding_sha256
            and checked.evidence_ids == expected
            and checked.executable is False
        )
    except Exception:
        return False


def _now_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.WRITE_FAILED)
    utc_value = value.astimezone(UTC)
    return utc_value.isoformat(timespec="microseconds")


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID) from None
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
        or parsed.isoformat(timespec="microseconds") != value
    ):
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    return parsed


def _require_registered_schema(connection: sqlite3.Connection) -> None:
    expected_history = tuple(
        (migration.migration_id, migration.artifact_sha256, 1) for migration in MIGRATIONS
    )
    try:
        history_rows = connection.execute(
            "SELECT migration_id, artifact_sha256, success FROM schema_migrations "
            "ORDER BY applied_at, migration_id"
        ).fetchall()
        if tuple(tuple(row) for row in history_rows) != expected_history:
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.SCHEMA_INVALID)
        schema_rows = connection.execute(
            """SELECT type, name, sql FROM sqlite_master
               WHERE name NOT GLOB 'sqlite_*'
                 AND type IN ('table', 'index', 'view', 'trigger')"""
        ).fetchall()
        actual = {(str(kind), str(name)): sql for kind, name, sql in schema_rows}
        expected = {(item.object_type, item.name): item.sql for item in CURRENT_SCHEMA.objects}
        if actual.keys() != expected.keys() or any(
            not isinstance(actual[key], str) or actual[key].strip() != sql.strip()
            for key, sql in expected.items()
        ):
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.SCHEMA_INVALID)
    except ProposalPersistenceError:
        raise
    except sqlite3.Error:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.SCHEMA_INVALID) from None


def _require_pinned_fixture_rows(connection: sqlite3.Connection) -> None:
    """Check body-free DB registrations/spans against the fixed manifest pins."""
    try:
        principal = connection.execute(
            "SELECT principal_id, kind, display_name, os_binding, created_at, revoked_at "
            "FROM principals WHERE principal_id = ?",
            (EXPECTED_MANIFEST.principal_row[0],),
        ).fetchone()
        if principal is None or tuple(principal) != EXPECTED_MANIFEST.principal_row:
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE)
        plugin = connection.execute(
            """SELECT plugin_id, plugin_version, manifest_ref, manifest_sha256, origin,
                      capability_json, trust, sensitivity, host_allowlist_json,
                      fixture_set_sha256, enabled, registered_at
               FROM plugin_manifests WHERE plugin_id = ? AND plugin_version = ?""",
            (EXPECTED_MANIFEST.plugin_row[0], EXPECTED_MANIFEST.plugin_row[1]),
        ).fetchone()
        if plugin is None or tuple(plugin) != EXPECTED_MANIFEST.plugin_row:
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE)
        source = connection.execute(
            """SELECT source_id, plugin_id, plugin_version, principal_id, source_type,
                      account_alias, scope_json, host_allowlist_json, trust,
                      default_sensitivity, enabled, created_at
               FROM sources WHERE source_id = ?""",
            (EXPECTED_MANIFEST.source_row[0],),
        ).fetchone()
        if source is None or tuple(source) != EXPECTED_MANIFEST.source_row:
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE)

        for expected_item in EXPECTED_MANIFEST.items:
            item_values = list(expected_item.values)
            item_values[5] = f"{_PUBLIC_BLOB_REF_PREFIX}{item_values[6]}"
            expected_item_values = tuple(item_values)
            item = connection.execute(
                """SELECT item_id, source_id, provider_item_id, provider_revision,
                          canonical_uri, content_ref, content_sha256, trust, sensitivity,
                          observed_at, source_at, deleted_at, metadata_json
                   FROM source_items WHERE item_id = ?""",
                (expected_item_values[0],),
            ).fetchone()
            if item is None or tuple(item) != expected_item_values:
                raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE)
            expected_spans = tuple(span.values for span in expected_item.spans)
            actual_spans = tuple(
                tuple(row)
                for row in connection.execute(
                    """SELECT span_id, item_id, start_byte, end_byte, text_sha256,
                              context_ref, derived_by_boundary_id
                       FROM source_spans WHERE item_id = ? ORDER BY start_byte, span_id""",
                    (expected_item_values[0],),
                ).fetchall()
            )
            if actual_spans != tuple(
                sorted(expected_spans, key=lambda span: (span[2], span[0]))
            ):
                raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE)
    except ProposalPersistenceError:
        raise
    except sqlite3.Error:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE) from None


def _ensure_supporting_lineage(
    connection: sqlite3.Connection,
    *,
    materials: _Materials,
    created_at: str,
) -> None:
    lineage = materials.lineage
    principal_values = (
        str(_PROPOSER_PRINCIPAL_ID),
        _PROPOSER_KIND,
        _PROPOSER_DISPLAY_NAME,
        _PROPOSER_OS_BINDING,
        created_at,
        None,
    )
    principal_row = connection.execute(
        """SELECT principal_id, kind, display_name, os_binding, created_at, revoked_at
           FROM principals WHERE principal_id = ?""",
        (str(_PROPOSER_PRINCIPAL_ID),),
    ).fetchone()
    if principal_row is None:
        connection.execute(
            """INSERT INTO principals
               (principal_id, kind, display_name, os_binding, created_at, revoked_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            principal_values,
        )
    else:
        actual = tuple(principal_row)
        if actual[:4] != principal_values[:4] or actual[5] is not None:
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
        _parse_utc(actual[4])

    config_values = (
        lineage.config_id,
        None,
        _CONFIG_LAYER_SET_JSON,
        lineage.config_schema,
        lineage.config_ref,
        lineage.config_sha256,
        "[]",
        None,
        created_at,
        _CONFIG_ACTIVATION_STATE,
    )
    config_row = connection.execute(
        """SELECT config_id, parent_config_id, layer_set_json, effective_schema_version,
                  effective_config_ref, effective_sha256, unsafe_overrides_json,
                  activated_at, created_at, activation_state
           FROM config_revisions WHERE config_id = ?""",
        (lineage.config_id,),
    ).fetchone()
    if config_row is None:
        # The config table also requires one row per digest; reject another identity.
        digest_owner = connection.execute(
            "SELECT config_id FROM config_revisions WHERE effective_sha256 = ?",
            (lineage.config_sha256,),
        ).fetchone()
        if digest_owner is not None:
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
        connection.execute(
            """INSERT INTO config_revisions
               (config_id, parent_config_id, layer_set_json, effective_schema_version,
                effective_config_ref, effective_sha256, unsafe_overrides_json,
                activated_at, created_at, activation_state)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            config_values,
        )
    else:
        actual_config = tuple(config_row)
        if actual_config[:8] != config_values[:8] or actual_config[9] != config_values[9]:
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
        _parse_utc(actual_config[8])

    manifest_values = (
        lineage.manifest_id,
        lineage.config_id,
        materials.policy_sha256,
        _GRAPH_BUILD,
        lineage.plugin_set_sha256,
        lineage.prompt_set_sha256,
        lineage.model_profile_sha256,
        "[]",
        EXPECTED_MANIFEST.sha256,
        created_at,
        lineage.manifest_sha256,
    )
    manifest_row = connection.execute(
        """SELECT manifest_id, config_id, policy_sha256, graph_build, plugin_set_sha256,
                  prompt_set_sha256, model_profile_sha256, unsafe_overrides_json,
                  fixture_manifest_sha256, created_at, manifest_sha256
           FROM run_manifests WHERE manifest_id = ?""",
        (lineage.manifest_id,),
    ).fetchone()
    if manifest_row is None:
        digest_owner = connection.execute(
            "SELECT manifest_id FROM run_manifests WHERE manifest_sha256 = ?",
            (lineage.manifest_sha256,),
        ).fetchone()
        if digest_owner is not None:
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
        connection.execute(
            """INSERT INTO run_manifests
               (manifest_id, config_id, policy_sha256, graph_build, plugin_set_sha256,
                prompt_set_sha256, model_profile_sha256, unsafe_overrides_json,
                fixture_manifest_sha256, created_at, manifest_sha256)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            manifest_values,
        )
    else:
        actual_manifest = tuple(manifest_row)
        if actual_manifest[:9] != manifest_values[:9] or actual_manifest[10] != manifest_values[10]:
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
        _parse_utc(actual_manifest[9])

    run_values = (
        str(materials.run_id),
        str(materials.thread_id),
        str(_PROPOSER_PRINCIPAL_ID),
        lineage.manifest_id,
        _RUN_MODE,
        _RUN_TRIGGER,
        created_at,
        created_at,
        _RUN_STATUS,
        None,
        None,
    )
    run_row = connection.execute(
        """SELECT run_id, thread_id, principal_id, manifest_id, mode, trigger_kind,
                  started_at, ended_at, status, error_code, briefing_id
           FROM runs WHERE run_id = ?""",
        (str(materials.run_id),),
    ).fetchone()
    if run_row is None:
        connection.execute(
            """INSERT INTO runs
               (run_id, thread_id, principal_id, manifest_id, mode, trigger_kind,
                started_at, ended_at, status, error_code, briefing_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            run_values,
        )
    else:
        if tuple(run_row) != run_values:
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)


def _make_proposal(materials: _Materials, created_at: datetime) -> SyntheticPendingProposal:
    expires_at = created_at + _PROPOSAL_TTL
    return SyntheticPendingProposal(
        proposal_id=materials.proposal_id,
        run_id=materials.run_id,
        principal_id=_PROPOSER_PRINCIPAL_ID,
        tool_id=_TOOL_ID,
        issue_number=materials.issue_number,
        proposal_title=f"Review synthetic GitHub issue #{materials.issue_number}",
        source_item_id=materials.source.item_id,
        source_envelope_id=materials.source.source_id,
        preview_id=materials.preview_id,
        provider_item_id=materials.source.provider_item_id,
        source_content_sha256=materials.source.content_sha256,
        source_binding_sha256=materials.source_binding_sha256,
        source_manifest_sha256=materials.source_manifest_sha256,
        evidence_span_ids=tuple(item.span_id for item in materials.source.citations),
        canonical_args_ref=f"sha256:{materials.canonical_args_sha256}",
        canonical_args_sha256=materials.canonical_args_sha256,
        display_sha256=materials.display_sha256,
        policy_request_sha256=materials.request_sha256,
        policy_sha256=materials.policy_sha256,
        registry_sha256=materials.registry_sha256,
        config_sha256=materials.config_sha256,
        created_at=created_at,
        expires_at=expires_at,
    )


_PROPOSAL_SELECT = """SELECT proposal_id, run_id, principal_id, tool_id, capability,
       canonical_args_ref, canonical_args_sha256, display_sha256, owner_intent_id,
       status, created_at, expires_at, credential_alias, proposal_schema_version,
       proposal_kind, preview_id, selected_source_item_id, selected_source_envelope_id,
       source_content_sha256, source_binding_sha256, source_manifest_sha256,
       policy_request_sha256, policy_sha256, registry_sha256, config_sha256,
       canonical_args_json, executable
       FROM action_proposals"""


def _row_to_proposal(row: Sequence[object]) -> SyntheticPendingProposal:
    if len(row) != 27 or type(row[26]) is not int or row[26] != 0:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    try:
        return SyntheticPendingProposal.model_validate(
            {
                "proposal_id": row[0],
                "run_id": UUID(str(row[1])),
                "principal_id": UUID(str(row[2])),
                "tool_id": row[3],
                "capability": Capability.C2_WRITE_LOCAL_PROPOSAL,
                "proposal_kind": row[14],
                "issue_number": json.loads(str(row[25]))["issue_number"],
                "proposal_title": (
                    "Review synthetic GitHub issue #"
                    f"{json.loads(str(row[25]))['issue_number']}"
                ),
                "source_item_id": UUID(str(row[16])),
                "source_envelope_id": UUID(str(row[17])),
                "preview_id": row[15],
                "provider_item_id": json.loads(str(row[25]))["provider_item_id"],
                "source_content_sha256": row[18],
                "source_binding_sha256": row[19],
                "source_manifest_sha256": row[20],
                "evidence_span_ids": tuple(
                    UUID(value) for value in json.loads(str(row[25]))["evidence_span_ids"]
                ),
                "canonical_args_ref": row[5],
                "canonical_args_sha256": row[6],
                "display_sha256": row[7],
                "policy_request_sha256": row[21],
                "policy_sha256": row[22],
                "registry_sha256": row[23],
                "config_sha256": row[24],
                "policy_rule_id": "P06",
                "status": row[9],
                "created_at": _parse_utc(row[10]),
                "expires_at": _parse_utc(row[11]),
                "owner_intent_id": row[8],
                "credential_alias": row[12],
                "source_trust": TrustLabel.T4_EXTERNAL,
                "source_sensitivity": SensitivityLabel.PUBLIC,
                "derived_trust": TrustLabel.T3_DERIVED,
                "derived_sensitivity": SensitivityLabel.PUBLIC,
                "executable": False,
            },
            strict=True,
        )
    except ProposalPersistenceError:
        raise
    except Exception:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID) from None


def _validate_supporting_lineage(
    connection: sqlite3.Connection,
    *,
    proposal: SyntheticPendingProposal,
    materials: _Materials,
) -> None:
    lineage = materials.lineage
    principal = connection.execute(
        """SELECT kind, display_name, os_binding, created_at, revoked_at
           FROM principals WHERE principal_id = ?""",
        (str(proposal.principal_id),),
    ).fetchone()
    if principal is None or tuple(principal)[:3] != (
        _PROPOSER_KIND,
        _PROPOSER_DISPLAY_NAME,
        _PROPOSER_OS_BINDING,
    ) or principal[4] is not None:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    _parse_utc(principal[3])

    config = connection.execute(
        """SELECT parent_config_id, layer_set_json, effective_schema_version,
                  effective_config_ref, effective_sha256, unsafe_overrides_json,
                  activated_at, created_at, activation_state
           FROM config_revisions WHERE config_id = ?""",
        (lineage.config_id,),
    ).fetchone()
    if config is None or tuple(config)[:7] != (
        None,
        _CONFIG_LAYER_SET_JSON,
        lineage.config_schema,
        lineage.config_ref,
        lineage.config_sha256,
        "[]",
        None,
    ) or config[8] != _CONFIG_ACTIVATION_STATE:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    _parse_utc(config[7])

    manifest = connection.execute(
        """SELECT config_id, policy_sha256, graph_build, plugin_set_sha256,
                  prompt_set_sha256, model_profile_sha256, unsafe_overrides_json,
                  fixture_manifest_sha256, created_at, manifest_sha256
           FROM run_manifests WHERE manifest_id = ?""",
        (lineage.manifest_id,),
    ).fetchone()
    if manifest is None or tuple(manifest)[:8] != (
        lineage.config_id,
        materials.policy_sha256,
        _GRAPH_BUILD,
        lineage.plugin_set_sha256,
        lineage.prompt_set_sha256,
        lineage.model_profile_sha256,
        "[]",
        EXPECTED_MANIFEST.sha256,
    ) or manifest[9] != lineage.manifest_sha256:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    _parse_utc(manifest[8])
    run = connection.execute(
        """SELECT thread_id, principal_id, manifest_id, mode, trigger_kind,
                  started_at, ended_at, status, error_code, briefing_id
           FROM runs WHERE run_id = ?""",
        (str(proposal.run_id),),
    ).fetchone()
    if run is None:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    actual = tuple(run)
    if (
        actual[:5]
        != (
            str(materials.thread_id),
            str(_PROPOSER_PRINCIPAL_ID),
            materials.lineage.manifest_id,
            _RUN_MODE,
            _RUN_TRIGGER,
        )
        or _parse_utc(actual[5]) != proposal.created_at
        or _parse_utc(actual[6]) < proposal.created_at
        or actual[7:] != (_RUN_STATUS, None, None)
    ):
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)


def _validate_persisted_proposal(
    connection: sqlite3.Connection,
    *,
    proposal_id: str,
    materials: _Materials,
) -> SyntheticPendingProposal:
    row = connection.execute(_PROPOSAL_SELECT + " WHERE proposal_id = ?", (proposal_id,)).fetchone()
    if row is None:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    proposal = _row_to_proposal(tuple(row))
    expected = _make_proposal(materials, proposal.created_at)
    if proposal != expected or proposal.proposal_id != proposal_id:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    raw_args = str(row[25])
    args_bytes = raw_args.encode("utf-8", errors="strict")
    if (
        len(args_bytes) > _MAX_ARGUMENT_BYTES
        or _domain_sha256("sentinel.synthetic-pending-proposal-arguments.v1", args_bytes)
        != proposal.canonical_args_sha256
        or raw_args != materials.canonical_args_json
    ):
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    if str(row[13]) != _PROPOSAL_SCHEMA or str(row[14]) != "REVIEW_SOURCE":
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    if (
        row[8] is not None
        or row[12] is not None
        or row[26] != 0
        or str(row[4]) != _CAPABILITY
        or str(row[3]) != _TOOL_ID
        or str(row[5]) != f"sha256:{proposal.canonical_args_sha256}"
    ):
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    _validate_supporting_lineage(connection, proposal=proposal, materials=materials)

    expected_sources = tuple(
        (
            str(proposal.source_item_id),
            str(span_id),
            "/evidence_span_ids",
            _ATTRIBUTION,
        )
        for span_id in proposal.evidence_span_ids
    )
    actual_sources = tuple(
        tuple(str(value) for value in source_row)
        for source_row in connection.execute(
            """SELECT item_id, span_id, argument_path, attribution_kind
               FROM proposal_sources WHERE proposal_id = ? ORDER BY span_id""",
            (proposal_id,),
        ).fetchall()
    )
    if actual_sources != tuple(sorted(expected_sources, key=lambda item: item[1])):
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    task = connection.execute(
        "SELECT 1 FROM tasks WHERE proposal_id = ?", (proposal_id,)
    ).fetchone()
    if task is not None:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    _require_pinned_fixture_rows(connection)
    return proposal


def _insert_proposal(
    connection: sqlite3.Connection,
    *,
    proposal: SyntheticPendingProposal,
    materials: _Materials,
) -> None:
    args_json = materials.canonical_args_json
    columns = (
        "proposal_id, run_id, principal_id, tool_id, capability, canonical_args_ref, "
        "canonical_args_sha256, display_sha256, owner_intent_id, status, created_at, "
        "expires_at, credential_alias, proposal_schema_version, proposal_kind, preview_id, "
        "selected_source_item_id, selected_source_envelope_id, source_content_sha256, "
        "source_binding_sha256, source_manifest_sha256, policy_request_sha256, policy_sha256, "
        "registry_sha256, config_sha256, canonical_args_json, executable"
    )
    values = (
        proposal.proposal_id,
        str(proposal.run_id),
        str(proposal.principal_id),
        proposal.tool_id,
        _CAPABILITY,
        proposal.canonical_args_ref,
        proposal.canonical_args_sha256,
        proposal.display_sha256,
        None,
        proposal.status,
        _now_text(proposal.created_at),
        _now_text(proposal.expires_at),
        None,
        _PROPOSAL_SCHEMA,
        "REVIEW_SOURCE",
        proposal.preview_id,
        str(proposal.source_item_id),
        str(proposal.source_envelope_id),
        proposal.source_content_sha256,
        proposal.source_binding_sha256,
        proposal.source_manifest_sha256,
        proposal.policy_request_sha256,
        proposal.policy_sha256,
        proposal.registry_sha256,
        proposal.config_sha256,
        args_json,
        0,
    )
    connection.execute(
        f"INSERT INTO action_proposals ({columns}) VALUES ({', '.join('?' for _ in values)})",
        values,
    )
    for span_id in proposal.evidence_span_ids:
        connection.execute(
            """INSERT INTO proposal_sources
               (proposal_id, item_id, span_id, argument_path, attribution_kind)
               VALUES (?, ?, ?, ?, ?)""",
            (
                proposal.proposal_id,
                str(proposal.source_item_id),
                str(span_id),
                "/evidence_span_ids",
                _ATTRIBUTION,
            ),
        )


def _recheck_source_snapshot(
    database: str | Path,
    store_root: str | Path,
    *,
    original: VerifiedGithubPublicRead,
    materials: _Materials,
) -> None:
    try:
        current = resolve_github_fixture_public_read(database, store_root=store_root)
    except Exception:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE) from None
    if (
        not validate_verified_github_public_read(current)
        or current.binding.source_set_sha256 != original.binding.source_set_sha256
        or current.binding != original.binding
        or current.evidence != original.evidence
    ):
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE)
    _evaluate_persistence(current, materials)


def save_github_fixture_proposal(
    database: str | Path,
    *,
    store_root: str | Path,
    issue_number: int,
) -> ProposalSaveReport:
    """Persist one P09/P06-approved pending proposal from a verified snapshot."""
    if type(issue_number) is not int or issue_number not in {101, 102, 103}:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.INVALID_SELECTION)
    try:
        verified_read = resolve_github_fixture_public_read(database, store_root=store_root)
        preview = _build_preview_from_verified_read(verified_read, issue_number=issue_number)
        verified_preview = _verified_preview_snapshot(preview)
        if verified_preview is None:
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.POLICY_DENIED)
        source = _selected_source(verified_read.binding, issue_number)
        if (
            verified_preview.issue_number != issue_number
            or verified_preview.source_item_id != source.item_id
            or verified_preview.source_envelope_id != source.source_id
            or verified_preview.source_content_sha256 != source.content_sha256
            or verified_preview.source_binding_sha256 != verified_read.binding.source_set_sha256
            or verified_preview.evidence_span_ids
            != tuple(span.span_id for span in source.citations)
        ):
            raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE)
        materials = _materials(
            binding=verified_read.binding,
            issue_number=issue_number,
            preview_id=verified_preview.preview_id,
        )
        _evaluate_persistence(verified_read, materials)
        _require_pinned_fixture_rows_before_lease(database)
        with acquire_writer_lease(database) as lease:
            with lease.transaction() as connection:
                _require_registered_schema(connection)
                _require_pinned_fixture_rows(connection)
                conflict = connection.execute(
                    "SELECT proposal_id FROM action_proposals "
                    "WHERE display_sha256 = ? AND run_id = ?",
                    (materials.display_sha256, str(materials.run_id)),
                ).fetchone()
                existing = connection.execute(
                    "SELECT proposal_id FROM action_proposals WHERE proposal_id = ?",
                    (materials.proposal_id,),
                ).fetchone()
                if conflict is not None and (
                    existing is None or str(conflict[0]) != materials.proposal_id
                ):
                    raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
                if existing is not None:
                    saved = _validate_persisted_proposal(
                        connection,
                        proposal_id=materials.proposal_id,
                        materials=materials,
                    )
                    _recheck_source_snapshot(
                        database,
                        store_root,
                        original=verified_read,
                        materials=materials,
                    )
                    return ProposalSaveReport(disposition="ALREADY_EXISTS", proposal=saved)

                created_at = datetime.now(UTC)
                proposal = _make_proposal(materials, created_at)
                _ensure_supporting_lineage(
                    connection,
                    materials=materials,
                    created_at=_now_text(created_at),
                )
                _insert_proposal(connection, proposal=proposal, materials=materials)
                saved = _validate_persisted_proposal(
                    connection,
                    proposal_id=materials.proposal_id,
                    materials=materials,
                )
                _recheck_source_snapshot(
                    database,
                    store_root,
                    original=verified_read,
                    materials=materials,
                )
            return ProposalSaveReport(disposition="CREATED", proposal=saved)
    except ProposalPersistenceError:
        raise
    except (WriterLeaseError, MigrationIntegrityError, DatabaseOpenError):
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.SCHEMA_INVALID) from None
    except Exception:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.WRITE_FAILED) from None


def _require_pinned_fixture_rows_before_lease(database: str | Path) -> None:
    try:
        with readonly_database_connection(database) as connection:
            _require_pinned_fixture_rows(connection)
    except ProposalPersistenceError:
        raise
    except Exception:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE) from None


def _expected_materials_for_row(row: Sequence[object]) -> _Materials:
    if len(row) != 27:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
    try:
        args_value = json.loads(str(row[25]))
        if type(args_value) is not dict or type(args_value.get("issue_number")) is not int:
            raise ValueError
        issue_number = args_value["issue_number"]
        if issue_number not in {101, 102, 103}:
            raise ValueError
        return _materials(binding=_pinned_binding(), issue_number=issue_number)
    except ProposalPersistenceError:
        raise
    except Exception:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID) from None


def list_github_fixture_proposals(database: str | Path) -> ProposalListReport:
    """Read and strictly validate every persisted bounded proposal record."""
    try:
        with readonly_database_connection(database) as connection:
            state = inspect_migration_state_readonly(connection)
            if not state.is_current or state.schema_version != CURRENT_SCHEMA.schema_version:
                raise ProposalPersistenceError(ProposalPersistenceErrorCode.SCHEMA_INVALID)
            _require_registered_schema(connection)
            verify_integrity(connection)
            rows = connection.execute(
                _PROPOSAL_SELECT + " ORDER BY proposal_id LIMIT ?",
                (_MAX_PROPOSALS + 1,),
            ).fetchall()
            if len(rows) > _MAX_PROPOSALS:
                raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
            if rows:
                _require_pinned_fixture_rows(connection)
            proposals: list[SyntheticPendingProposal] = []
            verify_integrity(connection)
            for row_value in rows:
                row = tuple(row_value)
                if len(row) != 27:
                    raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID)
                materials = _expected_materials_for_row(row)
                proposal = _validate_persisted_proposal(
                    connection,
                    proposal_id=str(row[0]),
                    materials=materials,
                )
                proposals.append(proposal)
            return ProposalListReport(proposal_count=len(proposals), proposals=tuple(proposals))
    except ProposalPersistenceError:
        raise
    except (
        DatabaseOpenError,
        MigrationIntegrityError,
        sqlite3.Error,
        OSError,
        ValueError,
        TypeError,
    ):
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.DATABASE_UNAVAILABLE) from None
    except Exception:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.RECORD_INVALID) from None


__all__ = [
    "ProposalPersistenceError",
    "ProposalPersistenceErrorCode",
    "list_github_fixture_proposals",
    "save_github_fixture_proposal",
]
