"""Credential-free read-only diagnostics for the implemented CR0 foundation."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from uuid import UUID

from sentinel.config import (
    CONFIG_SCHEMA_VERSION,
    canonical_config_bytes,
    config_sha256,
    load_bundled_defaults,
    validate_bundled_config,
)
from sentinel.contracts import BoundaryKind, SensitivityLabel, SourceEnvelope, TrustLabel
from sentinel.credentials import (
    BackendAvailability,
    CredentialBroker,
    CredentialStatus,
    SecretRef,
    SecretReferenceState,
)
from sentinel.gateways.model import ModelGateway
from sentinel.gateways.registry import (
    GatewayRegistry,
    ModelAdapterRegistration,
    ToolAdapterRegistration,
)
from sentinel.gateways.tool import ToolGateway
from sentinel.gateways.types import (
    DemoPayload,
    ExecutionMode,
    GatewayFailureCode,
    ModelAdapterOutput,
    ModelCallResult,
    ModelInvocation,
    ModelLocality,
    ModelProfile,
    ModelRequest,
    ModelTaskClass,
    ToolAdapterOutput,
    ToolCallResult,
    ToolCapability,
    ToolInvocation,
    ToolRequest,
)
from sentinel.storage.connection import (
    inspect_connection,
    readonly_database_connection,
)
from sentinel.storage.migrations import (
    MigrationIntegrityError,
    inspect_migration_history_readonly,
    verify_foreign_key_integrity,
    verify_schema_checkpoint_readonly,
    verify_sqlite_integrity,
)

_NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)
_RUN_ID = UUID("3ba1b2f0-9e7f-4e79-a92d-10f22e75cb11")
_SOURCE_ID = UUID("ac9f20d2-a8a3-4c3a-8d40-d93d0cfc59f2")
_CALL_ID = UUID("56b176bf-d637-4c90-9c01-593789e6636f")
_MODEL_ID = "synthetic/doctor-v1"
_MODEL_TEXT = b"synthetic doctor probe"
_TOOL_TEXT = b"synthetic read result"
_MODEL_ADAPTER_ID = "doctor.synthetic_model"
_TOOL_ID = "doctor.synthetic_read"
_PROVIDER_ID = "synthetic.memory"
_TEXT_SCHEMA = "sentinel.text.v1"


class DoctorStatus(StrEnum):
    """Stable per-check outcomes; only PASS means that check was verified."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


class DoctorCheckId(StrEnum):
    """Fixed diagnostic vocabulary for supported checks and explicit gaps."""

    DATABASE_READ_ONLY = "database.read_only"
    DATABASE_WAL = "database.wal"
    DATABASE_INTEGRITY = "database.integrity"
    DATABASE_FOREIGN_KEYS = "database.foreign_keys"
    DATABASE_FOREIGN_KEY_INTEGRITY = "database.foreign_key_integrity"
    MIGRATION_HISTORY = "storage.migration_history"
    SCHEMA_CHECKPOINT = "storage.schema_checkpoint"
    CONFIG_VALIDATION = "config.validation"
    CONFIG_FINGERPRINT = "config.fingerprint"
    CREDENTIAL_BACKEND = "credential.backend"
    MODEL_GATEWAY_DEMO = "gateway.model_demo"
    MODEL_GATEWAY_DENIALS = "gateway.model_denials"
    TOOL_GATEWAY_DEMO = "gateway.tool_demo"
    TOOL_GATEWAY_DENIALS = "gateway.tool_denials"
    LIVE_EFFECTS_DISABLED = "capability.live_effects_disabled"
    OS_KEYCHAIN = "capability.os_keychain"
    OWNER_VERIFICATION = "capability.owner_verification"
    POLICY_ENGINE = "capability.policy_engine"
    LIVE_MODEL_ROUTING = "capability.live_model_routing"
    MCP_SMOKE = "capability.mcp_smoke"
    BACKUP_VERIFICATION = "capability.backup_verification"
    SIGNED_AUDIT_ROOTS = "capability.signed_audit_roots"


_MESSAGES: dict[DoctorCheckId, dict[DoctorStatus, str]] = {
    DoctorCheckId.DATABASE_READ_ONLY: {
        DoctorStatus.PASS: "Existing database opened in SQLite read-only/query-only mode.",
        DoctorStatus.FAIL: "Existing database could not be inspected safely.",
    },
    DoctorCheckId.DATABASE_WAL: {
        DoctorStatus.PASS: "File-backed database is using WAL journal mode.",
        DoctorStatus.FAIL: "WAL mode is unavailable or could not be verified.",
    },
    DoctorCheckId.DATABASE_INTEGRITY: {
        DoctorStatus.PASS: "SQLite integrity check passed.",
        DoctorStatus.FAIL: "SQLite integrity check failed or could not be completed.",
    },
    DoctorCheckId.DATABASE_FOREIGN_KEYS: {
        DoctorStatus.PASS: "Foreign-key enforcement is enabled on this connection.",
        DoctorStatus.FAIL: "Foreign-key enforcement is disabled or could not be verified.",
    },
    DoctorCheckId.DATABASE_FOREIGN_KEY_INTEGRITY: {
        DoctorStatus.PASS: "SQLite foreign-key integrity check passed.",
        DoctorStatus.FAIL: "SQLite foreign-key integrity check failed or could not be completed.",
    },
    DoctorCheckId.MIGRATION_HISTORY: {
        DoctorStatus.PASS: (
            "Applied migration IDs, ordering and artifact digests match the trusted registry."
        ),
        DoctorStatus.FAIL: (
            "Applied migration history could not be verified against the trusted registry."
        ),
    },
    DoctorCheckId.SCHEMA_CHECKPOINT: {
        DoctorStatus.PASS: "Database schema matches its registered migration checkpoint.",
        DoctorStatus.FAIL: (
            "Database schema could not be verified against its registered checkpoint."
        ),
    },
    DoctorCheckId.CONFIG_VALIDATION: {
        DoctorStatus.PASS: "Bundled configuration validates with local-only defaults.",
        DoctorStatus.FAIL: "Bundled configuration validation failed.",
    },
    DoctorCheckId.CONFIG_FINGERPRINT: {
        DoctorStatus.PASS: "Bundled configuration fingerprint is deterministic.",
        DoctorStatus.FAIL: "Bundled configuration fingerprint verification failed.",
    },
    DoctorCheckId.CREDENTIAL_BACKEND: {
        DoctorStatus.UNAVAILABLE: (
            "Credential backend is unavailable by design; no credential was retrieved."
        ),
        DoctorStatus.FAIL: "Credential broker status did not match the unavailable default.",
    },
    DoctorCheckId.MODEL_GATEWAY_DEMO: {
        DoctorStatus.PASS: "Registered synthetic DEMO model call returned typed boundary metadata.",
        DoctorStatus.FAIL: "Synthetic model gateway contract probe failed.",
    },
    DoctorCheckId.MODEL_GATEWAY_DENIALS: {
        DoctorStatus.PASS: (
            "Unknown-model and SECRET model requests were denied before adapter execution."
        ),
        DoctorStatus.FAIL: "Synthetic model gateway denial probe failed.",
    },
    DoctorCheckId.TOOL_GATEWAY_DEMO: {
        DoctorStatus.PASS: (
            "Registered synthetic read-only tool call returned typed boundary metadata."
        ),
        DoctorStatus.FAIL: "Synthetic tool gateway contract probe failed.",
    },
    DoctorCheckId.TOOL_GATEWAY_DENIALS: {
        DoctorStatus.PASS: (
            "Unknown, write and approval tool requests were denied before handler execution."
        ),
        DoctorStatus.FAIL: "Synthetic tool gateway denial probe failed.",
    },
    DoctorCheckId.LIVE_EFFECTS_DISABLED: {
        DoctorStatus.PASS: (
            "CR0 diagnostics used only in-memory synthetic adapters; live effects remain disabled."
        ),
        DoctorStatus.FAIL: "A synthetic-only restriction probe did not pass.",
    },
    DoctorCheckId.OS_KEYCHAIN: {
        DoctorStatus.UNAVAILABLE: "Production OS keychain integration is unavailable.",
    },
    DoctorCheckId.OWNER_VERIFICATION: {
        DoctorStatus.NOT_IMPLEMENTED: "Authenticated owner verification is not implemented.",
    },
    DoctorCheckId.POLICY_ENGINE: {
        DoctorStatus.NOT_IMPLEMENTED: "Policy engine is not implemented.",
    },
    DoctorCheckId.LIVE_MODEL_ROUTING: {
        DoctorStatus.NOT_IMPLEMENTED: "Live model/provider routing is not implemented.",
    },
    DoctorCheckId.MCP_SMOKE: {
        DoctorStatus.NOT_IMPLEMENTED: "MCP smoke testing is not implemented.",
    },
    DoctorCheckId.BACKUP_VERIFICATION: {
        DoctorStatus.NOT_IMPLEMENTED: "Backup verification is not implemented.",
    },
    DoctorCheckId.SIGNED_AUDIT_ROOTS: {
        DoctorStatus.NOT_IMPLEMENTED: "Signed audit roots are not implemented.",
    },
}


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """One fixed check result; messages are selected only from the safe vocabulary."""

    check_id: DoctorCheckId
    status: DoctorStatus
    message: str

    def __post_init__(self) -> None:
        if type(self.check_id) is not DoctorCheckId or type(self.status) is not DoctorStatus:
            raise ValueError("doctor check identifiers and statuses must be registered values")
        expected_message = _MESSAGES[self.check_id].get(self.status)
        if (
            expected_message is None
            or type(self.message) is not str
            or self.message != expected_message
        ):
            raise ValueError("doctor check message is not registered")


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Stable read-only diagnostic result, not a readiness or authorization receipt."""

    checks: tuple[DoctorCheck, ...]

    def __post_init__(self) -> None:
        if type(self.checks) is not tuple or any(
            type(item) is not DoctorCheck for item in self.checks
        ):
            raise ValueError("doctor checks must be an immutable tuple of registered checks")
        ids = tuple(item.check_id for item in self.checks)
        if ids != tuple(DoctorCheckId):
            raise ValueError("doctor report must contain every check once in registered order")

    @property
    def successful(self) -> bool:
        """Supported checks must pass; designed unavailability is reported separately."""

        return all(check.status is not DoctorStatus.FAIL for check in self.checks)


def _check(check_id: DoctorCheckId, status: DoctorStatus) -> DoctorCheck:
    return DoctorCheck(check_id, status, _MESSAGES[check_id][status])


def _run_bool_check(check_id: DoctorCheckId, operation: Callable[[], bool]) -> DoctorCheck:
    try:
        succeeded = operation()
    except Exception:
        succeeded = False
    return _check(check_id, DoctorStatus.PASS if succeeded else DoctorStatus.FAIL)


def _source(
    payload: bytes,
    sensitivity: SensitivityLabel = SensitivityLabel.PUBLIC,
) -> SourceEnvelope:
    return SourceEnvelope(
        source_id=_SOURCE_ID,
        provider_id="synthetic.doctor",
        content_sha256=hashlib.sha256(payload).hexdigest(),
        observed_at=_NOW,
        trust=TrustLabel.T4_EXTERNAL,
        sensitivity=sensitivity,
        parent_ids=(),
        byte_spans=(),
    )


class _ModelProbe:
    demo_only = True

    def __init__(self) -> None:
        self.invocations: list[ModelInvocation] = []

    def generate(self, invocation: ModelInvocation) -> ModelAdapterOutput:
        self.invocations.append(invocation)
        return ModelAdapterOutput(output_bytes=b"synthetic doctor model result")


class _ToolProbe:
    demo_only = True

    def __init__(self) -> None:
        self.invocations: list[ToolInvocation] = []

    def call(self, invocation: ToolInvocation) -> ToolAdapterOutput:
        self.invocations.append(invocation)
        return ToolAdapterOutput(output_bytes=_TOOL_TEXT)


def _model_request(payload: bytes, sensitivity: SensitivityLabel) -> ModelRequest:
    digest = sha256(payload).hexdigest()
    return ModelRequest(
        call_id=_CALL_ID,
        run_id=_RUN_ID,
        adapter_id=_MODEL_ADAPTER_ID,
        model_id=_MODEL_ID,
        task_class=ModelTaskClass.SUMMARIZATION,
        prompt_id="doctor.synthetic",
        prompt_version="1.0.0",
        prompt_sha256="a" * 64,
        input_schema_id=_TEXT_SCHEMA,
        output_schema_id=_TEXT_SCHEMA,
        source_ids=(_SOURCE_ID,),
        sensitivity=sensitivity,
        payload_ref=f"sha256:{digest}",
        redaction_manifest_ref=None,
        config_sha256="b" * 64,
        temperature=0.0,
        max_output_tokens=32,
        deadline=datetime(2099, 1, 1, tzinfo=UTC),
        requested_profile=ModelProfile.LOCAL_ONLY,
        replay_mode=False,
    )


def _model_probe() -> tuple[bool, bool]:
    public_source = _source(_MODEL_TEXT)
    adapter = _ModelProbe()
    registration = ModelAdapterRegistration(
        adapter_id=_MODEL_ADAPTER_ID,
        provider_id=_PROVIDER_ID,
        model_id=_MODEL_ID,
        locality=ModelLocality.LOOPBACK,
        demo_only=True,
        adapter=adapter,
    )
    registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(public_source,),
        demo_payloads=(
            DemoPayload(
                payload_ref=f"sha256:{sha256(_MODEL_TEXT).hexdigest()}",
                payload_bytes=_MODEL_TEXT,
            ),
        ),
        model_adapters=(registration,),
    )
    gateway = ModelGateway(registry)
    success = gateway.generate(_model_request(_MODEL_TEXT, SensitivityLabel.PUBLIC))
    success_ok = _successful_model_result(success, adapter)

    unknown_adapter = _ModelProbe()
    unknown_registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(public_source,),
        demo_payloads=(
            DemoPayload(
                payload_ref=f"sha256:{sha256(_MODEL_TEXT).hexdigest()}",
                payload_bytes=_MODEL_TEXT,
            ),
        ),
        model_adapters=(
            ModelAdapterRegistration(
                adapter_id=_MODEL_ADAPTER_ID,
                provider_id=_PROVIDER_ID,
                model_id=_MODEL_ID,
                locality=ModelLocality.LOOPBACK,
                demo_only=True,
                adapter=unknown_adapter,
            ),
        ),
    )
    unknown_request = _model_request(_MODEL_TEXT, SensitivityLabel.PUBLIC).model_dump(mode="python")
    unknown_request["model_id"] = "synthetic/unknown-v1"
    unknown_result = ModelGateway(unknown_registry).generate(unknown_request)

    secret_text = b"synthetic doctor secret must not reach model"
    secret_adapter = _ModelProbe()
    secret_registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(_source(secret_text, SensitivityLabel.SECRET),),
        demo_payloads=(
            DemoPayload(
                payload_ref=f"sha256:{sha256(secret_text).hexdigest()}",
                payload_bytes=secret_text,
            ),
        ),
        model_adapters=(
            ModelAdapterRegistration(
                adapter_id=_MODEL_ADAPTER_ID,
                provider_id=_PROVIDER_ID,
                model_id=_MODEL_ID,
                locality=ModelLocality.LOOPBACK,
                demo_only=True,
                adapter=secret_adapter,
            ),
        ),
    )
    secret_result = ModelGateway(secret_registry).generate(
        _model_request(secret_text, SensitivityLabel.SECRET)
    )
    denials_ok = (
        unknown_result.failure is not None
        and unknown_result.failure.code is GatewayFailureCode.UNKNOWN_MODEL
        and unknown_adapter.invocations == []
        and secret_result.failure is not None
        and secret_result.failure.code is GatewayFailureCode.SENSITIVITY_DENIED
        and secret_adapter.invocations == []
    )
    return success_ok, denials_ok


def _successful_model_result(result: ModelCallResult, adapter: _ModelProbe) -> bool:
    if result.failure is not None or result.response is None or result.boundary is None:
        return False
    if len(adapter.invocations) != 1:
        return False
    invocation = adapter.invocations[0]
    boundary = result.boundary
    return (
        boundary.kind is BoundaryKind.MODEL
        and boundary.request_sha256 == sha256(invocation.request_bytes).hexdigest()
        and result.response.request_sha256 == boundary.request_sha256
        and boundary.response_sha256 == sha256(b"synthetic doctor model result").hexdigest()
        and result.response.raw_output_ref == boundary.response_ref
        and result.external_effect is False
    )


def _tool_request(tool_id: str = _TOOL_ID) -> ToolRequest:
    return ToolRequest(
        call_id=_CALL_ID,
        run_id=_RUN_ID,
        tool_id=tool_id,
        arguments=(("key", "synthetic"),),
        source_ids=(_SOURCE_ID,),
        sensitivity=SensitivityLabel.PUBLIC,
    )


def _tool_probe() -> tuple[bool, bool]:
    source = _source(b"synthetic doctor tool provenance")
    adapter = _ToolProbe()
    registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(source,),
        tool_adapters=(
            ToolAdapterRegistration(
                tool_id=_TOOL_ID,
                capability=ToolCapability.READ_ONLY,
                argument_names=("key",),
                demo_only=True,
                adapter=adapter,
            ),
        ),
    )
    result = ToolGateway(registry).call(_tool_request())
    success_ok = _successful_tool_result(result, adapter)

    calls_before_unknown = len(adapter.invocations)
    unknown = ToolGateway(registry).call(_tool_request("doctor.unknown"))
    denial_checks = (
        unknown.failure is not None
        and unknown.failure.code is GatewayFailureCode.UNKNOWN_TOOL
        and len(adapter.invocations) == calls_before_unknown
    )
    for capability in (ToolCapability.WRITE_EXTERNAL, ToolCapability.APPROVAL):
        denied_adapter = _ToolProbe()
        denied_registry = GatewayRegistry(
            execution_mode=ExecutionMode.DEMO,
            sources=(source,),
            tool_adapters=(
                ToolAdapterRegistration(
                    tool_id=_TOOL_ID,
                    capability=capability,
                    argument_names=("key",),
                    demo_only=True,
                    adapter=denied_adapter,
                ),
            ),
        )
        denied = ToolGateway(denied_registry).call(_tool_request())
        denial_checks = denial_checks and (
            denied.failure is not None
            and denied.failure.code is GatewayFailureCode.CAPABILITY_DENIED
            and denied_adapter.invocations == []
            and denied.external_effect is False
        )
    # The unknown tool probe is sent to a registry with no matching tool.
    return success_ok, denial_checks


def _successful_tool_result(result: ToolCallResult, adapter: _ToolProbe) -> bool:
    if result.failure is not None or result.response is None or result.boundary is None:
        return False
    if len(adapter.invocations) != 1:
        return False
    invocation = adapter.invocations[0]
    boundary = result.boundary
    return (
        boundary.kind is BoundaryKind.TOOL
        and boundary.request_sha256 == sha256(invocation.request_bytes).hexdigest()
        and boundary.response_sha256 == sha256(_TOOL_TEXT).hexdigest()
        and result.response.result_ref == boundary.response_ref
        and result.external_effect is False
    )


def _configuration_probes() -> tuple[bool, bool]:
    config = load_bundled_defaults()
    validated = validate_bundled_config(config)
    canonical = canonical_config_bytes(validated)
    fingerprint = config_sha256(validated)
    repeated = load_bundled_defaults()
    repeated_canonical = canonical_config_bytes(repeated)
    repeated_fingerprint = config_sha256(repeated)
    valid = (
        validated == config
        and validated == repeated
        and validated.schema_version == CONFIG_SCHEMA_VERSION
    )
    deterministic = (
        canonical == repeated_canonical
        and fingerprint == repeated_fingerprint
        and hashlib.sha256(canonical).hexdigest() == fingerprint
    )
    return valid, deterministic


def _credential_probe() -> CredentialStatus:
    broker = CredentialBroker()
    reference = SecretRef(
        secret_ref_id="doctor.synthetic",
        provider="synthetic",
        keychain_locator="sentinel:doctor.synthetic",
        scope_manifest_sha256="0" * 64,
        os_owner_binding="synthetic-doctor-owner",
        created_at=_NOW,
    )
    return broker.status(reference)


def _database_checks(database: str | Path) -> dict[DoctorCheckId, DoctorCheck]:
    results: dict[DoctorCheckId, DoctorCheck] = {}
    try:
        with readonly_database_connection(database) as connection:
            results[DoctorCheckId.DATABASE_READ_ONLY] = _check(
                DoctorCheckId.DATABASE_READ_ONLY,
                DoctorStatus.PASS
                if int(connection.execute("PRAGMA query_only").fetchone()[0]) == 1
                else DoctorStatus.FAIL,
            )
            settings = inspect_connection(connection)
            results[DoctorCheckId.DATABASE_WAL] = _check(
                DoctorCheckId.DATABASE_WAL,
                DoctorStatus.PASS if settings.journal_mode == "wal" else DoctorStatus.FAIL,
            )
            results[DoctorCheckId.DATABASE_FOREIGN_KEYS] = _check(
                DoctorCheckId.DATABASE_FOREIGN_KEYS,
                DoctorStatus.PASS if settings.foreign_keys_enabled else DoctorStatus.FAIL,
            )
            results[DoctorCheckId.DATABASE_INTEGRITY] = _run_bool_check(
                DoctorCheckId.DATABASE_INTEGRITY,
                lambda: _integrity_passes(verify_sqlite_integrity, connection),
            )
            results[DoctorCheckId.DATABASE_FOREIGN_KEY_INTEGRITY] = _run_bool_check(
                DoctorCheckId.DATABASE_FOREIGN_KEY_INTEGRITY,
                lambda: _integrity_passes(verify_foreign_key_integrity, connection),
            )
            migration_ids: tuple[str, ...] | None = None
            try:
                migration_ids = inspect_migration_history_readonly(connection)
                results[DoctorCheckId.MIGRATION_HISTORY] = _check(
                    DoctorCheckId.MIGRATION_HISTORY, DoctorStatus.PASS
                )
            except Exception:
                results[DoctorCheckId.MIGRATION_HISTORY] = _check(
                    DoctorCheckId.MIGRATION_HISTORY, DoctorStatus.FAIL
                )
            try:
                if migration_ids is None:
                    raise MigrationIntegrityError("history was not validated")
                verify_schema_checkpoint_readonly(connection, migration_ids)
                results[DoctorCheckId.SCHEMA_CHECKPOINT] = _check(
                    DoctorCheckId.SCHEMA_CHECKPOINT, DoctorStatus.PASS
                )
            except Exception:
                results[DoctorCheckId.SCHEMA_CHECKPOINT] = _check(
                    DoctorCheckId.SCHEMA_CHECKPOINT, DoctorStatus.FAIL
                )
    except Exception:
        results[DoctorCheckId.DATABASE_READ_ONLY] = _check(
            DoctorCheckId.DATABASE_READ_ONLY, DoctorStatus.FAIL
        )
        for check_id in (
            DoctorCheckId.DATABASE_WAL,
            DoctorCheckId.DATABASE_INTEGRITY,
            DoctorCheckId.DATABASE_FOREIGN_KEYS,
            DoctorCheckId.DATABASE_FOREIGN_KEY_INTEGRITY,
            DoctorCheckId.MIGRATION_HISTORY,
            DoctorCheckId.SCHEMA_CHECKPOINT,
        ):
            results.setdefault(check_id, _check(check_id, DoctorStatus.FAIL))
    return results


def _integrity_passes(
    operation: Callable[[sqlite3.Connection], None],
    connection: sqlite3.Connection,
) -> bool:
    operation(connection)
    return True


def run_doctor(database: str | Path) -> DoctorReport:
    """Run bounded diagnostics without creating or mutating application data.

    The returned report covers implemented local CR0 capabilities and explicitly
    marks unavailable/future systems. It never authorizes an operation or implies
    production readiness. All exception details and selected paths are withheld.
    """

    db_results = _database_checks(database)
    try:
        config_valid, fingerprint_valid = _configuration_probes()
    except Exception:
        config_valid, fingerprint_valid = False, False
    try:
        model_success, model_denials = _model_probe()
    except Exception:
        model_success, model_denials = False, False
    try:
        tool_success, tool_denials = _tool_probe()
    except Exception:
        tool_success, tool_denials = False, False
    try:
        credential_status = _credential_probe()
        credential_ok = (
            credential_status.backend is BackendAvailability.UNAVAILABLE
            and credential_status.reference is SecretReferenceState.UNKNOWN
        )
    except Exception:
        credential_ok = False

    results: dict[DoctorCheckId, DoctorCheck] = dict(db_results)
    results[DoctorCheckId.CONFIG_VALIDATION] = _check(
        DoctorCheckId.CONFIG_VALIDATION,
        DoctorStatus.PASS if config_valid else DoctorStatus.FAIL,
    )
    results[DoctorCheckId.CONFIG_FINGERPRINT] = _check(
        DoctorCheckId.CONFIG_FINGERPRINT,
        DoctorStatus.PASS if fingerprint_valid else DoctorStatus.FAIL,
    )
    results[DoctorCheckId.CREDENTIAL_BACKEND] = _check(
        DoctorCheckId.CREDENTIAL_BACKEND,
        DoctorStatus.UNAVAILABLE if credential_ok else DoctorStatus.FAIL,
    )
    results[DoctorCheckId.MODEL_GATEWAY_DEMO] = _check(
        DoctorCheckId.MODEL_GATEWAY_DEMO,
        DoctorStatus.PASS if model_success else DoctorStatus.FAIL,
    )
    results[DoctorCheckId.MODEL_GATEWAY_DENIALS] = _check(
        DoctorCheckId.MODEL_GATEWAY_DENIALS,
        DoctorStatus.PASS if model_denials else DoctorStatus.FAIL,
    )
    results[DoctorCheckId.TOOL_GATEWAY_DEMO] = _check(
        DoctorCheckId.TOOL_GATEWAY_DEMO,
        DoctorStatus.PASS if tool_success else DoctorStatus.FAIL,
    )
    results[DoctorCheckId.TOOL_GATEWAY_DENIALS] = _check(
        DoctorCheckId.TOOL_GATEWAY_DENIALS,
        DoctorStatus.PASS if tool_denials else DoctorStatus.FAIL,
    )
    safe_configuration = False
    try:
        config = load_bundled_defaults()
        dumped = config.model_dump(mode="python")
        safe_configuration = (
            config_valid
            and config.data.storage_path is None
            and not config.sources.enabled
            and not config.sources.host_allowlist
            and config.models.egress.internal_cloud_consent is False
            and all(not capability.enabled for capability in (
                config.security.external_writes.gmail_draft,
                config.security.external_writes.gmail_send,
                config.security.external_writes.github_comment,
                config.security.external_writes.github_label,
            ))
            and "credentials" not in dumped
        )
    except Exception:
        safe_configuration = False
    only_synthetic = model_success and model_denials and tool_success and tool_denials
    results[DoctorCheckId.LIVE_EFFECTS_DISABLED] = _check(
        DoctorCheckId.LIVE_EFFECTS_DISABLED,
        DoctorStatus.PASS if safe_configuration and only_synthetic else DoctorStatus.FAIL,
    )
    results[DoctorCheckId.OS_KEYCHAIN] = _check(
        DoctorCheckId.OS_KEYCHAIN, DoctorStatus.UNAVAILABLE
    )
    for check_id in (
        DoctorCheckId.OWNER_VERIFICATION,
        DoctorCheckId.POLICY_ENGINE,
        DoctorCheckId.LIVE_MODEL_ROUTING,
        DoctorCheckId.MCP_SMOKE,
        DoctorCheckId.BACKUP_VERIFICATION,
        DoctorCheckId.SIGNED_AUDIT_ROOTS,
    ):
        results[check_id] = _check(check_id, DoctorStatus.NOT_IMPLEMENTED)
    return DoctorReport(tuple(results[check_id] for check_id in DoctorCheckId))
