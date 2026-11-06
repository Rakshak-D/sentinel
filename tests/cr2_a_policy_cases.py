"""Small fixed builders for CR2-A behavioral tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sentinel.config.schema import CONFIG_SCHEMA_VERSION
from sentinel.contracts import SensitivityLabel, SourceEnvelope, TrustLabel
from sentinel.gateways.types import ExecutionMode
from sentinel.policy import (
    BUILTIN_REGISTRY,
    POLICY_ID,
    POLICY_VERSION,
    REGISTRY_ID,
    REGISTRY_VERSION,
    ArgumentKind,
    Capability,
    EffectClass,
    ExecutionBoundary,
    ModelRouteState,
    PolicyRequest,
    build_policy_context,
    builtin_registry_sha256,
    policy_sha256,
)

_EFFECTS = {
    Capability.C0_READ_PUBLIC: EffectClass.READ_ONLY,
    Capability.C1_READ_PRIVATE: EffectClass.READ_ONLY,
    Capability.C2_WRITE_LOCAL_PROPOSAL: EffectClass.LOCAL_PROPOSAL,
    Capability.C3_WRITE_LOCAL_ACCEPTED: EffectClass.LOCAL_ACCEPTED,
    Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB: EffectClass.EXTERNAL_DRAFT_OR_GITHUB,
    Capability.C5_SEND_EXTERNAL_EMAIL: EffectClass.EXTERNAL_SEND,
    Capability.C6_ACCESS_SECRET: EffectClass.SECRET_ACCESS,
}


def make_source(
    *,
    source_id: UUID | None = None,
    trust: TrustLabel = TrustLabel.T4_EXTERNAL,
    sensitivity: SensitivityLabel = SensitivityLabel.PRIVATE,
    observed_at: datetime = datetime(2026, 11, 6, tzinfo=UTC),
) -> SourceEnvelope:
    return SourceEnvelope(
        source_id=UUID(int=101) if source_id is None else source_id,
        provider_id="sentinel.cr2-test-source",
        content_sha256="a" * 64,
        observed_at=observed_at,
        trust=trust,
        sensitivity=sensitivity,
        parent_ids=(),
        byte_spans=(),
    )


def make_context(
    source: SourceEnvelope | None = None,
    *,
    model_route: ModelRouteState = ModelRouteState.UNVERIFIED,
):
    return build_policy_context(
        sources=() if source is None else (source,),
        model_route=model_route,
    )


def make_request(
    *,
    capability: Capability = Capability.C0_READ_PUBLIC,
    operation_id: str | None = None,
    source: SourceEnvelope | None = None,
    source_ids: tuple[UUID, ...] | None = None,
    arguments: tuple[tuple[str, str | int | bool], ...] | None = None,
    execution_mode: ExecutionMode = ExecutionMode.LIVE,
    execution_boundary: ExecutionBoundary = ExecutionBoundary.CORE,
    declared_sensitivity: SensitivityLabel | None = SensitivityLabel.PRIVATE,
    requested_effect_class: EffectClass | None = None,
) -> PolicyRequest:
    selected_operation = operation_id or next(
        entry.operation_id
        for entry in BUILTIN_REGISTRY.entries
        if entry.capability_id is capability
    )
    registration = BUILTIN_REGISTRY.find_operation(selected_operation)
    if arguments is None:
        if registration is None:
            arguments = (("resource_id", "synthetic-item"),)
        else:
            defaults: dict[ArgumentKind, str | int | bool] = {
                ArgumentKind.TEXT: "synthetic-item",
                ArgumentKind.INTEGER: 1,
                ArgumentKind.BOOLEAN: True,
            }
            arguments = tuple(
                (spec.name, defaults[spec.value_kind]) for spec in registration.argument_schema
            )
    source_value = source or make_source()
    context = make_context(source_value)
    return PolicyRequest(
        request_id=UUID(int=202),
        operation_id=selected_operation,
        capability=capability,
        execution_mode=execution_mode,
        execution_boundary=execution_boundary,
        arguments=arguments,
        source_ids=(source_value.source_id,) if source_ids is None else source_ids,
        declared_sensitivity=declared_sensitivity,
        registry_id=REGISTRY_ID,
        registry_version=REGISTRY_VERSION,
        registry_sha256=builtin_registry_sha256(),
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        policy_sha256=policy_sha256(),
        config_version=CONFIG_SCHEMA_VERSION,
        config_sha256=context.config_sha256,
        requested_effect_class=(
            requested_effect_class
            or (_EFFECTS[capability] if registration is None else registration.effect_class)
        ),
    )
