"""Pure deny-only policy evaluation for the bounded CR2-A foundation."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel

from sentinel.config.defaults import load_bundled_defaults
from sentinel.config.fingerprint import config_sha256 as fingerprint_config
from sentinel.config.schema import CONFIG_SCHEMA_VERSION
from sentinel.contracts import SensitivityLabel, SourceEnvelope, TrustLabel
from sentinel.policy.canonical import (
    policy_sha256,
    registry_sha256,
    request_sha256,
)
from sentinel.policy.registry import (
    BUILTIN_REGISTRY,
    POLICY_ID,
    POLICY_RULES,
    POLICY_VERSION,
    REGISTRY_ID,
    REGISTRY_VERSION,
    UNIMPLEMENTED_RULE_IDS,
    CapabilityRegistry,
)
from sentinel.policy.types import (
    ArgumentKind,
    AuthorizationClass,
    Capability,
    CapabilityRegistration,
    CapabilityStatus,
    EffectClass,
    ExecutionBoundary,
    ModelRouteState,
    PolicyContext,
    PolicyDecision,
    PolicyOutcome,
    PolicyReasonCode,
    PolicyRequest,
    PolicyRuleId,
    PolicyStatusReport,
    RegistrationState,
)

POLICY_RUNTIME_PRINCIPAL = "sentinel.policy-runtime"
POLICY_RUNTIME_TRUST = TrustLabel.T0_POLICY
_INVALID_REQUEST_SHA256 = "0" * 64
_BUILTIN_POLICY_SHA256 = policy_sha256()
_BUILTIN_REGISTRY_SHA256 = registry_sha256(BUILTIN_REGISTRY)
_BUNDLED_CONFIG_SHA256 = fingerprint_config(load_bundled_defaults())

_SENSITIVITY_ORDER = {
    SensitivityLabel.PUBLIC: 0,
    SensitivityLabel.INTERNAL: 1,
    SensitivityLabel.PRIVATE: 2,
    SensitivityLabel.SECRET: 3,
}


def build_policy_context(
    *,
    sources: tuple[SourceEnvelope, ...] = (),
    model_route: ModelRouteState = ModelRouteState.UNVERIFIED,
) -> PolicyContext:
    """Build a policy-runtime context without creating owner proof or permissions.

    Source envelopes must be supplied by trusted application code. This helper
    validates context structure only; it is not an identity/provenance resolver.
    """
    return PolicyContext(
        principal_id=POLICY_RUNTIME_PRINCIPAL,
        principal_trust=POLICY_RUNTIME_TRUST,
        registry_sha256=_BUILTIN_REGISTRY_SHA256,
        policy_sha256=_BUILTIN_POLICY_SHA256,
        config_version=CONFIG_SCHEMA_VERSION,
        config_sha256=_BUNDLED_CONFIG_SHA256,
        sources=sources,
        model_route=model_route,
        enabled_capabilities=(),
        isolated_worker_available=False,
        implementation_state="deny_only_foundation",
    )


def _validate_exact_model(value: object, model_type: type[BaseModel]) -> BaseModel:
    if type(value) is model_type:
        raw_value = value.model_dump(mode="python")
    elif type(value) is dict:
        raw_value = value
    else:
        raise ValueError("policy input has an unsupported type")
    return model_type.model_validate(raw_value, strict=True)


def _validate_context(value: object) -> PolicyContext:
    model = _validate_exact_model(value, PolicyContext)
    if type(model) is not PolicyContext:
        raise ValueError("invalid context type")
    return model


def _validate_request(value: object) -> PolicyRequest:
    model = _validate_exact_model(value, PolicyRequest)
    if type(model) is not PolicyRequest:
        raise ValueError("invalid request type")
    return model


def _validate_registry(value: object) -> CapabilityRegistry:
    model = _validate_exact_model(value, type(BUILTIN_REGISTRY))
    if type(model) is not type(BUILTIN_REGISTRY):
        raise ValueError("invalid registry type")
    return model


def _deny(
    rule_id: PolicyRuleId,
    reason_code: PolicyReasonCode,
    *,
    request_digest: str = _INVALID_REQUEST_SHA256,
    registry_digest: str = _BUILTIN_REGISTRY_SHA256,
    evidence_ids: tuple[UUID, ...] = (),
) -> PolicyDecision:
    return PolicyDecision(
        outcome=PolicyOutcome.DENY,
        rule_id=rule_id,
        reason_code=reason_code,
        policy_sha256=_BUILTIN_POLICY_SHA256,
        registry_sha256=registry_digest,
        request_sha256=request_digest,
        evidence_ids=evidence_ids[:8],
        executable=False,
    )


def _p00(
    reason: PolicyReasonCode,
    *,
    request_digest: str = _INVALID_REQUEST_SHA256,
    registry_digest: str = _BUILTIN_REGISTRY_SHA256,
    evidence_ids: tuple[UUID, ...] = (),
) -> PolicyDecision:
    return _deny(
        PolicyRuleId.P00,
        reason,
        request_digest=request_digest,
        registry_digest=registry_digest,
        evidence_ids=evidence_ids,
    )


def _arguments_match(
    registration: CapabilityRegistration,
    request: PolicyRequest,
) -> bool:
    supplied = request.arguments
    expected_by_name = {item.name: item for item in registration.argument_schema}
    supplied_names = tuple(name for name, _value in supplied)
    if any(name not in expected_by_name for name in supplied_names):
        return False
    if any(
        spec.required and spec.name not in supplied_names for spec in registration.argument_schema
    ):
        return False
    for name, value in supplied:
        spec = expected_by_name[name]
        if spec.value_kind is ArgumentKind.TEXT and type(value) is not str:
            return False
        if spec.value_kind is ArgumentKind.INTEGER and type(value) is not int:
            return False
        if spec.value_kind is ArgumentKind.BOOLEAN and type(value) is not bool:
            return False
    return True


def _effective_sensitivity(sources: tuple[SourceEnvelope, ...]) -> SensitivityLabel | None:
    if not sources:
        return None
    return max((source.sensitivity for source in sources), key=_SENSITIVITY_ORDER.__getitem__)


def _evaluate_validated(
    request: PolicyRequest,
    validated_registry: CapabilityRegistry,
    context: PolicyContext,
    request_digest: str,
) -> PolicyDecision:
    actual_registry_digest = registry_sha256(validated_registry)
    if validated_registry != BUILTIN_REGISTRY or actual_registry_digest != _BUILTIN_REGISTRY_SHA256:
        return _p00(
            PolicyReasonCode.REGISTRY_UNTRUSTED,
            request_digest=request_digest,
            registry_digest=_BUILTIN_REGISTRY_SHA256,
            evidence_ids=(request.request_id,),
        )
    if context.registry_sha256 != _BUILTIN_REGISTRY_SHA256:
        return _p00(
            PolicyReasonCode.REGISTRY_UNTRUSTED,
            request_digest=request_digest,
            evidence_ids=(request.request_id,),
        )

    if (
        context.principal_id != POLICY_RUNTIME_PRINCIPAL
        or context.principal_trust is not POLICY_RUNTIME_TRUST
    ):
        return _p00(
            PolicyReasonCode.PRINCIPAL_UNTRUSTED,
            request_digest=request_digest,
            evidence_ids=(request.request_id,),
        )
    if policy_sha256() != _BUILTIN_POLICY_SHA256 or context.policy_sha256 != _BUILTIN_POLICY_SHA256:
        return _p00(
            PolicyReasonCode.POLICY_UNTRUSTED,
            request_digest=request_digest,
            evidence_ids=(request.request_id,),
        )
    if (
        context.config_version != CONFIG_SCHEMA_VERSION
        or context.config_sha256 != _BUNDLED_CONFIG_SHA256
        or fingerprint_config(load_bundled_defaults()) != _BUNDLED_CONFIG_SHA256
    ):
        return _p00(
            PolicyReasonCode.CONFIG_UNTRUSTED,
            request_digest=request_digest,
            evidence_ids=(request.request_id,),
        )

    if (
        request.registry_id != REGISTRY_ID
        or request.registry_version != REGISTRY_VERSION
        or request.registry_sha256 != _BUILTIN_REGISTRY_SHA256
    ):
        return _p00(
            PolicyReasonCode.REGISTRY_UNTRUSTED,
            request_digest=request_digest,
            evidence_ids=(request.request_id,),
        )
    if (
        request.policy_id != POLICY_ID
        or request.policy_version != POLICY_VERSION
        or request.policy_sha256 != _BUILTIN_POLICY_SHA256
    ):
        return _p00(
            PolicyReasonCode.POLICY_UNTRUSTED,
            request_digest=request_digest,
            evidence_ids=(request.request_id,),
        )
    if (
        request.config_version != CONFIG_SCHEMA_VERSION
        or request.config_sha256 != _BUNDLED_CONFIG_SHA256
    ):
        return _p00(
            PolicyReasonCode.CONFIG_UNTRUSTED,
            request_digest=request_digest,
            evidence_ids=(request.request_id,),
        )

    registration = validated_registry.find_operation(request.operation_id)
    if registration is None:
        return _p00(
            PolicyReasonCode.OPERATION_UNREGISTERED,
            request_digest=request_digest,
            evidence_ids=(request.request_id,),
        )
    if (
        registration.capability_id is not request.capability
        or registration.effect_class is not request.requested_effect_class
    ):
        return _p00(
            PolicyReasonCode.CAPABILITY_MISMATCH,
            request_digest=request_digest,
            evidence_ids=(request.request_id,),
        )
    if not _arguments_match(registration, request):
        return _p00(
            PolicyReasonCode.ARGUMENTS_INVALID,
            request_digest=request_digest,
            evidence_ids=(request.request_id,),
        )

    source_map = {source.source_id: source for source in context.sources}
    if not request.source_ids:
        return _p00(
            PolicyReasonCode.SOURCE_MISSING,
            request_digest=request_digest,
            evidence_ids=(request.request_id,),
        )
    source_records = tuple(source_map.get(source_id) for source_id in request.source_ids)
    if request.source_ids and any(source is None for source in source_records):
        return _p00(
            PolicyReasonCode.SOURCE_MISSING,
            request_digest=request_digest,
            evidence_ids=(request.request_id,),
        )
    sources = tuple(source for source in source_records if source is not None)
    if any(source.trust is TrustLabel.T5_UNKNOWN for source in sources):
        return _p00(
            PolicyReasonCode.SOURCE_PROVENANCE_UNKNOWN,
            request_digest=request_digest,
            evidence_ids=(request.request_id, *(source.source_id for source in sources)),
        )
    if any(source.trust is TrustLabel.T1_OWNER_INTENT for source in sources):
        return _p00(
            PolicyReasonCode.SOURCE_PROVENANCE_UNKNOWN,
            request_digest=request_digest,
            evidence_ids=(request.request_id, *(source.source_id for source in sources)),
        )
    if any(
        registration.required_source_trust
        and source.trust not in registration.required_source_trust
        for source in sources
    ):
        return _p00(
            PolicyReasonCode.SOURCE_PROVENANCE_UNKNOWN,
            request_digest=request_digest,
            evidence_ids=(request.request_id, *(source.source_id for source in sources)),
        )

    evidence_ids = (request.request_id, *(source.source_id for source in sources))

    # Ordered hard denial rules: P00 preconditions, P01, P02, P03, P17, then P12.
    if request.execution_boundary is ExecutionBoundary.BYPASS_GATEWAY:
        return _deny(
            PolicyRuleId.P01,
            PolicyReasonCode.GATEWAY_BYPASS,
            request_digest=request_digest,
            evidence_ids=evidence_ids,
        )
    if (
        request.execution_mode.value == "REPLAY"
        and request.requested_effect_class is not EffectClass.READ_ONLY
    ):
        return _deny(
            PolicyRuleId.P01,
            PolicyReasonCode.REPLAY_LIVE_EFFECT,
            request_digest=request_digest,
            evidence_ids=evidence_ids,
        )

    if request.capability in {
        Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB,
        Capability.C5_SEND_EXTERNAL_EMAIL,
    } and (
        request.capability not in context.enabled_capabilities
        or registration.state is RegistrationState.OFF
        or context.isolated_worker_available is not True
    ):
        return _deny(
            PolicyRuleId.P02,
            PolicyReasonCode.EXTERNAL_CAPABILITY_OFF,
            request_digest=request_digest,
            evidence_ids=evidence_ids,
        )

    if request.execution_boundary is ExecutionBoundary.MODEL_GATEWAY:
        source_sensitivity = _effective_sensitivity(sources)
        if request.declared_sensitivity is None or source_sensitivity is None:
            return _deny(
                PolicyRuleId.P03,
                PolicyReasonCode.UNKNOWN_MODEL_SENSITIVITY,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        effective_sensitivity = max(
            (source_sensitivity, request.declared_sensitivity),
            key=_SENSITIVITY_ORDER.__getitem__,
        )
        declared_rank = _SENSITIVITY_ORDER[request.declared_sensitivity]
        effective_rank = _SENSITIVITY_ORDER[effective_sensitivity]
        if effective_sensitivity is SensitivityLabel.SECRET:
            return _deny(
                PolicyRuleId.P03,
                PolicyReasonCode.SECRET_MODEL_ROUTE,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if declared_rank < effective_rank:
            return _deny(
                PolicyRuleId.P03,
                PolicyReasonCode.SENSITIVITY_DOWNGRADE,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if (
            effective_sensitivity is SensitivityLabel.PRIVATE
            and context.model_route is not ModelRouteState.VERIFIED_LOOPBACK
        ):
            return _deny(
                PolicyRuleId.P03,
                PolicyReasonCode.PRIVATE_MODEL_ROUTE_UNVERIFIED,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if effective_sensitivity is SensitivityLabel.INTERNAL:
            return _deny(
                PolicyRuleId.P03,
                PolicyReasonCode.PRIVATE_MODEL_ROUTE_UNVERIFIED,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if request.declared_sensitivity is SensitivityLabel.SECRET:
            return _deny(
                PolicyRuleId.P03,
                PolicyReasonCode.SECRET_MODEL_ROUTE,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if (
            effective_sensitivity is SensitivityLabel.PRIVATE
            and context.model_route is ModelRouteState.CLOUD
        ):
            return _deny(
                PolicyRuleId.P03,
                PolicyReasonCode.PRIVATE_MODEL_ROUTE_UNVERIFIED,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )

    if request.capability is Capability.C6_ACCESS_SECRET:
        return _deny(
            PolicyRuleId.P17,
            PolicyReasonCode.SECRET_ACCESS_DENIED,
            request_digest=request_digest,
            evidence_ids=evidence_ids,
        )

    if registration.required_authorization_class is not AuthorizationClass.NONE:
        return _p00(
            PolicyReasonCode.PRINCIPAL_UNTRUSTED,
            request_digest=request_digest,
            evidence_ids=evidence_ids,
        )

    return _deny(
        PolicyRuleId.P12,
        PolicyReasonCode.UNSUPPORTED_POLICY,
        request_digest=request_digest,
        evidence_ids=evidence_ids,
    )


def evaluate_policy(
    *,
    request: object,
    registry: object = BUILTIN_REGISTRY,
    context: object,
) -> PolicyDecision:
    """Evaluate one policy DTO without external effects and fail closed on errors.

    The registry and context are revalidated at entry. No callback, storage,
    credential, gateway, environment, filesystem, network, or clock access occurs.
    CR2-A returns DENY for every outcome, including structurally valid requests.
    """
    try:
        validated_request = _validate_request(request)
    except Exception:
        return _p00(PolicyReasonCode.REQUEST_INVALID)
    try:
        request_digest = request_sha256(validated_request)
    except Exception:
        return _p00(PolicyReasonCode.REQUEST_INVALID)
    try:
        validated_context = _validate_context(context)
    except Exception:
        return _p00(
            PolicyReasonCode.IMPLEMENTATION_STATE_INVALID,
            request_digest=request_digest,
        )
    try:
        validated_registry = _validate_registry(registry)
    except Exception:
        return _p00(
            PolicyReasonCode.REGISTRY_UNTRUSTED,
            request_digest=request_digest,
        )
    try:
        return _evaluate_validated(
            validated_request,
            validated_registry,
            validated_context,
            request_digest,
        )
    except Exception:
        return _p00(
            PolicyReasonCode.INTERNAL_FAILURE,
            request_digest=request_digest,
        )


def build_policy_status_report() -> PolicyStatusReport:
    """Build a deterministic read-only report from static policy metadata."""
    registry_digest = registry_sha256(BUILTIN_REGISTRY)
    policy_digest = policy_sha256()
    statuses = tuple(
        CapabilityStatus(
            capability_id=entry.capability_id,
            effect_class=entry.effect_class,
            registration_state=entry.state,
            execution_available=False,
        )
        for entry in BUILTIN_REGISTRY.entries
    )
    return PolicyStatusReport(
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        policy_sha256=policy_digest,
        registry_id=REGISTRY_ID,
        registry_version=REGISTRY_VERSION,
        registry_sha256=registry_digest,
        capabilities=statuses,
        active_denial_rules=tuple(rule.rule_id for rule in POLICY_RULES),
        unimplemented_rules=UNIMPLEMENTED_RULE_IDS,
    )


__all__ = [
    "build_policy_context",
    "build_policy_status_report",
    "evaluate_policy",
]
