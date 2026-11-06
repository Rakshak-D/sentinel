"""Pure policy evaluation for bounded synthetic GitHub read and preview routes."""

from __future__ import annotations

from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel

from sentinel.config.defaults import load_bundled_defaults
from sentinel.config.fingerprint import config_sha256 as fingerprint_config
from sentinel.config.schema import CONFIG_SCHEMA_VERSION
from sentinel.contracts import SensitivityLabel, SourceEnvelope, TrustLabel
from sentinel.gateways.types import ExecutionMode
from sentinel.policy.canonical import (
    policy_sha256,
    registry_sha256,
    request_sha256,
)
from sentinel.policy.identities import proposal_preview_identity
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
from sentinel.policy.source_binding import (
    PublicSourceBinding,
    VerifiedGithubPublicRead,
    VerifiedPublicSourceSet,
    source_binding_sha256,
    validate_verified_github_public_read,
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
    PolicyRuleStatus,
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


def build_verified_public_read_policy_input(
    verified_read: VerifiedGithubPublicRead,
) -> tuple[PolicyRequest, PolicyContext]:
    """Build the one canonical request/context accepted by the P04 fixture route."""
    if not validate_verified_github_public_read(verified_read):
        raise ValueError("verified public source evidence is unavailable")
    binding = verified_read.binding
    context = build_policy_context(
        sources=verified_read.source_envelopes,
        source_binding_sha256=binding.source_set_sha256,
    )
    request = PolicyRequest(
        request_id=uuid5(
            NAMESPACE_URL,
            "sentinel.policy.public-github-read.v1:" + binding.source_set_sha256,
        ),
        operation_id="sentinel.synthetic.read.public",
        capability=Capability.C0_READ_PUBLIC,
        execution_mode=ExecutionMode.LIVE,
        execution_boundary=ExecutionBoundary.CORE,
        arguments=(("resource_id", "github.fixture"),),
        source_ids=tuple(source.source_id for source in binding.sources),
        evidence_span_ids=tuple(
            citation.span_id for source in binding.sources for citation in source.citations
        ),
        source_binding_sha256=binding.source_set_sha256,
        declared_sensitivity=SensitivityLabel.PUBLIC,
        registry_id=REGISTRY_ID,
        registry_version=REGISTRY_VERSION,
        registry_sha256=_BUILTIN_REGISTRY_SHA256,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        policy_sha256=_BUILTIN_POLICY_SHA256,
        config_version=context.config_version,
        config_sha256=context.config_sha256,
        requested_effect_class=EffectClass.READ_ONLY,
    )
    return request, context


def build_verified_proposal_preview_policy_input(
    verified_read: VerifiedGithubPublicRead,
    *,
    issue_number: int,
) -> tuple[PolicyRequest, PolicyContext]:
    """Build a fixed C2 request bound to one selected item in the verified fixture."""
    if (
        type(issue_number) is not int
        or issue_number not in {101, 102, 103}
        or not validate_verified_github_public_read(verified_read)
    ):
        raise ValueError("verified synthetic source is unavailable")
    binding = verified_read.binding
    provider_item_id = f"example-owner/fixture-project#{issue_number}"
    selected = tuple(
        source for source in binding.sources if source.provider_item_id == provider_item_id
    )
    if len(selected) != 1:
        raise ValueError("verified synthetic source is unavailable")
    context = build_policy_context(
        sources=verified_read.source_envelopes,
        source_binding_sha256=binding.source_set_sha256,
    )
    request = PolicyRequest(
        request_id=uuid5(
            NAMESPACE_URL,
            "sentinel.policy.github-proposal-preview.v1:"
            + binding.source_set_sha256
            + ":"
            + str(selected[0].item_id),
        ),
        operation_id="sentinel.synthetic.proposal.local",
        capability=Capability.C2_WRITE_LOCAL_PROPOSAL,
        execution_mode=ExecutionMode.LIVE,
        execution_boundary=ExecutionBoundary.CORE,
        arguments=(("label", "REVIEW_SOURCE:" + provider_item_id),),
        source_ids=tuple(source.source_id for source in binding.sources),
        evidence_span_ids=tuple(
            citation.span_id for source in binding.sources for citation in source.citations
        ),
        source_binding_sha256=binding.source_set_sha256,
        declared_sensitivity=SensitivityLabel.PUBLIC,
        registry_id=REGISTRY_ID,
        registry_version=REGISTRY_VERSION,
        registry_sha256=_BUILTIN_REGISTRY_SHA256,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        policy_sha256=_BUILTIN_POLICY_SHA256,
        config_version=context.config_version,
        config_sha256=context.config_sha256,
        requested_effect_class=EffectClass.LOCAL_PROPOSAL,
    )
    return request, context


def build_proposal_persistence_policy_request(
    *,
    binding: VerifiedPublicSourceSet,
    issue_number: int,
    preview_id: str,
) -> PolicyRequest:
    """Build the distinct C2 persistence request from body-free verified metadata.

    A request produced here is still only claims. ``evaluate_policy`` requires
    the resolver-created read object as its separate evidence binding.
    """
    if (
        type(binding) is not VerifiedPublicSourceSet
        or type(issue_number) is not int
        or issue_number not in {101, 102, 103}
        or type(preview_id) is not str
    ):
        raise ValueError("verified synthetic source is unavailable")
    provider_item_id = f"example-owner/fixture-project#{issue_number}"
    selected = tuple(item for item in binding.sources if item.provider_item_id == provider_item_id)
    if len(selected) != 1:
        raise ValueError("verified synthetic source is unavailable")
    source = selected[0]
    if preview_id != proposal_preview_identity(source.item_id, binding.source_set_sha256):
        raise ValueError("verified synthetic source is unavailable")
    context = build_policy_context(source_binding_sha256=binding.source_set_sha256)
    return PolicyRequest(
        request_id=uuid5(
            NAMESPACE_URL,
            "sentinel.policy.github-proposal-persist.v1:"
            + binding.source_set_sha256
            + ":"
            + str(source.item_id),
        ),
        operation_id="sentinel.synthetic.proposal.persist",
        capability=Capability.C2_WRITE_LOCAL_PROPOSAL,
        execution_mode=ExecutionMode.LIVE,
        execution_boundary=ExecutionBoundary.CORE,
        arguments=(
            ("issue_number", issue_number),
            ("preview_id", preview_id),
            ("source_content_sha256", source.content_sha256),
            ("source_item_id", str(source.item_id)),
        ),
        source_ids=tuple(source.source_id for source in binding.sources),
        evidence_span_ids=tuple(
            citation.span_id for source in binding.sources for citation in source.citations
        ),
        source_binding_sha256=binding.source_set_sha256,
        declared_sensitivity=SensitivityLabel.PUBLIC,
        registry_id=REGISTRY_ID,
        registry_version=REGISTRY_VERSION,
        registry_sha256=_BUILTIN_REGISTRY_SHA256,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        policy_sha256=_BUILTIN_POLICY_SHA256,
        config_version=context.config_version,
        config_sha256=context.config_sha256,
        requested_effect_class=EffectClass.LOCAL_PROPOSAL,
    )


def build_policy_context(
    *,
    sources: tuple[SourceEnvelope, ...] = (),
    model_route: ModelRouteState = ModelRouteState.UNVERIFIED,
    source_binding_sha256: str | None = None,
) -> PolicyContext:
    """Build context structure without authenticating sources or granting authority.

    A caller-declared binding digest is only a claim. P04 requires the separate
    resolver-created source object passed to :func:`evaluate_policy`.
    """
    return PolicyContext(
        principal_id=POLICY_RUNTIME_PRINCIPAL,
        principal_trust=POLICY_RUNTIME_TRUST,
        registry_sha256=_BUILTIN_REGISTRY_SHA256,
        policy_sha256=_BUILTIN_POLICY_SHA256,
        config_version=CONFIG_SCHEMA_VERSION,
        config_sha256=_BUNDLED_CONFIG_SHA256,
        source_binding_sha256=source_binding_sha256,
        sources=sources,
        model_route=model_route,
        enabled_capabilities=(),
        isolated_worker_available=False,
        implementation_state="bounded_public_read_foundation",
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
    evidence_binding: object | None,
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
    if registration.capability_id is not request.capability:
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

    # P09 is deliberately narrow: only fixed C0/P04 and C2/P06 GitHub routes
    # can use the resolver-created, pinned source binding.
    public_read_operation = (
        request.operation_id == "sentinel.synthetic.read.public"
        and request.capability is Capability.C0_READ_PUBLIC
    )
    proposal_preview_operation = (
        request.operation_id == "sentinel.synthetic.proposal.local"
        and request.capability is Capability.C2_WRITE_LOCAL_PROPOSAL
    )
    proposal_persistence_operation = (
        request.operation_id == "sentinel.synthetic.proposal.persist"
        and request.capability is Capability.C2_WRITE_LOCAL_PROPOSAL
    )
    if public_read_operation or proposal_preview_operation or proposal_persistence_operation:
        if request.requested_effect_class is not registration.effect_class:
            return _deny(
                PolicyRuleId.P09,
                PolicyReasonCode.EFFECT_CLASS_MISMATCH,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if type(evidence_binding) is not VerifiedGithubPublicRead:
            return _deny(
                PolicyRuleId.P09,
                PolicyReasonCode.EVIDENCE_BINDING_MISSING,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if not validate_verified_github_public_read(evidence_binding):
            return _deny(
                PolicyRuleId.P09,
                PolicyReasonCode.EVIDENCE_BINDING_INVALID,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        binding = evidence_binding.binding
        expected_sources = tuple(item.source_id for item in binding.sources)
        expected_spans = tuple(
            citation.span_id for item in binding.sources for citation in item.citations
        )
        if (
            request.source_binding_sha256 != binding.source_set_sha256
            or context.source_binding_sha256 != binding.source_set_sha256
            or binding.source_set_sha256 != source_binding_sha256(binding)
        ):
            return _deny(
                PolicyRuleId.P09,
                PolicyReasonCode.FIXTURE_PIN_MISMATCH,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if request.source_ids != expected_sources or tuple(
            source.source_id for source in context.sources
        ) != expected_sources:
            return _deny(
                PolicyRuleId.P09,
                PolicyReasonCode.SOURCE_SET_MISMATCH,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if request.evidence_span_ids != expected_spans:
            return _deny(
                PolicyRuleId.P09,
                PolicyReasonCode.CITATION_SET_MISMATCH,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if (
            tuple(context.sources) != evidence_binding.source_envelopes
            or any(
                source.trust is not TrustLabel.T4_EXTERNAL
                or source.sensitivity is not SensitivityLabel.PUBLIC
                for source in context.sources
            )
        ):
            return _deny(
                PolicyRuleId.P09,
                PolicyReasonCode.SOURCE_SET_MISMATCH,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if (
            binding.fixture_sha256 != evidence_binding.binding.fixture_sha256
            or binding.manifest_sha256 != evidence_binding.binding.manifest_sha256
        ):
            return _deny(
                PolicyRuleId.P09,
                PolicyReasonCode.FIXTURE_PIN_MISMATCH,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        common_route_invalid = (
            request.declared_sensitivity is not SensitivityLabel.PUBLIC
            or request.execution_mode.value != "LIVE"
            or request.execution_boundary is not ExecutionBoundary.CORE
            or context.implementation_state != "bounded_public_read_foundation"
            or context.model_route is not ModelRouteState.UNVERIFIED
            or context.enabled_capabilities
        )
        public_read_invalid = public_read_operation and (
            request.requested_effect_class is not EffectClass.READ_ONLY
            or request.arguments != (("resource_id", "github.fixture"),)
        )
        preview_route_invalid = proposal_preview_operation and (
            request.requested_effect_class is not EffectClass.LOCAL_PROPOSAL
            or registration.state is not RegistrationState.POLICY_ONLY
            or registration.required_authorization_class is not AuthorizationClass.NONE
        )
        persistence_route_invalid = proposal_persistence_operation and (
            request.requested_effect_class is not EffectClass.LOCAL_PROPOSAL
            or registration.state is not RegistrationState.POLICY_ONLY
            or registration.required_authorization_class is not AuthorizationClass.NONE
        )
        if (
            common_route_invalid
            or public_read_invalid
            or preview_route_invalid
            or persistence_route_invalid
        ):
            return _deny(
                PolicyRuleId.P09,
                (
                    PolicyReasonCode.PROPOSAL_PERSISTENCE_SCOPE_MISMATCH
                    if proposal_persistence_operation
                    else PolicyReasonCode.PROPOSAL_PREVIEW_SCOPE_MISMATCH
                    if proposal_preview_operation
                    else PolicyReasonCode.PUBLIC_READ_SCOPE_MISMATCH
                ),
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if not all(
            source.trust is TrustLabel.T4_EXTERNAL
            and source.sensitivity is SensitivityLabel.PUBLIC
            for source in context.sources
        ):
            return _deny(
                PolicyRuleId.P09,
                PolicyReasonCode.SOURCE_SET_MISMATCH,
                request_digest=request_digest,
                evidence_ids=evidence_ids,
            )
        if public_read_operation:
            return PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                rule_id=PolicyRuleId.P04,
                reason_code=PolicyReasonCode.PUBLIC_READ_ALLOWED,
                policy_sha256=_BUILTIN_POLICY_SHA256,
                registry_sha256=_BUILTIN_REGISTRY_SHA256,
                request_sha256=request_digest,
                evidence_binding_sha256=binding.source_set_sha256,
                evidence_ids=evidence_ids[:8],
                executable=False,
            )
        if proposal_preview_operation:
            selected_source = _selected_preview_source(request, binding.sources)
            if selected_source is None:
                return _deny(
                    PolicyRuleId.P09,
                    PolicyReasonCode.PROPOSAL_PREVIEW_SCOPE_MISMATCH,
                    request_digest=request_digest,
                    evidence_ids=evidence_ids,
                )
            expected_request_id = uuid5(
                NAMESPACE_URL,
                "sentinel.policy.github-proposal-preview.v1:"
                + binding.source_set_sha256
                + ":"
                + str(selected_source.item_id),
            )
            if request.request_id != expected_request_id:
                return _deny(
                    PolicyRuleId.P09,
                    PolicyReasonCode.PROPOSAL_PREVIEW_SCOPE_MISMATCH,
                    request_digest=request_digest,
                    evidence_ids=evidence_ids,
                )
            return PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                rule_id=PolicyRuleId.P06,
                reason_code=PolicyReasonCode.PROPOSAL_PREVIEW_ALLOWED,
                policy_sha256=_BUILTIN_POLICY_SHA256,
                registry_sha256=_BUILTIN_REGISTRY_SHA256,
                request_sha256=request_digest,
                evidence_binding_sha256=binding.source_set_sha256,
                evidence_ids=(
                    request.request_id,
                    selected_source.source_id,
                    *(citation.span_id for citation in selected_source.citations),
                ),
                executable=False,
            )
        if proposal_persistence_operation:
            selected_source = _selected_persistence_source(request, binding.sources)
            if selected_source is None:
                return _deny(
                    PolicyRuleId.P09,
                    PolicyReasonCode.PROPOSAL_PERSISTENCE_SCOPE_MISMATCH,
                    request_digest=request_digest,
                    evidence_ids=evidence_ids,
                )
            return PolicyDecision(
                outcome=PolicyOutcome.ALLOW,
                rule_id=PolicyRuleId.P06,
                reason_code=PolicyReasonCode.PROPOSAL_PERSISTENCE_ALLOWED,
                policy_sha256=_BUILTIN_POLICY_SHA256,
                registry_sha256=_BUILTIN_REGISTRY_SHA256,
                request_sha256=request_digest,
                evidence_binding_sha256=binding.source_set_sha256,
                evidence_ids=(
                    request.request_id,
                    selected_source.source_id,
                    *(citation.span_id for citation in selected_source.citations),
                ),
                executable=False,
            )
        return _deny(
            PolicyRuleId.P09,
            PolicyReasonCode.SOURCE_SET_MISMATCH,
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


def _selected_preview_source(
    request: PolicyRequest, sources: tuple[PublicSourceBinding, ...]
) -> PublicSourceBinding | None:
    """Resolve only the fixed label grammar against a resolver-verified source set."""
    if len(request.arguments) != 1 or request.arguments[0][0] != "label":
        return None
    label = request.arguments[0][1]
    if type(label) is not str or not label.startswith("REVIEW_SOURCE:"):
        return None
    provider_item_id = label.removeprefix("REVIEW_SOURCE:")
    if provider_item_id not in {
        "example-owner/fixture-project#101",
        "example-owner/fixture-project#102",
        "example-owner/fixture-project#103",
    }:
        return None
    matches = tuple(source for source in sources if source.provider_item_id == provider_item_id)
    if len(matches) != 1:
        return None
    return matches[0]


def _selected_persistence_source(
    request: PolicyRequest,
    sources: tuple[PublicSourceBinding, ...],
) -> PublicSourceBinding | None:
    """Resolve one exact fixed persistence request against the pinned source set."""
    expected_names = (
        "issue_number",
        "preview_id",
        "source_content_sha256",
        "source_item_id",
    )
    if tuple(name for name, _value in request.arguments) != expected_names:
        return None
    arguments = dict(request.arguments)
    issue_number = arguments.get("issue_number")
    if type(issue_number) is not int or issue_number not in {101, 102, 103}:
        return None
    provider_item_id = f"example-owner/fixture-project#{issue_number}"
    matches = tuple(source for source in sources if source.provider_item_id == provider_item_id)
    if len(matches) != 1:
        return None
    selected = matches[0]
    if (
        arguments.get("source_item_id") != str(selected.item_id)
        or arguments.get("source_content_sha256") != selected.content_sha256
        or arguments.get("preview_id")
        != proposal_preview_identity(selected.item_id, request.source_binding_sha256 or "")
    ):
        return None
    expected_request_id = uuid5(
        NAMESPACE_URL,
        "sentinel.policy.github-proposal-persist.v1:"
        + str(request.source_binding_sha256)
        + ":"
        + str(selected.item_id),
    )
    if request.request_id != expected_request_id:
        return None
    return selected


def evaluate_policy(
    *,
    request: object,
    registry: object = BUILTIN_REGISTRY,
    context: object,
    evidence_binding: object | None = None,
) -> PolicyDecision:
    """Evaluate one policy DTO without external effects and fail closed on errors.

    The registry and context are revalidated at entry. No callback, storage,
    credential, gateway, environment, filesystem, network, or clock access occurs.
    P04 can ALLOW the resolver-bound synthetic PUBLIC GitHub read; P06 can
    ALLOW only the fixed preview or pending-review persistence route for one
    pinned issue. Decisions are never executable authorization receipts.
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
            evidence_binding,
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
    status_entries = tuple(
        next(entry for entry in BUILTIN_REGISTRY.entries if entry.capability_id is capability)
        for capability in Capability
    )
    statuses = tuple(
        CapabilityStatus(
            capability_id=entry.capability_id,
            effect_class=entry.effect_class,
            registration_state=entry.state,
            execution_available=False,
        )
        for entry in status_entries
    )
    return PolicyStatusReport(
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        policy_sha256=policy_digest,
        registry_id=REGISTRY_ID,
        registry_version=REGISTRY_VERSION,
        registry_sha256=registry_digest,
        capabilities=statuses,
        active_rules=tuple(
            PolicyRuleStatus(
                rule_id=rule.rule_id,
                outcome=rule.outcome,
                priority=rule.priority,
            )
            for rule in POLICY_RULES
        ),
        unimplemented_rules=UNIMPLEMENTED_RULE_IDS,
        bounded_proposal_persistence_operation="sentinel.synthetic.proposal.persist",
        bounded_proposal_persistence_state="PENDING_REVIEW_ONLY",
    )


__all__ = [
    "build_policy_context",
    "build_proposal_persistence_policy_request",
    "build_policy_status_report",
    "evaluate_policy",
]
