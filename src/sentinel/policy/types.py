"""Strict, immutable data contracts for the bounded CR2 policy foundation."""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)

from sentinel.contracts import SensitivityLabel, SourceEnvelope, TrustLabel
from sentinel.gateways.types import ExecutionMode

POLICY_REQUEST_SCHEMA: Literal["sentinel.policy-request.v2"] = "sentinel.policy-request.v2"
POLICY_CONTEXT_SCHEMA: Literal["sentinel.policy-context.v2"] = "sentinel.policy-context.v2"
POLICY_STATUS_SCHEMA: Literal["sentinel.policy-status.v4"] = "sentinel.policy-status.v4"
POLICY_DECISION_SCHEMA: Literal["sentinel.policy-decision.v4"] = "sentinel.policy-decision.v4"
CAPABILITY_REGISTRATION_SCHEMA: Literal["sentinel.capability-registration.v1"] = (
    "sentinel.capability-registration.v1"
)
POLICY_RULE_SCHEMA: Literal["sentinel.policy-rule.v3"] = "sentinel.policy-rule.v3"
CAPABILITY_REGISTRY_SCHEMA: Literal["sentinel.capability-registry.v2"] = (
    "sentinel.capability-registry.v2"
)
MAX_POLICY_ARGUMENTS = 32
MAX_POLICY_ARGUMENT_BYTES = 16_384
MAX_POLICY_SOURCE_IDS = 32
MAX_DECISION_EVIDENCE_IDS = 8
MAX_CONTEXT_SOURCE_SPANS = 32
MAX_CONTEXT_SOURCE_PARENTS = 32

_IDENTIFIER_PATTERN = r"^[a-z][a-z0-9_.:-]{0,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_VERSION_PATTERN = r"^v[1-9][0-9]{0,5}$"
_RULE_REFERENCE_PATTERN = r"^P(?:0[0-9]|1[0-7])$"

PolicyIdentifier = Annotated[
    StrictStr,
    StringConstraints(strict=True, pattern=_IDENTIFIER_PATTERN, max_length=128),
]
PolicyVersion = Annotated[
    StrictStr,
    StringConstraints(strict=True, pattern=_VERSION_PATTERN, max_length=8),
]
RuleReference = Annotated[
    StrictStr,
    StringConstraints(strict=True, pattern=_RULE_REFERENCE_PATTERN, max_length=3),
]
ArgumentName = PolicyIdentifier
Sha256Digest = Annotated[
    StrictStr,
    StringConstraints(strict=True, pattern=_SHA256_PATTERN, max_length=64),
]
ArgumentText = Annotated[StrictStr, Field(max_length=4096)]
ArgumentInteger = Annotated[StrictInt, Field(ge=-(2**63), le=2**63 - 1)]
PolicyArgumentValue = ArgumentText | ArgumentInteger | StrictBool


class Capability(StrEnum):
    """The exact §6 C0-C6 capability vocabulary."""

    C0_READ_PUBLIC = "C0_READ_PUBLIC"
    C1_READ_PRIVATE = "C1_READ_PRIVATE"
    C2_WRITE_LOCAL_PROPOSAL = "C2_WRITE_LOCAL_PROPOSAL"
    C3_WRITE_LOCAL_ACCEPTED = "C3_WRITE_LOCAL_ACCEPTED"
    C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB = "C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB"
    C5_SEND_EXTERNAL_EMAIL = "C5_SEND_EXTERNAL_EMAIL"
    C6_ACCESS_SECRET = "C6_ACCESS_SECRET"


class EffectClass(StrEnum):
    """Closed classifications for registered operation metadata."""

    READ_ONLY = "READ_ONLY"
    LOCAL_PROPOSAL = "LOCAL_PROPOSAL"
    LOCAL_ACCEPTED = "LOCAL_ACCEPTED"
    EXTERNAL_DRAFT_OR_GITHUB = "EXTERNAL_DRAFT_OR_GITHUB"
    EXTERNAL_SEND = "EXTERNAL_SEND"
    SECRET_ACCESS = "SECRET_ACCESS"


class AuthorizationClass(StrEnum):
    """Authority a future enforcing slice would need; none is verified here."""

    NONE = "NONE"
    VERIFIED_OWNER = "VERIFIED_OWNER"
    ONE_USE_OWNER_PROOF = "ONE_USE_OWNER_PROOF"
    INTERNAL_SECRET_BROKER = "INTERNAL_SECRET_BROKER"


class RegistrationState(StrEnum):
    """Registrations are policy metadata, never executable handlers."""

    POLICY_ONLY = "POLICY_ONLY"
    OFF = "OFF"


class PolicyOutcome(StrEnum):
    """Closed decision vocabulary; only bounded P04/P06 routes may ALLOW in CR2-C."""

    ALLOW = "ALLOW"
    PENDING_HUMAN = "PENDING_HUMAN"
    DENY = "DENY"


class PolicyRuleId(StrEnum):
    """Rules represented by the bounded CR2-A/B/C policy slices."""

    P00 = "P00"
    P01 = "P01"
    P02 = "P02"
    P03 = "P03"
    P17 = "P17"
    P09 = "P09"
    P04 = "P04"
    P06 = "P06"
    P12 = "P12"


class PolicyReasonCode(StrEnum):
    """Bounded non-sensitive reason codes for policy decisions."""

    REQUEST_INVALID = "REQUEST_INVALID"
    OPERATION_UNREGISTERED = "OPERATION_UNREGISTERED"
    CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
    ARGUMENTS_INVALID = "ARGUMENTS_INVALID"
    PRINCIPAL_UNTRUSTED = "PRINCIPAL_UNTRUSTED"
    SOURCE_MISSING = "SOURCE_MISSING"
    SOURCE_PROVENANCE_UNKNOWN = "SOURCE_PROVENANCE_UNKNOWN"
    REGISTRY_UNTRUSTED = "REGISTRY_UNTRUSTED"
    POLICY_UNTRUSTED = "POLICY_UNTRUSTED"
    CONFIG_UNTRUSTED = "CONFIG_UNTRUSTED"
    IMPLEMENTATION_STATE_INVALID = "IMPLEMENTATION_STATE_INVALID"
    REPLAY_LIVE_EFFECT = "REPLAY_LIVE_EFFECT"
    GATEWAY_BYPASS = "GATEWAY_BYPASS"
    EXTERNAL_CAPABILITY_OFF = "EXTERNAL_CAPABILITY_OFF"
    SECRET_MODEL_ROUTE = "SECRET_MODEL_ROUTE"
    PRIVATE_MODEL_ROUTE_UNVERIFIED = "PRIVATE_MODEL_ROUTE_UNVERIFIED"
    UNKNOWN_MODEL_SENSITIVITY = "UNKNOWN_MODEL_SENSITIVITY"
    SENSITIVITY_DOWNGRADE = "SENSITIVITY_DOWNGRADE"
    SECRET_ACCESS_DENIED = "SECRET_ACCESS_DENIED"
    EVIDENCE_BINDING_MISSING = "EVIDENCE_BINDING_MISSING"
    EVIDENCE_BINDING_INVALID = "EVIDENCE_BINDING_INVALID"
    SOURCE_SET_MISMATCH = "SOURCE_SET_MISMATCH"
    CITATION_SET_MISMATCH = "CITATION_SET_MISMATCH"
    FIXTURE_PIN_MISMATCH = "FIXTURE_PIN_MISMATCH"
    EFFECT_CLASS_MISMATCH = "EFFECT_CLASS_MISMATCH"
    PUBLIC_READ_SCOPE_MISMATCH = "PUBLIC_READ_SCOPE_MISMATCH"
    PUBLIC_READ_ALLOWED = "PUBLIC_READ_ALLOWED"
    PROPOSAL_PREVIEW_SCOPE_MISMATCH = "PROPOSAL_PREVIEW_SCOPE_MISMATCH"
    PROPOSAL_PREVIEW_ALLOWED = "PROPOSAL_PREVIEW_ALLOWED"
    PROPOSAL_PERSISTENCE_SCOPE_MISMATCH = "PROPOSAL_PERSISTENCE_SCOPE_MISMATCH"
    PROPOSAL_PERSISTENCE_ALLOWED = "PROPOSAL_PERSISTENCE_ALLOWED"
    UNSUPPORTED_POLICY = "UNSUPPORTED_POLICY"
    INTERNAL_FAILURE = "INTERNAL_FAILURE"


class ExecutionBoundary(StrEnum):
    """Declared route class; the evaluator never dispatches through any route."""

    CORE = "CORE"
    MODEL_GATEWAY = "MODEL_GATEWAY"
    TOOL_GATEWAY = "TOOL_GATEWAY"
    BYPASS_GATEWAY = "BYPASS_GATEWAY"


class ModelRouteState(StrEnum):
    """Trusted-context route classification, not a route implementation."""

    UNVERIFIED = "UNVERIFIED"
    VERIFIED_LOOPBACK = "VERIFIED_LOOPBACK"
    CLOUD = "CLOUD"


class ArgumentKind(StrEnum):
    """Non-executable scalar schema kinds for static registration entries."""

    TEXT = "TEXT"
    INTEGER = "INTEGER"
    BOOLEAN = "BOOLEAN"


class _FrozenPolicyModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
        hide_input_in_errors=True,
    )


class ArgumentSpec(_FrozenPolicyModel):
    """One name/type pair; it contains no parser callback or executable schema."""

    name: ArgumentName
    value_kind: ArgumentKind
    required: StrictBool = True


class CapabilityRegistration(_FrozenPolicyModel):
    """Trusted application-defined, passive capability-operation metadata."""

    schema_version: Literal["sentinel.capability-registration.v1"] = CAPABILITY_REGISTRATION_SCHEMA
    registration_id: PolicyIdentifier
    registry_id: PolicyIdentifier
    capability_id: Capability
    operation_id: PolicyIdentifier
    argument_schema: Annotated[tuple[ArgumentSpec, ...], Field(max_length=MAX_POLICY_ARGUMENTS)]
    effect_class: EffectClass
    required_source_trust: Annotated[tuple[TrustLabel, ...], Field(max_length=6)]
    required_authorization_class: AuthorizationClass
    state: RegistrationState
    executable: Literal[False] = False

    @field_validator("argument_schema")
    @classmethod
    def require_canonical_argument_schema(
        cls, value: tuple[ArgumentSpec, ...]
    ) -> tuple[ArgumentSpec, ...]:
        names = tuple(item.name for item in value)
        if names != tuple(sorted(set(names))):
            raise ValueError("registered argument names must be unique and canonically ordered")
        return value

    @field_validator("required_source_trust")
    @classmethod
    def require_unique_source_trust(cls, value: tuple[TrustLabel, ...]) -> tuple[TrustLabel, ...]:
        if len(value) != len(set(value)):
            raise ValueError("required source trust labels must be unique")
        if value != tuple(sorted(value, key=lambda item: item.value)):
            raise ValueError("required source trust labels must be canonically ordered")
        return value

    @model_validator(mode="after")
    def require_capability_effect_pair(self) -> CapabilityRegistration:
        expected_effect = {
            Capability.C0_READ_PUBLIC: EffectClass.READ_ONLY,
            Capability.C1_READ_PRIVATE: EffectClass.READ_ONLY,
            Capability.C2_WRITE_LOCAL_PROPOSAL: EffectClass.LOCAL_PROPOSAL,
            Capability.C3_WRITE_LOCAL_ACCEPTED: EffectClass.LOCAL_ACCEPTED,
            Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB: EffectClass.EXTERNAL_DRAFT_OR_GITHUB,
            Capability.C5_SEND_EXTERNAL_EMAIL: EffectClass.EXTERNAL_SEND,
            Capability.C6_ACCESS_SECRET: EffectClass.SECRET_ACCESS,
        }[self.capability_id]
        if self.effect_class is not expected_effect:
            raise ValueError("registration effect class must match its capability")
        if self.executable is not False:
            raise ValueError("policy registrations are non-executable data")
        return self


class PolicyRequest(_FrozenPolicyModel):
    """Canonical, bounded request claims; it contains no authority proof."""

    schema_version: Literal["sentinel.policy-request.v2"] = POLICY_REQUEST_SCHEMA
    request_id: UUID
    operation_id: PolicyIdentifier
    capability: Capability
    execution_mode: ExecutionMode
    execution_boundary: ExecutionBoundary
    arguments: Annotated[
        tuple[tuple[ArgumentName, PolicyArgumentValue], ...],
        Field(max_length=MAX_POLICY_ARGUMENTS, repr=False),
    ]
    source_ids: Annotated[tuple[UUID, ...], Field(max_length=MAX_POLICY_SOURCE_IDS)]
    evidence_span_ids: Annotated[tuple[UUID, ...], Field(max_length=MAX_CONTEXT_SOURCE_SPANS)] = ()
    source_binding_sha256: Sha256Digest | None = None
    declared_sensitivity: SensitivityLabel | None
    registry_id: PolicyIdentifier
    registry_version: PolicyVersion
    registry_sha256: Sha256Digest
    policy_id: PolicyIdentifier
    policy_version: PolicyVersion
    policy_sha256: Sha256Digest
    config_version: PolicyIdentifier
    config_sha256: Sha256Digest
    requested_effect_class: EffectClass

    @field_validator("source_ids")
    @classmethod
    def require_unique_source_ids(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(value) != len(set(value)):
            raise ValueError("source identity references must be unique")
        return value

    @field_validator("evidence_span_ids")
    @classmethod
    def require_unique_evidence_span_ids(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(value) != len(set(value)):
            raise ValueError("evidence span references must be unique")
        return value

    @model_validator(mode="after")
    def require_canonical_bounded_arguments(self) -> PolicyRequest:
        names = tuple(name for name, _value in self.arguments)
        if names != tuple(sorted(set(names))):
            raise ValueError("argument names must be unique and canonically ordered")
        argument_bytes = json.dumps(
            self.arguments,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(argument_bytes) > MAX_POLICY_ARGUMENT_BYTES:
            raise ValueError("canonical arguments exceed the policy request limit")
        return self


class PolicyContext(_FrozenPolicyModel):
    """Separate evaluator context; this type is not an owner-authentication proof."""

    schema_version: Literal["sentinel.policy-context.v2"] = POLICY_CONTEXT_SCHEMA
    principal_id: PolicyIdentifier
    principal_trust: TrustLabel
    registry_sha256: Sha256Digest
    policy_sha256: Sha256Digest
    config_version: PolicyIdentifier
    config_sha256: Sha256Digest
    source_binding_sha256: Sha256Digest | None = None
    sources: Annotated[tuple[SourceEnvelope, ...], Field(max_length=MAX_POLICY_SOURCE_IDS)] = ()
    model_route: ModelRouteState = ModelRouteState.UNVERIFIED
    enabled_capabilities: Annotated[tuple[Capability, ...], Field(max_length=7)] = ()
    isolated_worker_available: Literal[False] = False
    implementation_state: Literal["bounded_public_read_foundation"] = (
        "bounded_public_read_foundation"
    )

    @field_validator("sources")
    @classmethod
    def require_unique_source_ids(
        cls, value: tuple[SourceEnvelope, ...]
    ) -> tuple[SourceEnvelope, ...]:
        source_ids = tuple(source.source_id for source in value)
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("trusted context source identities must be unique")
        if any(
            len(source.byte_spans) > MAX_CONTEXT_SOURCE_SPANS
            or len(source.parent_ids) > MAX_CONTEXT_SOURCE_PARENTS
            for source in value
        ):
            raise ValueError("trusted context source metadata exceeds its bounded limit")
        return value

    @field_validator("enabled_capabilities")
    @classmethod
    def keep_privileged_capabilities_disabled(
        cls, value: tuple[Capability, ...]
    ) -> tuple[Capability, ...]:
        if len(value) != len(set(value)):
            raise ValueError("enabled capability values must be unique")
        privileged = {
            Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB,
            Capability.C5_SEND_EXTERNAL_EMAIL,
            Capability.C6_ACCESS_SECRET,
        }
        if any(capability in privileged for capability in value):
            raise ValueError("CR2-A cannot enable external-write or secret capabilities")
        return value


class PolicyDecision(_FrozenPolicyModel):
    """Deterministic decision metadata; never an executable authorization receipt."""

    schema_version: Literal["sentinel.policy-decision.v4"] = POLICY_DECISION_SCHEMA
    outcome: PolicyOutcome
    rule_id: PolicyRuleId
    reason_code: PolicyReasonCode
    policy_sha256: Sha256Digest
    registry_sha256: Sha256Digest
    request_sha256: Sha256Digest
    evidence_binding_sha256: Sha256Digest | None = None
    evidence_ids: Annotated[tuple[UUID, ...], Field(max_length=MAX_DECISION_EVIDENCE_IDS)] = ()
    executable: Literal[False] = False

    @model_validator(mode="after")
    def bounded_decision_contract(self) -> PolicyDecision:
        if self.outcome is PolicyOutcome.PENDING_HUMAN:
            raise ValueError("CR2-C does not represent PENDING_HUMAN decisions")
        if self.outcome is PolicyOutcome.ALLOW and (
            self.rule_id not in {PolicyRuleId.P04, PolicyRuleId.P06}
            or self.evidence_binding_sha256 is None
        ):
            raise ValueError("CR2-C ALLOW is limited to evidence-bound P04/P06 decisions")
        if self.outcome is PolicyOutcome.ALLOW and not self.evidence_ids:
            raise ValueError("CR2-C ALLOW decisions must retain evidence references")
        if (
            self.rule_id is PolicyRuleId.P04
            and self.reason_code is not PolicyReasonCode.PUBLIC_READ_ALLOWED
        ):
            raise ValueError("P04 decisions must use the registered public-read reason")
        if self.rule_id is PolicyRuleId.P06 and self.reason_code not in {
            PolicyReasonCode.PROPOSAL_PREVIEW_ALLOWED,
            PolicyReasonCode.PROPOSAL_PERSISTENCE_ALLOWED,
        }:
            raise ValueError("P06 decisions must use a registered bounded proposal reason")
        if self.executable is not False:
            raise ValueError("policy decisions are not executable authorization receipts")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("decision evidence references must be unique")
        return self


class CapabilityStatus(_FrozenPolicyModel):
    """Non-sensitive status for one fixed C0-C6 capability."""

    capability_id: Capability
    effect_class: EffectClass
    registration_state: RegistrationState
    execution_available: Literal[False] = False

    @model_validator(mode="after")
    def enforce_fixed_capability_state(self) -> CapabilityStatus:
        expected_effect = {
            Capability.C0_READ_PUBLIC: EffectClass.READ_ONLY,
            Capability.C1_READ_PRIVATE: EffectClass.READ_ONLY,
            Capability.C2_WRITE_LOCAL_PROPOSAL: EffectClass.LOCAL_PROPOSAL,
            Capability.C3_WRITE_LOCAL_ACCEPTED: EffectClass.LOCAL_ACCEPTED,
            Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB: EffectClass.EXTERNAL_DRAFT_OR_GITHUB,
            Capability.C5_SEND_EXTERNAL_EMAIL: EffectClass.EXTERNAL_SEND,
            Capability.C6_ACCESS_SECRET: EffectClass.SECRET_ACCESS,
        }[self.capability_id]
        expected_state = (
            RegistrationState.OFF
            if self.capability_id
            in {
                Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB,
                Capability.C5_SEND_EXTERNAL_EMAIL,
                Capability.C6_ACCESS_SECRET,
            }
            else RegistrationState.POLICY_ONLY
        )
        if (
            self.effect_class is not expected_effect
            or self.registration_state is not expected_state
        ):
            raise ValueError("capability status cannot alter the fixed CR2-A registry state")
        return self


class PolicyRuleStatus(_FrozenPolicyModel):
    """One fixed active rule and its bounded outcome for policy-status display."""

    rule_id: PolicyRuleId
    outcome: PolicyOutcome
    priority: Annotated[StrictInt, Field(ge=0, le=17)]


class PolicyStatusReport(_FrozenPolicyModel):
    """Deterministic status DTO used by the read-only policy CLI."""

    schema_version: Literal["sentinel.policy-status.v4"] = POLICY_STATUS_SCHEMA
    policy_id: PolicyIdentifier
    policy_version: PolicyVersion
    policy_sha256: Sha256Digest
    registry_id: PolicyIdentifier
    registry_version: PolicyVersion
    registry_sha256: Sha256Digest
    capabilities: Annotated[tuple[CapabilityStatus, ...], Field(min_length=7, max_length=7)]
    active_rules: Annotated[tuple[PolicyRuleStatus, ...], Field(min_length=9, max_length=9)]
    unimplemented_rules: Annotated[tuple[RuleReference, ...], Field(max_length=12)]
    bounded_public_read_operation: Literal["sentinel.synthetic.read.public"] = (
        "sentinel.synthetic.read.public"
    )
    bounded_public_read_state: Literal["IMPLEMENTED"] = "IMPLEMENTED"
    bounded_proposal_preview_operation: Literal["sentinel.synthetic.proposal.local"] = (
        "sentinel.synthetic.proposal.local"
    )
    bounded_proposal_preview_state: Literal["IN_MEMORY_PREVIEW_ONLY"] = "IN_MEMORY_PREVIEW_ONLY"
    bounded_proposal_persistence_operation: Literal[
        "sentinel.synthetic.proposal.persist"
    ] = "sentinel.synthetic.proposal.persist"
    bounded_proposal_persistence_state: Literal["PENDING_REVIEW_ONLY"] = "PENDING_REVIEW_ONLY"
    inactive_capabilities: tuple[Capability, ...] = (
        Capability.C1_READ_PRIVATE,
        Capability.C3_WRITE_LOCAL_ACCEPTED,
    )
    disabled_capabilities: tuple[Capability, ...] = (
        Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB,
        Capability.C5_SEND_EXTERNAL_EMAIL,
        Capability.C6_ACCESS_SECRET,
    )
    default_outcome: Literal[PolicyOutcome.DENY] = PolicyOutcome.DENY
    pending_human_decisions: Literal["UNAVAILABLE"] = "UNAVAILABLE"
    approval_verifier: Literal["UNAVAILABLE"] = "UNAVAILABLE"
    live_effect_execution: Literal["UNAVAILABLE"] = "UNAVAILABLE"
    enforcement_integration: Literal["INCOMPLETE"] = "INCOMPLETE"

    @field_validator("capabilities")
    @classmethod
    def require_capability_order(
        cls, value: tuple[CapabilityStatus, ...]
    ) -> tuple[CapabilityStatus, ...]:
        if tuple(item.capability_id for item in value) != tuple(Capability):
            raise ValueError("policy status capabilities must use the fixed C0-C6 order")
        return value

    @model_validator(mode="after")
    def require_fixed_capability_activation(self) -> PolicyStatusReport:
        if self.inactive_capabilities != (
            Capability.C1_READ_PRIVATE,
            Capability.C3_WRITE_LOCAL_ACCEPTED,
        ):
            raise ValueError("private read and accepted-task write remain inactive")
        if self.disabled_capabilities != (
            Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB,
            Capability.C5_SEND_EXTERNAL_EMAIL,
            Capability.C6_ACCESS_SECRET,
        ):
            raise ValueError("external and secret capabilities remain disabled")
        return self

    @field_validator("active_rules")
    @classmethod
    def require_supported_rule_order(
        cls, value: tuple[PolicyRuleStatus, ...]
    ) -> tuple[PolicyRuleStatus, ...]:
        expected = (
            (PolicyRuleId.P00, PolicyOutcome.DENY),
            (PolicyRuleId.P01, PolicyOutcome.DENY),
            (PolicyRuleId.P02, PolicyOutcome.DENY),
            (PolicyRuleId.P03, PolicyOutcome.DENY),
            (PolicyRuleId.P17, PolicyOutcome.DENY),
            (PolicyRuleId.P09, PolicyOutcome.DENY),
            (PolicyRuleId.P04, PolicyOutcome.ALLOW),
            (PolicyRuleId.P06, PolicyOutcome.ALLOW),
            (PolicyRuleId.P12, PolicyOutcome.DENY),
        )
        if tuple((item.rule_id, item.outcome) for item in value) != expected:
            raise ValueError("active policy rules must use the supported fixed priority order")
        if tuple(item.priority for item in value) != tuple(range(len(expected))):
            raise ValueError("active policy rule priorities must be consecutive and fixed")
        return value

    @field_validator("unimplemented_rules")
    @classmethod
    def require_unimplemented_rule_order(
        cls, value: tuple[RuleReference, ...]
    ) -> tuple[RuleReference, ...]:
        expected = ("P05", "P07", "P08", "P10", "P11", "P13", "P14", "P15", "P16")
        if value != expected:
            raise ValueError("unimplemented rules must match the closed CR2-C remainder")
        return value
