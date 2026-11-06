"""Static policy and capability metadata; registrations contain no code paths."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from sentinel.contracts import TrustLabel
from sentinel.policy.types import (
    POLICY_RULE_SCHEMA,
    ArgumentKind,
    ArgumentSpec,
    AuthorizationClass,
    Capability,
    CapabilityRegistration,
    EffectClass,
    PolicyIdentifier,
    PolicyOutcome,
    PolicyRuleId,
    PolicyVersion,
    RegistrationState,
)

REGISTRY_SCHEMA_VERSION: Literal["sentinel.capability-registry.v1"] = (
    "sentinel.capability-registry.v1"
)
REGISTRY_ID = "sentinel.cr2.synthetic-capabilities"
REGISTRY_VERSION = "v1"
POLICY_ID = "sentinel.cr2.deny-only-policy"
POLICY_VERSION = "v1"

UNIMPLEMENTED_RULE_IDS: tuple[str, ...] = (
    "P04",
    "P05",
    "P06",
    "P07",
    "P08",
    "P09",
    "P10",
    "P11",
    "P13",
    "P14",
    "P15",
    "P16",
)


class CapabilityRegistry(BaseModel):
    """Immutable static registry values; handlers and imports are not representable."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
        hide_input_in_errors=True,
    )

    schema_version: Literal["sentinel.capability-registry.v1"] = REGISTRY_SCHEMA_VERSION
    registry_id: PolicyIdentifier = REGISTRY_ID
    registry_version: PolicyVersion = REGISTRY_VERSION
    entries: Annotated[tuple[CapabilityRegistration, ...], Field(min_length=7, max_length=7)]

    @classmethod
    def _entry_maps(
        cls, entries: tuple[CapabilityRegistration, ...]
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        return (
            tuple(entry.registration_id for entry in entries),
            tuple(entry.operation_id for entry in entries),
        )

    @classmethod
    def _validate_entries(
        cls, entries: tuple[CapabilityRegistration, ...]
    ) -> tuple[CapabilityRegistration, ...]:
        registration_ids, operation_ids = cls._entry_maps(entries)
        if len(registration_ids) != len(set(registration_ids)):
            raise ValueError("registration identities must be unique")
        if len(operation_ids) != len(set(operation_ids)):
            raise ValueError("operation identities must be unique")
        capabilities = tuple(entry.capability_id for entry in entries)
        if capabilities != tuple(Capability):
            raise ValueError("registry must contain exactly one canonical entry per capability")
        if any(entry.registry_id != REGISTRY_ID for entry in entries):
            raise ValueError("registration registry identity is invalid")
        return entries

    @model_validator(mode="after")
    def validate_trusted_registry_shape(self) -> CapabilityRegistry:
        self._validate_entries(self.entries)
        if self.registry_id != REGISTRY_ID or self.registry_version != REGISTRY_VERSION:
            raise ValueError("registry identity or version is not trusted")
        return self

    def find_operation(self, operation_id: str) -> CapabilityRegistration | None:
        """Return the exact static registration, without resolving code or resources."""
        return next((entry for entry in self.entries if entry.operation_id == operation_id), None)


class PolicyRuleContract(BaseModel):
    """Passive rule-order metadata; behavior is implemented in fixed evaluator code."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
        hide_input_in_errors=True,
    )

    schema_version: Literal["sentinel.policy-rule.v1"] = POLICY_RULE_SCHEMA
    rule_id: PolicyRuleId
    priority: Annotated[StrictInt, Field(ge=0, le=5)]
    outcome: Literal[PolicyOutcome.DENY] = PolicyOutcome.DENY
    summary: Annotated[StrictStr, Field(min_length=1, max_length=160)]
    hard: StrictBool


def _registration(
    *,
    capability: Capability,
    operation_id: str,
    arguments: tuple[ArgumentSpec, ...],
    trust: tuple[TrustLabel, ...],
    authorization: AuthorizationClass,
    state: RegistrationState,
) -> CapabilityRegistration:
    effect = {
        Capability.C0_READ_PUBLIC: EffectClass.READ_ONLY,
        Capability.C1_READ_PRIVATE: EffectClass.READ_ONLY,
        Capability.C2_WRITE_LOCAL_PROPOSAL: EffectClass.LOCAL_PROPOSAL,
        Capability.C3_WRITE_LOCAL_ACCEPTED: EffectClass.LOCAL_ACCEPTED,
        Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB: EffectClass.EXTERNAL_DRAFT_OR_GITHUB,
        Capability.C5_SEND_EXTERNAL_EMAIL: EffectClass.EXTERNAL_SEND,
        Capability.C6_ACCESS_SECRET: EffectClass.SECRET_ACCESS,
    }[capability]
    return CapabilityRegistration(
        registration_id=f"sentinel.cr2.registration.{capability.name.lower()}",
        registry_id=REGISTRY_ID,
        capability_id=capability,
        operation_id=operation_id,
        argument_schema=arguments,
        effect_class=effect,
        required_source_trust=trust,
        required_authorization_class=authorization,
        state=state,
        executable=False,
    )


BUILTIN_REGISTRY = CapabilityRegistry(
    entries=(
        _registration(
            capability=Capability.C0_READ_PUBLIC,
            operation_id="sentinel.synthetic.read.public",
            arguments=(ArgumentSpec(name="resource_id", value_kind=ArgumentKind.TEXT),),
            trust=(TrustLabel.T4_EXTERNAL,),
            authorization=AuthorizationClass.NONE,
            state=RegistrationState.POLICY_ONLY,
        ),
        _registration(
            capability=Capability.C1_READ_PRIVATE,
            operation_id="sentinel.synthetic.read.private",
            arguments=(ArgumentSpec(name="record_id", value_kind=ArgumentKind.TEXT),),
            trust=(TrustLabel.T4_EXTERNAL,),
            authorization=AuthorizationClass.VERIFIED_OWNER,
            state=RegistrationState.POLICY_ONLY,
        ),
        _registration(
            capability=Capability.C2_WRITE_LOCAL_PROPOSAL,
            operation_id="sentinel.synthetic.proposal.local",
            arguments=(ArgumentSpec(name="label", value_kind=ArgumentKind.TEXT),),
            trust=(TrustLabel.T3_DERIVED, TrustLabel.T4_EXTERNAL),
            authorization=AuthorizationClass.NONE,
            state=RegistrationState.POLICY_ONLY,
        ),
        _registration(
            capability=Capability.C3_WRITE_LOCAL_ACCEPTED,
            operation_id="sentinel.synthetic.task.local-accepted",
            arguments=(ArgumentSpec(name="task_id", value_kind=ArgumentKind.TEXT),),
            trust=(TrustLabel.T1_OWNER_INTENT,),
            authorization=AuthorizationClass.VERIFIED_OWNER,
            state=RegistrationState.POLICY_ONLY,
        ),
        _registration(
            capability=Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB,
            operation_id="sentinel.synthetic.external-draft.metadata",
            arguments=(),
            trust=(),
            authorization=AuthorizationClass.VERIFIED_OWNER,
            state=RegistrationState.OFF,
        ),
        _registration(
            capability=Capability.C5_SEND_EXTERNAL_EMAIL,
            operation_id="sentinel.synthetic.external-send.metadata",
            arguments=(),
            trust=(),
            authorization=AuthorizationClass.ONE_USE_OWNER_PROOF,
            state=RegistrationState.OFF,
        ),
        _registration(
            capability=Capability.C6_ACCESS_SECRET,
            operation_id="sentinel.synthetic.secret-access.metadata",
            arguments=(),
            trust=(),
            authorization=AuthorizationClass.INTERNAL_SECRET_BROKER,
            state=RegistrationState.OFF,
        ),
    )
)

POLICY_RULES: tuple[PolicyRuleContract, ...] = (
    PolicyRuleContract(
        rule_id=PolicyRuleId.P00,
        priority=0,
        summary="Malformed requests, invalid authority, provenance, hashes, or engine state deny.",
        hard=True,
    ),
    PolicyRuleContract(
        rule_id=PolicyRuleId.P01,
        priority=1,
        summary="Replay live effects and direct model/tool gateway bypasses deny.",
        hard=True,
    ),
    PolicyRuleContract(
        rule_id=PolicyRuleId.P02,
        priority=2,
        summary="C4/C5 remain off without isolated, explicitly enabled workers.",
        hard=True,
    ),
    PolicyRuleContract(
        rule_id=PolicyRuleId.P03,
        priority=3,
        summary="SECRET, raw PRIVATE, unknown, or downgraded model inputs deny.",
        hard=True,
    ),
    PolicyRuleContract(
        rule_id=PolicyRuleId.P17,
        priority=4,
        summary="C6 secret access is unavailable to every caller in CR2-A.",
        hard=True,
    ),
    PolicyRuleContract(
        rule_id=PolicyRuleId.P12,
        priority=5,
        summary="Unsupported rules and all otherwise unmatched requests deny.",
        hard=False,
    ),
)
