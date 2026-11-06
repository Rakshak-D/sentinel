import pytest
from cr2_a_policy_cases import make_request
from pydantic import ValidationError

from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.policy import (
    BUILTIN_REGISTRY,
    ArgumentKind,
    ArgumentSpec,
    Capability,
    CapabilityRegistration,
    EffectClass,
    PolicyDecision,
    PolicyOutcome,
    PolicyReasonCode,
    PolicyRuleId,
    RegistrationState,
)


def test_capabilities_are_the_exact_reused_c0_to_c6_vocabulary() -> None:
    assert tuple(item.value for item in Capability) == (
        "C0_READ_PUBLIC",
        "C1_READ_PRIVATE",
        "C2_WRITE_LOCAL_PROPOSAL",
        "C3_WRITE_LOCAL_ACCEPTED",
        "C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB",
        "C5_SEND_EXTERNAL_EMAIL",
        "C6_ACCESS_SECRET",
    )
    assert tuple(item.value for item in TrustLabel) == (
        "T0 POLICY",
        "T1 OWNER_INTENT",
        "T2 AUTH_METADATA",
        "T3 DERIVED",
        "T4 EXTERNAL",
        "T5 UNKNOWN",
    )
    assert tuple(item.value for item in SensitivityLabel) == (
        "PUBLIC",
        "INTERNAL",
        "PRIVATE",
        "SECRET",
    )


def test_registry_entries_and_policy_dtos_are_frozen_and_non_executable() -> None:
    registration = BUILTIN_REGISTRY.entries[0]
    assert registration.executable is False
    with pytest.raises(ValidationError):
        registration.operation_id = "sentinel.changed"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        CapabilityRegistration(
            registration_id="sentinel.registration.attack",
            registry_id="sentinel.cr2.synthetic-capabilities",
            capability_id=Capability.C0_READ_PUBLIC,
            operation_id="sentinel.attack.handler",
            argument_schema=(ArgumentSpec(name="resource_id", value_kind=ArgumentKind.TEXT),),
            effect_class=EffectClass.READ_ONLY,
            required_source_trust=(TrustLabel.T4_EXTERNAL,),
            required_authorization_class=registration.required_authorization_class,
            state=RegistrationState.POLICY_ONLY,
            executable=True,
        )


def test_policy_request_is_frozen_and_rejects_unknown_or_duplicate_claims() -> None:
    request = make_request()
    assert "synthetic-item" not in repr(request)
    with pytest.raises(ValidationError):
        request.operation_id = "sentinel.other"  # type: ignore[misc]
    with pytest.raises(ValidationError) as invalid_authority:
        type(request).model_validate(
            {**request.model_dump(), "owner_authenticated": "private-auth-canary"}, strict=True
        )
    assert "private-auth-canary" not in str(invalid_authority.value)
    with pytest.raises(ValidationError):
        type(request).model_validate(
            {
                **request.model_dump(),
                "arguments": (("resource_id", "first"), ("resource_id", "second")),
            },
            strict=True,
        )


def test_policy_decisions_can_only_represent_non_executable_denials() -> None:
    assert PolicyOutcome.ALLOW.value == "ALLOW"
    assert PolicyOutcome.PENDING_HUMAN.value == "PENDING_HUMAN"
    with pytest.raises(ValidationError):
        PolicyDecision(
            outcome=PolicyOutcome.ALLOW,
            rule_id=PolicyRuleId.P12,
            reason_code=PolicyReasonCode.UNSUPPORTED_POLICY,
            policy_sha256="a" * 64,
            registry_sha256="b" * 64,
            request_sha256="c" * 64,
            executable=False,
        )
    with pytest.raises(ValidationError):
        PolicyDecision(
            outcome=PolicyOutcome.DENY,
            rule_id=PolicyRuleId.P12,
            reason_code=PolicyReasonCode.UNSUPPORTED_POLICY,
            policy_sha256="a" * 64,
            registry_sha256="b" * 64,
            request_sha256="c" * 64,
            executable=True,
        )
