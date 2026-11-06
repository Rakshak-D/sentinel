from uuid import UUID

import pytest
from cr2_a_policy_cases import make_context, make_request, make_source
from pydantic import ValidationError

from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.gateways.types import ExecutionMode
from sentinel.policy import (
    BUILTIN_REGISTRY,
    Capability,
    ExecutionBoundary,
    ModelRouteState,
    PolicyReasonCode,
    PolicyRuleId,
    evaluate_policy,
)


def _decision(*, capability: Capability = Capability.C0_READ_PUBLIC, **kwargs: object):
    source = kwargs.pop("source", make_source())
    context = kwargs.pop("context", make_context(source))
    request = kwargs.pop("request", None)
    if request is None:
        request = make_request(capability=capability, source=source, **kwargs)  # type: ignore[arg-type]
    return evaluate_policy(request=request, context=context)


def test_unknown_operation_and_capability_mismatch_are_p00_denials() -> None:
    unknown = _decision(operation_id="sentinel.unknown.operation")
    mismatch = _decision(
        capability=Capability.C1_READ_PRIVATE,
        operation_id="sentinel.synthetic.read.public",
    )
    assert (unknown.rule_id, unknown.reason_code) == (
        PolicyRuleId.P00,
        PolicyReasonCode.OPERATION_UNREGISTERED,
    )
    assert (mismatch.rule_id, mismatch.reason_code) == (
        PolicyRuleId.P00,
        PolicyReasonCode.CAPABILITY_MISMATCH,
    )


def test_missing_or_unknown_source_provenance_is_denied() -> None:
    source = make_source()
    missing = evaluate_policy(
        request=make_request(source=source, source_ids=(UUID(int=999),)),
        context=make_context(source),
    )
    no_source = evaluate_policy(
        request=make_request(source=source, source_ids=()),
        context=make_context(source),
    )
    unknown_source = make_source(trust=TrustLabel.T5_UNKNOWN)
    unknown = evaluate_policy(
        request=make_request(source=unknown_source),
        context=make_context(unknown_source),
    )
    assert missing.reason_code is PolicyReasonCode.SOURCE_MISSING
    assert no_source.reason_code is PolicyReasonCode.SOURCE_MISSING
    assert unknown.reason_code is PolicyReasonCode.SOURCE_PROVENANCE_UNKNOWN
    assert all(item.rule_id is PolicyRuleId.P00 for item in (missing, no_source, unknown))


def test_request_source_cannot_mint_owner_intent() -> None:
    source = make_source(trust=TrustLabel.T1_OWNER_INTENT)
    result = evaluate_policy(
        request=make_request(
            capability=Capability.C3_WRITE_LOCAL_ACCEPTED,
            source=source,
        ),
        context=make_context(source),
    )
    assert result.rule_id is PolicyRuleId.P00
    assert result.reason_code is PolicyReasonCode.SOURCE_PROVENANCE_UNKNOWN


def test_request_claims_cannot_create_owner_authority_or_policy_trust() -> None:
    source = make_source()
    valid = make_request(source=source)
    forged = {**valid.model_dump(), "owner_authenticated": True}
    decision = evaluate_policy(request=forged, context=make_context(source))
    fake_registry = BUILTIN_REGISTRY.model_copy(update={"registry_id": "attacker.registry"})
    registry_decision = evaluate_policy(
        request=valid, registry=fake_registry, context=make_context(source)
    )
    untrusted_hash_context = make_context(source).model_copy(update={"policy_sha256": "0" * 64})
    hash_decision = evaluate_policy(request=valid, context=untrusted_hash_context)
    assert decision.reason_code is PolicyReasonCode.REQUEST_INVALID
    assert registry_decision.reason_code is PolicyReasonCode.REGISTRY_UNTRUSTED
    assert hash_decision.reason_code is PolicyReasonCode.POLICY_UNTRUSTED
    assert all(
        item.rule_id is PolicyRuleId.P00 for item in (decision, registry_decision, hash_decision)
    )


def test_invalid_principal_and_untrusted_request_hashes_are_p00() -> None:
    source = make_source()
    request = make_request(source=source)
    fake_principal = make_context(source).model_copy(
        update={"principal_id": "attacker.claimed-owner"}
    )
    wrong_registry_hash = request.model_copy(update={"registry_sha256": "0" * 64})
    wrong_policy_hash = request.model_copy(update={"policy_sha256": "0" * 64})
    principal_result = evaluate_policy(request=request, context=fake_principal)
    registry_result = evaluate_policy(request=wrong_registry_hash, context=make_context(source))
    policy_result = evaluate_policy(request=wrong_policy_hash, context=make_context(source))
    assert principal_result.rule_id is PolicyRuleId.P00
    assert principal_result.reason_code is PolicyReasonCode.PRINCIPAL_UNTRUSTED
    assert registry_result.reason_code is PolicyReasonCode.REGISTRY_UNTRUSTED
    assert policy_result.reason_code is PolicyReasonCode.POLICY_UNTRUSTED


def test_malformed_arguments_fail_p00_without_echoing_values() -> None:
    source = make_source()
    wrong_kind = make_request(source=source, arguments=(("resource_id", 42),))
    unknown_name = make_request(source=source, arguments=(("private_canary", "must-not-leak"),))
    assert evaluate_policy(request=wrong_kind, context=make_context(source)).reason_code is (
        PolicyReasonCode.ARGUMENTS_INVALID
    )
    result = evaluate_policy(request=unknown_name, context=make_context(source))
    assert result.reason_code is PolicyReasonCode.ARGUMENTS_INVALID
    assert "must-not-leak" not in repr(result)


def test_replay_effect_and_direct_gateway_bypass_are_p01_denials() -> None:
    derived_source = make_source(trust=TrustLabel.T3_DERIVED)
    replay = evaluate_policy(
        request=make_request(
            capability=Capability.C2_WRITE_LOCAL_PROPOSAL,
            source=derived_source,
            execution_mode=ExecutionMode.REPLAY,
        ),
        context=make_context(derived_source),
    )
    bypass = _decision(execution_boundary=ExecutionBoundary.BYPASS_GATEWAY)
    assert (replay.rule_id, replay.reason_code) == (
        PolicyRuleId.P01,
        PolicyReasonCode.REPLAY_LIVE_EFFECT,
    )
    assert (bypass.rule_id, bypass.reason_code) == (
        PolicyRuleId.P01,
        PolicyReasonCode.GATEWAY_BYPASS,
    )


@pytest.mark.parametrize(
    ("capability", "rule_id", "reason"),
    [
        (
            Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB,
            PolicyRuleId.P02,
            PolicyReasonCode.EXTERNAL_CAPABILITY_OFF,
        ),
        (
            Capability.C5_SEND_EXTERNAL_EMAIL,
            PolicyRuleId.P02,
            PolicyReasonCode.EXTERNAL_CAPABILITY_OFF,
        ),
        (
            Capability.C6_ACCESS_SECRET,
            PolicyRuleId.P17,
            PolicyReasonCode.SECRET_ACCESS_DENIED,
        ),
    ],
)
def test_external_and_secret_capabilities_remain_denied(
    capability: Capability, rule_id: PolicyRuleId, reason: PolicyReasonCode
) -> None:
    result = _decision(capability=capability)
    assert result.rule_id is rule_id
    assert result.reason_code is reason
    assert result.executable is False


def test_secret_private_and_unknown_sensitivity_model_routes_are_p03_denied() -> None:
    secret_source = make_source(sensitivity=SensitivityLabel.SECRET)
    secret = evaluate_policy(
        request=make_request(
            source=secret_source,
            execution_boundary=ExecutionBoundary.MODEL_GATEWAY,
            declared_sensitivity=SensitivityLabel.SECRET,
        ),
        context=make_context(secret_source),
    )
    private_source = make_source(sensitivity=SensitivityLabel.PRIVATE)
    private_cloud = evaluate_policy(
        request=make_request(
            source=private_source,
            execution_boundary=ExecutionBoundary.MODEL_GATEWAY,
            declared_sensitivity=SensitivityLabel.PRIVATE,
        ),
        context=make_context(private_source, model_route=ModelRouteState.CLOUD),
    )
    unknown = _decision(
        execution_boundary=ExecutionBoundary.MODEL_GATEWAY,
        declared_sensitivity=None,
    )
    assert secret.rule_id is PolicyRuleId.P03
    assert secret.reason_code is PolicyReasonCode.SECRET_MODEL_ROUTE
    assert private_cloud.rule_id is PolicyRuleId.P03
    assert private_cloud.reason_code is PolicyReasonCode.PRIVATE_MODEL_ROUTE_UNVERIFIED
    assert unknown.rule_id is PolicyRuleId.P03
    assert unknown.reason_code is PolicyReasonCode.UNKNOWN_MODEL_SENSITIVITY


def test_unbound_registered_c2_preview_uses_p09_and_no_result_can_allow() -> None:
    result = _decision(capability=Capability.C2_WRITE_LOCAL_PROPOSAL)
    assert result.rule_id is PolicyRuleId.P09
    assert result.reason_code is PolicyReasonCode.EVIDENCE_BINDING_MISSING
    assert result.outcome.value == "DENY"
    assert result.executable is False


def test_bad_context_and_internal_failure_fail_closed_p00(monkeypatch: pytest.MonkeyPatch) -> None:
    import sentinel.policy.evaluator as evaluator

    source = make_source()
    request = make_request(source=source)
    malformed_context = {**make_context(source).model_dump(), "implementation_state": "allow_all"}
    malformed = evaluate_policy(request=request, context=malformed_context)

    def fail_closed(*_args: object, **_kwargs: object):
        raise RuntimeError("private evaluator diagnostic canary")

    monkeypatch.setattr(evaluator, "_evaluate_validated", fail_closed)
    internal = evaluate_policy(request=request, context=make_context(source))
    assert malformed.rule_id is PolicyRuleId.P00
    assert malformed.reason_code is PolicyReasonCode.IMPLEMENTATION_STATE_INVALID
    assert internal.rule_id is PolicyRuleId.P00
    assert internal.reason_code is PolicyReasonCode.INTERNAL_FAILURE
    assert "private evaluator diagnostic canary" not in repr(internal)


def test_runtime_policy_or_bundled_config_digest_drift_fails_p00(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sentinel.policy.evaluator as evaluator

    source = make_source()
    request = make_request(source=source)
    monkeypatch.setattr(evaluator, "policy_sha256", lambda: "0" * 64)
    changed_policy = evaluate_policy(request=request, context=make_context(source))
    monkeypatch.undo()
    monkeypatch.setattr(evaluator, "fingerprint_config", lambda _config: "0" * 64)
    changed_config = evaluate_policy(request=request, context=make_context(source))
    assert changed_policy.rule_id is PolicyRuleId.P00
    assert changed_policy.reason_code is PolicyReasonCode.POLICY_UNTRUSTED
    assert changed_config.rule_id is PolicyRuleId.P00
    assert changed_config.reason_code is PolicyReasonCode.CONFIG_UNTRUSTED


def test_untrusted_registry_data_cannot_add_a_handler_or_operation() -> None:
    source = make_source()
    request = make_request(source=source)
    first = BUILTIN_REGISTRY.entries[0].model_copy(
        update={"operation_id": "sentinel.attacker.handler"}
    )
    forged = BUILTIN_REGISTRY.model_copy(update={"entries": (first, *BUILTIN_REGISTRY.entries[1:])})
    decision = evaluate_policy(request=request, registry=forged, context=make_context(source))
    assert decision.rule_id is PolicyRuleId.P00
    assert decision.reason_code is PolicyReasonCode.REGISTRY_UNTRUSTED


def test_policy_request_rejects_nonfinite_and_duplicate_arguments() -> None:
    request = make_request()
    payload = request.model_dump()
    with pytest.raises(ValidationError):
        type(request).model_validate({**payload, "arguments": (("resource_id", float("nan")),)})
    with pytest.raises(ValidationError):
        type(request).model_validate(
            {**payload, "arguments": (("resource_id", "a"), ("resource_id", "b"))}
        )
