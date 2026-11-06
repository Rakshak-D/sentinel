from cr2_a_policy_cases import make_context, make_request, make_source

from sentinel.config.defaults import load_bundled_defaults
from sentinel.policy import (
    BUILTIN_REGISTRY,
    POLICY_RULES,
    Capability,
    PolicyRuleId,
    RegistrationState,
    evaluate_policy,
)


def test_rules_follow_the_supported_priority_and_p12_is_always_last() -> None:
    assert tuple(rule.rule_id for rule in POLICY_RULES) == (
        PolicyRuleId.P00,
        PolicyRuleId.P01,
        PolicyRuleId.P02,
        PolicyRuleId.P03,
        PolicyRuleId.P17,
        PolicyRuleId.P12,
    )
    assert tuple(rule.priority for rule in POLICY_RULES) == tuple(range(6))
    assert POLICY_RULES[-1].rule_id is PolicyRuleId.P12
    assert POLICY_RULES[-1].hard is False
    assert all(rule.hard is True for rule in POLICY_RULES[:-1])


def test_privileged_capability_registry_and_bundled_write_defaults_are_off() -> None:
    entries = {entry.capability_id: entry for entry in BUILTIN_REGISTRY.entries}
    assert tuple(entries) == tuple(Capability)
    assert all(
        entries[capability].state is RegistrationState.OFF
        for capability in (
            Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB,
            Capability.C5_SEND_EXTERNAL_EMAIL,
            Capability.C6_ACCESS_SECRET,
        )
    )
    writes = load_bundled_defaults().security.external_writes
    assert writes.gmail_draft.enabled is False
    assert writes.gmail_send.enabled is False
    assert writes.github_comment.enabled is False
    assert writes.github_label.enabled is False


def test_every_static_registration_denies_and_context_cannot_enable_privileges() -> None:
    source = make_source()
    context = make_context(source)
    for entry in BUILTIN_REGISTRY.entries:
        request = make_request(
            capability=entry.capability_id,
            operation_id=entry.operation_id,
            source=source,
        )
        decision = evaluate_policy(request=request, context=context)
        assert decision.outcome.value == "DENY"
        assert decision.executable is False
    for capability in (
        Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB,
        Capability.C5_SEND_EXTERNAL_EMAIL,
        Capability.C6_ACCESS_SECRET,
    ):
        forged = context.model_copy(update={"enabled_capabilities": (capability,)})
        decision = evaluate_policy(
            request=make_request(capability=capability, source=source),
            context=forged,
        )
        assert decision.outcome.value == "DENY"
