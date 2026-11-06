from __future__ import annotations

from uuid import NAMESPACE_URL, uuid5

import pytest
from pydantic import ValidationError

from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.policy import (
    BUILTIN_REGISTRY,
    EffectClass,
    ExecutionBoundary,
    PolicyDecision,
    PolicyOutcome,
    PolicyReasonCode,
    PolicyRuleId,
    build_policy_context,
    evaluate_policy,
)
from sentinel.policy.evaluator import build_verified_proposal_preview_policy_input
from sentinel.policy.source_binding import resolve_github_fixture_public_read
from tests.test_cr1_i_support import promoted_case


@pytest.mark.parametrize("issue", [101, 102, 103])
def test_verified_selected_issue_gets_only_p06_preview_allow(tmp_path, issue: int) -> None:
    database, store_root = promoted_case(tmp_path, name=f"cr2-c-p06-{issue}")
    verified = resolve_github_fixture_public_read(database, store_root=store_root)
    request, context = build_verified_proposal_preview_policy_input(
        verified,
        issue_number=issue,
    )

    decision = evaluate_policy(
        request=request,
        registry=BUILTIN_REGISTRY,
        context=context,
        evidence_binding=verified,
    )

    selected = next(
        source
        for source in verified.binding.sources
        if source.provider_item_id == f"example-owner/fixture-project#{issue}"
    )
    assert decision.outcome is PolicyOutcome.ALLOW
    assert decision.rule_id is PolicyRuleId.P06
    assert decision.reason_code is PolicyReasonCode.PROPOSAL_PREVIEW_ALLOWED
    assert decision.executable is False
    assert decision.evidence_binding_sha256 == verified.binding.source_set_sha256
    assert decision.evidence_ids == (
        request.request_id,
        selected.source_id,
        *(citation.span_id for citation in selected.citations),
    )


def test_p06_rejects_selection_identity_changes_and_fabricated_context(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-c-p06-selection-denials")
    verified = resolve_github_fixture_public_read(database, store_root=store_root)
    request, context = build_verified_proposal_preview_policy_input(
        verified,
        issue_number=101,
    )
    request_id_for_101 = request.request_id
    changed_selection = request.model_copy(
        update={"arguments": (("label", "REVIEW_SOURCE:example-owner/fixture-project#102"),)}
    )
    wrong_effect = request.model_copy(update={"requested_effect_class": EffectClass.READ_ONLY})
    wrong_sensitivity = request.model_copy(
        update={"declared_sensitivity": SensitivityLabel.PRIVATE}
    )
    wrong_span_set = request.model_copy(
        update={"evidence_span_ids": request.evidence_span_ids[:-1]}
    )

    for changed in (changed_selection, wrong_effect, wrong_sensitivity, wrong_span_set):
        decision = evaluate_policy(
            request=changed,
            context=context,
            evidence_binding=verified,
        )
        assert decision.outcome is PolicyOutcome.DENY
        assert decision.rule_id is PolicyRuleId.P09

    assert request_id_for_101 != uuid5(
        NAMESPACE_URL,
        "sentinel.policy.github-proposal-preview.v1:"
        + verified.binding.source_set_sha256
        + ":"
        + str(
            next(
                source.item_id
                for source in verified.binding.sources
                if source.provider_item_id == "example-owner/fixture-project#102"
            )
        ),
    )

    fabricated = build_policy_context(
        sources=verified.source_envelopes,
        source_binding_sha256=verified.binding.source_set_sha256,
    )
    no_resolver = evaluate_policy(request=request, context=fabricated)
    assert no_resolver.outcome is PolicyOutcome.DENY
    assert no_resolver.rule_id is PolicyRuleId.P09
    assert no_resolver.reason_code is PolicyReasonCode.EVIDENCE_BINDING_MISSING


def test_p06_denies_tampered_request_source_and_policy_registry_claims(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-c-p06-claim-denials")
    verified = resolve_github_fixture_public_read(database, store_root=store_root)
    request, context = build_verified_proposal_preview_policy_input(verified, issue_number=102)
    cases = (
        (request.model_copy(update={"source_binding_sha256": "f" * 64}), PolicyRuleId.P09),
        (request.model_copy(update={"source_ids": request.source_ids[:-1]}), PolicyRuleId.P09),
        (request.model_copy(update={"policy_sha256": "f" * 64}), PolicyRuleId.P00),
        (request.model_copy(update={"registry_sha256": "f" * 64}), PolicyRuleId.P00),
        (
            request.model_copy(update={"operation_id": "sentinel.synthetic.read.public"}),
            PolicyRuleId.P00,
        ),
        (
            request.model_copy(update={"execution_boundary": ExecutionBoundary.BYPASS_GATEWAY}),
            PolicyRuleId.P01,
        ),
    )
    for changed, expected_rule in cases:
        decision = evaluate_policy(
            request=changed,
            context=context,
            evidence_binding=verified,
        )
        assert decision.outcome is PolicyOutcome.DENY
        assert decision.rule_id is expected_rule


def test_p06_rejects_fabricated_source_labels_in_policy_context(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-c-p06-context-labels")
    verified = resolve_github_fixture_public_read(database, store_root=store_root)
    request, context = build_verified_proposal_preview_policy_input(verified, issue_number=103)

    private_sources = tuple(
        source.model_copy(update={"sensitivity": SensitivityLabel.PRIVATE})
        for source in context.sources
    )
    private_context = context.model_copy(update={"sources": private_sources})
    private_decision = evaluate_policy(
        request=request,
        context=private_context,
        evidence_binding=verified,
    )
    assert private_decision.outcome is PolicyOutcome.DENY
    assert private_decision.rule_id is PolicyRuleId.P09

    owner_claim_sources = tuple(
        source.model_copy(update={"trust": TrustLabel.T1_OWNER_INTENT})
        for source in context.sources
    )
    owner_claim_context = context.model_copy(update={"sources": owner_claim_sources})
    owner_claim_decision = evaluate_policy(
        request=request,
        context=owner_claim_context,
        evidence_binding=verified,
    )
    assert owner_claim_decision.outcome is PolicyOutcome.DENY
    assert owner_claim_decision.rule_id is PolicyRuleId.P00


def test_policy_decision_schema_allows_only_evidence_bound_p04_or_p06() -> None:
    shared = {
        "policy_sha256": "a" * 64,
        "registry_sha256": "b" * 64,
        "request_sha256": "c" * 64,
        "evidence_binding_sha256": "d" * 64,
        "evidence_ids": (uuid5(NAMESPACE_URL, "preview-evidence"),),
        "executable": False,
    }
    allowed = PolicyDecision(
        outcome=PolicyOutcome.ALLOW,
        rule_id=PolicyRuleId.P06,
        reason_code=PolicyReasonCode.PROPOSAL_PREVIEW_ALLOWED,
        **shared,
    )
    assert allowed.schema_version == "sentinel.policy-decision.v3"
    assert allowed.executable is False
    with pytest.raises(ValidationError):
        PolicyDecision(
            outcome=PolicyOutcome.ALLOW,
            rule_id=PolicyRuleId.P06,
            reason_code=PolicyReasonCode.PROPOSAL_PREVIEW_ALLOWED,
            **{**shared, "evidence_binding_sha256": None},
        )
    with pytest.raises(ValidationError):
        PolicyDecision(
            outcome=PolicyOutcome.ALLOW,
            rule_id=PolicyRuleId.P12,
            reason_code=PolicyReasonCode.PROPOSAL_PREVIEW_ALLOWED,
            **shared,
        )
    with pytest.raises(ValidationError):
        PolicyDecision(
            outcome=PolicyOutcome.PENDING_HUMAN,
            rule_id=PolicyRuleId.P06,
            reason_code=PolicyReasonCode.PROPOSAL_PREVIEW_ALLOWED,
            **shared,
        )
