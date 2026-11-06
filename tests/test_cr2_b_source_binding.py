from __future__ import annotations

from dataclasses import replace

import pytest
from pydantic import ValidationError

from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.gateways.types import ExecutionMode
from sentinel.policy import (
    BUILTIN_REGISTRY,
    Capability,
    EffectClass,
    ExecutionBoundary,
    ModelRouteState,
    PolicyDecision,
    PolicyOutcome,
    PolicyReasonCode,
    PolicyRuleId,
    build_policy_context,
    evaluate_policy,
    request_sha256,
)
from sentinel.policy.evaluator import build_verified_public_read_policy_input
from sentinel.policy.source_binding import (
    PublicReadBindingError,
    _expected_binding_sources,
    canonical_source_binding_bytes,
    resolve_github_fixture_public_read,
    source_binding_sha256,
)
from tests.test_cr1_i_support import promoted_case


def test_resolved_public_binding_is_pinned_body_free_and_deterministic(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="policy-binding")
    read = resolve_github_fixture_public_read(database, store_root=store_root)

    binding_bytes = canonical_source_binding_bytes(read.binding)
    assert binding_bytes == canonical_source_binding_bytes(read.binding)
    assert read.binding.source_set_sha256 == source_binding_sha256(read.binding)
    assert len(read.binding.sources) == 3
    assert sum(len(source.citations) for source in read.binding.sources) == 9
    assert all(source.trust is TrustLabel.T4_EXTERNAL for source in read.binding.sources)
    assert all(source.sensitivity is SensitivityLabel.PUBLIC for source in read.binding.sources)
    assert "done" not in binding_bytes.decode("utf-8")
    assert "VerifiedGithubPublicRead" in repr(read)
    assert "done" not in repr(read)


def test_request_hash_binds_the_verified_source_set() -> None:
    from uuid import UUID

    from sentinel.policy import PolicyRequest

    first = PolicyRequest(
        request_id=UUID(int=900),
        operation_id="sentinel.synthetic.read.public",
        capability=Capability.C0_READ_PUBLIC,
        execution_mode=ExecutionMode.LIVE,
        execution_boundary=ExecutionBoundary.CORE,
        arguments=(("resource_id", "github.fixture"),),
        source_ids=(UUID(int=1),),
        evidence_span_ids=(UUID(int=2),),
        source_binding_sha256="a" * 64,
        declared_sensitivity=SensitivityLabel.PUBLIC,
        registry_id="sentinel.cr2.synthetic-capabilities",
        registry_version="v1",
        registry_sha256="b" * 64,
        policy_id="sentinel.cr2.bounded-public-read-policy",
        policy_version="v2",
        policy_sha256="c" * 64,
        config_version="sentinel.config.v1",
        config_sha256="d" * 64,
        requested_effect_class=EffectClass.READ_ONLY,
    )
    changed = first.model_copy(update={"source_binding_sha256": "e" * 64})
    assert request_sha256(first) != request_sha256(changed)


def test_fabricated_public_context_without_resolver_binding_is_denied() -> None:
    from cr2_a_policy_cases import make_request, make_source

    source = make_source(trust=TrustLabel.T4_EXTERNAL, sensitivity=SensitivityLabel.PUBLIC)
    request = make_request(
        source=source,
        declared_sensitivity=SensitivityLabel.PUBLIC,
    )
    decision = evaluate_policy(request=request, context=build_policy_context(sources=(source,)))

    assert decision.outcome is PolicyOutcome.DENY
    assert decision.rule_id is PolicyRuleId.P09
    assert decision.reason_code is PolicyReasonCode.EVIDENCE_BINDING_MISSING


def test_resolver_binding_rejects_tampered_citation_and_source_set(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="policy-binding-tamper")
    read = resolve_github_fixture_public_read(database, store_root=store_root)
    evidence = read.evidence
    first_item = evidence.items[0]
    first_citation = first_item.citations[0]
    bad_citation = replace(first_citation, start_byte=first_citation.start_byte + 1)
    bad_item = replace(
        first_item,
        citations=(bad_citation, *first_item.citations[1:]),
    )

    with pytest.raises(PublicReadBindingError):
        _expected_binding_sources(replace(evidence, items=(bad_item, *evidence.items[1:])))
    with pytest.raises(PublicReadBindingError):
        _expected_binding_sources(replace(evidence, items=evidence.items[:-1]))


def test_resolver_binding_rejects_fixture_hash_labels_body_hash_and_slice_changes(tmp_path) -> None:
    from uuid import UUID

    database, store_root = promoted_case(tmp_path, name="policy-binding-fields")
    evidence = resolve_github_fixture_public_read(database, store_root=store_root).evidence
    item = evidence.items[0]
    citation = item.citations[0]
    changed_citations = (
        replace(citation, span_id=UUID(int=999)),
        replace(citation, end_byte=citation.end_byte + 1),
        replace(citation, text_sha256="f" * 64),
        replace(citation, cited_text="tampered"),
    )
    invalid_items = (
        replace(item, trust=TrustLabel.T5_UNKNOWN),
        replace(item, sensitivity=SensitivityLabel.PRIVATE),
        replace(item, content_sha256="f" * 64),
        replace(item, citations=(changed_citations[0], *item.citations[1:])),
        replace(item, citations=(changed_citations[1], *item.citations[1:])),
        replace(item, citations=(changed_citations[2], *item.citations[1:])),
        replace(item, citations=(changed_citations[3], *item.citations[1:])),
    )
    for invalid_item in invalid_items:
        with pytest.raises(PublicReadBindingError):
            _expected_binding_sources(
                replace(evidence, items=(invalid_item, *evidence.items[1:]))
            )
    with pytest.raises(PublicReadBindingError):
        _expected_binding_sources(replace(evidence, fixture_sha256="f" * 64))
    with pytest.raises(PublicReadBindingError):
        _expected_binding_sources(replace(evidence, manifest_sha256="f" * 64))


def test_p09_denies_changed_request_source_span_effect_and_sensitivity(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="policy-binding-request-mismatch")
    read = resolve_github_fixture_public_read(database, store_root=store_root)
    request, context = build_verified_public_read_policy_input(read)

    cases = (
        request.model_copy(update={"source_ids": request.source_ids[:-1]}),
        request.model_copy(update={"evidence_span_ids": request.evidence_span_ids[:-1]}),
        request.model_copy(update={"requested_effect_class": EffectClass.LOCAL_PROPOSAL}),
        request.model_copy(update={"declared_sensitivity": SensitivityLabel.PRIVATE}),
        request.model_copy(update={"source_binding_sha256": "f" * 64}),
        request.model_copy(update={"execution_mode": ExecutionMode.REPLAY}),
        request.model_copy(update={"execution_boundary": ExecutionBoundary.MODEL_GATEWAY}),
    )
    expected_reasons = (
        PolicyReasonCode.SOURCE_SET_MISMATCH,
        PolicyReasonCode.CITATION_SET_MISMATCH,
        PolicyReasonCode.EFFECT_CLASS_MISMATCH,
        PolicyReasonCode.PUBLIC_READ_SCOPE_MISMATCH,
        PolicyReasonCode.FIXTURE_PIN_MISMATCH,
        PolicyReasonCode.PUBLIC_READ_SCOPE_MISMATCH,
        PolicyReasonCode.PUBLIC_READ_SCOPE_MISMATCH,
    )
    for changed, expected_reason in zip(cases, expected_reasons, strict=True):
        decision = evaluate_policy(
            request=changed,
            registry=BUILTIN_REGISTRY,
            context=context,
            evidence_binding=read,
        )
        assert decision.outcome is PolicyOutcome.DENY
        assert decision.rule_id is PolicyRuleId.P09
        assert decision.reason_code is expected_reason

    cloud_context = context.model_copy(update={"model_route": ModelRouteState.CLOUD})
    cloud_route = evaluate_policy(
        request=request,
        registry=BUILTIN_REGISTRY,
        context=cloud_context,
        evidence_binding=read,
    )
    assert cloud_route.rule_id is PolicyRuleId.P09
    assert cloud_route.reason_code is PolicyReasonCode.PUBLIC_READ_SCOPE_MISMATCH

    altered_sources = tuple(
        source.model_copy(update={"sensitivity": SensitivityLabel.PRIVATE})
        if index == 0
        else source
        for index, source in enumerate(context.sources)
    )
    forged_context = context.model_copy(update={"sources": altered_sources})
    altered_context = evaluate_policy(
        request=request,
        context=forged_context,
        evidence_binding=read,
    )
    assert altered_context.rule_id is PolicyRuleId.P09
    assert altered_context.reason_code is PolicyReasonCode.SOURCE_SET_MISMATCH


def test_all_nonpublic_or_nonread_capabilities_remain_denied(tmp_path) -> None:
    from cr2_a_policy_cases import make_request, make_source

    source = make_source(trust=TrustLabel.T4_EXTERNAL, sensitivity=SensitivityLabel.PUBLIC)
    context = build_policy_context(sources=(source,))
    for entry in BUILTIN_REGISTRY.entries:
        if entry.capability_id is Capability.C0_READ_PUBLIC:
            continue
        request = make_request(
            capability=entry.capability_id,
            operation_id=entry.operation_id,
            source=source,
        )
        decision = evaluate_policy(request=request, context=context)
        assert decision.outcome is PolicyOutcome.DENY
        assert decision.executable is False


def test_allow_decision_contract_is_p04_metadata_only() -> None:
    from uuid import UUID

    valid = PolicyDecision(
        outcome=PolicyOutcome.ALLOW,
        rule_id=PolicyRuleId.P04,
        reason_code=PolicyReasonCode.PUBLIC_READ_ALLOWED,
        policy_sha256="a" * 64,
        registry_sha256="b" * 64,
        request_sha256="c" * 64,
        evidence_binding_sha256="d" * 64,
        evidence_ids=(UUID(int=1),),
        executable=False,
    )
    assert valid.outcome is PolicyOutcome.ALLOW
    assert valid.executable is False
    with pytest.raises(ValidationError):
        PolicyDecision(
            outcome=PolicyOutcome.ALLOW,
            rule_id=PolicyRuleId.P04,
            reason_code=PolicyReasonCode.PUBLIC_READ_ALLOWED,
            policy_sha256="a" * 64,
            registry_sha256="b" * 64,
            request_sha256="c" * 64,
            executable=False,
        )
    with pytest.raises(ValidationError):
        PolicyDecision(
            outcome=PolicyOutcome.PENDING_HUMAN,
            rule_id=PolicyRuleId.P04,
            reason_code=PolicyReasonCode.PUBLIC_READ_ALLOWED,
            policy_sha256="a" * 64,
            registry_sha256="b" * 64,
            request_sha256="c" * 64,
            evidence_binding_sha256="d" * 64,
            executable=False,
        )


def test_missing_or_corrupted_blob_fails_closed_before_briefing(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="policy-binding-blob-missing")
    # A missing selected blob is rejected by the same complete-state reader.
    # The existing reader's focused tamper suite exercises the precise filesystem mutation.
    with pytest.raises(PublicReadBindingError):
        resolve_github_fixture_public_read(database, store_root=store_root / "missing")
