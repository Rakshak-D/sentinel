"""Complete decision snapshots captured from the pre-refactor evaluator."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest
from cr2_a_policy_cases import make_context, make_request, make_source

from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.gateways.types import ExecutionMode
from sentinel.policy import (
    BUILTIN_REGISTRY,
    AuthorizationClass,
    Capability,
    EffectClass,
    ExecutionBoundary,
    ModelRouteState,
    PolicyDecision,
    build_policy_context,
    build_proposal_persistence_policy_request,
    evaluate_policy,
)
from sentinel.policy.canonical import registry_sha256
from sentinel.policy.evaluator import (
    build_verified_proposal_preview_policy_input,
    build_verified_public_read_policy_input,
)
from sentinel.policy.identities import proposal_preview_identity
from sentinel.policy.registry import CapabilityRegistry
from sentinel.policy.source_binding import resolve_github_fixture_public_read
from tests.test_cr1_i_support import promoted_case


def _serialized(decision: PolicyDecision) -> str:
    """Return the complete canonical public decision shape for comparison."""
    return json.dumps(
        decision.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def build_characterization_matrix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, PolicyDecision]:
    """Exercise each supported stage and overlapping-rule precedence."""
    import sentinel.policy.evaluator as evaluator

    source = make_source()
    context = make_context(source)
    request = make_request(source=source)
    decisions: dict[str, PolicyDecision] = {}

    def add(
        name: str, current_request: object, current_context: object = context, **kwargs: object
    ) -> None:
        decisions[name] = evaluate_policy(
            request=current_request,
            context=current_context,
            **kwargs,
        )

    add("p00_request_invalid", {**request.model_dump(), "owner_authenticated": True})
    add(
        "p00_registry_untrusted",
        request,
        registry=BUILTIN_REGISTRY.model_copy(update={"registry_id": "attacker.registry"}),
    )
    add("p00_context_registry", request, context.model_copy(update={"registry_sha256": "0" * 64}))
    add("p00_principal", request, context.model_copy(update={"principal_id": "attacker.owner"}))
    add("p00_context_policy", request, context.model_copy(update={"policy_sha256": "0" * 64}))
    add("p00_context_config", request, context.model_copy(update={"config_sha256": "0" * 64}))
    add("p00_request_registry", request.model_copy(update={"registry_sha256": "0" * 64}))
    add("p00_request_policy", request.model_copy(update={"policy_sha256": "0" * 64}))
    add("p00_request_config", request.model_copy(update={"config_sha256": "0" * 64}))
    add(
        "p00_operation_unknown",
        make_request(source=source, operation_id="sentinel.unknown.operation"),
    )
    add(
        "p00_capability_mismatch",
        make_request(
            capability=Capability.C1_READ_PRIVATE,
            operation_id="sentinel.synthetic.read.public",
            source=source,
        ),
    )
    add("p00_arguments_invalid", make_request(source=source, arguments=(("resource_id", 42),)))
    add("p00_source_missing", make_request(source=source, source_ids=()))
    add("p00_source_unresolved", make_request(source=source, source_ids=(UUID(int=999),)))
    unknown_source = make_source(trust=TrustLabel.T5_UNKNOWN)
    add("p00_source_t5", make_request(source=unknown_source), make_context(unknown_source))
    owner_source = make_source(trust=TrustLabel.T1_OWNER_INTENT)
    add("p00_source_t1", make_request(source=owner_source), make_context(owner_source))
    wrong_trust_source = make_source(trust=TrustLabel.T3_DERIVED)
    add(
        "p00_required_source_trust",
        make_request(capability=Capability.C0_READ_PUBLIC, source=wrong_trust_source),
        make_context(wrong_trust_source),
    )
    add("p00_context_malformed", request, {**context.model_dump(), "unexpected": True})

    bypass = request.model_copy(update={"execution_boundary": ExecutionBoundary.BYPASS_GATEWAY})
    add("p01_bypass", bypass)
    replay = make_request(
        capability=Capability.C2_WRITE_LOCAL_PROPOSAL,
        source=source,
        execution_mode=ExecutionMode.REPLAY,
    )
    add("p01_replay", replay)
    add(
        "priority_p00_before_p01",
        request.model_copy(
            update={
                "registry_sha256": "0" * 64,
                "execution_boundary": ExecutionBoundary.BYPASS_GATEWAY,
            }
        ),
    )
    add(
        "priority_p01_before_p02",
        make_request(
            capability=Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB,
            source=source,
            execution_boundary=ExecutionBoundary.BYPASS_GATEWAY,
        ),
    )
    add(
        "p02_c4",
        make_request(capability=Capability.C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB, source=source),
    )
    add("p02_c5", make_request(capability=Capability.C5_SEND_EXTERNAL_EMAIL, source=source))

    add(
        "p03_unknown_sensitivity",
        make_request(
            source=source,
            execution_boundary=ExecutionBoundary.MODEL_GATEWAY,
            declared_sensitivity=None,
        ),
    )
    secret_source = make_source(sensitivity=SensitivityLabel.SECRET)
    add(
        "p03_secret",
        make_request(
            source=secret_source,
            execution_boundary=ExecutionBoundary.MODEL_GATEWAY,
            declared_sensitivity=SensitivityLabel.SECRET,
        ),
        make_context(secret_source),
    )
    private_source = make_source(sensitivity=SensitivityLabel.PRIVATE)
    add(
        "p03_sensitivity_downgrade",
        make_request(
            source=private_source,
            execution_boundary=ExecutionBoundary.MODEL_GATEWAY,
            declared_sensitivity=SensitivityLabel.PUBLIC,
        ),
        make_context(private_source),
    )
    add(
        "p03_private_cloud",
        make_request(
            source=private_source,
            execution_boundary=ExecutionBoundary.MODEL_GATEWAY,
            declared_sensitivity=SensitivityLabel.PRIVATE,
        ),
        make_context(private_source, model_route=ModelRouteState.CLOUD),
    )
    add(
        "priority_p03_before_p17",
        make_request(
            capability=Capability.C6_ACCESS_SECRET,
            source=secret_source,
            execution_boundary=ExecutionBoundary.MODEL_GATEWAY,
            declared_sensitivity=SensitivityLabel.SECRET,
        ),
        make_context(secret_source),
    )
    add("p17_c6", make_request(capability=Capability.C6_ACCESS_SECRET, source=source))

    database, store_root = promoted_case(tmp_path, name="r2-a-policy-characterization")
    verified = resolve_github_fixture_public_read(database, store_root=store_root)
    public_request, public_context = build_verified_public_read_policy_input(verified)
    add("p04_public_read_allow", public_request, public_context, evidence_binding=verified)
    add(
        "p09_binding_missing",
        make_request(capability=Capability.C2_WRITE_LOCAL_PROPOSAL, source=source),
        context,
    )
    add(
        "p09_wrong_effect",
        public_request.model_copy(update={"requested_effect_class": EffectClass.LOCAL_PROPOSAL}),
        public_context,
        evidence_binding=verified,
    )
    add(
        "p09_wrong_binding_digest",
        public_request.model_copy(update={"source_binding_sha256": "f" * 64}),
        public_context,
        evidence_binding=verified,
    )
    add(
        "p09_wrong_source_set",
        public_request.model_copy(update={"source_ids": public_request.source_ids[:-1]}),
        public_context,
        evidence_binding=verified,
    )
    add(
        "p09_wrong_citation_set",
        public_request.model_copy(
            update={"evidence_span_ids": public_request.evidence_span_ids[:-1]}
        ),
        public_context,
        evidence_binding=verified,
    )
    add(
        "p09_wrong_context_labels",
        public_request,
        public_context.model_copy(
            update={
                "sources": tuple(
                    item.model_copy(update={"sensitivity": SensitivityLabel.PRIVATE})
                    if index == 0
                    else item
                    for index, item in enumerate(public_context.sources)
                )
            }
        ),
        evidence_binding=verified,
    )

    preview_request, preview_context = build_verified_proposal_preview_policy_input(
        verified, issue_number=101
    )
    add("p06_preview_allow", preview_request, preview_context, evidence_binding=verified)
    add(
        "p09_preview_selection_mismatch",
        preview_request.model_copy(
            update={"arguments": (("label", "REVIEW_SOURCE:example-owner/fixture-project#102"),)}
        ),
        preview_context,
        evidence_binding=verified,
    )
    selected = next(
        item for item in verified.binding.sources if item.provider_item_id.endswith("#101")
    )
    preview_id = proposal_preview_identity(selected.item_id, verified.binding.source_set_sha256)
    persistence_request = build_proposal_persistence_policy_request(
        binding=verified.binding,
        issue_number=101,
        preview_id=preview_id,
    )
    persistence_context = build_policy_context(
        sources=verified.source_envelopes,
        source_binding_sha256=verified.binding.source_set_sha256,
    )
    add(
        "p06_persistence_allow", persistence_request, persistence_context, evidence_binding=verified
    )

    # P12 is otherwise unreachable under the fixed registry. Temporarily grant
    # no authority requirement to one supported C1 entry to characterize its
    # existing catch-all behavior without changing production metadata.
    c1_entry = next(
        item
        for item in BUILTIN_REGISTRY.entries
        if item.capability_id is Capability.C1_READ_PRIVATE
    )
    c1_index = BUILTIN_REGISTRY.entries.index(c1_entry)
    unsupported_entry = c1_entry.model_copy(
        update={"required_authorization_class": AuthorizationClass.NONE}
    )
    custom_entries = list(BUILTIN_REGISTRY.entries)
    custom_entries[c1_index] = unsupported_entry
    custom_registry = CapabilityRegistry.model_validate(
        BUILTIN_REGISTRY.model_dump(mode="python") | {"entries": tuple(custom_entries)},
        strict=True,
    )
    custom_registry_digest = registry_sha256(custom_registry)
    custom_request = make_request(capability=Capability.C1_READ_PRIVATE, source=source).model_copy(
        update={"registry_sha256": custom_registry_digest}
    )
    custom_context = context.model_copy(update={"registry_sha256": custom_registry_digest})
    with monkeypatch.context() as patch:
        patch.setattr(evaluator, "BUILTIN_REGISTRY", custom_registry)
        patch.setattr(evaluator, "_BUILTIN_REGISTRY_SHA256", custom_registry_digest)
        add("p12_unsupported", custom_request, custom_context, registry=custom_registry)

    def fail_arguments(*_args: object, **_kwargs: object) -> bool:
        raise RuntimeError("synthetic failure text must not escape")

    with monkeypatch.context() as patch:
        patch.setattr(evaluator, "_arguments_match", fail_arguments)
        add("p00_internal_failure", request)
    return decisions


def test_policy_decisions_match_complete_pre_refactor_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual = {
        name: decision.model_dump(mode="json")
        for name, decision in build_characterization_matrix(tmp_path, monkeypatch).items()
    }
    expected_path = Path(__file__).with_name("r2_a_policy_decision_snapshots.json")
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    assert actual == expected
