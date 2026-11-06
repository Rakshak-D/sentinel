from __future__ import annotations

import pytest
from typer.testing import CliRunner

import sentinel.policy.evaluator as policy_evaluator
from sentinel.briefing import build_github_fixture_brief
from sentinel.briefing.types import BriefingError
from sentinel.cli import app
from sentinel.policy import PolicyDecision, PolicyOutcome, PolicyReasonCode, PolicyRuleId
from tests.test_cr1_i_support import promoted_case


def test_briefing_refuses_to_return_when_policy_denies(tmp_path, monkeypatch) -> None:
    database, store_root = promoted_case(tmp_path, name="policy-deny-before-gate")

    def deny(**_kwargs) -> PolicyDecision:
        return PolicyDecision(
            outcome=PolicyOutcome.DENY,
            rule_id=PolicyRuleId.P09,
            reason_code=PolicyReasonCode.UNSUPPORTED_POLICY,
            policy_sha256="a" * 64,
            registry_sha256="b" * 64,
            request_sha256="c" * 64,
            executable=False,
        )

    monkeypatch.setattr(policy_evaluator, "evaluate_policy", deny)

    with pytest.raises(BriefingError):
        build_github_fixture_brief(database, store_root=store_root)


def test_cli_deny_emits_empty_stdout_and_bounded_stderr(tmp_path, monkeypatch) -> None:
    database, store_root = promoted_case(tmp_path, name="policy-deny-cli")

    def deny(**_kwargs) -> PolicyDecision:
        return PolicyDecision(
            outcome=PolicyOutcome.DENY,
            rule_id=PolicyRuleId.P09,
            reason_code=PolicyReasonCode.EVIDENCE_BINDING_INVALID,
            policy_sha256="a" * 64,
            registry_sha256="b" * 64,
            request_sha256="c" * 64,
            executable=False,
        )

    monkeypatch.setattr(policy_evaluator, "evaluate_policy", deny)
    result = CliRunner().invoke(
        app,
        [
            "brief",
            "github-fixture",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
        ],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == "Brief failed: verified synthetic evidence is unavailable.\n"
    assert str(database) not in result.stderr


def test_validated_fixture_brief_is_gated_by_one_p04_decision(tmp_path, monkeypatch) -> None:
    database, store_root = promoted_case(tmp_path, name="policy-allow-gate")
    decisions: list[PolicyDecision] = []
    original = policy_evaluator.evaluate_policy

    def capture(**kwargs) -> PolicyDecision:
        decision = original(**kwargs)
        decisions.append(decision)
        return decision

    monkeypatch.setattr(policy_evaluator, "evaluate_policy", capture)
    briefing = build_github_fixture_brief(database, store_root=store_root)

    assert len(decisions) == 1
    assert decisions[0].outcome is PolicyOutcome.ALLOW
    assert decisions[0].rule_id is PolicyRuleId.P04
    assert decisions[0].evidence_binding_sha256 is not None
    assert len(briefing.items) == 3
    assert sum(len(item.citations) for item in briefing.items) == 9


def test_rule_status_places_p09_before_p04_and_keeps_p12_last() -> None:
    report = policy_evaluator.build_policy_status_report()
    assert tuple(rule.rule_id.value for rule in report.active_rules) == (
        "P00",
        "P01",
        "P02",
        "P03",
        "P17",
        "P09",
        "P04",
        "P12",
    )
    assert report.active_rules[-1].rule_id is PolicyRuleId.P12
    assert report.active_rules[-2].rule_id is PolicyRuleId.P04
    assert report.active_rules[-2].outcome is PolicyOutcome.ALLOW


def test_forged_allow_with_wrong_binding_hash_cannot_release_brief(tmp_path, monkeypatch) -> None:
    database, store_root = promoted_case(tmp_path, name="policy-forged-allow")
    original = policy_evaluator.evaluate_policy
    valid = original
    accepted = build_github_fixture_brief(database, store_root=store_root)
    assert len(accepted.items) == 3

    # A decision returned by an injected test double is not supplied as an API input;
    # the gate still checks its binding identity against the verified snapshot.
    from sentinel.policy.evaluator import build_verified_public_read_policy_input
    from sentinel.policy.source_binding import resolve_github_fixture_public_read

    verified = resolve_github_fixture_public_read(database, store_root=store_root)
    request, context = build_verified_public_read_policy_input(verified)
    genuine = valid(request=request, context=context, evidence_binding=verified)
    forged = genuine.model_copy(update={"evidence_binding_sha256": "f" * 64})
    monkeypatch.setattr(policy_evaluator, "evaluate_policy", lambda **_kwargs: forged)

    with pytest.raises(BriefingError):
        build_github_fixture_brief(database, store_root=store_root)


def test_successful_policy_gated_briefing_does_not_write_db_or_blobs(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="policy-read-only")
    database_before = database.read_bytes()
    blob_files = tuple(
        sorted(path for path in store_root.rglob("*") if path.is_file())
    )
    blobs_before = tuple(path.read_bytes() for path in blob_files)

    briefing = build_github_fixture_brief(database, store_root=store_root)

    assert len(briefing.items) == 3
    assert sum(len(item.citations) for item in briefing.items) == 9
    assert database.read_bytes() == database_before
    assert tuple(sorted(path for path in store_root.rglob("*") if path.is_file())) == blob_files
    assert tuple(path.read_bytes() for path in blob_files) == blobs_before
