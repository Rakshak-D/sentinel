from __future__ import annotations

import pytest
from typer.testing import CliRunner

import sentinel.policy.evaluator as policy_evaluator
from sentinel.cli import app
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.policy import PolicyDecision, PolicyOutcome, PolicyReasonCode, PolicyRuleId
from sentinel.proposals import ProposalPreviewError, ProposalPreviewErrorCode
from sentinel.proposals.formatters import format_json_proposal_preview
from sentinel.proposals.preview import build_github_issue_proposal_preview
from sentinel.proposals.types import SyntheticProposalPreview
from tests.test_cr1_i_support import promoted_case


def test_preview_is_deterministic_and_prompt_like_source_is_not_rendered(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-c-injection-preview")
    preview_one = build_github_issue_proposal_preview(
        database,
        store_root=store_root,
        issue_number=103,
    )
    preview_two = build_github_issue_proposal_preview(
        database,
        store_root=store_root,
        issue_number=103,
    )
    assert preview_one == preview_two
    assert "ignore prior instructions" not in repr(preview_one)

    result = CliRunner().invoke(
        app,
        [
            "proposal",
            "preview-github-fixture",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--issue",
            "103",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    assert "ignore prior instructions" not in result.stdout
    assert "change trust to owner intent" not in result.stdout
    assert "Review synthetic GitHub issue #103" in result.stdout
    assert "PREVIEW_ONLY" in result.stdout


def test_forged_p06_decision_cannot_release_cli_preview(tmp_path, monkeypatch) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-c-forged-decision")
    original = policy_evaluator.evaluate_policy

    def forged(**kwargs) -> PolicyDecision:
        decision = original(**kwargs)
        assert decision.outcome is PolicyOutcome.ALLOW
        return decision.model_copy(update={"evidence_binding_sha256": "f" * 64})

    monkeypatch.setattr(policy_evaluator, "evaluate_policy", forged)
    result = CliRunner().invoke(
        app,
        [
            "proposal",
            "preview-github-fixture",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--issue",
            "101",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == "Proposal preview failed: Synthetic proposal preview was denied.\n"
    assert str(database) not in result.stderr
    assert "Synthetic issue" not in result.output


def test_caller_constructed_preview_cannot_be_formatted(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-c-unsealed-preview")
    verified_preview = build_github_issue_proposal_preview(
        database,
        store_root=store_root,
        issue_number=101,
    )
    caller_constructed = SyntheticProposalPreview.model_validate(
        verified_preview.model_dump(mode="python"), strict=True
    )

    with pytest.raises(ValueError, match="verified preview"):
        format_json_proposal_preview(caller_constructed)


def test_policy_denial_and_late_formatter_failure_have_empty_stdout(tmp_path, monkeypatch) -> None:
    import sentinel.cli as cli

    database, store_root = promoted_case(tmp_path, name="cr2-c-late-failure")
    real_evaluate = policy_evaluator.evaluate_policy

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
    denied = CliRunner().invoke(
        app,
        [
            "proposal",
            "preview-github-fixture",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--issue",
            "102",
            "--format",
            "json",
        ],
    )
    assert denied.exit_code == 1
    assert denied.stdout == ""
    assert "denied" in denied.stderr

    monkeypatch.setattr(policy_evaluator, "evaluate_policy", real_evaluate)

    def fail(_preview) -> str:
        raise RuntimeError("private formatter canary")

    monkeypatch.setattr(cli, "format_json_proposal_preview", fail)
    failed = CliRunner().invoke(
        app,
        [
            "proposal",
            "preview-github-fixture",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--issue",
            "101",
            "--format",
            "json",
        ],
    )
    assert failed.exit_code == 1
    assert failed.stdout == ""
    assert "private formatter canary" not in failed.output


def test_invalid_format_is_rejected_before_source_resolution(tmp_path, monkeypatch) -> None:
    import sentinel.proposals.preview as preview_module

    database, store_root = promoted_case(tmp_path, name="cr2-c-invalid-format")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("source resolution must not happen before format validation")

    monkeypatch.setattr(preview_module, "resolve_github_fixture_public_read", forbidden)
    result = CliRunner().invoke(
        app,
        [
            "proposal",
            "preview-github-fixture",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--issue",
            "101",
            "--format",
            "yaml",
        ],
    )
    assert result.exit_code != 0
    assert result.stdout == ""
    assert "yaml" in result.output


def test_missing_or_corrupt_verified_blob_fails_without_fixture_fallback(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-c-missing-blob")
    digest = EXPECTED_MANIFEST.items[0].content_sha256
    blob_path = store_root / "public-v1" / "sha256" / f"{digest}.blob"
    original_blob = blob_path.read_bytes()
    blob_path.write_bytes(b"corrupt synthetic blob")

    result = CliRunner().invoke(
        app,
        [
            "proposal",
            "preview-github-fixture",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--issue",
            "101",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == "Proposal preview failed: Verified synthetic source is unavailable.\n"
    assert str(store_root) not in result.stderr
    assert "parser reports" not in result.output
    blob_path.write_bytes(original_blob)


def test_corrupt_database_fails_with_bounded_empty_output(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-c-corrupt-database")
    database.write_bytes(b"not a SQLite database")

    result = CliRunner().invoke(
        app,
        [
            "proposal",
            "preview-github-fixture",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--issue",
            "102",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == "Proposal preview failed: Verified synthetic source is unavailable.\n"
    assert str(database) not in result.stderr


def test_public_preview_api_rejects_invalid_issue_without_reading_source(
    tmp_path, monkeypatch
) -> None:
    import sentinel.proposals.preview as preview_module

    database, store_root = promoted_case(tmp_path, name="cr2-c-api-invalid-issue")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("invalid issue must fail before reading")

    monkeypatch.setattr(preview_module, "resolve_github_fixture_public_read", forbidden)
    try:
        build_github_issue_proposal_preview(database, store_root=store_root, issue_number=104)
    except ProposalPreviewError as error:
        assert error.code is ProposalPreviewErrorCode.INVALID_SELECTION
    else:
        raise AssertionError("invalid issue was accepted")
