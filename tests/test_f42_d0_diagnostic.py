"""Behavioral contract for the developer-only F42-D0 diagnostic."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.f42_d0 import runner

EXPECTED_MANIFEST_SHA256 = "832414dee819bcc5e0d4312b7e37e7772c99709eedf812e95c421bf69cc3830e"
EXPECTED_SCENARIO_IDS = (
    "p00-unknown-operation",
    "p00-capability-mismatch",
    "p00-unknown-source-trust",
    "p01-replay-denial",
    "priority-p00-before-p01",
    "priority-p01-before-p02",
    "p02-external-capability-off",
    "p03-secret-model-route-denial",
    "priority-p03-before-p17",
    "p17-secret-access-denial",
    "p09-missing-resolver-binding",
    "p09-binding-digest-mismatch",
    "p09-citation-set-mismatch",
    "p04-verified-public-read-allow",
    "p06-preview-allow",
    "p06-pending-persistence-allow",
)
EXPECTED_ORACLE_SHA256 = "1e78c28b2e39f274e785865afb6028e9258ef738898be9322ac79704f2e9b18a"


def test_fixed_cases_match_complete_original_policy_decisions() -> None:
    report = runner.run_diagnostic()
    oracle_path = Path(__file__).with_name("r2_a_policy_decision_snapshots.json")
    oracle = json.loads(oracle_path.read_bytes())

    assert report["schema_version"] == runner.REPORT_SCHEMA_VERSION
    assert report["decision_oracle_sha256"] == EXPECTED_ORACLE_SHA256
    assert report["summary"] == {"executed": 16, "passed": 16, "failed": 0}
    assert tuple(case["id"] for case in report["scenarios"]) == EXPECTED_SCENARIO_IDS
    assert all(case["status"] == "PASS" for case in report["scenarios"])
    for case in report["scenarios"]:
        expected = oracle[case["oracle_case"]]
        assert case["expected_decision"] == expected
        assert case["actual_decision"] == expected
        assert case["actual_decision"]["executable"] is False


def test_oracle_content_digest_is_independent_of_checkout_line_endings() -> None:
    oracle_path = Path(__file__).with_name("r2_a_policy_decision_snapshots.json")
    raw = oracle_path.read_bytes()
    lf_bytes = raw.replace(b"\r\n", b"\n")
    crlf_bytes = lf_bytes.replace(b"\n", b"\r\n")
    digests = []
    for candidate in (lf_bytes, crlf_bytes):
        parsed = json.loads(candidate)
        canonical = runner.canonical_json_bytes(parsed)
        digests.append(
            hashlib.sha256(
                b"sentinel.f42-d0-policy-decision-oracle.v1\x00" + canonical
            ).hexdigest()
        )

    assert digests == [EXPECTED_ORACLE_SHA256, EXPECTED_ORACLE_SHA256]


def test_report_digest_is_canonical_and_security_readiness_is_static() -> None:
    report = runner.run_diagnostic()
    digest = report.get("report_sha256")
    assert isinstance(digest, str)
    digest_payload = {key: value for key, value in report.items() if key != "report_sha256"}
    expected = hashlib.sha256(
        runner.REPORT_DOMAIN + runner.canonical_json_bytes(digest_payload)
    ).hexdigest()

    assert digest == expected
    assert report["readiness"] == {
        "diagnostic_only": True,
        "complete_f42": False,
        "cr2_release_complete": False,
        "production_activation_eligible": False,
        "owner_verification_available": False,
        "os_isolation_verified": False,
        "external_effects_enabled": False,
    }
    assert all(
        item["status"] in {"NOT_IMPLEMENTED", "BLOCKED", "NOT_EVALUATED"}
        for item in report["coverage"]
        if item["requirement_id"]
        in {
            "P12",
            "P05_P07_P08_P10_P13_P14_P15_P16",
            "P11",
            "F42_BLUEPRINT_48_SCENARIOS",
            "PRODUCTION_OWNER_VERIFICATION",
            "WINDOWS_SERVICE_ISOLATION",
        }
    )
    coverage_by_id = {item["requirement_id"]: item["status"] for item in report["coverage"]}
    assert coverage_by_id["P12"] == "NOT_EVALUATED"
    assert coverage_by_id["P11"] == "BLOCKED"
    assert coverage_by_id["PRODUCTION_OWNER_VERIFICATION"] == "BLOCKED"
    assert coverage_by_id["WINDOWS_SERVICE_ISOLATION"] == "BLOCKED"


def test_manifest_identity_and_order_are_independently_pinned() -> None:
    document = runner.load_manifest_document()
    assert runner.PINNED_MANIFEST_SHA256 == EXPECTED_MANIFEST_SHA256
    assert runner.manifest_sha256(document) == EXPECTED_MANIFEST_SHA256
    checked = runner.validate_manifest_document(document)
    assert tuple(item["id"] for item in checked["scenarios"]) == EXPECTED_SCENARIO_IDS

    reordered = copy.deepcopy(document)
    reordered["scenarios"].reverse()
    with pytest.raises(runner.DiagnosticFailure) as error:
        runner.validate_manifest_document(reordered)
    assert error.value.code == "MANIFEST_PIN_MISMATCH"


@pytest.mark.parametrize("field", ["rule_id", "reason_code"])
def test_changed_expected_decision_metadata_invalidates_manifest(field: str) -> None:
    document = copy.deepcopy(runner.load_manifest_document())
    document["scenarios"][0]["expected"][field] = "P12"

    with pytest.raises(runner.DiagnosticFailure) as error:
        runner.validate_manifest_document(document)
    assert error.value.code == "MANIFEST_PIN_MISMATCH"


def test_report_is_byte_identical_in_separate_processes() -> None:
    command = [sys.executable, "-m", "tools.f42_d0"]
    environment = os.environ.copy()
    first = subprocess.run(command, capture_output=True, check=False, env=environment, timeout=60)
    second = subprocess.run(command, capture_output=True, check=False, env=environment, timeout=60)

    assert first.returncode == 0
    assert second.returncode == 0
    assert first.stderr == second.stderr == b""
    assert first.stdout == second.stdout
    assert len(first.stdout) <= 64 * 1024
    assert json.loads(first.stdout)["schema_version"] == runner.REPORT_SCHEMA_VERSION


@pytest.mark.parametrize(
    ("fingerprint_function", "expected_code"),
    [
        ("policy_sha256", "POLICY_FINGERPRINT_MISMATCH"),
        ("builtin_registry_sha256", "POLICY_FINGERPRINT_MISMATCH"),
        ("config_sha256", "POLICY_FINGERPRINT_MISMATCH"),
    ],
)
def test_any_baseline_fingerprint_drift_fails_without_partial_stdout(
    fingerprint_function: str,
    expected_code: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(runner, fingerprint_function, lambda *_args: "0" * 64)

    exit_code = runner.main([])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert captured.out == ""
    assert captured.err == f"F42_D0_FAILED {expected_code}\n"


def test_current_fingerprint_drift_fails_without_partial_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(runner, "policy_sha256", lambda: "0" * 64)

    exit_code = runner.main([])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert captured.out == ""
    assert captured.err == "F42_D0_FAILED POLICY_FINGERPRINT_MISMATCH\n"


def test_modified_manifest_fails_with_bounded_error_and_empty_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    document = copy.deepcopy(runner.load_manifest_document())
    document["scenarios"][0]["expected"]["reason_code"] = "INVENTED_REASON"
    monkeypatch.setattr(runner, "load_manifest_document", lambda: document)

    exit_code = runner.main([])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == "F42_D0_FAILED MANIFEST_PIN_MISMATCH\n"


def test_no_external_or_authority_gateway_is_called(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket
    import urllib.request

    from sentinel.credentials.broker import CredentialBroker
    from sentinel.gateways.model import ModelGateway
    from sentinel.gateways.tool import ToolGateway
    from sentinel.owner_proof import service as owner_service
    from sentinel.proposals import persistence as proposal_persistence
    from sentinel.tasks import store as task_store

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("prohibited integration invoked")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(ModelGateway, "generate", forbidden)
    monkeypatch.setattr(ToolGateway, "call", forbidden)
    monkeypatch.setattr(CredentialBroker, "status", forbidden)
    monkeypatch.setattr(CredentialBroker, "resolve_for_test", forbidden)
    monkeypatch.setattr(owner_service, "verify_synthetic_assertion", forbidden)
    monkeypatch.setattr(proposal_persistence, "save_github_fixture_proposal", forbidden)
    monkeypatch.setattr(task_store, "create_local_task", forbidden)

    report = runner.run_diagnostic()
    assert report.get("summary") == {"executed": 16, "passed": 16, "failed": 0}


def test_rejects_arbitrary_cli_arguments_without_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = runner.main(["--database", "C:\\private.sqlite3"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == "F42_D0_FAILED ARGUMENTS_UNSUPPORTED\n"


def test_failure_text_is_reduced_to_a_fixed_code() -> None:
    failure = runner.DiagnosticFailure("C:\\sensitive\\path\nraw body")
    assert str(failure) == "DIAGNOSTIC_INTERNAL_FAILURE"
    assert failure.code == "DIAGNOSTIC_INTERNAL_FAILURE"


def test_fixture_binding_is_fixed_and_temporary_workspace_is_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_temporary_directory = runner.TemporaryDirectory
    created_paths: list[Path] = []

    def tracked_temporary_directory(*args: object, **kwargs: object):
        manager = real_temporary_directory(*args, **kwargs)
        created_paths.append(Path(manager.name))
        return manager

    monkeypatch.setattr(runner, "TemporaryDirectory", tracked_temporary_directory)
    report = runner.run_diagnostic()

    assert {
        key: report["fixture"][key]
        for key in (
            "fixture_id",
            "fixture_version",
            "fixture_sha256",
            "manifest_version",
            "manifest_sha256",
            "source_set_sha256",
            "source_count",
            "citation_count",
        )
    } == {
        "fixture_id": "example-owner/fixture-project",
        "fixture_version": "sentinel.github-issues-fixture.v1",
        "fixture_sha256": "7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1",
        "manifest_version": "sentinel.github-fixture-persistence-manifest.v1",
        "manifest_sha256": "645aecaedd14d8e6c6071b9d8c32a5d91f664c715799191303eac315d6f9c08f",
        "source_set_sha256": "603c7bdf5a58702292b2b0966f9d67cf90f06c8a671d9ef76831fc43d8ccf69f",
        "source_count": 3,
        "citation_count": 9,
    }
    assert created_paths
    assert all(not path.exists() for path in created_paths)


def test_report_contains_no_fixture_body_or_absolute_checkout_path() -> None:
    from sentinel.readers.github_fixture import read_packaged_github_fixture

    report_bytes = runner.canonical_json_bytes(runner.run_diagnostic())
    fixture = read_packaged_github_fixture()
    for issue in fixture.issues:
        assert issue.normalized_source.original_bytes not in report_bytes
    assert str(Path.cwd()).encode("utf-8") not in report_bytes


def test_report_exposes_the_verified_body_free_source_and_citation_binding() -> None:
    from sentinel.contracts import SensitivityLabel, TrustLabel

    fixture = runner.run_diagnostic()["fixture"]
    assert fixture.get("source_set_sha256") == (
        "603c7bdf5a58702292b2b0966f9d67cf90f06c8a671d9ef76831fc43d8ccf69f"
    )
    sources = fixture.get("sources")
    assert isinstance(sources, list) and len(sources) == 3
    assert sum(len(item["citations"]) for item in sources) == 9
    assert all(item["trust"] == TrustLabel.T4_EXTERNAL.value for item in sources)
    assert all(item["sensitivity"] == SensitivityLabel.PUBLIC.value for item in sources)
    assert all(
        set(item)
        == {
            "source_id",
            "item_id",
            "provider_item_id",
            "content_sha256",
            "trust",
            "sensitivity",
            "citations",
        }
        for item in sources
    )
    assert all(
        set(citation) == {"span_id", "start_byte", "end_byte", "text_sha256"}
        for item in sources
        for citation in item["citations"]
    )


def test_decision_mismatch_is_not_reported_as_verified_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_evaluate = runner.evaluate_policy

    def return_denial_for_public_read(request, context, *, evidence_binding=None):
        if (
            request.operation_id == "sentinel.synthetic.read.public"
            and len(request.evidence_span_ids) == 9
        ):
            request = request.model_copy(update={"source_binding_sha256": "f" * 64})
        return original_evaluate(
            request=request,
            context=context,
            evidence_binding=evidence_binding,
        )

    monkeypatch.setattr(runner, "evaluate_policy", return_denial_for_public_read)
    report = runner.run_diagnostic()
    coverage = {item["requirement_id"]: item for item in report["coverage"]}

    assert report["summary"]["failed"] > 0
    assert coverage["P04"]["status"] == "FAILED_IN_BOUNDED_DIAGNOSTIC"
    assert coverage["P04"]["reason_code"] == "DECISION_MISMATCH"
    assert report["readiness"]["production_activation_eligible"] is False
