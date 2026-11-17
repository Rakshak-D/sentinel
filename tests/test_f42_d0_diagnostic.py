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

EXPECTED_MANIFEST_SHA256 = "d9817d20bf92855eeb6d89123d87ac8872bb860840c6e02736a7dc250534e8bd"
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
EXPECTED_ORACLE_SHA256 = "8cd02318482d926ee32c047129f0368ddfd5b435e5c20a60cf682fa5c9719b29"


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
        item["status"] != "PASS"
        for item in report["coverage"]
        if item["status"] in {"NOT_IMPLEMENTED", "BLOCKED", "NOT_EVALUATED"}
    )


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


def test_current_fingerprint_drift_fails_without_partial_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(runner, "policy_sha256", lambda: "0" * 64)

    exit_code = runner.main()
    captured = capsys.readouterr()

    assert exit_code != 0
    assert captured.out == ""
    assert captured.err == "F42_D0_FAILED POLICY_FINGERPRINT_MISMATCH\n"


def test_no_external_or_authority_gateway_is_called(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket
    import urllib.request

    from sentinel.credentials.broker import CredentialBroker
    from sentinel.gateways.model import ModelGateway
    from sentinel.gateways.tool import ToolGateway

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("prohibited integration invoked")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(ModelGateway, "generate", forbidden)
    monkeypatch.setattr(ToolGateway, "call", forbidden)
    monkeypatch.setattr(CredentialBroker, "status", forbidden)
    monkeypatch.setattr(CredentialBroker, "resolve_for_test", forbidden)

    report = runner.run_diagnostic()
    assert report.get("summary") == {"executed": 16, "passed": 16, "failed": 0}

