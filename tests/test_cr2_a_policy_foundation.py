"""Behavior-first checks for the CR2-A policy foundation."""

from typer.testing import CliRunner

import sentinel.policy as policy
from sentinel.cli import app


def test_policy_module_exposes_the_closed_c0_to_c6_capability_vocabulary() -> None:
    capability = getattr(policy, "Capability", None)

    assert capability is not None, "the policy module must expose its capability vocabulary"
    assert tuple(item.value for item in capability) == (
        "C0_READ_PUBLIC",
        "C1_READ_PRIVATE",
        "C2_WRITE_LOCAL_PROPOSAL",
        "C3_WRITE_LOCAL_ACCEPTED",
        "C4_WRITE_EXTERNAL_DRAFT_OR_GITHUB",
        "C5_SEND_EXTERNAL_EMAIL",
        "C6_ACCESS_SECRET",
    )


def test_policy_status_is_a_read_only_deterministic_cli_command() -> None:
    runner = CliRunner()

    text_result = runner.invoke(app, ["policy", "status", "--format", "text"])
    json_result = runner.invoke(app, ["policy", "status", "--format", "json"])

    assert text_result.exit_code == 0, text_result.output
    assert json_result.exit_code == 0, json_result.output
    assert "P12" in text_result.output
    assert '"schema_version":"sentinel.policy-status.v3"' in json_result.output
    assert json_result.output == runner.invoke(app, ["policy", "status", "--format", "json"]).output
