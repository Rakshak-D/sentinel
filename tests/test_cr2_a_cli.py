import os
import subprocess
import sys
from pathlib import Path

from typer.main import get_command
from typer.testing import CliRunner

from sentinel.cli import app

_SYNTHETIC_PROPOSAL_ID = "00000000-0000-4000-8000-000000000001"


def _assert_typer_rejects_approval_attempt(arguments: list[str]) -> None:
    root_command = get_command(app)
    assert "approve" not in root_command.commands

    result = CliRunner().invoke(app, arguments, input="yes\n")
    assert result.exit_code != 0
    assert result.stdout == ""


def _assert_installed_cli_rejects_approval_attempt(
    working_directory: Path,
    arguments: list[str],
    *,
    approval_environment_input: bool = False,
) -> None:
    root_command = get_command(app)
    assert "approve" not in root_command.commands

    executable = Path(sys.executable).with_name("sentinel.exe")
    assert executable.is_file()

    environment = os.environ.copy()
    environment.pop("SENTINEL_APPROVE", None)
    if approval_environment_input:
        # Synthetic AB02 attack input named by the Blueprint; this is not an
        # implemented or specified Sentinel environment-variable contract.
        environment["SENTINEL_APPROVE"] = "1"

    before_names = {path.name for path in working_directory.iterdir()}
    result = subprocess.run(
        [str(executable), *arguments],
        input="yes\n",
        text=True,
        capture_output=True,
        cwd=working_directory,
        env=environment,
        timeout=10,
        check=False,
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert {path.name for path in working_directory.iterdir()} == before_names


def test_ab01_redirected_stdin_cannot_reach_approval_command(tmp_path: Path) -> None:
    arguments = ["approve", _SYNTHETIC_PROPOSAL_ID]

    _assert_typer_rejects_approval_attempt(arguments)
    _assert_installed_cli_rejects_approval_attempt(tmp_path, arguments)


def test_ab02_yes_and_synthetic_approval_environment_cannot_bypass_approval(
    tmp_path: Path,
) -> None:
    arguments = ["approve", _SYNTHETIC_PROPOSAL_ID, "--yes"]

    _assert_typer_rejects_approval_attempt(arguments)
    _assert_installed_cli_rejects_approval_attempt(
        tmp_path,
        arguments,
        approval_environment_input=True,
    )


def test_policy_status_text_and_json_are_deterministic_and_agree() -> None:
    runner = CliRunner()
    text = runner.invoke(app, ["policy", "status", "--format", "text"])
    json_one = runner.invoke(app, ["policy", "status", "--format", "json"])
    json_two = runner.invoke(app, ["policy", "status", "--format", "json"])
    assert text.exit_code == json_one.exit_code == json_two.exit_code == 0
    assert "Schema: sentinel.policy-status.v4" in text.stdout
    assert (
        "P00:DENY -> P01:DENY -> P02:DENY -> P03:DENY -> "
        "P17:DENY -> P09:DENY -> P04:ALLOW -> P06:ALLOW -> P12:DENY"
    ) in text.stdout
    assert "Bounded PUBLIC read route: IMPLEMENTED" in text.stdout
    assert "C2: bounded pending-review proposal metadata only; no task or execution" in text.stdout
    assert "PENDING_HUMAN: UNAVAILABLE" in text.stdout
    assert "C5_SEND_EXTERNAL_EMAIL" in json_one.stdout
    assert '"default_outcome":"DENY"' in json_one.stdout
    assert '"bounded_public_read_state":"IMPLEMENTED"' in json_one.stdout
    assert '"bounded_proposal_persistence_state":"PENDING_REVIEW_ONLY"' in json_one.stdout
    assert '"pending_human_decisions":"UNAVAILABLE"' in json_one.stdout
    assert '"enforcement_integration":"INCOMPLETE"' in json_one.stdout
    assert json_one.stdout == json_two.stdout
    assert text.stderr == json_one.stderr == json_two.stderr == ""


def test_policy_status_rejects_unsupported_formats_and_bypass_flags() -> None:
    runner = CliRunner()
    invalid_format = runner.invoke(app, ["policy", "status", "--format", "yaml"])
    bypass = runner.invoke(app, ["policy", "status", "--unsafe"])
    assert invalid_format.exit_code != 0
    assert invalid_format.stdout == ""
    assert bypass.exit_code != 0
    assert bypass.stdout == ""


def test_policy_cli_failure_has_bounded_error_and_no_partial_stdout(monkeypatch) -> None:
    import sentinel.cli as cli

    def fail(_report):
        raise RuntimeError("private policy argument canary")

    monkeypatch.setattr(cli, "format_json_policy_status", fail)
    result = CliRunner().invoke(app, ["policy", "status", "--format", "json"])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == (
        "Policy status failed: static policy metadata could not be verified.\n"
    )
    assert "private policy argument canary" not in result.output
