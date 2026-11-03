"""CLI behavior tests for the deterministic synthetic demo command."""

import json

from typer.testing import CliRunner

import sentinel.cli as cli_module
import sentinel.demo.runner as demo_runner
from sentinel.cli import app
from sentinel.demo.runner import DemoExecutionError

runner = CliRunner()


def test_demo_is_listed_and_has_help() -> None:
    root = runner.invoke(app, ["--help"])
    help_result = runner.invoke(app, ["demo", "--help"])

    assert root.exit_code == 0
    assert "demo" in root.output
    assert help_result.exit_code == 0
    assert "synthetic" in help_result.output.casefold()


def test_demo_emits_one_valid_json_document_and_is_repeatable() -> None:
    first = runner.invoke(app, ["demo"])
    second = runner.invoke(app, ["demo"])

    assert first.exit_code == 0
    assert first.stderr == ""
    assert first.output.endswith("\n")
    document = json.loads(first.output)
    assert document["execution_mode"] == "DEMO"
    assert document["external_effects"] is False
    assert "Fictional note: sample-card-001" not in first.output
    assert "Ready for the local demonstration." not in first.output
    assert "SYNTHETIC_SECRET_INPUT_CANARY" not in first.output
    assert "SYNTHETIC_PRIVATE_INPUT_CANARY" not in first.output
    assert first.output == second.output


def test_demo_failure_has_no_partial_stdout_or_exception_text(
    monkeypatch,
) -> None:
    canary = "SYNTHETIC_EXCEPTION_SECRET_CANARY"

    def fail() -> None:
        raise DemoExecutionError(canary)

    monkeypatch.setattr(cli_module, "run_demo", fail)
    result = runner.invoke(app, ["demo"])

    assert result.exit_code != 0
    assert result.stdout == ""
    assert "Demo failed" in result.stderr
    assert canary not in result.output
    assert "Traceback" not in result.output


def test_missing_packaged_fixture_is_a_nonzero_path_free_cli_failure(
    monkeypatch,
) -> None:
    def missing_fixture() -> bytes:
        raise FileNotFoundError("C:\\private\\synthetic\\fixture.json")

    monkeypatch.setattr(demo_runner, "_read_fixture_resource", missing_fixture)
    result = runner.invoke(app, ["demo"])

    assert result.exit_code != 0
    assert result.stdout == ""
    assert result.stderr == "Demo failed: synthetic execution could not be verified.\n"
    assert "private" not in result.output
    assert "Traceback" not in result.output
