from pathlib import Path

from typer.testing import CliRunner

from sentinel.cli import app
from tests.cr1_r_workspace import new_database


def test_fixture_workspace_nested_cli_is_registered() -> None:
    result = CliRunner().invoke(app, ["fixture-workspace", "--help"])
    assert result.exit_code == 0
    assert "prepare" in result.output
    assert "verify" in result.output


def test_prepare_and_verify_cli_output_is_bounded(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "cli")
    runner = CliRunner()
    args = ["--database", str(database), "--store-root", str(store_root)]
    prepared = runner.invoke(app, ["fixture-workspace", "prepare", *args])
    verified = runner.invoke(app, ["fixture-workspace", "verify", *args])
    repeated = runner.invoke(app, ["fixture-workspace", "prepare", *args])

    assert prepared.exit_code == verified.exit_code == repeated.exit_code == 0
    assert "Fixture workspace prepared" in prepared.output
    assert "synthetic workspace ready" in verified.output
    assert "Fixture workspace already prepared" in repeated.output
    assert "Synthetic cursor: 0/3 READY" in repeated.output
    for output in (prepared.output, verified.output, repeated.output):
        assert str(database) not in output
        assert str(store_root) not in output
        assert "Live integrations: not configured" in output


def test_verify_incomplete_returns_failure_without_success_output(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "cli-incomplete")
    result = CliRunner().invoke(
        app,
        [
            "fixture-workspace",
            "verify",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
        ],
    )
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "incomplete" in result.stderr.casefold()
