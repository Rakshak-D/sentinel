"""Behavioral tests for the supported Sentinel CLI surface."""

from importlib.metadata import PackageNotFoundError, entry_points, version

from typer.testing import CliRunner

from sentinel import __version__
from sentinel.cli import app

runner = CliRunner()


def test_help_exits_successfully_and_lists_version() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "version" in result.output


def test_help_lists_explicit_init_command() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "init" in result.output


def test_version_reports_package_metadata() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    try:
        expected = version("sentinel")
    except PackageNotFoundError:
        expected = __version__
    assert result.output.strip() == expected


def test_invalid_command_fails_cleanly() -> None:
    result = runner.invoke(app, ["not-a-command"])

    assert result.exit_code != 0
    assert "not-a-command" in result.output


def test_package_import_and_entry_point_are_available() -> None:
    assert __version__
    scripts = {point.name: point.value for point in entry_points(group="console_scripts")}
    assert scripts["sentinel"] == "sentinel.cli:app"
