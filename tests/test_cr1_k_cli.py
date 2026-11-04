from pathlib import Path

from typer.testing import CliRunner

from sentinel.cli import app
from tests.cr1_k_support import promoted_case


def test_fixture_sync_cli_setup_advance_and_status(tmp_path: Path) -> None:
    database, store_root = promoted_case(tmp_path, name="cli")
    runner = CliRunner()
    setup = runner.invoke(
        app,
        ["fixture-sync", "setup", "--database", str(database), "--store-root", str(store_root)],
    )
    assert setup.exit_code == 0, setup.output
    advance = runner.invoke(
        app,
        [
            "fixture-sync",
            "advance",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--expected-generation",
            "0",
        ],
    )
    assert advance.exit_code == 0, advance.output
    status = runner.invoke(
        app,
        ["fixture-sync", "status", "--database", str(database), "--store-root", str(store_root)],
    )
    assert status.exit_code == 0, status.output
    assert '"generation":1' in status.output
    assert '"item_count":1' in status.output
    assert '"span_count":3' in status.output


def test_fixture_sync_help_is_nested_and_explicit(tmp_path: Path) -> None:
    runner = CliRunner()
    root = runner.invoke(app, ["--help"])
    group = runner.invoke(app, ["fixture-sync", "--help"])
    assert root.exit_code == 0
    assert "fixture-sync" in root.output
    assert group.exit_code == 0
    assert all(name in group.output for name in ("setup", "advance", "status"))
