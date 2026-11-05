from __future__ import annotations

from typer.testing import CliRunner

from sentinel.cli import app


def test_triage_command_is_nested_under_source_and_shows_safe_summary(tmp_path) -> None:
    runner = CliRunner()
    source_help = runner.invoke(app, ["source", "--help"])
    command_help = runner.invoke(app, ["source", "triage-job-alerts", "--help"])
    assert source_help.exit_code == command_help.exit_code == 0
    assert "triage-job-alerts" in source_help.stdout
    assert all(
        flag in command_help.stdout
        for flag in ("--allow-root", "--file", "--format", "--show-fields")
    )

    root = tmp_path / "alerts"
    root.mkdir()
    first = root / "first.txt"
    first.write_text("Company: Fictional Corp\nRole: Engineer\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "source",
            "triage-job-alerts",
            "--allow-root",
            str(root),
            "--file",
            str(first),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    assert result.stderr == ""
    assert "Fictional Corp" not in result.stdout


def test_invalid_format_and_late_source_failure_have_no_partial_output(
    tmp_path, monkeypatch
) -> None:
    import sentinel.cli as cli

    root = tmp_path / "alerts"
    root.mkdir()
    first = root / "first.txt"
    first.write_text("Company: Canary Corp\nRole: Engineer\n", encoding="utf-8")

    def forbidden(**_kwargs):
        raise AssertionError("invalid format must be rejected before reading files")

    monkeypatch.setattr(cli, "triage_selected_job_alerts", forbidden)
    invalid = CliRunner().invoke(
        app,
        [
            "source",
            "triage-job-alerts",
            "--allow-root",
            str(root),
            "--file",
            str(first),
            "--format",
            "yaml",
        ],
    )
    assert invalid.exit_code != 0
    assert invalid.stdout == ""
    assert "Traceback" not in invalid.stderr
    monkeypatch.undo()

    missing = root / "late-missing.txt"
    failed = CliRunner().invoke(
        app,
        [
            "source",
            "triage-job-alerts",
            "--allow-root",
            str(root),
            "--file",
            str(first),
            "--file",
            str(missing),
            "--format",
            "text",
        ],
    )
    assert failed.exit_code != 0
    assert failed.stdout == ""
    assert str(root) not in failed.stderr
    assert "Canary Corp" not in failed.stderr
    assert "Traceback" not in failed.stderr
