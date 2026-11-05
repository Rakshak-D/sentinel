from __future__ import annotations

import json

from typer.testing import CliRunner

from sentinel.cli import app
from tests.test_cr1_p_batch import _candidate, _selected_files


def test_nested_command_is_available_and_existing_source_commands_remain(tmp_path) -> None:
    runner = CliRunner()
    source_help = runner.invoke(app, ["source", "--help"])
    command_help = runner.invoke(app, ["source", "review-job-alerts", "--help"])
    assert source_help.exit_code == 0
    assert "parse-job-alert" in source_help.stdout
    assert "inspect-file" in source_help.stdout
    assert "search-files" in source_help.stdout
    assert "review-job-alerts" in source_help.stdout
    assert command_help.exit_code == 0
    assert "--allow-root" in command_help.stdout
    assert "--file" in command_help.stdout
    assert "--show-fields" in command_help.stdout
    assert runner.invoke(app, ["task", "--help"]).exit_code == 0
    assert runner.invoke(app, ["fixture-sync", "--help"]).exit_code == 0
    assert runner.invoke(app, ["brief", "--help"]).exit_code == 0


def test_cli_default_hides_private_values_and_json_is_deterministic(tmp_path) -> None:
    root, paths = _selected_files(
        tmp_path,
        [
            _candidate("PRIVATE_FICTIONAL_COMPANY", "PRIVATE_FICTIONAL_ROLE"),
            "not an alert\n",
        ],
    )
    runner = CliRunner()
    base = ["source", "review-job-alerts", "--allow-root", str(root)]
    for path in paths:
        base.extend(["--file", str(path)])
    hidden = runner.invoke(app, base)
    first_json = runner.invoke(app, [*base, "--format", "json"])
    second_json = runner.invoke(app, [*base, "--format", "json"])
    shown = runner.invoke(app, [*base, "--show-fields", "--format", "json"])
    assert hidden.exit_code == first_json.exit_code == second_json.exit_code == shown.exit_code == 0
    assert "PRIVATE_FICTIONAL_COMPANY" not in hidden.stdout
    assert "PRIVATE_FICTIONAL_ROLE" not in hidden.stdout
    assert first_json.stdout == second_json.stdout
    assert json.loads(first_json.stdout)["classification_counts"]["candidate"] == 1
    assert json.loads(first_json.stdout)["classification_counts"]["no_match"] == 1
    assert "PRIVATE_FICTIONAL_COMPANY" in shown.stdout
    assert str(root) not in hidden.stdout and paths[0].name not in hidden.stdout


def test_unknown_format_fails_before_source_reads(monkeypatch, tmp_path) -> None:
    from sentinel import cli

    calls = 0

    def fail_if_review(*, allowed_root, file_paths):
        nonlocal calls
        calls += 1
        raise AssertionError("batch API must not run")

    monkeypatch.setattr(cli, "review_selected_job_alerts", fail_if_review)
    result = CliRunner().invoke(
        app,
        [
            "source",
            "review-job-alerts",
            "--allow-root",
            str(tmp_path),
            "--file",
            str(tmp_path / "missing.txt"),
            "--format",
            "yaml",
        ],
    )
    assert result.exit_code != 0
    assert result.stdout == ""
    assert "output format must be text or json" in result.stderr
    assert calls == 0


def test_late_file_failure_emits_no_partial_output_or_private_canaries(tmp_path) -> None:
    root, paths = _selected_files(tmp_path, [_candidate("PRIVATE_CANARY", "Engineer")])
    missing = root / "late-missing.md"
    result = CliRunner().invoke(
        app,
        [
            "source",
            "review-job-alerts",
            "--allow-root",
            str(root),
            "--file",
            str(paths[0]),
            "--file",
            str(missing),
        ],
    )
    assert result.exit_code != 0
    assert result.stdout == ""
    assert "PRIVATE_CANARY" not in result.stderr
    assert str(root) not in result.stderr
    assert "traceback" not in result.stderr.lower()


def test_late_citation_failure_emits_no_partial_success_output(monkeypatch, tmp_path) -> None:
    from dataclasses import replace

    from sentinel.extraction import batch

    root, paths = _selected_files(
        tmp_path,
        [
            _candidate("PRIVATE_FIRST_CANARY", "Engineer"),
            _candidate("PRIVATE_LAST_CANARY", "Analyst"),
        ],
    )
    real_parse = batch.parse_local_job_alert

    def tamper_later(*, allowed_root, file_path):
        result = real_parse(allowed_root=allowed_root, file_path=file_path)
        if file_path == paths[-1]:
            field = result.fields[0]
            evidence = replace(field.evidence, end_byte=field.evidence.end_byte + 1)
            return replace(result, fields=(replace(field, evidence=evidence), *result.fields[1:]))
        return result

    monkeypatch.setattr(batch, "parse_local_job_alert", tamper_later)
    args = ["source", "review-job-alerts", "--allow-root", str(root)]
    for path in paths:
        args.extend(["--file", str(path)])
    result = CliRunner().invoke(app, args)
    assert result.exit_code != 0
    assert result.stdout == ""
    assert "PRIVATE_FIRST_CANARY" not in result.stderr
    assert "PRIVATE_LAST_CANARY" not in result.stderr
    assert str(root) not in result.stderr
