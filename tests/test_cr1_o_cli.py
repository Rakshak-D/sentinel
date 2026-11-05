from __future__ import annotations

import json

from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.extraction import parse_gmail_fixture_job_alert, parse_local_job_alert
from sentinel.extraction.formatters import format_json_job_alert, format_text_job_alert
from tests.cr1_o_support import gmail_message


def test_local_adapter_reads_one_explicit_markdown_body_without_rewriting(tmp_path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    path = root / "alert.md"
    body = "Job opportunity\r\nCompany: Mistral Fictional\r\nRole: 日本語設計者\r\n"
    path.write_bytes(body.encode())
    before = path.read_bytes()
    result = parse_local_job_alert(allowed_root=root, file_path=path)
    assert result.status.value == "CANDIDATE"
    assert result.provider_id == "local.file"
    assert result.synthetic_data is False
    assert result.normalized_source.original_bytes == before
    assert path.read_bytes() == before


def test_default_renderers_omit_private_values_and_subject_or_body() -> None:
    result = parse_gmail_fixture_job_alert(
        gmail_message(
            "Company: PRIVATE_COMPANY_CANARY\nRole: PRIVATE_ROLE_CANARY\n",
            subject="PRIVATE_SUBJECT_CANARY",
        )
    )
    text = format_text_job_alert(result)
    document = json.loads(format_json_job_alert(result))
    encoded = json.dumps(document)
    for canary in ("PRIVATE_COMPANY_CANARY", "PRIVATE_ROLE_CANARY", "PRIVATE_SUBJECT_CANARY"):
        assert canary not in text
        assert canary not in encoded
    assert document["schema_version"] == "sentinel.job-alert-extraction.v1"
    assert document["values_included"] is False


def test_opt_in_renderers_include_only_verified_field_values() -> None:
    result = parse_gmail_fixture_job_alert(
        gmail_message("Company: Fictional Systems\nRole: Systems Analyst\n")
    )
    text = format_text_job_alert(result, show_fields=True)
    document = json.loads(format_json_job_alert(result, show_fields=True))
    assert '"Fictional Systems"' in text
    assert '"Systems Analyst"' in text
    assert document["values_included"] is True
    assert [item["value"] for item in document["fields"] if "value" in item] == [
        "Fictional Systems",
        "Systems Analyst",
    ]


def test_nested_cli_command_is_available_and_existing_commands_remain() -> None:
    runner = CliRunner()
    root = runner.invoke(app, ["--help"])
    source = runner.invoke(app, ["source", "--help"])
    command = runner.invoke(app, ["source", "parse-job-alert", "--help"])
    assert root.exit_code == 0 and "source" in root.stdout
    assert source.exit_code == 0 and "inspect-file" in source.stdout
    assert source.exit_code == 0 and "search-files" in source.stdout
    assert command.exit_code == 0
    assert "--show-fields" in command.stdout
    assert runner.invoke(app, ["brief", "github-fixture", "--help"]).exit_code == 0
    assert runner.invoke(app, ["task", "--help"]).exit_code == 0
    assert runner.invoke(app, ["fixture-sync", "--help"]).exit_code == 0


def test_cli_default_hides_fields_and_show_fields_is_explicit(tmp_path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    path = root / "alert.txt"
    path.write_text("Company: CLI Private Canary\nRole: Fictional Reviewer\n", encoding="utf-8")
    runner = CliRunner()
    args = ["source", "parse-job-alert", "--allow-root", str(root), "--file", str(path)]
    hidden = runner.invoke(app, args)
    shown = runner.invoke(app, [*args, "--show-fields", "--format", "json"])
    assert hidden.exit_code == 0
    assert "CLI Private Canary" not in hidden.stdout
    assert shown.exit_code == 0
    assert json.loads(shown.stdout)["values_included"] is True
    assert "CLI Private Canary" in shown.stdout


def test_cli_failure_has_no_stdout_or_path_leak(tmp_path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    missing = root / "missing.txt"
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["source", "parse-job-alert", "--allow-root", str(root), "--file", str(missing)],
    )
    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(root) not in result.stderr
    assert "traceback" not in result.stderr.lower()


def test_invalid_format_is_rejected_before_local_file_read(monkeypatch, tmp_path) -> None:
    from sentinel import cli

    calls = 0

    def fail_if_read(*, allowed_root, file_path):
        nonlocal calls
        calls += 1
        raise AssertionError("reader should not run")

    monkeypatch.setattr(cli, "parse_local_job_alert", fail_if_read)
    result = CliRunner().invoke(
        app,
        [
            "source",
            "parse-job-alert",
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
    assert "format must be text or json" in result.stderr
    assert calls == 0


def test_late_citation_verification_failure_emits_no_partial_cli_output(
    monkeypatch, tmp_path
) -> None:
    from dataclasses import replace as dataclass_replace

    from sentinel import cli
    from sentinel.extraction import parse_gmail_fixture_job_alert

    result_model = parse_gmail_fixture_job_alert(
        gmail_message("Company: CLI_CITATION_CANARY\nRole: Fictional Analyst\n")
    )
    company = result_model.fields[0]
    assert company.evidence is not None
    bad_evidence = dataclass_replace(company.evidence, start_byte=company.evidence.start_byte + 1)
    bad_company = dataclass_replace(company, evidence=bad_evidence)
    bad_result = dataclass_replace(
        result_model,
        fields=(bad_company, *result_model.fields[1:]),
    )
    monkeypatch.setattr(cli, "parse_local_job_alert", lambda **_kwargs: bad_result)
    root = tmp_path / "allowed"
    root.mkdir()
    path = root / "alert.txt"
    path.write_text("safe", encoding="utf-8")
    output = CliRunner().invoke(
        app,
        ["source", "parse-job-alert", "--allow-root", str(root), "--file", str(path)],
    )
    assert output.exit_code != 0
    assert output.stdout == ""
    assert "CLI_CITATION_CANARY" not in output.stderr
    assert str(root) not in output.stderr


def test_formatter_rejects_malformed_field_records_with_bounded_error() -> None:
    from dataclasses import replace as dataclass_replace

    import pytest

    from sentinel.extraction import JobAlertError

    result = parse_gmail_fixture_job_alert(gmail_message("Company: Aster\nRole: Engineer\n"))
    invalid_element = dataclass_replace(result, fields=(object(), *result.fields[1:]))
    invalid_identifier = dataclass_replace(
        result,
        fields=(
            result.fields[0],
            result.fields[1],
            dataclass_replace(result.fields[2], field_id="location"),
            *result.fields[3:],
        ),
    )
    for malformed in (invalid_element, invalid_identifier):
        with pytest.raises(JobAlertError):
            format_json_job_alert(malformed)
