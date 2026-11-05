from __future__ import annotations

import json
from types import SimpleNamespace

from typer.testing import CliRunner

from sentinel import cli
from sentinel.readers.source_status_types import SourceCapabilityId

runner = CliRunner()


def test_source_status_is_nested_and_preserves_existing_commands() -> None:
    status_help = runner.invoke(cli.app, ["source", "status", "--help"])
    source_help = runner.invoke(cli.app, ["source", "--help"])
    root_help = runner.invoke(cli.app, ["--help"])
    assert status_help.exit_code == 0
    assert "--format" in status_help.stdout
    assert source_help.exit_code == 0
    for command in ("inspect-file", "search-files", "parse-job-alert", "review-job-alerts"):
        assert command in source_help.stdout
    assert root_help.exit_code == 0
    for command in ("version", "init", "doctor", "demo", "brief", "task", "fixture-sync"):
        assert command in root_help.stdout


def test_text_and_json_are_deterministic_and_report_fixture_vs_live_status() -> None:
    first_text = runner.invoke(cli.app, ["source", "status", "--format", "text"])
    second_text = runner.invoke(cli.app, ["source", "status", "--format", "text"])
    first_json = runner.invoke(cli.app, ["source", "status", "--format", "json"])
    second_json = runner.invoke(cli.app, ["source", "status", "--format", "json"])
    assert first_text.exit_code == second_text.exit_code == 0
    assert first_json.exit_code == second_json.exit_code == 0
    assert first_text.stdout == second_text.stdout
    assert first_json.stdout == second_json.stdout
    assert "Gmail fixture" in first_text.stdout
    assert "NOT IMPLEMENTED" in first_text.stdout
    document = json.loads(first_json.stdout)
    assert document["schema_version"] == "sentinel.source-capability-status.v1"
    assert document["safe_defaults_state"] == "VERIFIED"
    assert document["live_sources_enabled"] is False
    assert document["external_writes_enabled"] is False
    capabilities = {item["capability_id"]: item for item in document["capabilities"]}
    assert capabilities[SourceCapabilityId.GMAIL_FIXTURE.value]["readiness"] == "FIXTURE_READY"
    assert (
        capabilities[SourceCapabilityId.GMAIL_LIVE_READ.value]["account_check_state"]
        == "NOT_CHECKED"
    )
    assert "password" not in first_json.stdout.lower()
    assert "@" not in first_json.stdout
    for private_canary in (
        "SYNTHETIC_SUBJECT_CANARY",
        "SYNTHETIC_PRIVATE_BODY_CANARY",
        "Synthetic parser issue report",
        "Synthetic focus review",
        "ignore prior instructions",
        "ignore previous instructions",
    ):
        assert private_canary not in first_json.stdout
        assert private_canary not in first_text.stdout


def test_source_status_omits_fixture_titles_bodies_paths_and_account_names() -> None:
    from sentinel.readers.calendar_fixture import read_packaged_calendar_fixture
    from sentinel.readers.github_fixture import read_packaged_github_fixture
    from sentinel.readers.gmail_fixture import read_packaged_gmail_fixture

    fixture_values = [
        *(
            value
            for message in read_packaged_gmail_fixture().messages
            for value in (message.subject, message.body_text)
        ),
        *(
            value
            for issue in read_packaged_github_fixture().issues
            for value in (issue.title, issue.body_text)
        ),
        *(
            value
            for event in read_packaged_calendar_fixture().events
            for value in (event.summary, event.description_text)
        ),
    ]
    result = runner.invoke(cli.app, ["source", "status", "--format", "json"])
    assert result.exit_code == 0
    assert all(value not in result.stdout for value in fixture_values)
    assert "C:" not in result.stdout
    assert '"account_check_state":"NOT_CHECKED"' in result.stdout


def test_invalid_format_is_rejected_before_fixture_validation(monkeypatch) -> None:
    from sentinel.readers import source_status

    def fail_if_read() -> None:
        raise AssertionError("fixture reader must not run for an invalid format")

    monkeypatch.setattr(source_status.gmail_fixture, "read_packaged_gmail_fixture", fail_if_read)
    result = runner.invoke(cli.app, ["source", "status", "--format", "xml"])
    assert result.exit_code != 0
    assert result.stdout == ""
    assert "text or json" in result.stderr


def test_fixture_integrity_failure_returns_complete_report_and_unhealthy_exit(monkeypatch) -> None:
    from sentinel.readers import source_status

    def broken_fixture():
        raise RuntimeError(r"C:\private\mail.json SECRET_CANARY body")

    monkeypatch.setattr(source_status.gmail_fixture, "read_packaged_gmail_fixture", broken_fixture)
    result = runner.invoke(cli.app, ["source", "status", "--format", "json"])
    assert result.exit_code != 0
    assert result.stderr == ""
    document = json.loads(result.stdout)
    gmail = next(
        item for item in document["capabilities"] if item["capability_id"] == "gmail.fixture"
    )
    assert gmail["readiness"] == "FIXTURE_INVALID"
    assert len(document["capabilities"]) == 14
    assert "SECRET_CANARY" not in result.stdout
    assert "mail.json" not in result.stdout


def test_invalid_bundled_defaults_produce_complete_failed_report(monkeypatch) -> None:
    from sentinel.readers import source_status

    monkeypatch.setattr(source_status, "load_bundled_defaults", lambda: SimpleNamespace())
    result = runner.invoke(cli.app, ["source", "status", "--format", "json"])
    assert result.exit_code == 1
    assert result.stderr == ""
    document = json.loads(result.stdout)
    assert document["validation"] == "FAILED"
    assert document["safe_defaults_state"] == "INVALID"
    assert document["live_sources_enabled"] is None
    assert document["external_writes_enabled"] is None
    assert len(document["capabilities"]) == 14
