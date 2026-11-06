from typer.testing import CliRunner

from sentinel.cli import app


def test_policy_status_text_and_json_are_deterministic_and_agree() -> None:
    runner = CliRunner()
    text = runner.invoke(app, ["policy", "status", "--format", "text"])
    json_one = runner.invoke(app, ["policy", "status", "--format", "json"])
    json_two = runner.invoke(app, ["policy", "status", "--format", "json"])
    assert text.exit_code == json_one.exit_code == json_two.exit_code == 0
    assert "Schema: sentinel.policy-status.v2" in text.stdout
    assert (
        "P00:DENY -> P01:DENY -> P02:DENY -> P03:DENY -> "
        "P17:DENY -> P09:DENY -> P04:ALLOW -> P12:DENY"
    ) in text.stdout
    assert "Bounded PUBLIC read route: IMPLEMENTED" in text.stdout
    assert "PENDING_HUMAN: UNAVAILABLE" in text.stdout
    assert "C5_SEND_EXTERNAL_EMAIL" in json_one.stdout
    assert '"default_outcome":"DENY"' in json_one.stdout
    assert '"bounded_public_read_state":"IMPLEMENTED"' in json_one.stdout
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
