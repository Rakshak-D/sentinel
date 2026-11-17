"""Characterization of the installed CLI contract before R2-B modularization."""

from __future__ import annotations

import json
from pathlib import Path

from typer.main import get_command
from typer.testing import CliRunner

import sentinel.cli as cli
from sentinel.storage.migrations import initialize_storage

SNAPSHOT_PATH = Path(__file__).with_name("r2_b_cli_characterization.json")
HELP_ENV = {
    "TERM": "dumb",
    "NO_COLOR": "1",
    "FORCE_COLOR": None,
    "TTY_COMPATIBLE": "0",
    "TTY_INTERACTIVE": "0",
}
runner = CliRunner()


def _safe_snapshot_value(value: object) -> object:
    if value is None or type(value) in (str, int, float, bool):
        return value
    return str(value)


def _annotation_name(parameter: object) -> str:
    annotation = parameter.type_descriptor.annotation  # type: ignore[attr-defined]
    if isinstance(annotation, type):
        return f"{annotation.__module__}.{annotation.__qualname__}"
    return str(annotation)


def _describe_command(command: object) -> dict[str, object]:
    params = []
    for parameter in command.params:  # type: ignore[attr-defined]
        params.append(
            {
                "name": parameter.name,
                "kind": parameter.param_type_name,
                "annotation": _annotation_name(parameter),
                "opts": list(parameter.opts),
                "secondary_opts": list(parameter.secondary_opts),
                "required": parameter.required,
                "default": _safe_snapshot_value(parameter.default),
                "nargs": parameter.nargs,
                "multiple": parameter.multiple,
                "is_flag": parameter.is_flag,
                "is_bool_flag": parameter.is_bool_flag,
                "min": _safe_snapshot_value(parameter.min),
                "max": _safe_snapshot_value(parameter.max),
                "help": parameter.help,
            }
        )
    result: dict[str, object] = {
        "name": command.name,  # type: ignore[attr-defined]
        "kind": "group" if hasattr(command, "commands") else "command",
        "help": command.help,  # type: ignore[attr-defined]
        "params": params,
    }
    if hasattr(command, "commands"):
        result["commands"] = [
            _describe_command(child) for child in command.commands.values()
        ]
    return result


def _command_paths(command: object, path: tuple[str, ...] = ()):
    yield path
    for name, child in getattr(command, "commands", {}).items():
        yield from _command_paths(child, (*path, name))


def _snapshot() -> dict[str, object]:
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


def test_complete_command_tree_and_help_match_original_snapshot() -> None:
    expected = _snapshot()
    root = get_command(cli.app)

    assert _describe_command(root) == expected["command_tree"]
    expected_help = expected["help"]
    assert isinstance(expected_help, dict)
    actual_paths = list(_command_paths(root))
    assert len(actual_paths) == len(expected_help) == 42

    for path in actual_paths:
        key = " ".join(path)
        result = runner.invoke(
            cli.app,
            [*path, "--help"],
            env=HELP_ENV,
            terminal_width=100,
            color=False,
        )
        assert {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        } == expected_help[key]


def test_representative_outputs_and_validation_errors_match_original_snapshot(
    tmp_path: Path,
) -> None:
    expected_outputs = _snapshot()["outputs"]
    assert isinstance(expected_outputs, dict)
    scenarios = {
        "version": ["version"],
        "demo": ["demo"],
        "policy_status_text": ["policy", "status", "--format", "text"],
        "policy_status_json": ["policy", "status", "--format", "json"],
        "source_status_text": ["source", "status", "--format", "text"],
        "source_status_json": ["source", "status", "--format", "json"],
        "calendar_fixture_text": ["source", "calendar-fixture", "--format", "text"],
        "calendar_fixture_json": ["source", "calendar-fixture", "--format", "json"],
        "missing_source_required_args": ["source", "parse-job-alert"],
        "invalid_due_timestamp": [
            "task",
            "add",
            "--database",
            str(tmp_path / "not-opened.sqlite3"),
            "--title",
            "Task",
            "--due-at",
            "2027-01-01T00:00:00",
            "--request-id",
            "0b79ddbb-4ad3-46e0-94bf-31a28c977e46",
        ],
    }
    for name, args in scenarios.items():
        result = runner.invoke(
            cli.app,
            args,
            env=HELP_ENV,
            terminal_width=100,
            color=False,
        )
        assert {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        } == expected_outputs[name]

    database = tmp_path / "auth-status.sqlite3"
    initialize_storage(database, create=True)
    for output_format in ("text", "json"):
        result = runner.invoke(
            cli.app,
            ["auth", "status", "--database", str(database), "--format", output_format],
            env=HELP_ENV,
            terminal_width=100,
            color=False,
        )
        assert {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        } == expected_outputs[f"auth_status_{output_format}"]


def test_cli_dispatch_keeps_run_demo_module_global_patchable(monkeypatch) -> None:
    class SyntheticReport:
        def to_json_bytes(self) -> bytes:
            return b'{"case":"module-global-dispatch"}'

    calls = 0

    def replacement():
        nonlocal calls
        calls += 1
        return SyntheticReport()

    monkeypatch.setattr(cli, "run_demo", replacement)
    result = runner.invoke(cli.app, ["demo"], env=HELP_ENV)

    assert calls == 1
    assert result.exit_code == 0
    assert result.stdout == '{"case":"module-global-dispatch"}\n'
    assert result.stderr == ""


def test_cli_dispatch_keeps_policy_renderer_patchable_and_stdout_atomic(monkeypatch) -> None:
    calls = 0

    def fail_after_report(_report) -> str:
        nonlocal calls
        calls += 1
        raise RuntimeError("private renderer diagnostic")

    monkeypatch.setattr(cli, "format_json_policy_status", fail_after_report)
    result = runner.invoke(
        cli.app,
        ["policy", "status", "--format", "json"],
        env=HELP_ENV,
    )

    assert calls == 1
    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == (
        "Policy status failed: static policy metadata could not be verified.\n"
    )
    assert "private renderer diagnostic" not in result.output


def test_local_task_add_persists_and_list_is_read_only(tmp_path: Path) -> None:
    database = tmp_path / "cli-task.sqlite3"
    initialize_storage(database, create=True)
    db_option = ["--database", str(database)]
    setup = runner.invoke(cli.app, ["task", "setup", *db_option], env=HELP_ENV)
    assert setup.exit_code == 0

    request_id = "0b79ddbb-4ad3-46e0-94bf-31a28c977e46"
    added = runner.invoke(
        cli.app,
        [
            "task",
            "add",
            *db_option,
            "--title",
            "Review caf\u00e9 release notes",
            "--due-at",
            "2027-05-01T12:00:00+05:30",
            "--request-id",
            request_id,
        ],
        env=HELP_ENV,
    )
    assert added.exit_code == 0
    assert added.stderr == ""
    assert request_id in added.stdout
    task_id = added.stdout.split("Task created: ", 1)[1].split(" ", 1)[0]

    state_after_add = database.read_bytes()
    listed = runner.invoke(cli.app, ["task", "list", *db_option], env=HELP_ENV)

    assert listed.exit_code == 0
    assert listed.stderr == ""
    assert listed.stdout == (
        f"Task: {task_id} [OPEN, revision 1] due=2027-05-01T06:30:00+00:00 "
        "Review caf\u00e9 release notes\n"
    )
    assert database.read_bytes() == state_after_add
