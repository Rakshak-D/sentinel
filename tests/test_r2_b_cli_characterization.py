"""Characterization of the installed CLI contract before R2-B modularization."""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer import rich_utils
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


_RICH_FRAME_CHARS = frozenset("─━│┃┌┐└┘├┤┬┴┼╭╮╰╯")
_RICH_VERTICAL_CHARS = frozenset("│┃")
_RICH_TOP_LEFT_CHARS = frozenset("┌╭")


def _command_for_path(command: object, path: tuple[str, ...]) -> object:
    for name in path:
        command = command.commands[name]  # type: ignore[attr-defined]
    return command


def _registered_option_names(command: object) -> tuple[str, ...]:
    names: list[str] = []
    for parameter in command.params:  # type: ignore[attr-defined]
        names.extend(parameter.opts)
        names.extend(parameter.secondary_opts)
    return tuple(names)


def _normalize_rich_geometry(
    value: str,
    *,
    option_names: tuple[str, ...] = (),
) -> str:
    """Ignore Rich frame width and wrapping while retaining ordered text."""
    semantic_lines: list[str] = []
    for raw_line in value.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if all(character in _RICH_FRAME_CHARS for character in line):
            continue
        if line[0] in _RICH_TOP_LEFT_CHARS:
            line = re.sub(r"^[┌╭][─━]+\s*", "", line)
            line = re.sub(r"[─━]+[┐╮]$", "", line)
        if line[0] in _RICH_VERTICAL_CHARS:
            line = line[1:]
        if line[-1:] in _RICH_VERTICAL_CHARS:
            line = line[:-1]
        semantic_line = re.sub(r"\s+", " ", line).strip()
        if semantic_line:
            semantic_lines.append(semantic_line)
    semantic_text = " ".join(semantic_lines)

    def expand_rendered_option(match: re.Match[str]) -> str:
        rendered = match.group(0)
        prefix = rendered[:-1]
        matches = [name for name in option_names if name.startswith(prefix)]
        return matches[0] if len(matches) == 1 else rendered

    return re.sub(
        r"(?<!\S)--[A-Za-z0-9][A-Za-z0-9-]*…",
        expand_rendered_option,
        semantic_text,
    )


def _rich_result_contract(
    result: dict[str, object],
    *,
    option_names: tuple[str, ...] = (),
) -> dict[str, object]:
    stdout = result["stdout"]
    stderr = result["stderr"]
    assert isinstance(stdout, str)
    assert isinstance(stderr, str)
    return {
        "exit_code": result["exit_code"],
        "stdout": _normalize_rich_geometry(stdout, option_names=option_names),
        "stderr": _normalize_rich_geometry(stderr, option_names=option_names),
    }


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
        option_names = _registered_option_names(_command_for_path(root, path))
        result = runner.invoke(
            cli.app,
            [*path, "--help"],
            env=HELP_ENV,
            terminal_width=100,
            color=False,
        )
        assert _rich_result_contract(
            {
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
            option_names=option_names,
        ) == _rich_result_contract(expected_help[key], option_names=option_names)


def test_representative_outputs_and_validation_errors_match_original_snapshot(
    tmp_path: Path,
) -> None:
    expected_outputs = _snapshot()["outputs"]
    assert isinstance(expected_outputs, dict)
    root = get_command(cli.app)
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
        actual_contract = {
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        if name == "missing_source_required_args":
            assert result.stdout == ""
            option_names = _registered_option_names(
                _command_for_path(root, ("source", "parse-job-alert"))
            )
            assert _rich_result_contract(
                actual_contract,
                option_names=option_names,
            ) == _rich_result_contract(
                expected_outputs[name],
                option_names=option_names,
            )
        else:
            assert actual_contract == expected_outputs[name]

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


def test_rich_geometry_is_ignored_but_help_and_error_text_is_not(monkeypatch) -> None:
    snapshot = _snapshot()
    help_text = snapshot["help"][""]["stdout"]
    assert isinstance(help_text, str)
    option_names = _registered_option_names(get_command(cli.app))

    # GitHub Actions makes Typer force Rich terminal rendering. This produces
    # the same one-column geometry difference seen in CI without changing the
    # captured pre-refactor snapshot.
    monkeypatch.setattr(rich_utils, "FORCE_TERMINAL", True)
    result = runner.invoke(
        cli.app,
        ["--help"],
        env=HELP_ENV,
        terminal_width=100,
        color=False,
    )
    assert result.exit_code == 0
    assert result.stdout != help_text
    assert _normalize_rich_geometry(
        result.stdout,
        option_names=option_names,
    ) == _normalize_rich_geometry(
        help_text,
        option_names=option_names,
    )

    advance_path = ("fixture-sync", "advance")
    advance_options = _registered_option_names(
        _command_for_path(get_command(cli.app), advance_path)
    )
    expected_advance = snapshot["help"][" ".join(advance_path)]["stdout"]
    advance_result = runner.invoke(
        cli.app,
        [*advance_path, "--help"],
        env=HELP_ENV,
        terminal_width=100,
        color=False,
    )
    assert isinstance(expected_advance, str)
    assert advance_result.stdout != expected_advance
    assert _normalize_rich_geometry(
        advance_result.stdout,
        option_names=advance_options,
    ) == _normalize_rich_geometry(
        expected_advance,
        option_names=advance_options,
    )

    mutations = (
        help_text.replace("Usage: root", "Usage: renamed-root", 1),
        help_text.replace("version            ", "version-renamed    ", 1),
        help_text.replace("--show-completion", "--show-options", 1),
        help_text.replace(
            "Print the installed Sentinel package version.",
            "Print a different package description.",
            1,
        ),
    )
    for changed_help in mutations:
        assert changed_help != help_text
        assert _normalize_rich_geometry(
            changed_help,
            option_names=option_names,
        ) != _normalize_rich_geometry(
            help_text,
            option_names=option_names,
        )

    error_text = snapshot["outputs"]["missing_source_required_args"]["stderr"]
    assert isinstance(error_text, str)
    changed_error = error_text.replace("--allow-root", "--allow-other", 1)
    error_option_names = _registered_option_names(
        _command_for_path(get_command(cli.app), ("source", "parse-job-alert"))
    )
    assert _normalize_rich_geometry(
        changed_error,
        option_names=error_option_names,
    ) != _normalize_rich_geometry(
        error_text,
        option_names=error_option_names,
    )
    changed_reason = error_text.replace("Missing option", "Unexpected option", 1)
    assert _normalize_rich_geometry(
        changed_reason,
        option_names=error_option_names,
    ) != _normalize_rich_geometry(
        error_text,
        option_names=error_option_names,
    )
    expected_error_contract = _rich_result_contract(
        {"exit_code": 2, "stdout": "", "stderr": error_text},
        option_names=error_option_names,
    )
    changed_exit_code = _rich_result_contract(
        {"exit_code": 1, "stdout": "", "stderr": error_text},
        option_names=error_option_names,
    )
    assert changed_exit_code != expected_error_contract
    changed_channel = _rich_result_contract(
        {"exit_code": 2, "stdout": error_text, "stderr": ""},
        option_names=error_option_names,
    )
    assert changed_channel != expected_error_contract


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
