"""CR1-J nested CLI behavior and safe task display."""

import uuid
from pathlib import Path

from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.storage.migrations import initialize_storage
from tests.test_cr1_j_support import historical_prefix_database, migration_history

runner = CliRunner()


def test_task_help_lists_workflow_and_preserves_existing_commands() -> None:
    root = runner.invoke(app, ["--help"])
    group = runner.invoke(app, ["task", "--help"])
    assert root.exit_code == 0 and "task" in root.stdout
    assert group.exit_code == 0
    for command in ("setup", "add", "list", "edit", "complete", "reopen"):
        assert command in group.stdout
    for command in ("version", "init", "doctor", "demo", "brief"):
        assert command in root.stdout


def test_cli_setup_add_list_edit_complete_reopen_and_restart(tmp_path: Path) -> None:
    database = tmp_path / "cli-task.sqlite3"
    initialize_storage(database, create=True)
    db_option = ["--database", str(database)]

    setup = runner.invoke(app, ["task", "setup", *db_option])
    assert setup.exit_code == 0 and "unauthenticated" in setup.stdout
    request_id = uuid.uuid4()
    add = runner.invoke(
        app,
        [
            "task",
            "add",
            *db_option,
            "--title",
            "Review café release notes",
            "--due-at",
            "2027-05-01T12:00:00+05:30",
            "--request-id",
            str(request_id),
        ],
    )
    assert add.exit_code == 0 and str(request_id) in add.stdout
    task_id = add.stdout.split("Task created: ", 1)[1].split(" ", 1)[0]
    replay = runner.invoke(
        app,
        [
            "task",
            "add",
            *db_option,
            "--title",
            "Review café release notes",
            "--due-at",
            "2027-05-01T06:30:00Z",
            "--request-id",
            str(request_id),
        ],
    )
    assert replay.exit_code == 0 and "already exists" in replay.stdout
    listed = runner.invoke(app, ["task", "list", *db_option])
    assert listed.exit_code == 0 and task_id in listed.stdout
    assert "Review café release notes" in listed.stdout
    edited = runner.invoke(
        app,
        [
            "task",
            "edit",
            *db_option,
            "--task-id",
            task_id,
            "--expected-revision",
            "1",
            "--title",
            "Review revised notes",
        ],
    )
    assert edited.exit_code == 0 and "revision 2" in edited.stdout
    completed = runner.invoke(
        app,
        ["task", "complete", *db_option, "--task-id", task_id, "--expected-revision", "2"],
    )
    assert completed.exit_code == 0 and "COMPLETED, revision 3" in completed.stdout
    reopened = runner.invoke(
        app,
        ["task", "reopen", *db_option, "--task-id", task_id, "--expected-revision", "3"],
    )
    assert reopened.exit_code == 0 and "OPEN, revision 4" in reopened.stdout
    assert (
        "Traceback"
        not in setup.output + add.output + edited.output + completed.output + reopened.output
    )


def test_task_cli_requires_explicit_database_and_does_not_migrate(tmp_path: Path) -> None:
    missing = runner.invoke(app, ["task", "setup"])
    assert missing.exit_code != 0

    database = historical_prefix_database(tmp_path / "historical-cli.sqlite3", 3)
    before = migration_history(database)
    result = runner.invoke(app, ["task", "setup", "--database", str(database)])
    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(database) not in result.stderr
    assert "current Sentinel schema" in result.stderr
    assert migration_history(database) == before


def test_cli_rejects_naive_due_date_with_bounded_error(tmp_path: Path) -> None:
    database = tmp_path / "naive-cli.sqlite3"
    initialize_storage(database, create=True)
    runner.invoke(app, ["task", "setup", "--database", str(database)])
    result = runner.invoke(
        app,
        [
            "task",
            "add",
            "--database",
            str(database),
            "--title",
            "Task",
            "--due-at",
            "2027-01-01T00:00:00",
            "--request-id",
            str(uuid.uuid4()),
        ],
    )
    assert result.exit_code != 0
    assert result.stdout == ""
    assert (
        result.stderr
        == "Task operation failed: due-at must be an ISO-8601 timestamp with an offset.\n"
    )


def test_cli_generates_and_reports_new_request_id_when_omitted(tmp_path: Path) -> None:
    database = tmp_path / "automatic-request.sqlite3"
    initialize_storage(database, create=True)
    runner.invoke(app, ["task", "setup", "--database", str(database)])

    first = runner.invoke(
        app,
        ["task", "add", "--database", str(database), "--title", "First manual intent"],
    )
    second = runner.invoke(
        app,
        ["task", "add", "--database", str(database), "--title", "First manual intent"],
    )

    assert first.exit_code == second.exit_code == 0
    first_request = uuid.UUID(first.stdout.split(" request=", 1)[1].split(" ", 1)[0])
    second_request = uuid.UUID(second.stdout.split(" request=", 1)[1].split(" ", 1)[0])
    assert first_request.version == second_request.version == 4
    assert first_request != second_request
    assert "Task created:" in first.stdout and "Task created:" in second.stdout
