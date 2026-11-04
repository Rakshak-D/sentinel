"""CR1-J fail-closed input, schema and ownership boundaries."""

import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from sentinel.storage.connection import database_connection
from sentinel.storage.writer import acquire_writer_lease
from sentinel.tasks import (
    TaskStoreError,
    TaskStoreErrorCode,
    create_local_task,
    list_local_tasks,
    setup_local_task_operator,
)
from tests.test_cr1_j_support import historical_prefix_database, initialized_task_database


@pytest.mark.parametrize(
    "title",
    [
        "",
        "   ",
        "x" * 201,
        "\x00nul",
        "escape\x1b[31m",
        "line\nfeed",
        "line\u2028separator",
        "override\u202e",
        "\ud800",
    ],
)
def test_invalid_titles_are_rejected_without_persisting(title: str, tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "invalid-title.sqlite3")
    setup_local_task_operator(database)
    with pytest.raises(TaskStoreError) as error:
        create_local_task(database, request_id=uuid4(), title=title)
    assert error.value.code is TaskStoreErrorCode.INVALID_INPUT
    assert str(error.value) == "Task input is invalid."
    assert list_local_tasks(database) == ()


def test_international_title_and_exact_byte_limit_are_allowed(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "unicode-title.sqlite3")
    setup_local_task_operator(database)
    title = "🙂" * 200
    task = create_local_task(database, request_id=uuid4(), title=title).task
    assert len(task.title) == 200
    assert len(task.title.encode("utf-8")) == 800


@pytest.mark.parametrize(
    "due_at",
    [datetime(2027, 1, 1), "2027-01-01T00:00:00Z", True],
)
def test_due_at_requires_aware_datetime_without_coercion(due_at: object, tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "invalid-date.sqlite3")
    setup_local_task_operator(database)
    with pytest.raises(TaskStoreError) as error:
        create_local_task(database, request_id=uuid4(), title="Task", due_at=due_at)  # type: ignore[arg-type]
    assert error.value.code is TaskStoreErrorCode.INVALID_INPUT
    assert list_local_tasks(database) == ()


def test_due_at_that_cannot_be_represented_in_utc_is_rejected_bounded(
    tmp_path: Path,
) -> None:
    database = initialized_task_database(tmp_path / "date-overflow.sqlite3")
    setup_local_task_operator(database)
    unrepresentable = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1)))
    with pytest.raises(TaskStoreError) as error:
        create_local_task(
            database,
            request_id=uuid4(),
            title="Synthetic date boundary",
            due_at=unrepresentable,
        )
    assert error.value.code is TaskStoreErrorCode.INVALID_INPUT
    assert str(error.value) == "Task input is invalid."
    assert list_local_tasks(database) == ()


def test_missing_and_historical_databases_are_not_created_or_upgraded(tmp_path: Path) -> None:
    missing = tmp_path / "missing.sqlite3"
    with pytest.raises(TaskStoreError) as missing_error:
        setup_local_task_operator(missing)
    assert missing_error.value.code in {
        TaskStoreErrorCode.DATABASE_UNAVAILABLE,
        TaskStoreErrorCode.SCHEMA_NOT_CURRENT,
    }
    assert not missing.exists()

    historical = historical_prefix_database(tmp_path / "historical.sqlite3", 3)
    with pytest.raises(TaskStoreError) as historical_error:
        setup_local_task_operator(historical)
    assert historical_error.value.code is TaskStoreErrorCode.SCHEMA_NOT_CURRENT
    with database_connection(historical) as connection:
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone() == (3,)
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='tasks'"
        ).fetchone() == (0,)


def test_task_writes_are_manual_and_never_create_proposal_or_source_links(
    tmp_path: Path,
) -> None:
    database = initialized_task_database(tmp_path / "manual-boundary.sqlite3")
    setup_local_task_operator(database)
    result = create_local_task(
        database, request_id=uuid4(), title="Manually typed, not source-derived"
    )
    with database_connection(database) as connection:
        row = connection.execute(
            "SELECT source_item_id, proposal_id, body_ref FROM tasks WHERE task_id = ?",
            (str(result.task.task_id),),
        ).fetchone()
        proposals = connection.execute("SELECT COUNT(*) FROM action_proposals").fetchone()
    assert row == (None, None, None)
    assert proposals == (0,)


def test_invalid_persisted_title_fails_closed_on_read_without_echoing_value(
    tmp_path: Path,
) -> None:
    database = initialized_task_database(tmp_path / "tampered-title.sqlite3")
    setup_local_task_operator(database)
    task = create_local_task(database, request_id=uuid4(), title="Valid title").task
    canary = "persisted\x1b[31mcanary"
    with database_connection(database) as connection:
        connection.execute(
            "UPDATE tasks SET title = ? WHERE task_id = ?",
            (canary, str(task.task_id)),
        )

    with pytest.raises(TaskStoreError) as error:
        list_local_tasks(database)
    assert error.value.code is TaskStoreErrorCode.TASK_CONFLICT
    assert canary not in str(error.value)
    assert "\x1b" not in str(error.value)


def test_read_operations_do_not_acquire_writer_lease_or_change_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sentinel.tasks.store as store_module

    database = initialized_task_database(tmp_path / "readonly-list.sqlite3")
    setup_local_task_operator(database)
    create_local_task(database, request_id=uuid4(), title="Read-only check")
    with database_connection(database) as connection:
        before = connection.execute("SELECT * FROM tasks ORDER BY task_id").fetchall()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("read path acquired a writer lease")

    monkeypatch.setattr(store_module, "acquire_writer_lease", forbidden)
    assert len(list_local_tasks(database)) == 1
    with database_connection(database) as connection:
        after = connection.execute("SELECT * FROM tasks ORDER BY task_id").fetchall()
    assert after == before


def test_second_process_cannot_create_while_cooperating_lease_is_held(
    tmp_path: Path,
) -> None:
    database = initialized_task_database(tmp_path / "contended-task.sqlite3")
    setup_local_task_operator(database)
    script = "\n".join(
        (
            "import sys",
            "from pathlib import Path",
            "from uuid import UUID",
            "from sentinel.tasks import create_local_task, TaskStoreError",
            "try:",
            "    create_local_task(",
            "        Path(sys.argv[1]), request_id=UUID(sys.argv[2]), title='child task'",
            "    )",
            "except TaskStoreError:",
            "    raise SystemExit(17)",
        )
    )
    request_id = uuid4()
    with acquire_writer_lease(database):
        result = subprocess.run(
            [sys.executable, "-c", script, str(database), str(request_id)],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
            env=os.environ.copy(),
        )
    assert result.returncode == 17
    assert "Traceback" not in result.stderr
    assert list_local_tasks(database) == ()


def test_failed_receipt_insert_rolls_back_task_creation_and_hides_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sentinel.tasks.store as store_module

    database = initialized_task_database(tmp_path / "task-atomic.sqlite3")
    operator = setup_local_task_operator(database)
    with database_connection(database) as connection:
        principal_before = connection.execute(
            "SELECT * FROM principals WHERE principal_id = ?",
            (str(operator.principal_id),),
        ).fetchone()

    def fail_receipt(*_args: object) -> None:
        raise sqlite3.IntegrityError("synthetic private SQL detail")

    monkeypatch.setattr(store_module, "_insert_creation_receipt", fail_receipt)
    title_canary = "Synthetic private title canary"
    with pytest.raises(TaskStoreError) as error:
        create_local_task(database, request_id=uuid4(), title=title_canary)
    assert error.value.code is TaskStoreErrorCode.DATABASE_UNAVAILABLE
    assert str(database) not in str(error.value)
    assert title_canary not in str(error.value)
    assert "SQL detail" not in str(error.value)
    with database_connection(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM task_creation_requests").fetchone() == (0,)
        assert (
            connection.execute(
                "SELECT * FROM principals WHERE principal_id = ?",
                (str(operator.principal_id),),
            ).fetchone()
            == principal_before
        )
