"""CR1-J request-key idempotency and operator identity tests."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from sentinel.storage.connection import database_connection
from sentinel.tasks import (
    TaskStoreError,
    TaskStoreErrorCode,
    create_local_task,
    edit_local_task,
    setup_local_task_operator,
)
from sentinel.tasks.store import LOCAL_TASK_OPERATOR_ID
from tests.test_cr1_j_support import initialized_task_database


def test_setup_reuses_exact_deterministic_unauthenticated_operator(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "operator.sqlite3")
    first = setup_local_task_operator(database)
    second = setup_local_task_operator(database)
    assert first == second
    assert first.principal_id == LOCAL_TASK_OPERATOR_ID
    assert first.kind == "local-task-operator"
    assert first.os_binding == "local-cli-unverified"
    with database_connection(database) as connection:
        rows = connection.execute(
            "SELECT principal_id FROM principals WHERE kind = 'local-task-operator'"
        ).fetchall()
    assert rows == [(str(LOCAL_TASK_OPERATOR_ID),)]


def test_conflicting_operator_row_fails_without_repair(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "operator-conflict.sqlite3")
    with database_connection(database) as connection:
        connection.execute(
            "INSERT INTO principals VALUES (?, ?, ?, ?, ?, NULL)",
            (str(LOCAL_TASK_OPERATOR_ID), "owner", "Other", "other", "2026-11-01T00:00:00Z"),
        )
    with pytest.raises(TaskStoreError) as error:
        setup_local_task_operator(database)
    assert error.value.code is TaskStoreErrorCode.OPERATOR_CONFLICT
    with database_connection(database) as connection:
        assert connection.execute(
            "SELECT kind, display_name, os_binding FROM principals WHERE principal_id = ?",
            (str(LOCAL_TASK_OPERATOR_ID),),
        ).fetchone() == ("owner", "Other", "other")


def test_revoked_local_operator_is_not_reused(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "revoked-operator.sqlite3")
    operator = setup_local_task_operator(database)
    with database_connection(database) as connection:
        connection.execute(
            "UPDATE principals SET revoked_at = ? WHERE principal_id = ?",
            ("2026-11-04T12:00:00.000000Z", str(operator.principal_id)),
        )

    with pytest.raises(TaskStoreError) as error:
        setup_local_task_operator(database)
    assert error.value.code is TaskStoreErrorCode.OPERATOR_CONFLICT
    with database_connection(database) as connection:
        assert connection.execute(
            "SELECT revoked_at FROM principals WHERE principal_id = ?",
            (str(operator.principal_id),),
        ).fetchone() == ("2026-11-04T12:00:00.000000Z",)


def test_request_replay_returns_same_task_and_different_inputs_conflict(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "request-idempotency.sqlite3")
    setup_local_task_operator(database)
    request_id = uuid4()
    due = datetime(2027, 4, 5, 8, 0, tzinfo=UTC)
    first = create_local_task(database, request_id=request_id, title="Prepare review", due_at=due)
    replay = create_local_task(database, request_id=request_id, title="Prepare review", due_at=due)
    assert first.created is True and replay.created is False
    assert first.task == replay.task
    with pytest.raises(TaskStoreError) as title_error:
        create_local_task(database, request_id=request_id, title="Different title", due_at=due)
    assert title_error.value.code is TaskStoreErrorCode.REQUEST_CONFLICT
    with pytest.raises(TaskStoreError) as due_error:
        create_local_task(
            database,
            request_id=request_id,
            title="Prepare review",
            due_at=due + timedelta(days=1),
        )
    assert due_error.value.code is TaskStoreErrorCode.REQUEST_CONFLICT
    with database_connection(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM task_creation_requests").fetchone() == (1,)


def test_idempotency_receipt_preserves_create_arguments_after_task_edit(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "edited-replay.sqlite3")
    setup_local_task_operator(database)
    request_id = uuid4()
    created = create_local_task(database, request_id=request_id, title="Original title")
    edit_local_task(
        database, task_id=created.task.task_id, expected_revision=1, title="Edited title"
    )
    replay = create_local_task(database, request_id=request_id, title="Original title")
    assert replay.created is False
    assert replay.task.task_id == created.task.task_id
    assert replay.task.title == "Edited title"
    with pytest.raises(TaskStoreError) as error:
        create_local_task(database, request_id=request_id, title="Edited title")
    assert error.value.code is TaskStoreErrorCode.REQUEST_CONFLICT


def test_different_request_ids_create_distinct_task_ids(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "distinct-requests.sqlite3")
    setup_local_task_operator(database)
    first = create_local_task(database, request_id=uuid4(), title="Task")
    second = create_local_task(database, request_id=uuid4(), title="Task")
    assert first.task.task_id != second.task.task_id
