"""CR1-J revision-controlled task edits and transitions."""

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from sentinel.tasks import (
    TaskStatus,
    TaskStoreError,
    TaskStoreErrorCode,
    complete_local_task,
    create_local_task,
    edit_local_task,
    list_local_tasks,
    reopen_local_task,
    setup_local_task_operator,
)
from tests.test_cr1_j_support import initialized_task_database


def test_due_at_normalizes_to_utc_and_task_edit_increments_once(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "edit.sqlite3")
    setup_local_task_operator(database)
    original_due = datetime(2027, 3, 2, 11, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    created = create_local_task(
        database, request_id=uuid4(), title="Review café notes", due_at=original_due
    ).task
    assert created.due_at == datetime(2027, 3, 2, 6, 0, tzinfo=UTC)
    edited_due = datetime(2027, 3, 4, 9, 0, tzinfo=UTC)
    edited = edit_local_task(
        database,
        task_id=created.task_id,
        expected_revision=1,
        title="Review revised notes",
        due_at=edited_due,
    )
    assert edited.title == "Review revised notes"
    assert edited.due_at == edited_due
    assert edited.revision == 2
    assert edited.created_at == created.created_at
    assert edited.updated_at >= created.updated_at


def test_edit_can_clear_due_date_and_noop_is_a_conflict(tmp_path: Path) -> None:
    from sentinel.tasks import UNCHANGED

    database = initialized_task_database(tmp_path / "clear-due.sqlite3")
    setup_local_task_operator(database)
    task = create_local_task(
        database,
        request_id=uuid4(),
        title="Task",
        due_at=datetime(2027, 1, 1, tzinfo=UTC),
    ).task
    cleared = edit_local_task(database, task_id=task.task_id, expected_revision=1, due_at=None)
    assert cleared.due_at is None and cleared.revision == 2
    with pytest.raises(TaskStoreError) as no_fields:
        edit_local_task(database, task_id=task.task_id, expected_revision=2, title=UNCHANGED)
    assert no_fields.value.code is TaskStoreErrorCode.NO_CHANGES
    with pytest.raises(TaskStoreError) as same_value:
        edit_local_task(database, task_id=task.task_id, expected_revision=2, title="Task")
    assert same_value.value.code is TaskStoreErrorCode.NO_CHANGES
    assert list_local_tasks(database)[0].revision == 2


def test_transition_sequence_rejects_repeated_state_without_revision_change(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "transitions.sqlite3")
    setup_local_task_operator(database)
    task = create_local_task(database, request_id=uuid4(), title="Manual task").task
    completed = complete_local_task(database, task_id=task.task_id, expected_revision=1)
    assert completed.status is TaskStatus.COMPLETED
    assert completed.revision == 2 and completed.completed_at is not None
    with pytest.raises(TaskStoreError) as repeated:
        complete_local_task(database, task_id=task.task_id, expected_revision=2)
    assert repeated.value.code is TaskStoreErrorCode.INVALID_TRANSITION
    reopened = reopen_local_task(database, task_id=task.task_id, expected_revision=2)
    assert reopened.status is TaskStatus.OPEN
    assert reopened.revision == 3 and reopened.completed_at is None
    with pytest.raises(TaskStoreError) as repeated_reopen:
        reopen_local_task(database, task_id=task.task_id, expected_revision=3)
    assert repeated_reopen.value.code is TaskStoreErrorCode.INVALID_TRANSITION
    assert list_local_tasks(database, status=TaskStatus.OPEN) == (reopened,)
    assert list_local_tasks(database, status=TaskStatus.COMPLETED) == ()


def test_stale_revision_and_unknown_task_fail_without_modifying_rows(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "stale.sqlite3")
    setup_local_task_operator(database)
    task = create_local_task(database, request_id=uuid4(), title="Manual task").task
    edited = edit_local_task(database, task_id=task.task_id, expected_revision=1, title="Updated")
    with pytest.raises(TaskStoreError) as stale:
        complete_local_task(database, task_id=task.task_id, expected_revision=1)
    assert stale.value.code is TaskStoreErrorCode.REVISION_CONFLICT
    with pytest.raises(TaskStoreError) as missing:
        complete_local_task(database, task_id=uuid4(), expected_revision=edited.revision)
    assert missing.value.code is TaskStoreErrorCode.TASK_NOT_FOUND
    assert list_local_tasks(database) == (edited,)


def test_list_order_is_due_then_creation_then_task_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sentinel.tasks.store as store_module

    database = initialized_task_database(tmp_path / "task-order.sqlite3")
    fixed_now = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(store_module, "_utc_now", lambda: fixed_now)
    setup_local_task_operator(database)
    tie_later_id = create_local_task(
        database,
        request_id=UUID("00000000-0000-4000-8000-000000000002"),
        title="Later task ID, same due",
        due_at=datetime(2027, 1, 1, tzinfo=UTC),
    ).task
    undated = create_local_task(
        database,
        request_id=UUID("00000000-0000-4000-8000-000000000004"),
        title="Undated task",
    ).task
    earlier_due = create_local_task(
        database,
        request_id=UUID("00000000-0000-4000-8000-000000000003"),
        title="Earlier due",
        due_at=datetime(2026, 12, 31, tzinfo=UTC),
    ).task
    tie_earlier_id = create_local_task(
        database,
        request_id=UUID("00000000-0000-4000-8000-000000000001"),
        title="Earlier task ID, same due",
        due_at=datetime(2027, 1, 1, tzinfo=UTC),
    ).task

    assert list_local_tasks(database) == (
        earlier_due,
        tie_earlier_id,
        tie_later_id,
        undated,
    )
