"""Behavior-level red checks for the CR1-J public task API."""

from pathlib import Path
from uuid import uuid4

from sentinel.tasks import (
    TaskStatus,
    complete_local_task,
    create_local_task,
    list_local_tasks,
    reopen_local_task,
    setup_local_task_operator,
)
from tests.test_cr1_j_support import initialized_task_database


def test_manual_task_api_can_setup_create_list_and_transition(tmp_path: Path) -> None:
    database = tmp_path / "manual-tasks.sqlite3"
    initialized_task_database(database)
    operator = setup_local_task_operator(database)
    creation = create_local_task(database, request_id=uuid4(), title="Review release notes")
    listed = list_local_tasks(database)
    completed = complete_local_task(database, task_id=creation.task.task_id, expected_revision=1)
    reopened = reopen_local_task(
        database, task_id=creation.task.task_id, expected_revision=completed.revision
    )

    assert operator.principal_id == creation.task.owner_principal_id
    assert listed == (creation.task,)
    assert creation.created is True
    assert completed.status is TaskStatus.COMPLETED and completed.revision == 2
    assert completed.completed_at is not None
    assert reopened.status is TaskStatus.OPEN and reopened.revision == 3
    assert reopened.completed_at is None
