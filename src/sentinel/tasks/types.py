"""Typed immutable values for the manual local-task workflow."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class TaskStatus(StrEnum):
    OPEN = "OPEN"
    COMPLETED = "COMPLETED"


@dataclass(frozen=True, slots=True)
class LocalTaskOperator:
    """Unauthenticated local CLI principal used only to own manual tasks."""

    principal_id: UUID
    kind: str
    display_name: str
    os_binding: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class LocalTask:
    """One persisted manual task; its title is ordinary unencrypted SQLite text."""

    task_id: UUID
    owner_principal_id: UUID
    title: str
    due_at: datetime | None
    status: TaskStatus
    revision: int
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None


@dataclass(frozen=True, slots=True)
class TaskCreateResult:
    """Task creation or idempotent replay result."""

    task: LocalTask
    request_id: UUID
    created: bool
