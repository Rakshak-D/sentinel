"""Immutable result types for the local overview."""

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum
from uuid import UUID

from sentinel.briefing.types import EvidenceBriefing
from sentinel.sync.types import FixtureSyncCursorStatus
from sentinel.tasks.types import TaskStatus


class OverviewErrorCode(StrEnum):
    INVALID_AS_OF = "invalid_as_of"
    TASK_OPERATOR_MISSING = "task_operator_missing"
    TASKS_UNAVAILABLE = "tasks_unavailable"
    SYNC_UNAVAILABLE = "sync_unavailable"
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    STATE_CHANGED = "state_changed"


_ERROR_MESSAGES = {
    OverviewErrorCode.INVALID_AS_OF: (
        "as-of must be an ISO-8601 timestamp with an explicit UTC offset."
    ),
    OverviewErrorCode.TASK_OPERATOR_MISSING: (
        "the local task operator is not initialized; run 'sentinel task setup' first."
    ),
    OverviewErrorCode.TASKS_UNAVAILABLE: "manual local task state could not be verified.",
    OverviewErrorCode.SYNC_UNAVAILABLE: (
        "synthetic fixture-sync state could not be verified; check "
        "'sentinel fixture-sync status' and satisfy the overview preconditions."
    ),
    OverviewErrorCode.EVIDENCE_UNAVAILABLE: (
        "promoted synthetic GitHub evidence and PUBLIC blobs could not be verified."
    ),
    OverviewErrorCode.STATE_CHANGED: (
        "local state changed while the overview was being assembled; retry the read."
    ),
}


class OverviewError(RuntimeError):
    """Fixed-message overview error without paths or source data."""

    def __init__(self, code: OverviewErrorCode) -> None:
        if type(code) is not OverviewErrorCode:
            raise TypeError("overview error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


class TaskDayCategory(StrEnum):
    OVERDUE = "OVERDUE"
    DUE_TODAY = "DUE_TODAY"
    UPCOMING = "UPCOMING"
    NO_DUE_DATE = "NO_DUE_DATE"
    COMPLETED = "COMPLETED"


@dataclass(frozen=True, slots=True)
class LocalOverviewTask:
    task_id: UUID
    title: str = field(repr=False)
    status: TaskStatus
    revision: int
    due_at: datetime | None
    created_at: datetime
    completed_at: datetime | None


@dataclass(frozen=True, slots=True)
class LocalOverviewTaskSection:
    category: TaskDayCategory
    provenance: str
    tasks: tuple[LocalOverviewTask, ...]


@dataclass(frozen=True, slots=True)
class LocalOverviewSyncSection:
    provenance: str
    source_id: UUID
    cursor_id: UUID
    fixture_version: str
    fixture_sha256: str
    generation: int
    completed_pages: int
    total_pages: int
    item_count: int
    span_count: int
    status: FixtureSyncCursorStatus


@dataclass(frozen=True, slots=True)
class LocalOverview:
    schema_version: str
    synthetic_data: bool
    as_of_utc: datetime
    reporting_offset: str
    local_day: date
    task_sections: tuple[LocalOverviewTaskSection, ...]
    evidence: EvidenceBriefing
    sync: LocalOverviewSyncSection

    @property
    def task_count(self) -> int:
        return sum(len(section.tasks) for section in self.task_sections)

    @property
    def task_counts(self) -> tuple[tuple[TaskDayCategory, int], ...]:
        return tuple((section.category, len(section.tasks)) for section in self.task_sections)


__all__ = [
    "LocalOverview",
    "LocalOverviewSyncSection",
    "LocalOverviewTask",
    "LocalOverviewTaskSection",
    "OverviewError",
    "OverviewErrorCode",
    "TaskDayCategory",
]
