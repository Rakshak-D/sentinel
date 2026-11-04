"""Read-only composition of local tasks, verified evidence, and fixture-sync state."""

import re
from datetime import UTC, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Final

from sentinel.briefing import build_github_fixture_brief
from sentinel.briefing.types import EvidenceBriefing
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.overview.types import (
    LocalOverview,
    LocalOverviewSyncSection,
    LocalOverviewTask,
    LocalOverviewTaskSection,
    OverviewError,
    OverviewErrorCode,
    TaskDayCategory,
)
from sentinel.sync import (
    FixtureSyncCursorStatus,
    IncrementalGithubFixtureState,
    read_incremental_github_fixture_state,
)
from sentinel.tasks import TaskStoreError, list_local_tasks
from sentinel.tasks.store import TaskStoreErrorCode
from sentinel.tasks.types import LocalTask, TaskStatus

OVERVIEW_SCHEMA_VERSION: Final = "sentinel.local-overview.v1"
TASK_PROVENANCE: Final = "manually entered local tasks; unauthenticated local operator"
SYNC_PROVENANCE: Final = "synthetic incremental fixture replay; not live provider freshness"
_CATEGORY_ORDER: Final = (
    TaskDayCategory.OVERDUE,
    TaskDayCategory.DUE_TODAY,
    TaskDayCategory.UPCOMING,
    TaskDayCategory.NO_DUE_DATE,
    TaskDayCategory.COMPLETED,
)
_EXPECTED_SPAN_COUNTS: Final = (0, 3, 8, 9)
_UNKNOWN_ZERO_OFFSET = re.compile(r"-00(?::?00)?(?::?00(?:\.0+)?)?$")


def parse_as_of_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp only when it contains an explicit UTC offset."""

    if type(value) is not str:
        raise OverviewError(OverviewErrorCode.INVALID_AS_OF)
    try:
        if _UNKNOWN_ZERO_OFFSET.search(value) is not None:
            raise ValueError
        normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed
    except (OverflowError, ValueError):
        raise OverviewError(OverviewErrorCode.INVALID_AS_OF) from None


def _utc(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise OverviewError(OverviewErrorCode.INVALID_AS_OF)
    return value.astimezone(UTC)


def _format_offset(offset: timedelta) -> str:
    total_microseconds = (
        (offset.days * 86_400 + offset.seconds) * 1_000_000 + offset.microseconds
    )
    sign = "+" if total_microseconds >= 0 else "-"
    hours, remainder = divmod(abs(total_microseconds), 3_600_000_000)
    minutes, remainder = divmod(remainder, 60_000_000)
    seconds, microseconds = divmod(remainder, 1_000_000)
    base = f"{sign}{hours:02d}:{minutes:02d}"
    if seconds or microseconds:
        base += f":{seconds:02d}"
    if microseconds:
        base += f".{microseconds:06d}"
    return base


def _task_category(
    task: LocalTask,
    *,
    day_start_utc: datetime,
    next_day_start_utc: datetime,
) -> TaskDayCategory:
    if task.status is TaskStatus.COMPLETED:
        if task.completed_at is None:
            raise OverviewError(OverviewErrorCode.TASKS_UNAVAILABLE)
        _utc(task.completed_at)
        return TaskDayCategory.COMPLETED
    if task.status is not TaskStatus.OPEN:
        raise OverviewError(OverviewErrorCode.TASKS_UNAVAILABLE)
    if task.due_at is None:
        return TaskDayCategory.NO_DUE_DATE
    due_at_utc = _utc(task.due_at)
    if due_at_utc < day_start_utc:
        return TaskDayCategory.OVERDUE
    if due_at_utc < next_day_start_utc:
        return TaskDayCategory.DUE_TODAY
    return TaskDayCategory.UPCOMING


def _task_sort_key(
    task: LocalOverviewTask,
) -> tuple[datetime, datetime, str]:
    task_id = str(task.task_id)
    if task.status is TaskStatus.COMPLETED:
        if task.completed_at is None:
            raise OverviewError(OverviewErrorCode.TASKS_UNAVAILABLE)
        completed = _utc(task.completed_at)
        return (completed, completed, task_id)
    if task.due_at is None:
        created = _utc(task.created_at)
        return (created, created, task_id)
    return (_utc(task.due_at), _utc(task.created_at), task_id)


def _overview_tasks(
    tasks: tuple[LocalTask, ...], *, day_start_utc: datetime, next_day_start_utc: datetime
) -> tuple[LocalOverviewTaskSection, ...]:
    grouped: dict[TaskDayCategory, list[LocalOverviewTask]] = {
        category: [] for category in _CATEGORY_ORDER
    }
    for task in tasks:
        if type(task) is not LocalTask:
            raise OverviewError(OverviewErrorCode.TASKS_UNAVAILABLE)
        category = _task_category(
            task,
            day_start_utc=day_start_utc,
            next_day_start_utc=next_day_start_utc,
        )
        grouped[category].append(
            LocalOverviewTask(
                task_id=task.task_id,
                title=task.title,
                status=task.status,
                revision=task.revision,
                due_at=task.due_at,
                created_at=task.created_at,
                completed_at=task.completed_at,
            )
        )
    sections: list[LocalOverviewTaskSection] = []
    for category in _CATEGORY_ORDER:
        rows = grouped[category]
        rows.sort(key=_task_sort_key)
        sections.append(
            LocalOverviewTaskSection(
                category=category,
                provenance=TASK_PROVENANCE,
                tasks=tuple(rows),
            )
        )
    return tuple(sections)


def _validate_sync_state(state: IncrementalGithubFixtureState) -> None:
    expected_counts = _EXPECTED_SPAN_COUNTS
    if (
        type(state) is not IncrementalGithubFixtureState
        or type(state.generation) is not int
        or not 0 <= state.generation <= 3
        or state.completed_pages != state.generation
        or state.total_pages != 3
        or state.item_count != state.generation
        or state.span_count != expected_counts[state.generation]
        or state.fixture_version != EXPECTED_MANIFEST.fixture_version
        or state.fixture_sha256 != EXPECTED_MANIFEST.fixture_sha256
        or state.cursor_status
        is not (
            FixtureSyncCursorStatus.COMPLETE
            if state.generation == 3
            else FixtureSyncCursorStatus.READY
        )
    ):
        raise OverviewError(OverviewErrorCode.SYNC_UNAVAILABLE)


def _read_tasks(database: str | Path) -> tuple[LocalTask, ...]:
    try:
        return list_local_tasks(database)
    except TaskStoreError as error:
        if error.code is TaskStoreErrorCode.OPERATOR_NOT_INITIALIZED:
            raise OverviewError(OverviewErrorCode.TASK_OPERATOR_MISSING) from None
        raise OverviewError(OverviewErrorCode.TASKS_UNAVAILABLE) from None
    except Exception:
        raise OverviewError(OverviewErrorCode.TASKS_UNAVAILABLE) from None


def _read_sync(
    database: str | Path, store_root: str | Path
) -> IncrementalGithubFixtureState:
    try:
        state = read_incremental_github_fixture_state(database, store_root=store_root)
        _validate_sync_state(state)
        return state
    except OverviewError:
        raise
    except Exception:
        raise OverviewError(OverviewErrorCode.SYNC_UNAVAILABLE) from None


def _read_evidence(database: str | Path, store_root: str | Path) -> EvidenceBriefing:
    try:
        return build_github_fixture_brief(database, store_root=store_root)
    except Exception:
        raise OverviewError(OverviewErrorCode.EVIDENCE_UNAVAILABLE) from None


def build_local_overview(
    database: str | Path,
    *,
    store_root: str | Path,
    as_of: datetime,
) -> LocalOverview:
    """Assemble one verified overview for an explicit fixed-offset local day."""

    as_of_utc = _utc(as_of)
    offset = as_of.utcoffset()
    if offset is None:
        raise OverviewError(OverviewErrorCode.INVALID_AS_OF)
    reporting_timezone = timezone(offset)
    local_day = as_of.astimezone(reporting_timezone).date()
    try:
        day_start = datetime.combine(local_day, time.min, tzinfo=reporting_timezone)
        next_day_start = day_start + timedelta(days=1)
    except (OverflowError, ValueError):
        raise OverviewError(OverviewErrorCode.INVALID_AS_OF) from None
    day_start_utc = day_start.astimezone(UTC)
    next_day_start_utc = next_day_start.astimezone(UTC)

    tasks_before = _read_tasks(database)
    sync_before = _read_sync(database, store_root)
    evidence = _read_evidence(database, store_root)
    tasks_after = _read_tasks(database)
    sync_after = _read_sync(database, store_root)
    if tasks_before != tasks_after or sync_before != sync_after:
        raise OverviewError(OverviewErrorCode.STATE_CHANGED)

    if not evidence.synthetic_data or len(evidence.items) != 3:
        raise OverviewError(OverviewErrorCode.EVIDENCE_UNAVAILABLE)
    if sum(len(item.citations) for item in evidence.items) != 9:
        raise OverviewError(OverviewErrorCode.EVIDENCE_UNAVAILABLE)

    return LocalOverview(
        schema_version=OVERVIEW_SCHEMA_VERSION,
        synthetic_data=True,
        as_of_utc=as_of_utc,
        reporting_offset=_format_offset(offset),
        local_day=local_day,
        task_sections=_overview_tasks(
            tasks_before,
            day_start_utc=day_start_utc,
            next_day_start_utc=next_day_start_utc,
        ),
        evidence=evidence,
        sync=LocalOverviewSyncSection(
            provenance=SYNC_PROVENANCE,
            source_id=sync_before.source_id,
            cursor_id=sync_before.cursor_id,
            fixture_version=sync_before.fixture_version,
            fixture_sha256=sync_before.fixture_sha256,
            generation=sync_before.generation,
            completed_pages=sync_before.completed_pages,
            total_pages=sync_before.total_pages,
            item_count=sync_before.item_count,
            span_count=sync_before.span_count,
            status=sync_before.cursor_status,
        ),
    )


__all__ = ["OVERVIEW_SCHEMA_VERSION", "build_local_overview", "parse_as_of_timestamp"]
