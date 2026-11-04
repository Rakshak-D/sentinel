"""Deterministic text and JSON presentation for the local overview."""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Final
from uuid import UUID

from sentinel.briefing.formatters import escape_display_text, format_json_brief, format_text_brief
from sentinel.briefing.types import EvidenceBriefing
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.overview.assembly import OVERVIEW_SCHEMA_VERSION, SYNC_PROVENANCE, TASK_PROVENANCE
from sentinel.overview.types import (
    LocalOverview,
    LocalOverviewSyncSection,
    LocalOverviewTask,
    LocalOverviewTaskSection,
    OverviewError,
    OverviewErrorCode,
    TaskDayCategory,
)
from sentinel.sync.types import FixtureSyncCursorStatus
from sentinel.tasks.types import TaskStatus

_CATEGORY_ORDER: Final = (
    TaskDayCategory.OVERDUE,
    TaskDayCategory.DUE_TODAY,
    TaskDayCategory.UPCOMING,
    TaskDayCategory.NO_DUE_DATE,
    TaskDayCategory.COMPLETED,
)
_REPORTING_OFFSET = re.compile(r"^[+-][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,6})?)?$")


def _datetime_utc(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise OverviewError(OverviewErrorCode.TASKS_UNAVAILABLE)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _datetime_local(value: datetime | None, overview: LocalOverview) -> str:
    if value is None:
        return "none"
    try:
        offset = datetime.fromisoformat(
            f"{overview.local_day.isoformat()}T00:00:00{overview.reporting_offset}"
        ).utcoffset()
        if offset is None:
            raise ValueError
        fixed_timezone = timezone(offset)
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError
        return value.astimezone(fixed_timezone).isoformat()
    except (OverflowError, ValueError):
        raise OverviewError(OverviewErrorCode.TASKS_UNAVAILABLE) from None


def _validate_task(task: LocalOverviewTask, category: TaskDayCategory) -> None:
    if (
        type(task) is not LocalOverviewTask
        or type(task.title) is not str
        or type(task.task_id) is not UUID
        or type(task.status) is not TaskStatus
        or type(task.revision) is not int
        or task.revision < 1
        or (
            task.due_at is not None
            and (type(task.due_at) is not datetime or task.due_at.utcoffset() is None)
        )
        or type(task.created_at) is not datetime
        or task.created_at.tzinfo is None
        or task.created_at.utcoffset() is None
        or (
            task.completed_at is not None
            and (
                type(task.completed_at) is not datetime
                or task.completed_at.utcoffset() is None
            )
        )
        or (category is TaskDayCategory.COMPLETED) != (task.status is TaskStatus.COMPLETED)
        or (category is TaskDayCategory.COMPLETED and task.completed_at is None)
        or (category is TaskDayCategory.NO_DUE_DATE and task.due_at is not None)
        or (
            category is not TaskDayCategory.NO_DUE_DATE
            and category is not TaskDayCategory.COMPLETED
            and task.due_at is None
        )
    ):
        raise OverviewError(OverviewErrorCode.TASKS_UNAVAILABLE)


def _validated(overview: LocalOverview) -> None:
    if (
        type(overview) is not LocalOverview
        or overview.schema_version != OVERVIEW_SCHEMA_VERSION
        or overview.synthetic_data is not True
        or type(overview.as_of_utc) is not datetime
        or overview.as_of_utc.tzinfo is None
        or overview.as_of_utc.utcoffset() != timedelta(0)
        or type(overview.local_day) is not date
        or type(overview.reporting_offset) is not str
        or not _REPORTING_OFFSET.fullmatch(overview.reporting_offset)
        or type(overview.evidence) is not EvidenceBriefing
        or type(overview.sync) is not LocalOverviewSyncSection
        or type(overview.task_sections) is not tuple
        or any(type(section) is not LocalOverviewTaskSection for section in overview.task_sections)
        or any(type(section.category) is not TaskDayCategory for section in overview.task_sections)
        or tuple(section.category for section in overview.task_sections) != _CATEGORY_ORDER
        or any(
            type(section.tasks) is not tuple
            or section.provenance != TASK_PROVENANCE
            for section in overview.task_sections
        )
        or type(overview.sync.provenance) is not str
        or overview.sync.provenance != SYNC_PROVENANCE
        or type(overview.sync.source_id) is not UUID
        or type(overview.sync.cursor_id) is not UUID
        or overview.sync.fixture_version != EXPECTED_MANIFEST.fixture_version
        or overview.sync.fixture_sha256 != EXPECTED_MANIFEST.fixture_sha256
        or type(overview.sync.generation) is not int
        or type(overview.sync.completed_pages) is not int
        or type(overview.sync.total_pages) is not int
        or type(overview.sync.item_count) is not int
        or type(overview.sync.span_count) is not int
        or type(overview.sync.status) is not FixtureSyncCursorStatus
        or overview.sync.total_pages != 3
        or overview.sync.generation not in {0, 1, 2, 3}
        or overview.sync.completed_pages != overview.sync.generation
        or overview.sync.item_count != overview.sync.generation
        or overview.sync.span_count != (0, 3, 8, 9)[overview.sync.generation]
        or overview.sync.status
        is not (
            FixtureSyncCursorStatus.COMPLETE
            if overview.sync.generation == 3
            else FixtureSyncCursorStatus.READY
        )
        or overview.evidence.fixture_sha256 != EXPECTED_MANIFEST.fixture_sha256
        or overview.evidence.manifest_sha256 != EXPECTED_MANIFEST.sha256
        or overview.evidence.fixture_version != EXPECTED_MANIFEST.fixture_version
        or overview.evidence.provider_id != "github.fixture"
        or len(overview.evidence.items) != 3
        or sum(len(item.citations) for item in overview.evidence.items) != 9
    ):
        raise OverviewError(OverviewErrorCode.EVIDENCE_UNAVAILABLE)
    for section in overview.task_sections:
        for task in section.tasks:
            _validate_task(task, section.category)
    # The existing CR1-I formatter validates the complete evidence contract.
    format_text_brief(overview.evidence)


def _task_text(task: LocalOverviewTask, overview: LocalOverview) -> str:
    due = _datetime_local(task.due_at, overview)
    suffix = ""
    if task.status is TaskStatus.COMPLETED and task.completed_at is not None:
        suffix = f" completed_at={_datetime_local(task.completed_at, overview)}"
    return (
        f"  {task.task_id} [{task.status.value}, revision {task.revision}] "
        f"due={due}{suffix} title=\"{escape_display_text(task.title)}\""
    )


def format_text_local_overview(overview: LocalOverview) -> str:
    _validated(overview)
    lines = [
        "Sentinel - Local overview",
        "Selected local day: manually selected fixed-offset calendar day",
        f"As of (UTC): {_datetime_utc(overview.as_of_utc)}",
        f"Reporting offset: {overview.reporting_offset}",
        f"Local calendar day: {overview.local_day.isoformat()}",
        f"Manually entered local tasks: {overview.task_count}",
        "Task operator: unauthenticated local CLI identity",
        "Task ordering: due time ascending, then creation time and task UUID; "
        "undated tasks by creation time and UUID; completed by completion time and UUID.",
    ]
    for section in overview.task_sections:
        lines.extend(["", f"{section.category.value} ({len(section.tasks)}):"])
        if not section.tasks:
            lines.append("  None")
        else:
            lines.extend(_task_text(task, overview) for task in section.tasks)
    lines.extend(
        [
            "",
            "Source data: fictional synthetic GitHub fixture; not live GitHub information.",
            "Task entries are manually entered data, not claims extracted from sources.",
            "No task, deadline, priority, resolution, or recommendation is inferred from evidence.",
            "",
            format_text_brief(overview.evidence),
            "",
            "Synthetic incremental replay status (not live GitHub freshness):",
            f"  Source UUID: {overview.sync.source_id}",
            f"  Cursor UUID: {overview.sync.cursor_id}",
            f"  Fixture: {overview.sync.fixture_version} ({overview.sync.fixture_sha256})",
            f"  Generation: {overview.sync.generation}; pages: "
            f"{overview.sync.completed_pages}/{overview.sync.total_pages}",
            f"  Incremental items: {overview.sync.item_count}; spans: {overview.sync.span_count}",
            f"  Fixture replay status: {overview.sync.status.value}",
            "  This status describes only the fixed synthetic replay; "
            "it is not a provider sync claim.",
        ]
    )
    return "\n".join(lines)


def _task_document(task: LocalOverviewTask, overview: LocalOverview) -> dict[str, object]:
    return {
        "task_id": str(task.task_id),
        "title": escape_display_text(task.title),
        "status": task.status.value,
        "revision": task.revision,
        "due_at_utc": None if task.due_at is None else _datetime_utc(task.due_at),
        "due_at_local": None if task.due_at is None else _datetime_local(task.due_at, overview),
        "completed_at_utc": (
            None if task.completed_at is None else _datetime_utc(task.completed_at)
        ),
    }


def format_json_local_overview(overview: LocalOverview) -> str:
    _validated(overview)
    try:
        evidence = json.loads(format_json_brief(overview.evidence))
        document = {
            "schema_version": overview.schema_version,
            "synthetic_data": overview.synthetic_data,
            "synthetic_data_scope": (
                "GitHub evidence and fixture-sync state only; tasks are manual entries"
            ),
            "as_of_utc": _datetime_utc(overview.as_of_utc),
            "reporting_offset": overview.reporting_offset,
            "local_day": overview.local_day.isoformat(),
            "task_count": overview.task_count,
            "task_counts": {
                section.category.value: len(section.tasks)
                for section in overview.task_sections
            },
            "task_provenance": TASK_PROVENANCE,
            "task_operator_authenticated": False,
            "task_sections": [
                {
                    "category": section.category.value,
                    "provenance": section.provenance,
                    "tasks": [_task_document(task, overview) for task in section.tasks],
                }
                for section in overview.task_sections
            ],
            "synthetic_evidence": evidence,
            "incremental_sync": {
                "provenance": overview.sync.provenance,
                "source_id": str(overview.sync.source_id),
                "cursor_id": str(overview.sync.cursor_id),
                "fixture_version": overview.sync.fixture_version,
                "fixture_sha256": overview.sync.fixture_sha256,
                "generation": overview.sync.generation,
                "completed_pages": overview.sync.completed_pages,
                "total_pages": overview.sync.total_pages,
                "item_count": overview.sync.item_count,
                "span_count": overview.sync.span_count,
                "status": overview.sync.status.value,
                "live_provider_freshness_claim": False,
            },
        }
        return json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except OverviewError:
        raise
    except (TypeError, ValueError, OverflowError):
        raise OverviewError(OverviewErrorCode.EVIDENCE_UNAVAILABLE) from None


__all__ = ["format_json_local_overview", "format_text_local_overview"]
