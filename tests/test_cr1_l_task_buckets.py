from datetime import datetime

from sentinel.overview import TaskDayCategory, build_local_overview
from sentinel.tasks import complete_local_task
from tests.cr1_l_support import AS_OF, add_task, overview_case


def test_calendar_day_buckets_use_fixed_offset_half_open_boundaries(tmp_path) -> None:
    database, store_root = overview_case(tmp_path, name="boundaries")
    tasks = {
        "overdue": add_task(
            database,
            key="overdue",
            title="Overdue",
            due_at=datetime.fromisoformat("2026-11-03T18:29:59.999999Z"),
        ),
        "at_start": add_task(
            database,
            key="at-start",
            title="At local midnight",
            due_at=datetime.fromisoformat("2026-11-03T18:30:00Z"),
        ),
        "earlier_today": add_task(
            database,
            key="earlier-today",
            title="Earlier today stays due today",
            due_at=datetime.fromisoformat("2026-11-04T01:30:00Z"),
        ),
        "before_end": add_task(
            database,
            key="before-end",
            title="Last instant today",
            due_at=datetime.fromisoformat("2026-11-04T18:29:59.999999Z"),
        ),
        "at_end": add_task(
            database,
            key="at-end",
            title="At next local midnight",
            due_at=datetime.fromisoformat("2026-11-04T18:30:00Z"),
        ),
        "undated": add_task(database, key="undated", title="No due date"),
        "completed": add_task(
            database,
            key="completed",
            title="Completed task",
            due_at=datetime.fromisoformat("2026-11-02T12:00:00Z"),
        ),
    }
    complete_local_task(
        database,
        task_id=tasks["completed"].task_id,
        expected_revision=tasks["completed"].revision,
    )

    overview = build_local_overview(database, store_root=store_root, as_of=AS_OF)
    by_category = {section.category: section.tasks for section in overview.task_sections}

    assert [task.task_id for task in by_category[TaskDayCategory.OVERDUE]] == [
        tasks["overdue"].task_id
    ]
    assert [task.task_id for task in by_category[TaskDayCategory.DUE_TODAY]] == [
        tasks["at_start"].task_id,
        tasks["earlier_today"].task_id,
        tasks["before_end"].task_id,
    ]
    assert [task.task_id for task in by_category[TaskDayCategory.UPCOMING]] == [
        tasks["at_end"].task_id
    ]
    assert [task.task_id for task in by_category[TaskDayCategory.NO_DUE_DATE]] == [
        tasks["undated"].task_id
    ]
    completed = by_category[TaskDayCategory.COMPLETED]
    assert len(completed) == 1
    assert completed[0].task_id == tasks["completed"].task_id
    assert completed[0].completed_at is not None


def test_day_uses_supplied_offset_as_a_fixed_offset(tmp_path) -> None:
    database, store_root = overview_case(tmp_path, name="fixed-offset")
    task = add_task(
        database,
        key="day-edge",
        title="Offset boundary",
        due_at=datetime.fromisoformat("2026-11-04T04:00:00Z"),
    )
    selected_as_of = datetime.fromisoformat("2026-11-04T23:59:00-04:00")

    overview = build_local_overview(database, store_root=store_root, as_of=selected_as_of)

    assert overview.local_day.isoformat() == "2026-11-04"
    assert overview.reporting_offset == "-04:00"
    assert overview.as_of_utc.isoformat() == "2026-11-05T03:59:00+00:00"
    assert overview.task_sections[1].tasks[0].task_id == task.task_id
