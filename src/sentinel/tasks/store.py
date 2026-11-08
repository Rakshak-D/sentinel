"""Transactional, manual-only local task storage."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Final
from uuid import NAMESPACE_URL, UUID, uuid5

from sentinel.storage.connection import readonly_database_connection
from sentinel.storage.migrations import (
    MIGRATIONS,
    MigrationIntegrityError,
    has_registered_migration,
    inspect_migration_state_readonly,
    verify_integrity,
)
from sentinel.storage.schema import CURRENT_SCHEMA
from sentinel.storage.writer import (
    WriterLeaseError,
    WriterLeaseErrorCode,
    acquire_writer_lease,
)
from sentinel.tasks.types import (
    LocalTask,
    LocalTaskOperator,
    TaskCreateResult,
    TaskStatus,
)

LOCAL_TASK_OPERATOR_ID: Final = uuid5(NAMESPACE_URL, "sentinel:local-task-operator:v1")
_TASK_ID_NAMESPACE: Final = uuid5(NAMESPACE_URL, "sentinel:manual-task-id:v1")
_OPERATOR_KIND: Final = "local-task-operator"
_OPERATOR_DISPLAY_NAME: Final = "Sentinel local task operator (unauthenticated)"
_OPERATOR_OS_BINDING: Final = "local-cli-unverified"
_MAX_TITLE_CHARACTERS: Final = 200
_MAX_TITLE_UTF8_BYTES: Final = 800
_SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
_BIDI_CONTROLS: Final = frozenset(
    {
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
    }
)


class TaskStoreErrorCode(StrEnum):
    INVALID_INPUT = "invalid_input"
    DATABASE_UNAVAILABLE = "database_unavailable"
    SCHEMA_NOT_CURRENT = "schema_not_current"
    WRITER_UNAVAILABLE = "writer_unavailable"
    OPERATOR_CONFLICT = "operator_conflict"
    OPERATOR_NOT_INITIALIZED = "operator_not_initialized"
    REQUEST_CONFLICT = "request_conflict"
    TASK_NOT_FOUND = "task_not_found"
    TASK_CONFLICT = "task_conflict"
    REVISION_CONFLICT = "revision_conflict"
    INVALID_TRANSITION = "invalid_transition"
    NO_CHANGES = "no_changes"


_ERROR_MESSAGES: Final[dict[TaskStoreErrorCode, str]] = {
    TaskStoreErrorCode.INVALID_INPUT: "Task input is invalid.",
    TaskStoreErrorCode.DATABASE_UNAVAILABLE: "The selected Sentinel database is unavailable.",
    TaskStoreErrorCode.SCHEMA_NOT_CURRENT: (
        "The database does not have the current Sentinel schema."
    ),
    TaskStoreErrorCode.WRITER_UNAVAILABLE: "Another Sentinel writer is active or unavailable.",
    TaskStoreErrorCode.OPERATOR_CONFLICT: (
        "The local task operator identity conflicts with stored data."
    ),
    TaskStoreErrorCode.OPERATOR_NOT_INITIALIZED: (
        "Initialize the local task operator with 'sentinel task setup' first."
    ),
    TaskStoreErrorCode.REQUEST_CONFLICT: (
        "The request ID was already used with different task arguments."
    ),
    TaskStoreErrorCode.TASK_NOT_FOUND: "The selected local task does not exist.",
    TaskStoreErrorCode.TASK_CONFLICT: "The selected local task has conflicting stored state.",
    TaskStoreErrorCode.REVISION_CONFLICT: (
        "The task revision is stale; list tasks and retry with its current revision."
    ),
    TaskStoreErrorCode.INVALID_TRANSITION: "The requested task status transition is not allowed.",
    TaskStoreErrorCode.NO_CHANGES: "At least one task field must change.",
}


class TaskStoreError(RuntimeError):
    """Fixed-message task operation failure with no user data or paths."""

    def __init__(self, code: TaskStoreErrorCode) -> None:
        if type(code) is not TaskStoreErrorCode:
            raise TypeError("task error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


@contextmanager
def _write_transaction(database: str | Path) -> Iterator[sqlite3.Connection]:
    _require_current_readonly(database)
    try:
        with acquire_writer_lease(database) as lease:
            with lease.transaction() as connection:
                _require_current_in_transaction(connection)
                yield connection
    except TaskStoreError:
        raise
    except WriterLeaseError as exc:
        code = (
            TaskStoreErrorCode.SCHEMA_NOT_CURRENT
            if exc.code is WriterLeaseErrorCode.MIGRATION_INVALID
            else TaskStoreErrorCode.WRITER_UNAVAILABLE
            if exc.code in {WriterLeaseErrorCode.LOCK_CONTENDED, WriterLeaseErrorCode.REENTRANT}
            else TaskStoreErrorCode.DATABASE_UNAVAILABLE
        )
        raise TaskStoreError(code) from None
    except (sqlite3.Error, OSError, ValueError, TypeError):
        raise TaskStoreError(TaskStoreErrorCode.DATABASE_UNAVAILABLE) from None
    except Exception:
        # Keep public errors bounded even when an unexpected storage error occurs.
        raise TaskStoreError(TaskStoreErrorCode.DATABASE_UNAVAILABLE) from None


@contextmanager
def _read_connection(database: str | Path) -> Iterator[sqlite3.Connection]:
    try:
        with readonly_database_connection(database) as connection:
            state = inspect_migration_state_readonly(connection)
            if not has_registered_migration(state, MIGRATIONS[3].migration_id):
                raise TaskStoreError(TaskStoreErrorCode.SCHEMA_NOT_CURRENT)
            verify_integrity(connection)
            yield connection
    except TaskStoreError:
        raise
    except MigrationIntegrityError:
        raise TaskStoreError(TaskStoreErrorCode.SCHEMA_NOT_CURRENT) from None
    except (sqlite3.Error, OSError, ValueError, TypeError):
        raise TaskStoreError(TaskStoreErrorCode.DATABASE_UNAVAILABLE) from None
    except Exception:
        raise TaskStoreError(TaskStoreErrorCode.DATABASE_UNAVAILABLE) from None


def _require_current_readonly(database: str | Path) -> None:
    with _read_connection(database):
        pass


def _require_current_in_transaction(connection: sqlite3.Connection) -> None:
    """Recheck migration identity and the whole DDL inventory before first DML."""

    try:
        rows = connection.execute(
            """SELECT migration_id, artifact_sha256, success
               FROM schema_migrations ORDER BY applied_at, migration_id"""
        ).fetchall()
        expected_history = tuple(
            (migration.migration_id, migration.artifact_sha256, 1) for migration in MIGRATIONS
        )
        if tuple(tuple(row) for row in rows) != expected_history:
            raise TaskStoreError(TaskStoreErrorCode.SCHEMA_NOT_CURRENT)

        actual_rows = connection.execute(
            """SELECT type, name, sql FROM sqlite_master
               WHERE name NOT GLOB 'sqlite_*'
                 AND type IN ('table', 'index', 'view', 'trigger')"""
        ).fetchall()
        actual = {(str(kind), str(name)): sql for kind, name, sql in actual_rows}
        expected = {(item.object_type, item.name): item.sql for item in CURRENT_SCHEMA.objects}
        if actual.keys() != expected.keys() or any(
            not isinstance(actual[key], str) or actual[key].strip() != sql.strip()
            for key, sql in expected.items()
        ):
            raise TaskStoreError(TaskStoreErrorCode.SCHEMA_NOT_CURRENT)
    except TaskStoreError:
        raise
    except sqlite3.Error:
        raise TaskStoreError(TaskStoreErrorCode.SCHEMA_NOT_CURRENT) from None


def _validate_database_arg(database: str | Path) -> None:
    if type(database) is str:
        path = Path(database)
    elif isinstance(database, Path):
        path = database
    else:
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)
    if not path.is_absolute() or "\x00" in str(path):
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)


def _utc_now() -> datetime:
    """Internal trusted clock seam; not exposed as a caller option."""

    return datetime.now(UTC)


def _canonical_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_datetime(value: object) -> datetime:
    if type(value) is not str:
        raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
    normalized = parsed.astimezone(UTC)
    if _canonical_datetime(normalized) != value:
        raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
    return normalized


def _current_time() -> datetime:
    now = _utc_now()
    if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
        raise TaskStoreError(TaskStoreErrorCode.DATABASE_UNAVAILABLE)
    return now.astimezone(UTC)


def _validate_task_title(title: object) -> str:
    if type(title) is not str or not title or title.isspace():
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)
    if len(title) > _MAX_TITLE_CHARACTERS:
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)
    try:
        encoded = title.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT) from None
    if len(encoded) > _MAX_TITLE_UTF8_BYTES:
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)
    for character in title:
        codepoint = ord(character)
        category = unicodedata.category(character)
        if codepoint == 0 or codepoint in _BIDI_CONTROLS or category in {"Cc", "Cs", "Zl", "Zp"}:
            raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)
    return title


def _normalize_due_at(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not datetime:
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)
    try:
        offset = value.utcoffset()
    except (OverflowError, TypeError, ValueError):
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT) from None
    if value.tzinfo is None or offset is None:
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)
    try:
        return _canonical_datetime(value)
    except (OverflowError, TypeError, ValueError):
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT) from None


def _task_id(request_id: UUID) -> UUID:
    return uuid5(_TASK_ID_NAMESPACE, f"{LOCAL_TASK_OPERATOR_ID}:{request_id}")


def _request_sha256(title: str, due_at: str | None) -> str:
    value = json.dumps(
        {"due_at": due_at, "title": title},
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _operator_matches(row: tuple[object, ...]) -> bool:
    if len(row) != 6:
        return False
    principal_id, kind, display_name, os_binding, created_at, revoked_at = row
    if (
        principal_id != str(LOCAL_TASK_OPERATOR_ID)
        or kind != _OPERATOR_KIND
        or display_name != _OPERATOR_DISPLAY_NAME
        or os_binding != _OPERATOR_OS_BINDING
        or revoked_at is not None
    ):
        return False
    try:
        return _canonical_datetime(_parse_datetime(created_at)) == created_at
    except TaskStoreError:
        return False


def _require_operator(connection: sqlite3.Connection) -> LocalTaskOperator:
    rows = connection.execute(
        """SELECT principal_id, kind, display_name, os_binding, created_at, revoked_at
           FROM principals WHERE kind = ? ORDER BY principal_id""",
        (_OPERATOR_KIND,),
    ).fetchall()
    if len(rows) > 1 or (rows and not _operator_matches(tuple(rows[0]))):
        raise TaskStoreError(TaskStoreErrorCode.OPERATOR_CONFLICT)
    row = connection.execute(
        """SELECT principal_id, kind, display_name, os_binding, created_at, revoked_at
           FROM principals WHERE principal_id = ?""",
        (str(LOCAL_TASK_OPERATOR_ID),),
    ).fetchone()
    if row is None:
        raise TaskStoreError(TaskStoreErrorCode.OPERATOR_NOT_INITIALIZED)
    if not _operator_matches(tuple(row)):
        raise TaskStoreError(TaskStoreErrorCode.OPERATOR_CONFLICT)
    return LocalTaskOperator(
        principal_id=LOCAL_TASK_OPERATOR_ID,
        kind=_OPERATOR_KIND,
        display_name=_OPERATOR_DISPLAY_NAME,
        os_binding=_OPERATOR_OS_BINDING,
        created_at=_parse_datetime(row[4]),
    )


def _task_from_row(row: tuple[object, ...]) -> LocalTask:
    if len(row) != 12:
        raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
    (
        task_id,
        owner_principal_id,
        source_item_id,
        proposal_id,
        title,
        body_ref,
        due_at,
        status,
        revision,
        created_at,
        updated_at,
        completed_at,
    ) = row
    try:
        if type(status) is not str:
            raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
        parsed_status = TaskStatus(status)
        parsed_task_id = UUID(task_id) if type(task_id) is str else None
        parsed_operator = UUID(owner_principal_id) if type(owner_principal_id) is str else None
    except (ValueError, TypeError):
        raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT) from None
    if (
        parsed_task_id is None
        or str(parsed_task_id) != task_id
        or parsed_operator != LOCAL_TASK_OPERATOR_ID
        or str(parsed_operator) != owner_principal_id
        or source_item_id is not None
        or proposal_id is not None
        or body_ref is not None
        or type(title) is not str
        or isinstance(revision, bool)
        or type(revision) is not int
        or revision < 1
    ):
        raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
    try:
        _validate_task_title(title)
    except TaskStoreError:
        raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT) from None
    parsed_due = None if due_at is None else _parse_datetime(due_at)
    parsed_completed = None if completed_at is None else _parse_datetime(completed_at)
    if (parsed_status is TaskStatus.OPEN) != (parsed_completed is None):
        raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
    return LocalTask(
        task_id=parsed_task_id,
        owner_principal_id=parsed_operator,
        title=title,
        due_at=parsed_due,
        status=parsed_status,
        revision=revision,
        created_at=_parse_datetime(created_at),
        updated_at=_parse_datetime(updated_at),
        completed_at=parsed_completed,
    )


def _select_task(connection: sqlite3.Connection, task_id: UUID) -> LocalTask | None:
    row = connection.execute(
        """SELECT task_id, owner_principal_id, source_item_id, proposal_id,
                  title, body_ref, due_at, status, revision, created_at,
                  updated_at, completed_at
           FROM tasks WHERE task_id = ?""",
        (str(task_id),),
    ).fetchone()
    return None if row is None else _task_from_row(tuple(row))


def _validate_task_id(task_id: object) -> UUID:
    if type(task_id) is not UUID:
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)
    return task_id


def _validate_revision(expected_revision: object) -> int:
    if (
        isinstance(expected_revision, bool)
        or type(expected_revision) is not int
        or expected_revision < 1
    ):
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)
    return expected_revision


def _check_request_receipt(connection: sqlite3.Connection, task: LocalTask) -> tuple[UUID, str]:
    row = connection.execute(
        "SELECT request_id, task_id, request_sha256 FROM task_creation_requests WHERE task_id = ?",
        (str(task.task_id),),
    ).fetchone()
    if row is None or type(row[0]) is not str or type(row[2]) is not str:
        raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
    try:
        request_id = UUID(row[0])
    except (ValueError, TypeError):
        raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT) from None
    if (
        str(request_id) != row[0]
        or row[1] != str(task.task_id)
        or _task_id(request_id) != task.task_id
        or not _SHA256_PATTERN.fullmatch(row[2])
    ):
        raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
    return request_id, row[2]


def _insert_creation_receipt(
    connection: sqlite3.Connection,
    request_id: UUID,
    task_id: UUID,
    request_sha256: str,
) -> None:
    connection.execute(
        """INSERT INTO task_creation_requests (request_id, task_id, request_sha256)
           VALUES (?, ?, ?)""",
        (str(request_id), str(task_id), request_sha256),
    )


def _load_owned_task(
    connection: sqlite3.Connection,
    task_id: UUID,
    expected_revision: int | None = None,
) -> LocalTask:
    _require_operator(connection)
    task = _select_task(connection, task_id)
    if task is None:
        raise TaskStoreError(TaskStoreErrorCode.TASK_NOT_FOUND)
    _check_request_receipt(connection, task)
    if expected_revision is not None and task.revision != expected_revision:
        raise TaskStoreError(TaskStoreErrorCode.REVISION_CONFLICT)
    return task


def setup_local_task_operator(database: str | Path) -> LocalTaskOperator:
    """Register/reuse the deterministic unauthenticated local CLI operator."""

    _validate_database_arg(database)
    with _write_transaction(database) as connection:
        row = connection.execute(
            """SELECT principal_id, kind, display_name, os_binding, created_at, revoked_at
               FROM principals WHERE principal_id = ?""",
            (str(LOCAL_TASK_OPERATOR_ID),),
        ).fetchone()
        other_rows = connection.execute(
            "SELECT principal_id FROM principals WHERE kind = ? AND principal_id != ?",
            (_OPERATOR_KIND, str(LOCAL_TASK_OPERATOR_ID)),
        ).fetchall()
        if other_rows or (row is not None and not _operator_matches(tuple(row))):
            raise TaskStoreError(TaskStoreErrorCode.OPERATOR_CONFLICT)
        if row is None:
            created_at = _canonical_datetime(_current_time())
            connection.execute(
                """INSERT INTO principals
                   (principal_id, kind, display_name, os_binding, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    str(LOCAL_TASK_OPERATOR_ID),
                    _OPERATOR_KIND,
                    _OPERATOR_DISPLAY_NAME,
                    _OPERATOR_OS_BINDING,
                    created_at,
                ),
            )
            return LocalTaskOperator(
                principal_id=LOCAL_TASK_OPERATOR_ID,
                kind=_OPERATOR_KIND,
                display_name=_OPERATOR_DISPLAY_NAME,
                os_binding=_OPERATOR_OS_BINDING,
                created_at=_parse_datetime(created_at),
            )
        return _require_operator(connection)


def create_local_task(
    database: str | Path,
    *,
    request_id: UUID,
    title: str,
    due_at: datetime | None = None,
) -> TaskCreateResult:
    """Create a manual task once per explicit request UUID; never source-derived."""

    _validate_database_arg(database)
    if type(request_id) is not UUID:
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)
    validated_title = _validate_task_title(title)
    canonical_due_at = _normalize_due_at(due_at)
    task_id = _task_id(request_id)
    request_sha256 = _request_sha256(validated_title, canonical_due_at)

    with _write_transaction(database) as connection:
        operator = _require_operator(connection)
        receipt = connection.execute(
            "SELECT task_id, request_sha256 FROM task_creation_requests WHERE request_id = ?",
            (str(request_id),),
        ).fetchone()
        if receipt is not None:
            if receipt[0] != str(task_id) or receipt[1] != request_sha256:
                raise TaskStoreError(TaskStoreErrorCode.REQUEST_CONFLICT)
            existing = _select_task(connection, task_id)
            if existing is None or existing.owner_principal_id != operator.principal_id:
                raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
            _check_request_receipt(connection, existing)
            return TaskCreateResult(task=existing, request_id=request_id, created=False)

        if _select_task(connection, task_id) is not None:
            raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
        now = _canonical_datetime(_current_time())
        connection.execute(
            """INSERT INTO tasks
               (task_id, owner_principal_id, source_item_id, proposal_id, title,
                body_ref, due_at, status, revision, created_at, updated_at, completed_at)
               VALUES (?, ?, NULL, NULL, ?, NULL, ?, 'OPEN', 1, ?, ?, NULL)""",
            (str(task_id), str(operator.principal_id), validated_title, canonical_due_at, now, now),
        )
        _insert_creation_receipt(connection, request_id, task_id, request_sha256)
        created = _select_task(connection, task_id)
        if created is None:
            raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
        return TaskCreateResult(task=created, request_id=request_id, created=True)


def list_local_tasks(
    database: str | Path,
    *,
    status: TaskStatus | None = None,
) -> tuple[LocalTask, ...]:
    """Read manual operator tasks in due/creation/ID order using a query-only DB."""

    _validate_database_arg(database)
    if status is not None and type(status) is not TaskStatus:
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)
    with _read_connection(database) as connection:
        operator_row = connection.execute(
            """SELECT principal_id, kind, display_name, os_binding, created_at, revoked_at
               FROM principals WHERE principal_id = ?""",
            (str(LOCAL_TASK_OPERATOR_ID),),
        ).fetchone()
        if operator_row is None:
            raise TaskStoreError(TaskStoreErrorCode.OPERATOR_NOT_INITIALIZED)
        if not _operator_matches(tuple(operator_row)):
            raise TaskStoreError(TaskStoreErrorCode.OPERATOR_CONFLICT)
        query = """SELECT task_id, owner_principal_id, source_item_id, proposal_id,
                          title, body_ref, due_at, status, revision, created_at,
                          updated_at, completed_at
                   FROM tasks WHERE owner_principal_id = ?"""
        parameters: tuple[object, ...] = (str(LOCAL_TASK_OPERATOR_ID),)
        if status is not None:
            query += " AND status = ?"
            parameters += (status.value,)
        query += " ORDER BY due_at IS NULL, due_at, created_at, task_id"
        rows = connection.execute(query, parameters).fetchall()
        tasks = tuple(_task_from_row(tuple(row)) for row in rows)
        for task in tasks:
            _check_request_receipt(connection, task)
        return tasks


class _Unchanged:
    __slots__ = ()


UNCHANGED: Final = _Unchanged()


def edit_local_task(
    database: str | Path,
    *,
    task_id: UUID,
    expected_revision: int,
    title: str | _Unchanged = UNCHANGED,
    due_at: datetime | None | _Unchanged = UNCHANGED,
) -> LocalTask:
    """Edit selected task fields with an optimistic revision check."""

    _validate_database_arg(database)
    task_uuid = _validate_task_id(task_id)
    revision = _validate_revision(expected_revision)
    if title is UNCHANGED and due_at is UNCHANGED:
        raise TaskStoreError(TaskStoreErrorCode.NO_CHANGES)
    new_title = None if title is UNCHANGED else _validate_task_title(title)
    new_due = None if due_at is UNCHANGED else _normalize_due_at(due_at)

    with _write_transaction(database) as connection:
        current = _load_owned_task(connection, task_uuid, revision)
        selected_title = current.title if title is UNCHANGED else new_title
        selected_due = (
            current.due_at
            if due_at is UNCHANGED
            else (None if new_due is None else _parse_datetime(new_due))
        )
        if selected_title == current.title and selected_due == current.due_at:
            raise TaskStoreError(TaskStoreErrorCode.NO_CHANGES)
        now = _canonical_datetime(_current_time())
        cursor = connection.execute(
            """UPDATE tasks SET title = ?, due_at = ?, revision = revision + 1,
                      updated_at = ? WHERE task_id = ? AND revision = ?""",
            (
                selected_title,
                None if selected_due is None else _canonical_datetime(selected_due),
                now,
                str(task_uuid),
                revision,
            ),
        )
        if cursor.rowcount != 1:
            raise TaskStoreError(TaskStoreErrorCode.REVISION_CONFLICT)
        updated = _select_task(connection, task_uuid)
        if updated is None:
            raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
        return updated


def _transition_local_task(
    database: str | Path,
    *,
    task_id: UUID,
    expected_revision: int,
    target: TaskStatus,
) -> LocalTask:
    _validate_database_arg(database)
    task_uuid = _validate_task_id(task_id)
    revision = _validate_revision(expected_revision)
    if type(target) is not TaskStatus:
        raise TaskStoreError(TaskStoreErrorCode.INVALID_INPUT)
    with _write_transaction(database) as connection:
        current = _load_owned_task(connection, task_uuid, revision)
        expected_source = (
            TaskStatus.OPEN if target is TaskStatus.COMPLETED else TaskStatus.COMPLETED
        )
        if current.status is not expected_source:
            raise TaskStoreError(TaskStoreErrorCode.INVALID_TRANSITION)
        now = _canonical_datetime(_current_time())
        completed_at = now if target is TaskStatus.COMPLETED else None
        cursor = connection.execute(
            """UPDATE tasks SET status = ?, completed_at = ?, revision = revision + 1,
                      updated_at = ? WHERE task_id = ? AND revision = ?""",
            (target.value, completed_at, now, str(task_uuid), revision),
        )
        if cursor.rowcount != 1:
            raise TaskStoreError(TaskStoreErrorCode.REVISION_CONFLICT)
        updated = _select_task(connection, task_uuid)
        if updated is None:
            raise TaskStoreError(TaskStoreErrorCode.TASK_CONFLICT)
        return updated


def complete_local_task(
    database: str | Path,
    *,
    task_id: UUID,
    expected_revision: int,
) -> LocalTask:
    """Transition one OPEN task to COMPLETED."""

    return _transition_local_task(
        database,
        task_id=task_id,
        expected_revision=expected_revision,
        target=TaskStatus.COMPLETED,
    )


def reopen_local_task(
    database: str | Path,
    *,
    task_id: UUID,
    expected_revision: int,
) -> LocalTask:
    """Transition one COMPLETED task back to OPEN."""

    return _transition_local_task(
        database,
        task_id=task_id,
        expected_revision=expected_revision,
        target=TaskStatus.OPEN,
    )


__all__ = [
    "LOCAL_TASK_OPERATOR_ID",
    "UNCHANGED",
    "TaskStoreError",
    "TaskStoreErrorCode",
    "complete_local_task",
    "create_local_task",
    "edit_local_task",
    "list_local_tasks",
    "reopen_local_task",
    "setup_local_task_operator",
]
