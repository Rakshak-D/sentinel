"""Disposable state for the read-only CR1-L overview tests."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from sentinel.storage.connection import readonly_database_connection
from sentinel.sync import advance_incremental_github_fixture, setup_incremental_github_fixture
from sentinel.tasks import create_local_task, setup_local_task_operator
from tests.cr1_k_support import promoted_case

AS_OF = datetime.fromisoformat("2026-11-04T18:00:00+05:30")


def overview_case(
    tmp_path: Path,
    *,
    name: str = "overview",
    generation: int = 0,
    operator: bool = True,
    cursor: bool = True,
) -> tuple[Path, Path]:
    database, store_root = promoted_case(tmp_path, name=name)
    if operator:
        setup_local_task_operator(database)
    if cursor:
        setup_incremental_github_fixture(database, store_root=store_root)
    for expected_generation in range(generation):
        advance_incremental_github_fixture(
            database,
            store_root=store_root,
            expected_generation=expected_generation,
        )
    return database, store_root


def add_task(
    database: Path,
    *,
    key: str,
    title: str,
    due_at: datetime | None = None,
):
    return create_local_task(
        database,
        request_id=uuid5(NAMESPACE_URL, f"sentinel:test:cr1-l:{key}"),
        title=title,
        due_at=due_at,
    ).task


def persisted_state(database: Path, store_root: Path):
    with readonly_database_connection(database) as connection:
        table_order = (
            ("tasks", "task_id"),
            ("task_creation_requests", "request_id"),
            ("source_items", "item_id"),
            ("source_spans", "span_id"),
            ("sync_cursors", "cursor_id"),
        )
        rows = {
            table: tuple(
                tuple(row)
                for row in connection.execute(
                    f"SELECT * FROM {table} ORDER BY {primary_key}"
                ).fetchall()
            )
            for table, primary_key in table_order
        }
    blobs = {
        path.relative_to(store_root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in store_root.rglob("*.blob")
    }
    return rows, blobs
