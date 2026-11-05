"""Synthetic fixtures for CR1-R workspace tests."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

from sentinel.bootstrap.init import initialize_new_database


def new_database(tmp_path: Path, name: str = "workspace") -> tuple[Path, Path]:
    database = tmp_path / f"{name}.sqlite3"
    store_root = tmp_path / f"{name}-public-store"
    initialize_new_database(database)
    return database, store_root


def sentinel_executable() -> Path:
    return Path(sys.executable).parent / "sentinel.exe"


def run_cli(arguments: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(sentinel_executable()), *arguments],
        cwd=cwd,
        capture_output=True,
        timeout=60,
        check=False,
    )


def table_rows(database: Path, table: str) -> tuple[tuple[object, ...], ...]:
    allowed = {
        "principals",
        "plugin_manifests",
        "sources",
        "sync_cursors",
        "source_items",
        "source_spans",
        "tasks",
        "task_creation_requests",
        "action_proposals",
    }
    if table not in allowed:
        raise ValueError("test table name is not allowlisted")
    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    try:
        return tuple(tuple(row) for row in connection.execute(f'SELECT * FROM "{table}"'))
    finally:
        connection.close()
