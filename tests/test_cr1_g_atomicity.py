"""Atomicity, lease contention and process-death coverage for CR1-G."""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import sentinel.ingestion.github_fixture as ingestion_module
from sentinel.ingestion import (
    GithubFixtureIngestionError,
    GithubFixtureIngestionErrorCode,
    ingest_packaged_github_fixture,
)
from sentinel.storage.connection import readonly_database_connection
from tests.cr1_g_support import initialized_database


@pytest.mark.parametrize("failure_stage", ["registration", "item", "span"])
def test_injected_failure_at_each_batch_stage_rolls_back_everything(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    database = initialized_database(tmp_path / f"rollback-{failure_stage}.sqlite3")
    helper_name = {
        "registration": "_register_source_rows",
        "item": "_ensure_item",
        "span": "_ensure_span",
    }[failure_stage]
    original = getattr(ingestion_module, helper_name)
    calls = 0

    def fail_after(*args: object, **kwargs: object) -> object:
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if failure_stage == "registration" or calls == 1:
            raise RuntimeError("synthetic injected failure")
        return result

    monkeypatch.setattr(ingestion_module, helper_name, fail_after)
    with pytest.raises(GithubFixtureIngestionError) as error:
        ingest_packaged_github_fixture(database)
    assert error.value.code is GithubFixtureIngestionErrorCode.PERSISTENCE_FAILURE
    assert "synthetic injected failure" not in str(error.value)
    assert _application_counts(database) == (0, 0, 0, 0, 0)


def test_process_termination_before_commit_leaves_no_partial_batch(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "killed-writer.sqlite3")
    marker = tmp_path / "span-inserted.marker"
    script = r'''
import sys, time
import sentinel.ingestion.github_fixture as module
original = module._ensure_span
def pause_after_first_span(connection, expected):
    result = original(connection, expected)
    with open(sys.argv[2], "w", encoding="ascii") as marker:
        marker.write("ready")
    time.sleep(60)
    return result
module._ensure_span = pause_after_first_span
module.ingest_packaged_github_fixture(sys.argv[1])
'''
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(database), str(marker)],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    try:
        assert marker.exists(), "child did not reach the in-transaction span insert"
    finally:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    assert process.returncode is not None and process.returncode != 0
    assert "Traceback" not in stderr or "synthetic" not in stderr
    assert stdout == ""
    assert _application_counts(database) == (0, 0, 0, 0, 0)


def test_second_process_cannot_acquire_writer_or_insert_rows(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "contended.sqlite3")
    marker = tmp_path / "lease-held.marker"
    script = r'''
import sys, time
from sentinel.storage.writer import acquire_writer_lease
with acquire_writer_lease(sys.argv[1]):
    with open(sys.argv[2], "w", encoding="ascii") as marker:
        marker.write("ready")
    time.sleep(60)
'''
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(database), str(marker)],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    try:
        assert marker.exists(), "independent writer process did not acquire its lease"
        started = time.monotonic()
        with pytest.raises(GithubFixtureIngestionError) as error:
            ingest_packaged_github_fixture(database)
        assert error.value.code is GithubFixtureIngestionErrorCode.WRITER_UNAVAILABLE
        assert time.monotonic() - started < 3
        assert _application_counts(database) == (0, 0, 0, 0, 0)
    finally:
        process.kill()
        process.communicate(timeout=5)


def test_detectable_hard_linked_database_is_refused(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "hardlinked.sqlite3")
    alias = tmp_path / "hardlink-alias.sqlite3"
    os.link(database, alias)
    assert database.stat().st_nlink > 1

    with pytest.raises(GithubFixtureIngestionError) as error:
        ingest_packaged_github_fixture(database)
    assert error.value.code is GithubFixtureIngestionErrorCode.MULTIPLE_HARD_LINKS
    assert _application_counts(database) == (0, 0, 0, 0, 0)


def _application_counts(database: Path) -> tuple[int, int, int, int, int]:
    with readonly_database_connection(database) as connection:
        values = tuple(
            int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in (
                "principals",
                "plugin_manifests",
                "sources",
                "source_items",
                "source_spans",
            )
        )
    assert len(values) == 5
    return values  # type: ignore[return-value]
