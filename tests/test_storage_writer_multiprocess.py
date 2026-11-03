"""Real independent-process writer ownership and crash-release tests."""

from __future__ import annotations

import multiprocessing
import sqlite3
import time
from pathlib import Path
from typing import Any

from sentinel.storage.migrations import initialize_storage
from sentinel.storage.writer import WriterLeaseError, acquire_writer_lease


def _child_attempt_acquire(database: str, sender: Any) -> None:
    started = time.monotonic()
    try:
        with acquire_writer_lease(Path(database)) as lease:
            with lease.transaction() as connection:
                connection.execute("PRAGMA user_version = 88")
        sender.send(("acquired", time.monotonic() - started))
    except WriterLeaseError as exc:
        sender.send((exc.code.value, time.monotonic() - started))
    finally:
        sender.close()


def _child_hold_uncommitted_transaction(database: str, ready: Any, wait: Any) -> None:
    with acquire_writer_lease(Path(database)) as lease:
        with lease.transaction() as connection:
            connection.execute("PRAGMA user_version = 777")
            ready.set()
            wait.wait(30)


def _fresh_database(tmp_path: Path) -> Path:
    database = tmp_path / "sentinel.sqlite3"
    initialize_storage(database, create=True)
    return database


def _join_or_terminate(process: multiprocessing.Process, timeout: float = 8.0) -> None:
    process.join(timeout)
    if process.is_alive():
        process.terminate()
        process.join(3)
        raise AssertionError("writer lease child exceeded its bounded test timeout")


def test_competing_process_fails_fast_without_executing_caller_sql(tmp_path: Path) -> None:
    database = _fresh_database(tmp_path)
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_child_attempt_acquire, args=(str(database), sender))

    with acquire_writer_lease(database) as lease:
        process.start()
        sender.close()
        try:
            assert receiver.poll(8), "competing writer did not return before test timeout"
            outcome, elapsed = receiver.recv()
            _join_or_terminate(process)
            assert outcome == "lock_contended"
            assert elapsed < 1.0
            with sqlite3.connect(
                f"{database.resolve().as_uri()}?mode=ro", uri=True
            ) as connection:
                assert connection.execute("PRAGMA user_version").fetchone() == (0,)
            with lease.transaction() as connection:
                connection.execute("PRAGMA user_version = 21")
        finally:
            if process.is_alive():
                process.terminate()
                process.join(3)
            receiver.close()
    with sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (21,)


def test_process_can_acquire_after_normal_release(tmp_path: Path) -> None:
    database = _fresh_database(tmp_path)
    with acquire_writer_lease(database):
        pass

    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_child_attempt_acquire, args=(str(database), sender))
    process.start()
    sender.close()
    try:
        assert receiver.poll(8), "writer child did not finish before test timeout"
        outcome, _elapsed = receiver.recv()
        _join_or_terminate(process)
        assert outcome == "acquired"
    finally:
        if process.is_alive():
            process.terminate()
            process.join(3)
        receiver.close()


def test_process_termination_releases_mutex_and_rolls_back_sqlite_transaction(
    tmp_path: Path,
) -> None:
    database = _fresh_database(tmp_path)
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    wait = context.Event()
    process = context.Process(
        target=_child_hold_uncommitted_transaction,
        args=(str(database), ready, wait),
    )
    process.start()
    try:
        assert ready.wait(8), "writer child did not enter transaction before test timeout"
        process.terminate()
        process.join(5)
        assert not process.is_alive()

        with acquire_writer_lease(database) as lease:
            with lease.transaction() as connection:
                assert connection.execute("PRAGMA user_version").fetchone() == (0,)
                connection.execute("PRAGMA user_version = 13")
    finally:
        if process.is_alive():
            process.terminate()
            process.join(3)

    with sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (13,)
