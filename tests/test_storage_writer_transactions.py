"""SQLite transaction behavior through an active writer lease."""

import socket
import sqlite3
import subprocess
import time
from pathlib import Path

import pytest

from sentinel.bootstrap.doctor import run_doctor
from sentinel.credentials.broker import CredentialBroker
from sentinel.gateways.model import ModelGateway
from sentinel.gateways.tool import ToolGateway
from sentinel.storage.connection import inspect_connection
from sentinel.storage.migrations import initialize_storage
from sentinel.storage.writer import (
    WriterLeaseError,
    WriterLeaseErrorCode,
    acquire_writer_lease,
)


def _database(tmp_path: Path) -> Path:
    path = tmp_path / "sentinel.sqlite3"
    initialize_storage(path, create=True)
    return path


def test_transaction_uses_begin_immediate_and_commits_user_version(tmp_path: Path) -> None:
    path = _database(tmp_path)

    with acquire_writer_lease(path) as lease:
        with lease.transaction() as connection:
            assert connection.in_transaction is True
            connection.execute("PRAGMA user_version = 37")
        assert connection.in_transaction is False

    with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (37,)


def test_failed_transaction_rolls_back_and_lease_releases(tmp_path: Path) -> None:
    path = _database(tmp_path)

    with pytest.raises(RuntimeError, match="synthetic transaction failure"):
        with acquire_writer_lease(path) as lease:
            with lease.transaction() as connection:
                connection.execute("PRAGMA user_version = 91")
                raise RuntimeError("synthetic transaction failure")

    with acquire_writer_lease(path) as lease:
        with lease.transaction() as connection:
            assert connection.execute("PRAGMA user_version").fetchone() == (0,)


def test_caller_cannot_commit_outside_the_lease_transaction_context(tmp_path: Path) -> None:
    path = _database(tmp_path)

    with acquire_writer_lease(path) as lease:
        with pytest.raises(WriterLeaseError) as error:
            with lease.transaction() as connection:
                connection.execute("PRAGMA user_version = 81")
                connection.commit()
        assert error.value.code is WriterLeaseErrorCode.TRANSACTION_FAILED

    with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (0,)


def test_retained_connection_cannot_write_after_transaction_context(tmp_path: Path) -> None:
    path = _database(tmp_path)

    with acquire_writer_lease(path) as lease:
        with lease.transaction() as connection:
            connection.execute("PRAGMA user_version = 41")

        with pytest.raises(sqlite3.DatabaseError):
            connection.execute("PRAGMA user_version = 42")

    with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (41,)


def test_transaction_rejects_schema_changes_reserved_for_trusted_migrations(
    tmp_path: Path,
) -> None:
    path = _database(tmp_path)

    with acquire_writer_lease(path) as lease:
        with lease.transaction() as connection:
            with pytest.raises(sqlite3.DatabaseError):
                connection.execute("CREATE TABLE unregistered_synthetic (value TEXT)")

    with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'unregistered_synthetic'"
        ).fetchone() is None


def test_writer_connection_enables_foreign_keys_and_preserves_wal(tmp_path: Path) -> None:
    path = _database(tmp_path)

    with acquire_writer_lease(path) as lease:
        with lease.transaction() as connection:
            settings = inspect_connection(connection)
            assert settings.foreign_keys_enabled is True
            assert settings.journal_mode == "wal"
            assert connection.execute("PRAGMA foreign_keys").fetchone() == (1,)
            assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)


def test_released_lease_cannot_be_reused_and_context_exit_releases_mutex(
    tmp_path: Path,
) -> None:
    path = _database(tmp_path)
    with acquire_writer_lease(path) as lease:
        pass

    with pytest.raises(WriterLeaseError) as error:
        with lease.transaction():
            pytest.fail("released lease started a transaction")
    assert error.value.code is WriterLeaseErrorCode.LEASE_INACTIVE

    with acquire_writer_lease(path) as reacquired:
        with reacquired.transaction() as connection:
            connection.execute("PRAGMA user_version = 2")


def test_exceptional_lease_exit_releases_ownership(tmp_path: Path) -> None:
    path = _database(tmp_path)

    with pytest.raises(RuntimeError, match="synthetic outer failure"):
        with acquire_writer_lease(path):
            raise RuntimeError("synthetic outer failure")

    with acquire_writer_lease(path):
        pass


def test_same_process_reentrant_acquisition_and_nested_transaction_are_rejected(
    tmp_path: Path,
) -> None:
    path = _database(tmp_path)
    with acquire_writer_lease(path) as lease:
        with pytest.raises(WriterLeaseError) as reentrant:
            with acquire_writer_lease(path):
                pytest.fail("same-process reentrant acquisition succeeded")
        assert reentrant.value.code is WriterLeaseErrorCode.REENTRANT

        with lease.transaction():
            with pytest.raises(WriterLeaseError) as nested:
                with lease.transaction():
                    pytest.fail("nested transaction started")
            assert nested.value.code is WriterLeaseErrorCode.TRANSACTION_ACTIVE


def test_sqlite_busy_transaction_fails_with_a_bounded_path_free_error(
    tmp_path: Path,
) -> None:
    path = _database(tmp_path)
    noncooperating = sqlite3.connect(path, isolation_level=None)
    noncooperating.execute("BEGIN IMMEDIATE")
    try:
        with acquire_writer_lease(path) as lease:
            started = time.monotonic()
            with pytest.raises(WriterLeaseError) as error:
                with lease.transaction():
                    pytest.fail("busy SQLite transaction unexpectedly began")
            elapsed = time.monotonic() - started
            assert error.value.code is WriterLeaseErrorCode.TRANSACTION_BUSY
            assert str(path) not in str(error.value)
            assert elapsed < 3.0
    finally:
        noncooperating.rollback()
        noncooperating.close()


def test_readonly_doctor_remains_usable_when_lease_has_no_write_transaction(
    tmp_path: Path,
) -> None:
    path = _database(tmp_path)

    with acquire_writer_lease(path):
        assert run_doctor(path).successful is True


def test_writer_api_does_not_trigger_network_subprocess_credentials_or_gateways(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def forbidden(name: str):
        def fail(*_args: object, **_kwargs: object) -> None:
            calls.append(name)
            raise AssertionError("unexpected external capability")

        return fail

    monkeypatch.setattr(socket, "create_connection", forbidden("network"))
    monkeypatch.setattr(socket, "socket", forbidden("socket"))
    monkeypatch.setattr(subprocess, "Popen", forbidden("process"))
    monkeypatch.setattr(subprocess, "run", forbidden("process.run"))
    monkeypatch.setattr(CredentialBroker, "status", forbidden("credential status"))
    monkeypatch.setattr(CredentialBroker, "resolve_for_test", forbidden("credential"))
    monkeypatch.setattr(ModelGateway, "generate", forbidden("model"))
    monkeypatch.setattr(ToolGateway, "call", forbidden("tool"))
    path = _database(tmp_path)

    with acquire_writer_lease(path) as lease:
        with lease.transaction() as connection:
            connection.execute("PRAGMA user_version = 3")

    assert calls == []
