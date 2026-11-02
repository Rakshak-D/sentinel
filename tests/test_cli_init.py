"""Integration tests for the explicit ``sentinel init`` command."""

import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

import sentinel.bootstrap.init as init_module
from sentinel.cli import app
from sentinel.storage.connection import database_connection, inspect_connection
from sentinel.storage.migrations import initialize_storage, verify_integrity

runner = CliRunner()


def test_init_help_describes_required_database_option() -> None:
    result = runner.invoke(app, ["init", "--help"])

    assert result.exit_code == 0
    assert "--database" in result.output


def test_missing_database_option_fails_without_creating_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["init"])

    assert result.exit_code != 0
    assert "--database" in result.output
    assert list(tmp_path.iterdir()) == []


def test_cli_initializes_explicit_absolute_path_and_reports_bounded_result(
    tmp_path: Path,
) -> None:
    database = tmp_path / "cli-init.sqlite3"

    result = runner.invoke(app, ["init", "--database", str(database)])

    assert result.exit_code == 0
    assert "Initialized new Sentinel database" in result.output
    assert str(database) not in result.output
    assert database.is_file()
    with database_connection(database) as connection:
        migration = connection.execute(
            "SELECT migration_id, artifact_sha256, success FROM schema_migrations"
        ).fetchone()
        settings = inspect_connection(connection)
        verify_integrity(connection)
    assert migration == (
        "cr0-c-0001-schema-migrations",
        "b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217",
        1,
    )
    assert settings.foreign_keys_enabled is True
    assert settings.journal_mode == "wal"


def test_cli_refuses_relative_path_without_file_or_path_disclosure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    database = "synthetic-private-path.sqlite3"

    result = runner.invoke(app, ["init", "--database", database])

    assert result.exit_code != 0
    assert database not in result.output
    assert "Traceback" not in result.output
    assert not (tmp_path / database).exists()


def test_cli_refuses_existing_initialized_database_without_reinitializing(
    tmp_path: Path,
) -> None:
    database = tmp_path / "existing.sqlite3"
    initialize_storage(database, create=True)
    original_bytes = database.read_bytes()

    result = runner.invoke(app, ["init", "--database", str(database)])

    assert result.exit_code != 0
    assert "already exists" in result.output
    assert str(database) not in result.output
    assert "Traceback" not in result.output
    assert database.read_bytes() == original_bytes


def test_sqlite_failure_is_nonzero_and_never_exposes_exception_or_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "synthetic-private-database.sqlite3"
    canary = "SYNTHETIC_SQLITE_SECRET_CANARY"

    def fail_storage(_database: str | Path, **_kwargs: object) -> tuple[str, ...]:
        raise sqlite3.OperationalError(f"{canary} at {database}")

    monkeypatch.setattr(init_module, "initialize_storage", fail_storage)
    result = runner.invoke(app, ["init", "--database", str(database)])

    assert result.exit_code != 0
    assert "Initialization failed" in result.output
    assert "Traceback" not in result.output
    assert canary not in result.output
    assert str(database) not in result.output
    assert database.is_file()


def test_invalid_path_error_does_not_include_a_synthetic_canary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    database = "SYNTHETIC_PRIVATE_PATH_CANARY.sqlite3"

    result = runner.invoke(app, ["init", "--database", database])

    assert result.exit_code != 0
    assert database not in result.output
    assert "Traceback" not in result.output
    assert "absolute" in result.output
    assert not (tmp_path / database).exists()
