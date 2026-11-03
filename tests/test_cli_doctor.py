"""CLI behavior tests for read-only CR0 diagnostics."""

import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.storage.migrations import initialize_storage

runner = CliRunner()


def test_doctor_is_listed_and_help_requires_database() -> None:
    root_help = runner.invoke(app, ["--help"])
    doctor_help = runner.invoke(app, ["doctor", "--help"])

    assert root_help.exit_code == 0
    assert "doctor" in root_help.output
    assert doctor_help.exit_code == 0
    assert "--database" in doctor_help.output
    assert "required" in doctor_help.output.casefold()


def test_missing_database_option_fails_without_creating_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code != 0
    assert "--database" in result.output
    assert list(tmp_path.iterdir()) == []


def test_doctor_does_not_create_missing_absolute_database(tmp_path: Path) -> None:
    database = tmp_path / "missing.sqlite3"

    result = runner.invoke(app, ["doctor", "--database", str(database)])

    assert result.exit_code != 0
    assert "FAIL database.read_only" in result.output
    assert str(database) not in result.output
    assert "Traceback" not in result.output
    assert not database.exists()


def test_relative_database_path_fails_without_creating_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    selected = "SYNTHETIC_PRIVATE_DOCTOR_PATH.sqlite3"

    result = runner.invoke(app, ["doctor", "--database", selected])

    assert result.exit_code != 0
    assert "FAIL database.read_only" in result.output
    assert selected not in result.output
    assert "Traceback" not in result.output
    assert not (tmp_path / selected).exists()


def test_relative_path_fails_without_disclosing_path_or_creating_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    database = "SYNTHETIC_PRIVATE_DOCTOR_PATH.sqlite3"

    result = runner.invoke(app, ["doctor", "--database", database])

    assert result.exit_code != 0
    assert database not in result.output
    assert "Traceback" not in result.output
    assert not (tmp_path / database).exists()


def test_fresh_initialized_database_reports_checks_and_exits_zero(
    tmp_path: Path,
) -> None:
    database = tmp_path / "fresh-sentinel.sqlite3"
    initialize_storage(database, create=True)
    original_bytes = database.read_bytes()

    result = runner.invoke(app, ["doctor", "--database", str(database)])

    assert result.exit_code == 0
    assert "PASS database.read_only" in result.output
    assert "PASS storage.migration_history" in result.output
    assert "PASS storage.schema_checkpoint" in result.output
    assert "PASS config.fingerprint" in result.output
    assert "UNAVAILABLE capability.os_keychain" in result.output
    assert "NOT_IMPLEMENTED capability.policy_engine" in result.output
    assert "NOT_IMPLEMENTED capability.mcp_smoke" in result.output
    assert "not a production readiness" in result.output.casefold()
    assert str(database) not in result.output
    assert database.read_bytes() == original_bytes


def test_malformed_database_failure_has_no_exception_or_content_leak(
    tmp_path: Path,
) -> None:
    database = tmp_path / "SYNTHETIC_PRIVATE_DOCTOR_PATH.sqlite3"
    canary = "SYNTHETIC_SECRET_DATABASE_CANARY"
    database.write_bytes(canary.encode())

    result = runner.invoke(app, ["doctor", "--database", str(database)])

    assert result.exit_code != 0
    assert "FAIL database.read_only" in result.output
    assert str(database) not in result.output
    assert canary not in result.output
    assert "Traceback" not in result.output


def test_tampered_migration_hash_fails_cli_without_database_disclosure(
    tmp_path: Path,
) -> None:
    database = tmp_path / "tampered.sqlite3"
    initialize_storage(database, create=True)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE schema_migrations SET artifact_sha256 = ?",
            ("0" * 64,),
        )

    result = runner.invoke(app, ["doctor", "--database", str(database)])

    assert result.exit_code != 0
    assert "FAIL storage.migration_history" in result.output
    assert str(database) not in result.output
    assert "Traceback" not in result.output
