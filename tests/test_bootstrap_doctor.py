"""Read-only diagnostic tests over temporary synthetic SQLite databases."""

import socket
import sqlite3
import subprocess
from pathlib import Path

import pytest

import sentinel.bootstrap.doctor as doctor_module
from sentinel.bootstrap.doctor import DoctorCheck, DoctorCheckId, DoctorStatus, run_doctor
from sentinel.storage.connection import (
    DatabaseOpenError,
    open_database_readonly,
    readonly_database_connection,
)
from sentinel.storage.migrations import (
    initialize_storage,
    inspect_migration_history_readonly,
    verify_integrity,
    verify_schema_checkpoint_readonly,
)

FOUNDATION_ID = "cr0-c-0001-schema-migrations"
FOUNDATION_SHA256 = "b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217"


def _fresh_database(tmp_path: Path, name: str = "sentinel.sqlite3") -> Path:
    database = tmp_path / name
    initialize_storage(database, create=True)
    return database


def _checks(database: Path):
    return {check.check_id: check for check in run_doctor(database).checks}


def test_fresh_database_passes_supported_checks_and_reports_expected_limits(
    tmp_path: Path,
) -> None:
    database = _fresh_database(tmp_path)

    report = run_doctor(database)
    checks = {check.check_id: check for check in report.checks}

    assert report.successful is True
    for check_id in (
        DoctorCheckId.DATABASE_READ_ONLY,
        DoctorCheckId.DATABASE_WAL,
        DoctorCheckId.DATABASE_INTEGRITY,
        DoctorCheckId.DATABASE_FOREIGN_KEYS,
        DoctorCheckId.DATABASE_FOREIGN_KEY_INTEGRITY,
        DoctorCheckId.MIGRATION_HISTORY,
        DoctorCheckId.SCHEMA_CHECKPOINT,
        DoctorCheckId.CONFIG_VALIDATION,
        DoctorCheckId.CONFIG_FINGERPRINT,
        DoctorCheckId.MODEL_GATEWAY_DEMO,
        DoctorCheckId.MODEL_GATEWAY_DENIALS,
        DoctorCheckId.TOOL_GATEWAY_DEMO,
        DoctorCheckId.TOOL_GATEWAY_DENIALS,
        DoctorCheckId.LIVE_EFFECTS_DISABLED,
    ):
        assert checks[check_id].status is DoctorStatus.PASS
    assert checks[DoctorCheckId.CREDENTIAL_BACKEND].status is DoctorStatus.UNAVAILABLE
    assert checks[DoctorCheckId.OS_KEYCHAIN].status is DoctorStatus.UNAVAILABLE
    for check_id in (
        DoctorCheckId.OWNER_VERIFICATION,
        DoctorCheckId.POLICY_ENGINE,
        DoctorCheckId.LIVE_MODEL_ROUTING,
        DoctorCheckId.MCP_SMOKE,
        DoctorCheckId.BACKUP_VERIFICATION,
        DoctorCheckId.SIGNED_AUDIT_ROOTS,
    ):
        assert checks[check_id].status is DoctorStatus.NOT_IMPLEMENTED


def test_report_contract_cannot_mark_unimplemented_check_passed() -> None:
    with pytest.raises(ValueError, match="message is not registered"):
        DoctorCheck(DoctorCheckId.POLICY_ENGINE, DoctorStatus.PASS, None)  # type: ignore[arg-type]


def test_readonly_connection_is_query_only_and_blocks_sql_writes(tmp_path: Path) -> None:
    database = _fresh_database(tmp_path)
    original_bytes = database.read_bytes()
    files_before = {path.name for path in tmp_path.iterdir()}

    with readonly_database_connection(database) as connection:
        assert connection.execute("PRAGMA query_only").fetchone() == (1,)
        assert connection.execute("PRAGMA foreign_keys").fetchone() == (1,)
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
        assert connection.execute(
            "SELECT migration_id, artifact_sha256 FROM schema_migrations"
        ).fetchone() == (FOUNDATION_ID, FOUNDATION_SHA256)
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("CREATE TABLE doctor_write_probe (value TEXT)")
        connection.execute("PRAGMA query_only = OFF")
        connection.execute("BEGIN")
        try:
            with pytest.raises(sqlite3.OperationalError):
                connection.execute("CREATE TABLE doctor_uri_write_probe (value TEXT)")
        finally:
            connection.rollback()
        connection.execute("PRAGMA query_only = ON")

    assert database.read_bytes() == original_bytes
    new_files = {path.name for path in tmp_path.iterdir()} - files_before
    assert new_files <= {f"{database.name}-wal", f"{database.name}-shm"}


def test_readonly_api_does_not_create_missing_database_or_parent(tmp_path: Path) -> None:
    missing = tmp_path / "not-created.sqlite3"
    parent_missing = tmp_path / "absent" / "child.sqlite3"

    for database in (missing, parent_missing):
        with pytest.raises(DatabaseOpenError):
            open_database_readonly(database)
        assert not database.exists()
    assert not parent_missing.parent.exists()


def test_readonly_migration_and_schema_verifiers_use_trusted_registry(
    tmp_path: Path,
) -> None:
    database = _fresh_database(tmp_path)

    with readonly_database_connection(database) as connection:
        migration_ids = inspect_migration_history_readonly(connection)
        schema_version = verify_schema_checkpoint_readonly(connection, migration_ids)
        verify_integrity(connection)

    assert migration_ids == (FOUNDATION_ID,)
    assert schema_version == FOUNDATION_ID


def test_missing_database_fails_without_creation(tmp_path: Path) -> None:
    database = tmp_path / "missing.sqlite3"

    report = run_doctor(database)

    assert report.successful is False
    assert _checks(database)[DoctorCheckId.DATABASE_READ_ONLY].status is DoctorStatus.FAIL
    assert not database.exists()


def test_invalid_database_bytes_fail_without_disclosing_path_or_contents(
    tmp_path: Path,
) -> None:
    database = tmp_path / "SYNTHETIC_PRIVATE_PATH_CANARY.sqlite3"
    content_canary = b"SYNTHETIC_SQLITE_SECRET_CANARY"
    database.write_bytes(content_canary)

    report = run_doctor(database)

    assert report.successful is False
    rendered = "\n".join(
        f"{check.status.value} {check.check_id.value}: {check.message}"
        for check in report.checks
    )
    assert str(database) not in rendered
    assert content_canary.decode() not in rendered
    assert "Traceback" not in rendered


@pytest.mark.parametrize(
    ("sql", "expected_check"),
    [
        (
            "UPDATE schema_migrations SET migration_id = 'unknown-doctor-migration'",
            DoctorCheckId.MIGRATION_HISTORY,
        ),
        (
            "UPDATE schema_migrations SET artifact_sha256 = '0' || substr(artifact_sha256, 2)",
            DoctorCheckId.MIGRATION_HISTORY,
        ),
        (
            "CREATE TABLE unauthorized_doctor_object (value TEXT)",
            DoctorCheckId.SCHEMA_CHECKPOINT,
        ),
        (
            "DROP INDEX schema_migrations_applied_at_idx",
            DoctorCheckId.SCHEMA_CHECKPOINT,
        ),
    ],
)
def test_tampered_history_or_schema_fails_closed(
    tmp_path: Path, sql: str, expected_check: DoctorCheckId
) -> None:
    database = _fresh_database(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute(sql)

    report = run_doctor(database)
    checks = {check.check_id: check for check in report.checks}

    assert report.successful is False
    assert checks[expected_check].status is DoctorStatus.FAIL


def test_foreign_key_integrity_failure_is_reported(tmp_path: Path) -> None:
    database = _fresh_database(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("CREATE TABLE probe_parent (item_id INTEGER PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE probe_child (parent_id INTEGER REFERENCES probe_parent(item_id))"
        )
        connection.execute("INSERT INTO probe_child VALUES (999)")

    checks = _checks(database)

    assert checks[DoctorCheckId.DATABASE_FOREIGN_KEY_INTEGRITY].status is DoctorStatus.FAIL


def test_repeated_doctor_runs_leave_main_database_bytes_unchanged(tmp_path: Path) -> None:
    database = _fresh_database(tmp_path)
    before = database.read_bytes()

    first = run_doctor(database)
    middle = database.read_bytes()
    second = run_doctor(database)
    after = database.read_bytes()

    assert first == second
    assert before == middle == after


def test_config_and_credentials_checks_use_bundled_defaults_without_secrets(
    tmp_path: Path,
) -> None:
    checks = _checks(_fresh_database(tmp_path))

    assert checks[DoctorCheckId.CONFIG_VALIDATION].status is DoctorStatus.PASS
    assert checks[DoctorCheckId.CONFIG_FINGERPRINT].status is DoctorStatus.PASS
    assert checks[DoctorCheckId.CREDENTIAL_BACKEND].status is DoctorStatus.UNAVAILABLE
    assert "unavailable" in checks[DoctorCheckId.CREDENTIAL_BACKEND].message.casefold()


def test_synthetic_payloads_and_secrets_never_enter_report_or_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = run_doctor(_fresh_database(tmp_path))
    captured = capsys.readouterr()
    rendered = repr(report)

    assert captured.out == ""
    assert captured.err == ""
    for canary in (
        "synthetic doctor probe",
        "synthetic doctor secret must not reach model",
        "synthetic doctor model result",
        "synthetic read result",
    ):
        assert canary not in rendered
        assert canary not in captured.out
        assert canary not in captured.err


def test_unexpected_integrity_exception_never_becomes_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = _fresh_database(tmp_path)
    canary = "SYNTHETIC_EXCEPTION_SECRET_CANARY"

    def fail_check(_connection: sqlite3.Connection) -> None:
        raise RuntimeError(canary)

    monkeypatch.setattr(doctor_module, "verify_sqlite_integrity", fail_check)
    report = run_doctor(database)
    checks = {check.check_id: check for check in report.checks}

    assert report.successful is False
    assert checks[DoctorCheckId.DATABASE_INTEGRITY].status is DoctorStatus.FAIL
    assert canary not in str(report)


def test_doctor_requires_no_network_or_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = _fresh_database(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network or subprocess must not be used")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    assert run_doctor(database).successful is True
