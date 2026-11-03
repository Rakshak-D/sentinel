"""Writer ownership and existing-database precondition tests."""

import hashlib
import os
import sqlite3
from pathlib import Path

import pytest

import sentinel.storage.migrations as migration_module
import sentinel.storage.writer as writer_module
from sentinel.storage.connection import database_connection
from sentinel.storage.migrations import Migration, initialize_storage
from sentinel.storage.schema import FOUNDATION_SCHEMA, SchemaDefinition
from sentinel.storage.writer import (
    WriterLeaseError,
    WriterLeaseErrorCode,
    acquire_writer_lease,
)

FOUNDATION_ID = "cr0-c-0001-schema-migrations"
FOUNDATION_SHA256 = "b69c069e019213d1aa1ecc5bb29b34cde252d41fbff390ef0219c1d013632217"


def _database(tmp_path: Path, name: str = "sentinel.sqlite3") -> Path:
    path = tmp_path / name
    initialize_storage(path, create=True)
    return path


def test_existing_valid_sentinel_database_acquires_and_checks_registered_foundation(
    tmp_path: Path,
) -> None:
    path = _database(tmp_path)

    with acquire_writer_lease(path):
        with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
            row = connection.execute(
                "SELECT migration_id, artifact_sha256, success FROM schema_migrations"
            ).fetchone()

    assert row == (FOUNDATION_ID, FOUNDATION_SHA256, 1)


@pytest.mark.parametrize("path_kind", ["relative", "missing", "missing_parent"])
def test_invalid_or_missing_paths_fail_without_database_creation(
    tmp_path: Path, path_kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if path_kind == "relative":
        monkeypatch.chdir(tmp_path)
        path = Path("relative.sqlite3")
    elif path_kind == "missing":
        path = tmp_path / "missing.sqlite3"
    else:
        path = tmp_path / "absent" / "missing.sqlite3"

    with pytest.raises(WriterLeaseError):
        with acquire_writer_lease(path):
            pytest.fail("invalid path acquired a writer lease")

    assert not path.exists()
    if path_kind == "missing_parent":
        assert not path.parent.exists()


def test_existing_non_sentinel_database_is_rejected_without_migration(tmp_path: Path) -> None:
    path = tmp_path / "uninitialized.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE synthetic_existing (value TEXT)")
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(WriterLeaseError):
        with acquire_writer_lease(path):
            pytest.fail("uninitialized SQLite database acquired a lease")

    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'schema_migrations'"
        ).fetchone() is None


def test_malformed_database_and_tampered_migration_records_fail_closed(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.sqlite3"
    malformed.write_bytes(b"synthetic malformed sqlite bytes")
    with pytest.raises(WriterLeaseError):
        with acquire_writer_lease(malformed):
            pytest.fail("malformed database acquired a lease")

    for name, change in (
        ("tampered.sqlite3", "UPDATE schema_migrations SET artifact_sha256 = ?"),
        (
            "unknown.sqlite3",
            "UPDATE schema_migrations SET migration_id = ? "
            "WHERE migration_id = 'cr0-c-0001-schema-migrations'",
        ),
    ):
        path = _database(tmp_path, name)
        value = "0" * 64 if name.startswith("tampered") else "unknown-0001"
        with sqlite3.connect(path) as connection:
            connection.execute(change, (value,))
        with pytest.raises(WriterLeaseError) as error:
            with acquire_writer_lease(path):
                pytest.fail("tampered database acquired a lease")
        assert error.value.code is WriterLeaseErrorCode.MIGRATION_INVALID


def test_sqlite_access_failure_is_distinguished_without_exposing_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _database(tmp_path)
    canary = f"SYNTHETIC_PRIVATE_PATH_{path}"

    def fail_open(*_args: object, **_kwargs: object) -> sqlite3.Connection:
        error = sqlite3.OperationalError(canary)
        error.sqlite_errorcode = sqlite3.SQLITE_CANTOPEN  # type: ignore[attr-defined]
        raise error

    monkeypatch.setattr(writer_module.sqlite3, "connect", fail_open)
    with pytest.raises(WriterLeaseError) as error:
        with acquire_writer_lease(path):
            pytest.fail("database opened despite the simulated access failure")

    assert error.value.code is WriterLeaseErrorCode.DATABASE_UNAVAILABLE
    assert canary not in str(error.value)
    assert str(path) not in str(error.value)


def test_schema_drift_fails_without_repair(tmp_path: Path) -> None:
    path = _database(tmp_path)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE unauthorized_synthetic (item_id TEXT)")
    before = path.read_bytes()

    with pytest.raises(WriterLeaseError) as error:
        with acquire_writer_lease(path):
            pytest.fail("schema drift acquired a writer lease")

    assert error.value.code is WriterLeaseErrorCode.MIGRATION_INVALID
    assert path.read_bytes() == before


def test_hardlink_alias_cannot_create_a_second_same_process_lease(tmp_path: Path) -> None:
    target = _database(tmp_path)
    alias = tmp_path / "hardlink.sqlite3"
    try:
        os.link(target, alias)
    except OSError as exc:
        pytest.skip(f"hard link creation is unavailable on this filesystem: {type(exc).__name__}")

    with acquire_writer_lease(target):
        with pytest.raises(WriterLeaseError) as error:
            with acquire_writer_lease(alias):
                pytest.fail("hard-link alias acquired a second lease")
    assert error.value.code is WriterLeaseErrorCode.REENTRANT


def test_os_mutex_creation_failure_is_bounded_and_releases_process_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _database(tmp_path)
    canary = f"SYNTHETIC_MUTEX_FAILURE_{path}"

    class ApiFunction:
        argtypes: object = None
        restype: object = None

        def __init__(self, result: int | None = None, failure: Exception | None = None) -> None:
            self.result = result
            self.failure = failure

        def __call__(self, *_args: object) -> int | None:
            if self.failure is not None:
                raise self.failure
            return self.result

    class FakeKernel:
        def __init__(self) -> None:
            self.GetDriveTypeW = ApiFunction(result=3)
            self.CreateMutexW = ApiFunction(failure=OSError(canary))

    monkeypatch.setattr(writer_module, "_kernel32", FakeKernel)
    with pytest.raises(WriterLeaseError) as error:
        with acquire_writer_lease(path):
            pytest.fail("lease acquired without an OS mutex")
    assert error.value.code is WriterLeaseErrorCode.LOCK_UNAVAILABLE
    assert canary not in str(error.value)
    assert str(path) not in str(error.value)

    monkeypatch.undo()
    with acquire_writer_lease(path):
        pass


def test_writer_validation_does_not_apply_registered_pending_migrations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _database(tmp_path)
    pending = Migration(
        "test-0002-pending-writer",
        ("CREATE TABLE must_not_be_applied (item_id TEXT)",),
        SchemaDefinition("test-0002-pending-writer", FOUNDATION_SCHEMA.objects),
    )
    monkeypatch.setattr(migration_module, "MIGRATIONS", (*migration_module.MIGRATIONS, pending))

    with acquire_writer_lease(path):
        with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
            rows = connection.execute(
                "SELECT migration_id FROM schema_migrations ORDER BY migration_id"
            ).fetchall()
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'must_not_be_applied'"
            ).fetchone()

    assert rows == [(migration.migration_id,) for migration in migration_module.MIGRATIONS[:2]]
    assert table is None


def test_writer_lease_does_not_apply_pending_cr1_e_migration(tmp_path: Path) -> None:
    path = tmp_path / "historical-cr0-pending.sqlite3"
    with database_connection(path, create=True) as connection:
        migration_module._apply_migration(
            connection,
            migration_module.MIGRATIONS[0],
            app_build="synthetic-cr0-history",
        )

    with acquire_writer_lease(path):
        with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as connection:
            rows = connection.execute(
                "SELECT migration_id FROM schema_migrations ORDER BY migration_id"
            ).fetchall()
            sources = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sources'"
            ).fetchone()

    assert rows == [(FOUNDATION_ID,)]
    assert sources is None


def test_final_component_symlink_is_refused_when_host_allows_creation(tmp_path: Path) -> None:
    target = _database(tmp_path, "target.sqlite3")
    link = tmp_path / "linked.sqlite3"
    try:
        link.symlink_to(target)
    except OSError as exc:
        reason = (
            "final-component symlink creation is unavailable on this host: "
            f"{type(exc).__name__}"
        )
        pytest.skip(reason)

    with pytest.raises(WriterLeaseError) as error:
        with acquire_writer_lease(link):
            pytest.fail("database symlink acquired a writer lease")
    assert error.value.code is WriterLeaseErrorCode.INVALID_PATH


def test_public_path_errors_are_bounded_and_do_not_echo_hostile_objects(
    tmp_path: Path,
) -> None:
    canary = "SYNTHETIC_PRIVATE_PATH_CANARY"

    class Hostile:
        called = False

        def __str__(self) -> str:
            self.called = True
            raise AssertionError("str called")

        def __repr__(self) -> str:
            self.called = True
            raise AssertionError("repr called")

    hostile = Hostile()
    with pytest.raises(WriterLeaseError) as error:
        with acquire_writer_lease(hostile):  # type: ignore[arg-type]
            pytest.fail("hostile path acquired a writer lease")
    assert hostile.called is False
    assert canary not in str(error.value)
    assert str(tmp_path) not in str(error.value)


def test_unc_path_is_rejected_before_filesystem_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_filesystem_access(_path: Path) -> None:
        raise AssertionError("UNC path reached filesystem resolution")

    monkeypatch.setattr(Path, "lstat", unexpected_filesystem_access)
    with pytest.raises(WriterLeaseError) as error:
        with acquire_writer_lease(Path(r"\\synthetic.invalid\share\sentinel.sqlite3")):
            pytest.fail("UNC database path acquired a lease")
    assert error.value.code is WriterLeaseErrorCode.INVALID_PATH


@pytest.mark.parametrize("drive_type", [0, 1, 4, 5])
def test_nonlocal_drive_types_are_rejected_before_database_access(
    drive_type: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    class DriveTypeFunction:
        argtypes: object = None
        restype: object = None

        def __init__(self, result: int) -> None:
            self.result = result
            self.roots: list[str] = []

        def __call__(self, root: str) -> int:
            self.roots.append(root)
            return self.result

    class FakeKernel:
        def __init__(self, result: int) -> None:
            self.GetDriveTypeW = DriveTypeFunction(result)

    kernel = FakeKernel(drive_type)
    monkeypatch.setattr(writer_module, "_kernel32", lambda: kernel)
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda _path: (_ for _ in ()).throw(
            AssertionError("remote drive reached filesystem resolution")
        ),
    )

    with pytest.raises(WriterLeaseError) as error:
        with acquire_writer_lease(Path("Z:\\sentinel.sqlite3")):
            pytest.fail("mapped remote path acquired a lease")
    assert error.value.code is WriterLeaseErrorCode.INVALID_PATH
    assert kernel.GetDriveTypeW.roots == ["Z:\\"]
