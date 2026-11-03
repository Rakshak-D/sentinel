"""Fail-closed database, registration, and private-data boundaries."""

import inspect
import socket
import sqlite3
import subprocess
from pathlib import Path

import pytest

import sentinel.ingestion.github_fixture as ingestion_module
from sentinel.credentials.broker import CredentialBroker
from sentinel.gateways.model import ModelGateway
from sentinel.gateways.tool import ToolGateway
from sentinel.ingestion import (
    GithubFixtureIngestionError,
    GithubFixtureIngestionErrorCode,
    ingest_packaged_github_fixture,
    read_persisted_github_fixture,
)
from sentinel.readers.types import GithubFixtureError, GithubFixtureErrorCode
from sentinel.storage.connection import readonly_database_connection
from sentinel.storage.migrations import MIGRATIONS
from tests.cr1_g_support import initialized_database, migration_prefix_database


@pytest.mark.parametrize("count", [1, 2])
def test_historical_prefix_is_rejected_without_upgrade(tmp_path: Path, count: int) -> None:
    database = migration_prefix_database(tmp_path / f"prefix-{count}.sqlite3", count)
    with pytest.raises(GithubFixtureIngestionError) as error:
        ingest_packaged_github_fixture(database)
    assert error.value.code is GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT
    with readonly_database_connection(database) as connection:
        assert connection.execute("SELECT count(*) FROM schema_migrations").fetchone() == (count,)


def test_relative_and_missing_database_paths_fail_without_creation(tmp_path: Path) -> None:
    with pytest.raises(GithubFixtureIngestionError) as relative:
        ingest_packaged_github_fixture("relative.sqlite3")
    assert relative.value.code is GithubFixtureIngestionErrorCode.INVALID_PATH
    missing = tmp_path / "missing.sqlite3"
    with pytest.raises(GithubFixtureIngestionError):
        ingest_packaged_github_fixture(missing)
    assert not missing.exists()


def test_unc_database_path_is_refused_before_sqlite_open() -> None:
    network_path = Path(r"\\synthetic-server\share\sentinel.sqlite3")
    with pytest.raises(GithubFixtureIngestionError) as error:
        read_persisted_github_fixture(network_path)
    assert error.value.code is GithubFixtureIngestionErrorCode.INVALID_PATH
    with pytest.raises(GithubFixtureIngestionError) as ingestion_error:
        ingest_packaged_github_fixture(network_path)
    assert ingestion_error.value.code is GithubFixtureIngestionErrorCode.INVALID_PATH


def test_mapped_network_drive_is_refused_by_windows_drive_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    class FakeDriveType:
        argtypes: object = None
        restype: object = None

        def __call__(self, root: str) -> int:
            observed.append(root)
            return 4  # DRIVE_REMOTE

    class FakeKernel:
        GetDriveTypeW = FakeDriveType()

    monkeypatch.setattr(ingestion_module.ctypes, "WinDLL", lambda *_args, **_kwargs: FakeKernel())
    with pytest.raises(GithubFixtureIngestionError) as error:
        ingestion_module._require_local_windows_path(Path("Z:/synthetic/db.sqlite3"))
    assert error.value.code is GithubFixtureIngestionErrorCode.INVALID_PATH
    assert observed == ["Z:\\"]


def test_read_rejects_tampered_item_digest_and_exposes_no_body_or_path(
    tmp_path: Path,
) -> None:
    database = initialized_database(tmp_path / "tampered.sqlite3")
    ingest_packaged_github_fixture(database)
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE source_items SET content_sha256 = ?", ("f" * 64,))

    with pytest.raises(GithubFixtureIngestionError) as error:
        read_persisted_github_fixture(database)
    assert error.value.code is GithubFixtureIngestionErrorCode.ITEM_CONFLICT
    assert str(database) not in str(error.value)
    assert "Synthetic issue:" not in str(error.value)


def test_private_gmail_store_is_not_read_or_written(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "no-gmail.sqlite3")
    report = ingest_packaged_github_fixture(database)
    with readonly_database_connection(database) as connection:
        assert connection.execute("SELECT count(*) FROM sources").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM source_items").fetchone() == (3,)
    assert report.inserted_items == 3


def test_public_ingestion_accepts_only_an_explicit_database_argument() -> None:
    parameters = tuple(inspect.signature(ingest_packaged_github_fixture).parameters)
    assert parameters == ("database",)


def test_fixture_failure_is_bounded_and_happens_before_any_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = initialized_database(tmp_path / "fixture-error.sqlite3")

    def fail_fixture():
        raise GithubFixtureError(GithubFixtureErrorCode.FIXTURE_HASH_MISMATCH)

    monkeypatch.setattr(ingestion_module, "read_packaged_github_fixture", fail_fixture)
    with pytest.raises(GithubFixtureIngestionError) as error:
        ingest_packaged_github_fixture(database)
    assert error.value.code is GithubFixtureIngestionErrorCode.FIXTURE_INVALID
    assert "Synthetic issue:" not in str(error.value)
    assert _counts(database) == (0, 0, 0)


def test_tampered_registered_migration_is_rejected_before_ingestion(
    tmp_path: Path,
) -> None:
    database = initialized_database(tmp_path / "migration-tampered.sqlite3")
    migration = MIGRATIONS[-1]
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE schema_migrations SET artifact_sha256 = ? WHERE migration_id = ?",
            ("f" * 64, migration.migration_id),
        )

    with pytest.raises(GithubFixtureIngestionError) as error:
        ingest_packaged_github_fixture(database)
    assert error.value.code is GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT
    assert _counts(database) == (0, 0, 0)


def test_unregistered_schema_object_is_rejected_without_repair(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "schema-drift.sqlite3")
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE INDEX unexpected_ingestion_idx ON sources(enabled)")

    with pytest.raises(GithubFixtureIngestionError) as error:
        read_persisted_github_fixture(database)
    assert error.value.code is GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT
    with readonly_database_connection(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE name = ?",
            ("unexpected_ingestion_idx",),
        ).fetchone() == (1,)


def test_ingested_database_integrity_and_foreign_keys_are_clean(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "integrity.sqlite3")
    ingest_packaged_github_fixture(database)

    with readonly_database_connection(database) as connection:
        assert connection.execute("PRAGMA query_only").fetchone() == (1,)
        assert connection.execute("PRAGMA foreign_keys").fetchone() == (1,)
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_ingestion_invokes_no_network_subprocess_credentials_or_gateways(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def forbidden(name: str):
        def fail(*_args: object, **_kwargs: object) -> None:
            calls.append(name)
            raise AssertionError("unexpected external capability")

        return fail

    monkeypatch.setattr(socket, "socket", forbidden("socket"))
    monkeypatch.setattr(socket, "create_connection", forbidden("network"))
    monkeypatch.setattr(subprocess, "Popen", forbidden("subprocess"))
    monkeypatch.setattr(CredentialBroker, "status", forbidden("credential-status"))
    monkeypatch.setattr(CredentialBroker, "resolve_for_test", forbidden("credential"))
    monkeypatch.setattr(ModelGateway, "generate", forbidden("model"))
    monkeypatch.setattr(ToolGateway, "call", forbidden("tool"))
    database = initialized_database(tmp_path / "no-external.sqlite3")

    report = ingest_packaged_github_fixture(database)

    assert report.inserted_items == 3
    assert calls == []


def test_instruction_like_issue_body_does_not_change_labels_or_call_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = ingestion_module.read_packaged_github_fixture()
    issue = next(issue for issue in fixture.issues if issue.issue_number == 103)
    assert "ignore prior instructions" in issue.body_text

    calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        calls.append("tool")
        raise AssertionError("fixture text must not activate a tool")

    monkeypatch.setattr(ToolGateway, "call", forbidden)
    database = initialized_database(tmp_path / "instruction-like-content.sqlite3")
    ingest_packaged_github_fixture(database)

    with readonly_database_connection(database) as connection:
        row = connection.execute(
            "SELECT trust, sensitivity FROM source_items WHERE provider_item_id = ?",
            ("example-owner/fixture-project#103",),
        ).fetchone()

    assert row == ("T4 EXTERNAL", "PUBLIC")
    assert calls == []


def test_malformed_database_is_rejected_without_raw_error_or_body(tmp_path: Path) -> None:
    database = tmp_path / "malformed.sqlite3"
    database.write_bytes(b"synthetic non-SQLite bytes")
    with pytest.raises(GithubFixtureIngestionError) as error:
        ingest_packaged_github_fixture(database)
    assert str(database) not in str(error.value)
    assert "synthetic non-SQLite bytes" not in str(error.value)


def _counts(database: Path) -> tuple[int, int, int]:
    with readonly_database_connection(database) as connection:
        return tuple(
            int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in ("principals", "plugin_manifests", "sources")
        )  # type: ignore[return-value]
