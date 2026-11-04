"""Fail-closed schema and path boundaries for the synthetic replay API."""

import subprocess
from pathlib import Path

import pytest

from sentinel.sync import (
    FixtureSyncError,
    FixtureSyncErrorCode,
    advance_incremental_github_fixture,
    read_incremental_github_fixture_state,
    setup_incremental_github_fixture,
)
from tests.cr1_h1_support import prepared_case
from tests.cr1_k_support import setup_case
from tests.test_cr1_j_support import historical_prefix_database


@pytest.mark.parametrize("migration_count", (1, 2, 3))
@pytest.mark.parametrize("operation", ("setup", "advance", "status"))
def test_historical_schema_prefixes_are_not_implicitly_upgraded(
    tmp_path: Path, migration_count: int, operation: str
) -> None:
    database = historical_prefix_database(
        tmp_path / f"historical-{migration_count}-{operation}.sqlite3", migration_count
    )
    with pytest.raises(FixtureSyncError) as caught:
        if operation == "setup":
            setup_incremental_github_fixture(database, store_root=tmp_path / "unused-store")
        elif operation == "advance":
            advance_incremental_github_fixture(
                database, store_root=tmp_path / "unused-store", expected_generation=0
            )
        else:
            read_incremental_github_fixture_state(database, store_root=tmp_path / "unused-store")
    assert caught.value.code is FixtureSyncErrorCode.SCHEMA_NOT_CURRENT
    assert database.exists()


def test_missing_database_is_not_created(tmp_path: Path) -> None:
    database = tmp_path / "missing.sqlite3"
    with pytest.raises(FixtureSyncError) as caught:
        read_incremental_github_fixture_state(database, store_root=tmp_path / "unused-store")
    assert caught.value.code in {
        FixtureSyncErrorCode.DATABASE_UNAVAILABLE,
        FixtureSyncErrorCode.INVALID_PATH,
    }
    assert not database.exists()


def test_advance_requires_setup_and_pinned_public_store(tmp_path: Path) -> None:
    database, store_root = prepared_case(tmp_path, name="not-promoted")
    with pytest.raises(FixtureSyncError) as caught:
        advance_incremental_github_fixture(database, store_root=store_root, expected_generation=0)
    assert caught.value.code in {
        FixtureSyncErrorCode.SOURCE_CONFLICT,
        FixtureSyncErrorCode.BLOB_INVALID,
    }


def test_network_entry_points_are_not_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import socket
    import urllib.request

    database, store_root, _source_id = setup_case(tmp_path, name="offline")

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("unexpected network operation")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    setup_incremental_github_fixture(database, store_root=store_root)
    advance_incremental_github_fixture(database, store_root=store_root, expected_generation=0)
    assert read_incremental_github_fixture_state(database, store_root=store_root).generation == 1


def test_error_text_does_not_echo_private_paths(tmp_path: Path) -> None:
    database = tmp_path / "credential-canary-PRIVATE-Path.sqlite3"
    try:
        setup_incremental_github_fixture(database, store_root=tmp_path / "private-store")
    except FixtureSyncError as error:
        assert str(tmp_path) not in str(error)
        assert "credential-canary" not in str(error)
    else:
        pytest.fail("uninitialized database was accepted")
