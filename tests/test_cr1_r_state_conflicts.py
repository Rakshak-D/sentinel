import hashlib
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.ingestion.blob_readback import read_blob_backed_github_fixture
from sentinel.ingestion.types import GithubBlobIntegrationError
from sentinel.tasks.store import LOCAL_TASK_OPERATOR_ID
from sentinel.workspace import (
    FixtureWorkspaceError,
    FixtureWorkspaceErrorCode,
    FixtureWorkspaceStatus,
    prepare_fixture_workspace,
    verify_fixture_workspace,
)
from tests.cr1_r_workspace import new_database, table_rows


def test_invalid_cursor_is_not_reset_by_prepare(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "bad-cursor")
    prepare_fixture_workspace(database, store_root=store_root)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE sync_cursors SET value_cipher_ref = ?",
            ("untrusted-cursor-ref",),
        )
    with pytest.raises(FixtureWorkspaceError) as caught:
        prepare_fixture_workspace(database, store_root=store_root)
    assert caught.value.code is FixtureWorkspaceErrorCode.CURSOR_INVALID


def test_conflicting_operator_is_not_repaired(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "bad-operator")
    prepare_fixture_workspace(database, store_root=store_root)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE principals SET display_name = ? WHERE principal_id = ?",
            ("conflicting test principal", str(LOCAL_TASK_OPERATOR_ID)),
        )
    with pytest.raises(FixtureWorkspaceError) as caught:
        verify_fixture_workspace(database, store_root=store_root)
    assert caught.value.code is FixtureWorkspaceErrorCode.OPERATOR_INVALID
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT display_name FROM principals WHERE principal_id = ?",
            (str(LOCAL_TASK_OPERATOR_ID),),
        ).fetchone()
    assert row == ("conflicting test principal",)


def test_missing_operator_is_incomplete_and_verify_does_not_repair(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "missing-operator")
    prepare_fixture_workspace(database, store_root=store_root)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "DELETE FROM principals WHERE principal_id = ?", (str(LOCAL_TASK_OPERATOR_ID),)
        )

    result = verify_fixture_workspace(database, store_root=store_root)

    assert result.state.status is FixtureWorkspaceStatus.INCOMPLETE
    assert result.state.task_operator_ready is False
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM principals WHERE principal_id = ?", (str(LOCAL_TASK_OPERATOR_ID),)
            ).fetchone()
            is None
        )


def test_migration_history_tampering_is_rejected_before_store_write(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "bad-history")
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE schema_migrations SET artifact_sha256 = ? WHERE migration_id = ?",
            ("0" * 64, "cr1-j-0004-local-tasks"),
        )

    with pytest.raises(FixtureWorkspaceError) as caught:
        prepare_fixture_workspace(database, store_root=store_root)

    assert caught.value.code is FixtureWorkspaceErrorCode.SCHEMA_NOT_CURRENT
    assert not store_root.exists()


def test_extra_source_item_is_rejected_without_repair(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "extra-item")
    prepare_fixture_workspace(database, store_root=store_root)
    with sqlite3.connect(database) as connection:
        parent = connection.execute(
            """SELECT source_id, content_ref, content_sha256, trust, sensitivity,
                      observed_at, source_at, metadata_json
               FROM source_items ORDER BY provider_item_id LIMIT 1"""
        ).fetchone()
        connection.execute(
            """INSERT INTO source_items
               (item_id, source_id, provider_item_id, provider_revision, canonical_uri,
                content_ref, content_sha256, trust, sensitivity, observed_at, source_at,
                deleted_at, metadata_json)
               VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, NULL, ?)""",
            (
                str(uuid4()),
                parent[0],
                "example-owner/fixture-project#999",
                parent[1],
                parent[2],
                parent[3],
                parent[4],
                parent[5],
                parent[6],
                parent[7],
            ),
        )

    with pytest.raises(FixtureWorkspaceError) as caught:
        verify_fixture_workspace(database, store_root=store_root)
    assert caught.value.code is FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID
    with pytest.raises(GithubBlobIntegrationError):
        read_blob_backed_github_fixture(database, store_root=store_root)


def test_missing_blob_is_not_repaired_by_verify_or_prepare(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "missing-blob")
    prepare_fixture_workspace(database, store_root=store_root)
    digest = EXPECTED_MANIFEST.items[0].content_sha256
    blob_path = store_root / "public-v1" / "sha256" / f"{digest}.blob"
    blob_path.unlink()

    with pytest.raises(FixtureWorkspaceError):
        verify_fixture_workspace(database, store_root=store_root)
    with pytest.raises(FixtureWorkspaceError):
        prepare_fixture_workspace(database, store_root=store_root)
    assert not blob_path.exists()


def test_corrupt_blob_is_not_overwritten_by_prepare(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "corrupt-blob")
    prepare_fixture_workspace(database, store_root=store_root)
    digest = EXPECTED_MANIFEST.items[0].content_sha256
    blob_path = store_root / "public-v1" / "sha256" / f"{digest}.blob"
    blob_path.write_bytes(b"tampered synthetic blob")
    before = hashlib.sha256(blob_path.read_bytes()).hexdigest()

    with pytest.raises(FixtureWorkspaceError):
        prepare_fixture_workspace(database, store_root=store_root)

    assert hashlib.sha256(blob_path.read_bytes()).hexdigest() == before


def test_missing_span_is_rejected(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "missing-span")
    prepare_fixture_workspace(database, store_root=store_root)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "DELETE FROM source_spans WHERE span_id = (SELECT span_id FROM source_spans LIMIT 1)"
        )
    with pytest.raises(FixtureWorkspaceError) as caught:
        verify_fixture_workspace(database, store_root=store_root)
    assert caught.value.code is FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID


def test_extra_span_is_rejected(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "extra-span")
    prepare_fixture_workspace(database, store_root=store_root)
    with sqlite3.connect(database) as connection:
        item_id = connection.execute("SELECT item_id FROM source_items LIMIT 1").fetchone()[0]
        connection.execute(
            """INSERT INTO source_spans
               (span_id, item_id, start_byte, end_byte, text_sha256, context_ref,
                derived_by_boundary_id)
               VALUES (?, ?, 0, 1, ?, NULL, NULL)""",
            (str(uuid4()), item_id, hashlib.sha256(b"x").hexdigest()),
        )
    with pytest.raises(FixtureWorkspaceError) as caught:
        verify_fixture_workspace(database, store_root=store_root)
    assert caught.value.code is FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID


def test_missing_incremental_cursor_is_not_silently_recreated(tmp_path: Path) -> None:
    database, store_root = new_database(tmp_path, "missing-cursor")
    prepare_fixture_workspace(database, store_root=store_root)
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM sync_cursors")
    with pytest.raises(FixtureWorkspaceError) as caught:
        prepare_fixture_workspace(database, store_root=store_root)
    assert caught.value.code is FixtureWorkspaceErrorCode.CURSOR_INVALID
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sync_cursors").fetchone() == (0,)


def test_missing_database_is_not_created(tmp_path: Path) -> None:
    database = tmp_path / "missing.sqlite3"
    store_root = tmp_path / "missing-store"
    with pytest.raises(FixtureWorkspaceError) as caught:
        prepare_fixture_workspace(database, store_root=store_root)
    assert caught.value.code is FixtureWorkspaceErrorCode.DATABASE_UNAVAILABLE
    assert not database.exists()
    assert not store_root.exists()


def test_unsupported_store_root_is_rejected_without_database_changes(tmp_path: Path) -> None:
    database, _store_root = new_database(tmp_path, "bad-store-root")
    tables = ("sources", "source_items", "source_spans", "sync_cursors", "tasks")
    before = {table: table_rows(database, table) for table in tables}
    unsupported_root = Path(r"\\sentinel.invalid\share\workspace")

    with pytest.raises(FixtureWorkspaceError):
        prepare_fixture_workspace(database, store_root=unsupported_root)

    after = {table: table_rows(database, table) for table in before}
    assert before == after
