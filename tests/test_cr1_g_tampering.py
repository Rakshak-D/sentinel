"""Restart verification compares every persisted row with trusted expectations."""

import sqlite3
from pathlib import Path

import pytest

from sentinel.ingestion import (
    GithubFixtureIngestionError,
    ingest_packaged_github_fixture,
    read_persisted_github_fixture,
)
from sentinel.storage.connection import readonly_database_connection
from tests.cr1_g_support import initialized_database


@pytest.mark.parametrize(
    ("table", "column", "value"),
    [
        ("source_items", "content_sha256", "f" * 64),
        ("source_items", "item_id", "tampered-item-id"),
        ("source_items", "source_id", "tampered-source-id"),
        ("source_items", "provider_item_id", "wrong-repository#101"),
        ("source_items", "content_ref", "https://invalid.example/body"),
        ("source_items", "metadata_json", "{\"tampered\":true}"),
        ("source_items", "trust", "T1 OWNER_INTENT"),
        ("source_items", "sensitivity", "PRIVATE"),
        ("source_spans", "start_byte", 0),
        ("source_spans", "text_sha256", "0" * 64),
        ("source_spans", "item_id", "tampered-item-id"),
    ],
)
def test_read_rejects_tampered_item_or_span_fields(
    tmp_path: Path,
    table: str,
    column: str,
    value: object,
) -> None:
    database = initialized_database(tmp_path / f"tamper-{table}-{column}.sqlite3")
    ingest_packaged_github_fixture(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            f"UPDATE {table} SET {column} = ? WHERE rowid = (SELECT min(rowid) FROM {table})",
            (value,),
        )

    with pytest.raises(GithubFixtureIngestionError) as error:
        read_persisted_github_fixture(database)
    assert str(database) not in str(error.value)
    assert "Synthetic issue:" not in str(error.value)


def test_read_rejects_tampered_span_end_byte(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "tamper-end-byte.sqlite3")
    ingest_packaged_github_fixture(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE source_spans SET end_byte = end_byte + 1 "
            "WHERE rowid = (SELECT min(rowid) FROM source_spans)"
        )

    with pytest.raises(GithubFixtureIngestionError):
        read_persisted_github_fixture(database)


@pytest.mark.parametrize(
    ("table", "column", "value"),
    [
        ("principals", "display_name", "tampered principal"),
        ("plugin_manifests", "plugin_version", "9.9.9"),
        ("plugin_manifests", "manifest_sha256", "f" * 64),
        ("plugin_manifests", "fixture_set_sha256", "e" * 64),
        ("sources", "source_id", "tampered-source"),
        ("sources", "plugin_version", "9.9.9"),
        ("sources", "scope_json", "{}"),
        ("sources", "trust", "T1 OWNER_INTENT"),
        ("sources", "default_sensitivity", "PRIVATE"),
    ],
)
def test_read_rejects_tampered_registration_metadata(
    tmp_path: Path,
    table: str,
    column: str,
    value: object,
) -> None:
    database = initialized_database(tmp_path / f"registration-{table}-{column}.sqlite3")
    ingest_packaged_github_fixture(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            f"UPDATE {table} SET {column} = ? WHERE rowid = (SELECT min(rowid) FROM {table})",
            (value,),
        )

    with pytest.raises(GithubFixtureIngestionError):
        read_persisted_github_fixture(database)


@pytest.mark.parametrize("action", ["missing", "extra"])
def test_read_rejects_missing_or_extra_spans(tmp_path: Path, action: str) -> None:
    database = initialized_database(tmp_path / f"span-set-{action}.sqlite3")
    report = ingest_packaged_github_fixture(database)
    with sqlite3.connect(database) as connection:
        if action == "missing":
            connection.execute(
                "DELETE FROM source_spans WHERE rowid = "
                "(SELECT min(rowid) FROM source_spans)"
            )
        else:
            item_id = connection.execute(
                "SELECT item_id FROM source_items ORDER BY item_id LIMIT 1"
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO source_spans(span_id, item_id, start_byte, end_byte, text_sha256) "
                "VALUES (?, ?, 0, 1, ?)",
                ("extra-span-id", item_id, "a" * 64),
            )
    assert report.inserted_spans == 9
    with pytest.raises(GithubFixtureIngestionError):
        read_persisted_github_fixture(database)


def test_read_rejects_missing_item(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "missing-item.sqlite3")
    ingest_packaged_github_fixture(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "DELETE FROM source_spans WHERE rowid = "
            "(SELECT min(rowid) FROM source_spans)"
        )
        connection.execute(
            "DELETE FROM source_items WHERE rowid = (SELECT min(rowid) FROM source_items)"
        )
    with pytest.raises(GithubFixtureIngestionError):
        read_persisted_github_fixture(database)


def test_read_rejects_extra_item_for_registered_source(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "extra-item.sqlite3")
    report = ingest_packaged_github_fixture(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO source_items "
            "(item_id, source_id, provider_item_id, content_ref, content_sha256, trust, "
            "sensitivity, observed_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ",
            (
                "unexpected-item",
                str(report.registry_source_id),
                "example-owner/fixture-project#999",
                "fixture:sentinel.github-issues-fixture.v1:example-owner/fixture-project#999",
                "a" * 64,
                "T4 EXTERNAL",
                "PUBLIC",
                "2026-11-03T12:00:00+00:00",
                "{}",
            ),
        )

    with pytest.raises(GithubFixtureIngestionError):
        read_persisted_github_fixture(database)


def test_ingestion_does_not_replace_conflicting_item_or_span_rows(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "conflicting-item.sqlite3")
    ingest_packaged_github_fixture(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE source_items SET metadata_json = ? WHERE rowid = "
            "(SELECT min(rowid) FROM source_items)",
            ("{}",),
        )
    with pytest.raises(GithubFixtureIngestionError):
        ingest_packaged_github_fixture(database)


def test_read_only_connection_proves_no_application_dml(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "readonly.sqlite3")
    ingest_packaged_github_fixture(database)
    with readonly_database_connection(database) as connection:
        assert connection.execute("PRAGMA query_only").fetchone() == (1,)
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM source_items")
