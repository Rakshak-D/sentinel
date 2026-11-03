"""The fixture ingestion commit must leave its entire owned dataset complete."""

import sqlite3
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest

import sentinel.ingestion.github_fixture as ingestion_module
from sentinel.ingestion import (
    GithubFixtureIngestionError,
    GithubFixtureIngestionErrorCode,
    ingest_packaged_github_fixture,
    read_persisted_github_fixture,
)
from sentinel.ingestion.github_fixture import FIXTURE_REGISTRY_SOURCE_ID
from sentinel.readers.github_fixture import FIXTURE_SCHEMA_VERSION
from sentinel.storage.connection import readonly_database_connection
from tests.cr1_g_support import initialized_database

_EXTRA_ITEM_ID = uuid5(NAMESPACE_URL, "sentinel:test:cr1-g:unexpected-item")
_OTHER_SOURCE_ID = uuid5(NAMESPACE_URL, "sentinel:test:cr1-g:unrelated-source")
_OTHER_ITEM_ID = uuid5(NAMESPACE_URL, "sentinel:test:cr1-g:unrelated-item")
_OBSERVED_AT = "2026-11-03T12:00:00+00:00"


def test_repeat_ingestion_rejects_extra_item_and_preserves_committed_rows(
    tmp_path: Path,
) -> None:
    database = initialized_database(tmp_path / "repeat-extra-item.sqlite3")
    ingest_packaged_github_fixture(database)
    _insert_extra_item(database, FIXTURE_REGISTRY_SOURCE_ID)

    with pytest.raises(GithubFixtureIngestionError):
        read_persisted_github_fixture(database)
    before = _owned_rows(database)

    with pytest.raises(GithubFixtureIngestionError) as error:
        ingest_packaged_github_fixture(database)

    assert error.value.code is GithubFixtureIngestionErrorCode.ITEM_CONFLICT
    assert _owned_rows(database) == before


def test_first_ingestion_rejects_extra_item_in_preseeded_source_and_rolls_back(
    tmp_path: Path,
) -> None:
    database = initialized_database(tmp_path / "first-extra-item.sqlite3")
    ingest_packaged_github_fixture(database)
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM source_spans")
        connection.execute("DELETE FROM source_items")
    _insert_extra_item(database, FIXTURE_REGISTRY_SOURCE_ID)
    before = _owned_rows(database)

    with pytest.raises(GithubFixtureIngestionError) as error:
        ingest_packaged_github_fixture(database)

    assert error.value.code is GithubFixtureIngestionErrorCode.ITEM_CONFLICT
    assert _owned_rows(database) == before


def test_extra_span_is_rejected_without_rewriting_existing_rows(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "extra-span.sqlite3")
    ingest_packaged_github_fixture(database)
    with sqlite3.connect(database) as connection:
        item_id = connection.execute(
            "SELECT item_id FROM source_items ORDER BY item_id LIMIT 1"
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO source_spans "
            "(span_id, item_id, start_byte, end_byte, text_sha256) "
            "VALUES (?, ?, 0, 1, ?)",
            ("unexpected-span", item_id, "d" * 64),
        )
    before = _owned_rows(database)

    with pytest.raises(GithubFixtureIngestionError) as error:
        ingest_packaged_github_fixture(database)

    assert error.value.code is GithubFixtureIngestionErrorCode.SPAN_CONFLICT
    assert _owned_rows(database) == before


@pytest.mark.parametrize(
    ("table", "column", "value", "expected_code"),
    [
        (
            "source_items",
            "metadata_json",
            "{\"tampered\":true}",
            GithubFixtureIngestionErrorCode.ITEM_CONFLICT,
        ),
        (
            "source_spans",
            "text_sha256",
            "e" * 64,
            GithubFixtureIngestionErrorCode.SPAN_CONFLICT,
        ),
    ],
)
def test_ingestion_rejects_tampered_expected_rows_without_changes(
    tmp_path: Path,
    table: str,
    column: str,
    value: str,
    expected_code: GithubFixtureIngestionErrorCode,
) -> None:
    database = initialized_database(tmp_path / f"tampered-{table}.sqlite3")
    ingest_packaged_github_fixture(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            f"UPDATE {table} SET {column} = ? WHERE rowid = "
            f"(SELECT min(rowid) FROM {table})",
            (value,),
        )
    before = _owned_rows(database)

    with pytest.raises(GithubFixtureIngestionError) as error:
        ingest_packaged_github_fixture(database)

    assert error.value.code is expected_code
    assert _owned_rows(database) == before


def test_final_complete_state_verification_is_in_transaction_and_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = initialized_database(tmp_path / "verification-rollback.sqlite3")
    observed_transaction_state: list[bool] = []

    def fail_postcondition(
        connection: sqlite3.Connection,
        _items: object,
    ) -> None:
        observed_transaction_state.append(connection.in_transaction)
        raise GithubFixtureIngestionError(GithubFixtureIngestionErrorCode.ITEM_CONFLICT)

    monkeypatch.setattr(ingestion_module, "_verify_persisted_items", fail_postcondition)
    before = _owned_rows(database)

    with pytest.raises(GithubFixtureIngestionError) as error:
        ingest_packaged_github_fixture(database)

    assert error.value.code is GithubFixtureIngestionErrorCode.ITEM_CONFLICT
    assert observed_transaction_state == [True]
    assert _owned_rows(database) == before


def test_unrelated_registered_source_and_item_do_not_break_fixture_completeness(
    tmp_path: Path,
) -> None:
    database = initialized_database(tmp_path / "unrelated-source.sqlite3")
    ingest_packaged_github_fixture(database)
    with sqlite3.connect(database) as connection:
        principal_id = connection.execute(
            "SELECT principal_id FROM principals LIMIT 1"
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO sources "
            "(source_id, plugin_id, plugin_version, principal_id, source_type, account_alias, "
            "scope_json, host_allowlist_json, trust, default_sensitivity, enabled, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(_OTHER_SOURCE_ID),
                "github.fixture",
                "1.0.0",
                principal_id,
                "github_issue_fixture",
                "another-owner/another-project",
                "{}",
                "[]",
                "T4 EXTERNAL",
                "PUBLIC",
                1,
                _OBSERVED_AT,
            ),
        )
        connection.execute(
            "INSERT INTO source_items "
            "(item_id, source_id, provider_item_id, content_ref, content_sha256, trust, "
            "sensitivity, observed_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(_OTHER_ITEM_ID),
                str(_OTHER_SOURCE_ID),
                "another-owner/another-project#1",
                "fixture:unrelated:item-1",
                "f" * 64,
                "T4 EXTERNAL",
                "PUBLIC",
                _OBSERVED_AT,
                "{}",
            ),
        )

    report = ingest_packaged_github_fixture(database)
    persisted = read_persisted_github_fixture(database)

    assert (report.inserted_items, report.existing_items) == (0, 3)
    assert (report.inserted_spans, report.existing_spans) == (0, 9)
    assert len(persisted.items) == 3
    with readonly_database_connection(database) as connection:
        assert connection.execute("SELECT count(*) FROM sources").fetchone() == (2,)
        assert connection.execute("SELECT count(*) FROM source_items").fetchone() == (4,)


def _insert_extra_item(database: Path, source_id: UUID) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO source_items "
            "(item_id, source_id, provider_item_id, content_ref, content_sha256, trust, "
            "sensitivity, observed_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(_EXTRA_ITEM_ID),
                str(source_id),
                "example-owner/fixture-project#999",
                f"fixture:{FIXTURE_SCHEMA_VERSION}:example-owner/fixture-project#999",
                "a" * 64,
                "T4 EXTERNAL",
                "PUBLIC",
                _OBSERVED_AT,
                "{}",
            ),
        )


def _owned_rows(database: Path) -> tuple[tuple[tuple[object, ...], ...], ...]:
    with readonly_database_connection(database) as connection:
        return (
            tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM principals ORDER BY principal_id"
                ).fetchall()
            ),
            tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM plugin_manifests ORDER BY plugin_id, plugin_version"
                ).fetchall()
            ),
            tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM sources ORDER BY source_id"
                ).fetchall()
            ),
            tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM source_items ORDER BY item_id"
                ).fetchall()
            ),
            tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM source_spans ORDER BY span_id"
                ).fetchall()
            ),
        )
