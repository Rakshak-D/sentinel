"""Repeated ingestion must preserve committed synthetic source revisions."""

import sqlite3
from pathlib import Path

import pytest

from sentinel.ingestion import (
    GithubFixtureIngestionError,
    GithubFixtureIngestionErrorCode,
    ingest_packaged_github_fixture,
)
from sentinel.ingestion.github_fixture import _persisted_item_id, _persisted_span_id
from sentinel.storage.connection import readonly_database_connection
from tests.cr1_g_support import initialized_database


def test_three_ingestions_are_idempotent_and_report_existing_counts(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "idempotent.sqlite3")
    first = ingest_packaged_github_fixture(database)
    before = _rows(database)

    second = ingest_packaged_github_fixture(database)
    third = ingest_packaged_github_fixture(database)

    assert (first.inserted_items, first.existing_items) == (3, 0)
    assert (first.inserted_spans, first.existing_spans) == (9, 0)
    assert (second.inserted_items, second.existing_items) == (0, 3)
    assert (second.inserted_spans, second.existing_spans) == (0, 9)
    assert (third.inserted_items, third.existing_items) == (0, 3)
    assert (third.inserted_spans, third.existing_spans) == (0, 9)
    assert first.items == second.items == third.items
    assert _rows(database) == before


def test_revisions_with_same_provider_identity_and_different_digest_have_distinct_ids(
    tmp_path: Path,
) -> None:
    database = initialized_database(tmp_path / "revisions.sqlite3")
    report = ingest_packaged_github_fixture(database)
    item = report.items[0]

    revised = _persisted_item_id(
        report.registry_source_id,
        item.provider_item_id,
        "f" * 64 if item.content_sha256 != "f" * 64 else "e" * 64,
    )
    assert revised != item.item_id
    original_span_id = item.spans[0].in_memory_span_id
    assert _persisted_span_id(item.item_id, original_span_id) == item.spans[0].span_id
    assert _persisted_span_id(revised, original_span_id) != item.spans[0].span_id


def test_existing_conflicting_source_row_is_not_replaced(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "source-conflict.sqlite3")
    ingest_packaged_github_fixture(database)
    with readonly_database_connection(database) as connection:
        source_id = connection.execute("SELECT source_id FROM sources").fetchone()[0]
    with readonly_database_connection(database) as connection:
        before = connection.execute(
            "SELECT source_id, trust, default_sensitivity FROM sources WHERE source_id = ?",
            (source_id,),
        ).fetchone()
    # The test opens a dedicated direct SQLite connection to simulate out-of-band tampering.
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE sources SET trust = 'T1 OWNER_INTENT' WHERE source_id = ?",
            (source_id,),
        )

    with pytest.raises(GithubFixtureIngestionError) as error:
        ingest_packaged_github_fixture(database)
    assert error.value.code is GithubFixtureIngestionErrorCode.REGISTRATION_CONFLICT
    with readonly_database_connection(database) as connection:
        after = connection.execute(
            "SELECT source_id, trust, default_sensitivity FROM sources WHERE source_id = ?",
            (source_id,),
        ).fetchone()
    assert before != after
    assert after[1] == "T1 OWNER_INTENT"


def _rows(database: Path) -> tuple[object, ...]:
    with readonly_database_connection(database) as connection:
        return (
            tuple(connection.execute("SELECT * FROM principals").fetchall()),
            tuple(connection.execute("SELECT * FROM plugin_manifests").fetchall()),
            tuple(connection.execute("SELECT * FROM sources").fetchall()),
            tuple(connection.execute("SELECT * FROM source_items ORDER BY item_id").fetchall()),
            tuple(connection.execute("SELECT * FROM source_spans ORDER BY span_id").fetchall()),
        )
