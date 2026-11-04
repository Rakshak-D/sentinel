"""Disposable fixtures for CR1-H1 promotion/readback tests."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from sentinel.content import initialize_public_fixture_store
from sentinel.ingestion import ingest_packaged_github_fixture
from sentinel.readers.github_fixture import read_packaged_github_fixture
from sentinel.storage.connection import readonly_database_connection
from sentinel.storage.migrations import initialize_storage

PUBLIC_BLOB_REF_PREFIX = "sentinel-public-blob-v1:sha256:"


def initialized_unpromoted_database(database: Path) -> Path:
    initialize_storage(database, create=True)
    ingest_packaged_github_fixture(database)
    return database


def prepared_case(tmp_path: Path, *, name: str = "case") -> tuple[Path, Path]:
    database = initialized_unpromoted_database(tmp_path / f"{name}.sqlite3")
    store_root = tmp_path / f"{name}-store"
    initialize_public_fixture_store(store_root)
    return database, store_root


def expected_bodies() -> dict[str, bytes]:
    fixture = read_packaged_github_fixture()
    return {
        issue.normalized_source.envelope.content_sha256: issue.normalized_source.original_bytes
        for issue in fixture.issues
    }


def item_rows(database: Path) -> tuple[tuple[object, ...], ...]:
    with readonly_database_connection(database) as connection:
        return tuple(
            tuple(row)
            for row in connection.execute(
                """SELECT item_id, source_id, provider_item_id, provider_revision,
                          canonical_uri, content_ref, content_sha256, trust, sensitivity,
                          observed_at, source_at, deleted_at, metadata_json
                   FROM source_items ORDER BY item_id"""
            ).fetchall()
        )


def span_rows(database: Path) -> tuple[tuple[object, ...], ...]:
    with readonly_database_connection(database) as connection:
        return tuple(
            tuple(row)
            for row in connection.execute(
                """SELECT span_id, item_id, start_byte, end_byte, text_sha256,
                          context_ref, derived_by_boundary_id
                   FROM source_spans ORDER BY span_id"""
            ).fetchall()
        )


def refs_by_item(database: Path) -> dict[UUID, str]:
    with readonly_database_connection(database) as connection:
        return {
            UUID(str(item_id)): str(content_ref)
            for item_id, content_ref in connection.execute(
                "SELECT item_id, content_ref FROM source_items ORDER BY item_id"
            ).fetchall()
        }


def blob_ref(digest: str) -> str:
    return f"{PUBLIC_BLOB_REF_PREFIX}{digest}"


def blob_files(store_root: Path) -> tuple[Path, ...]:
    return tuple(sorted((store_root / "public-v1" / "sha256").glob("*.blob")))
