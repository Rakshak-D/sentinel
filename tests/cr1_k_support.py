"""Disposable CR1-K databases and SQLite snapshots for behavioral tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any
from uuid import UUID

from sentinel.content import store_packaged_github_public_bodies
from sentinel.ingestion import promote_github_fixture_to_public_blobs
from sentinel.storage.connection import readonly_database_connection
from sentinel.sync import setup_incremental_github_fixture
from tests.cr1_h1_support import prepared_case


def promoted_case(tmp_path: Path, *, name: str = "sync") -> tuple[Path, Path]:
    database, store_root = prepared_case(tmp_path, name=name)
    store_packaged_github_public_bodies(store_root)
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    return database, store_root


def setup_case(tmp_path: Path, *, name: str = "sync") -> tuple[Path, Path, UUID]:
    database, store_root = promoted_case(tmp_path, name=name)
    state = setup_incremental_github_fixture(database, store_root=store_root)
    return database, store_root, state.source_id


def source_rows(database: Path, source_id: UUID) -> dict[str, Any]:
    with readonly_database_connection(database) as connection:
        source = connection.execute(
            """SELECT source_id, plugin_id, plugin_version, principal_id, source_type,
                      account_alias, scope_json, host_allowlist_json, trust,
                      default_sensitivity, enabled, created_at
               FROM sources WHERE source_id = ?""",
            (str(source_id),),
        ).fetchone()
        cursor = connection.execute(
            """SELECT cursor_id, source_id, cursor_kind, value_cipher_ref, etag,
                      generation, last_full_sync_at, last_commit_at, status
               FROM sync_cursors WHERE source_id = ?""",
            (str(source_id),),
        ).fetchone()
        items = tuple(
            tuple(row)
            for row in connection.execute(
                """SELECT item_id, source_id, provider_item_id, provider_revision,
                          canonical_uri, content_ref, content_sha256, trust, sensitivity,
                          observed_at, source_at, deleted_at, metadata_json
                   FROM source_items WHERE source_id = ? ORDER BY provider_item_id""",
                (str(source_id),),
            ).fetchall()
        )
        spans = tuple(
            tuple(row)
            for row in connection.execute(
                """SELECT sp.span_id, sp.item_id, sp.start_byte, sp.end_byte,
                          sp.text_sha256, sp.context_ref, sp.derived_by_boundary_id
                   FROM source_spans AS sp JOIN source_items AS si ON si.item_id = sp.item_id
                   WHERE si.source_id = ? ORDER BY sp.item_id, sp.span_id""",
                (str(source_id),),
            ).fetchall()
        )
        return {
            "source": None if source is None else tuple(source),
            "cursor": None if cursor is None else tuple(cursor),
            "items": items,
            "spans": spans,
        }


def direct_connection(database: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database, isolation_level=None)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection
