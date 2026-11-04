import json
import sqlite3
from pathlib import Path
from uuid import UUID

from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.sync import setup_incremental_github_fixture
from sentinel.sync.github_fixture import (
    INCREMENTAL_ACCOUNT_ALIAS,
    INCREMENTAL_CURSOR_ID,
    INCREMENTAL_CURSOR_KIND,
    INCREMENTAL_SOURCE_ID,
    INCREMENTAL_SOURCE_LABEL,
)
from tests.cr1_k_support import promoted_case


def test_setup_registers_distinct_source_and_generation_zero(tmp_path: Path) -> None:
    database, store_root = promoted_case(tmp_path, name="setup-red")

    state = setup_incremental_github_fixture(database, store_root=store_root)

    assert state is not None
    assert state.generation == 0
    assert state.item_count == 0
    assert state.span_count == 0
    assert state.source_id != UUID(EXPECTED_MANIFEST.source_row[0])
    assert state.source_id == INCREMENTAL_SOURCE_ID

    connection = sqlite3.connect(database)
    try:
        source = connection.execute(
            """SELECT source_id, plugin_id, plugin_version, principal_id, source_type,
                      account_alias, scope_json, trust, default_sensitivity, enabled
               FROM sources WHERE source_id = ?""",
            (str(INCREMENTAL_SOURCE_ID),),
        ).fetchone()
        cursor = connection.execute(
            """SELECT cursor_id, source_id, cursor_kind, value_cipher_ref, etag,
                      generation, last_full_sync_at, status
               FROM sync_cursors WHERE source_id = ?""",
            (str(INCREMENTAL_SOURCE_ID),),
        ).fetchone()
        plugin = connection.execute(
            "SELECT enabled FROM plugin_manifests WHERE plugin_id = 'github.fixture'"
        ).fetchone()
    finally:
        connection.close()

    assert source is not None
    assert source[5] == INCREMENTAL_ACCOUNT_ALIAS
    assert source[7:10] == ("T4 EXTERNAL", "PUBLIC", 1)
    assert json.loads(source[6]) == {
        "fixture_sha256": EXPECTED_MANIFEST.fixture_sha256,
        "fixture_version": EXPECTED_MANIFEST.fixture_version,
        "mode": INCREMENTAL_SOURCE_LABEL,
        "repository": "example-owner/fixture-project",
    }
    assert cursor is not None
    assert cursor[:3] == (
        str(INCREMENTAL_CURSOR_ID),
        str(INCREMENTAL_SOURCE_ID),
        INCREMENTAL_CURSOR_KIND,
    )
    assert cursor[4:] == (None, 0, None, "READY")
    assert plugin == (0,)
