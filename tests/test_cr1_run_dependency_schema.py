"""Relational dependency and constraint tests for CR1-F tables."""

import hashlib
import sqlite3
from pathlib import Path

import pytest

from sentinel.storage.connection import database_connection
from sentinel.storage.migrations import initialize_storage, verify_integrity


def _database(tmp_path: Path) -> Path:
    database = tmp_path / "run-dependencies.sqlite3"
    initialize_storage(database, create=True)
    return database


def _seed_source_item(connection: sqlite3.Connection) -> None:
    connection.execute(
        "INSERT INTO principals VALUES (?, ?, ?, ?, ?, ?)",
        (
            "principal-r",
            "owner",
            "Synthetic principal",
            "synthetic:binding",
            "2026-11-03T00:00:00Z",
            None,
        ),
    )
    connection.execute(
        """INSERT INTO plugin_manifests
           (plugin_id, plugin_version, manifest_ref, manifest_sha256, origin,
            capability_json, trust, sensitivity, host_allowlist_json,
            fixture_set_sha256, enabled, registered_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "synthetic.reader", "1.0.0", "manifest:reader", "3" * 64,
            "fixture", "[]", "T4_EXTERNAL", "PRIVATE", "[]", "4" * 64,
            1, "2026-11-03T00:00:00Z",
        ),
    )
    connection.execute(
        """INSERT INTO sources
           (source_id, plugin_id, plugin_version, principal_id, source_type,
            account_alias, scope_json, host_allowlist_json, trust,
            default_sensitivity, enabled, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "source-r", "synthetic.reader", "1.0.0", "principal-r",
            "fixture", "synthetic-account", "{}", "[]", "T4_EXTERNAL",
            "PRIVATE", 1, "2026-11-03T00:00:00Z",
        ),
    )
    connection.execute(
        """INSERT INTO source_items
           (item_id, source_id, provider_item_id, content_ref, content_sha256,
            trust, sensitivity, observed_at, metadata_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "item-r", "source-r", "synthetic-item", "opaque:item",
            hashlib.sha256(b"synthetic bytes").hexdigest(), "T4_EXTERNAL",
            "PRIVATE", "2026-11-03T00:00:00Z", "{}",
        ),
    )


def _insert_config(connection: sqlite3.Connection, config_id: str, digest: str) -> None:
    connection.execute(
        """INSERT INTO config_revisions
           (config_id, parent_config_id, layer_set_json, effective_schema_version,
            effective_config_ref, effective_sha256, unsafe_overrides_json,
            activated_at, created_at, activation_state)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            config_id, None, "[]", "sentinel.config.v1", "opaque:config",
            digest, "[]", None, "2026-11-03T00:00:00Z", "inactive",
        ),
    )


def _insert_manifest(
    connection: sqlite3.Connection, manifest_id: str = "manifest-r"
) -> None:
    connection.execute(
        """INSERT INTO run_manifests
           (manifest_id, config_id, policy_sha256, graph_build, plugin_set_sha256,
            prompt_set_sha256, model_profile_sha256, unsafe_overrides_json,
            fixture_manifest_sha256, created_at, manifest_sha256)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            manifest_id, "config-r", "5" * 64, "synthetic-build", "6" * 64,
            "7" * 64, "8" * 64, "[]", None,
            "2026-11-03T00:00:00Z", "9" * 64,
        ),
    )


def _insert_run(connection: sqlite3.Connection, run_id: str = "run-r") -> None:
    connection.execute(
        """INSERT INTO runs
           (run_id, thread_id, principal_id, manifest_id, mode, trigger_kind,
            started_at, ended_at, status, error_code, briefing_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            run_id, "thread-r", "principal-r", "manifest-r", "DEMO", "cli",
            "2026-11-03T00:00:00Z", None, "started", None, None,
        ),
    )


def _insert_boundary(
    connection: sqlite3.Connection,
    boundary_id: str = "boundary-r",
    seq: int = 1,
    replay_injected: int = 0,
    response_sha256: str | None = None,
) -> None:
    connection.execute(
        """INSERT INTO boundary_envelopes
           (boundary_id, run_id, seq, kind, adapter_id, request_ref, response_ref,
            request_sha256, response_sha256, sensitivity, source_ids_json,
            replay_injected, error_code, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            boundary_id, "run-r", seq, "model", "synthetic.adapter",
            "opaque:req", None, "a" * 64, response_sha256, "PUBLIC", "[]",
            replay_injected, None, "2026-11-03T00:00:00Z",
        ),
    )


def test_five_new_tables_have_the_blueprint_column_shapes(tmp_path: Path) -> None:
    database = _database(tmp_path)
    expected = {
        "config_revisions": (
            ("config_id", "TEXT"), ("parent_config_id", "TEXT"),
            ("layer_set_json", "TEXT"), ("effective_schema_version", "TEXT"),
            ("effective_config_ref", "TEXT"), ("effective_sha256", "TEXT"),
            ("unsafe_overrides_json", "TEXT"), ("activated_at", "TEXT"),
            ("created_at", "TEXT"), ("activation_state", "TEXT"),
        ),
        "run_manifests": (
            ("manifest_id", "TEXT"), ("config_id", "TEXT"), ("policy_sha256", "TEXT"),
            ("graph_build", "TEXT"), ("plugin_set_sha256", "TEXT"),
            ("prompt_set_sha256", "TEXT"), ("model_profile_sha256", "TEXT"),
            ("unsafe_overrides_json", "TEXT"), ("fixture_manifest_sha256", "TEXT"),
            ("created_at", "TEXT"), ("manifest_sha256", "TEXT"),
        ),
        "runs": (
            ("run_id", "TEXT"), ("thread_id", "TEXT"), ("principal_id", "TEXT"),
            ("manifest_id", "TEXT"), ("mode", "TEXT"), ("trigger_kind", "TEXT"),
            ("started_at", "TEXT"), ("ended_at", "TEXT"), ("status", "TEXT"),
            ("error_code", "TEXT"), ("briefing_id", "TEXT"),
        ),
        "boundary_envelopes": (
            ("boundary_id", "TEXT"), ("run_id", "TEXT"), ("seq", "INTEGER"),
            ("kind", "TEXT"), ("adapter_id", "TEXT"), ("request_ref", "TEXT"),
            ("response_ref", "TEXT"), ("request_sha256", "TEXT"),
            ("response_sha256", "TEXT"), ("sensitivity", "TEXT"),
            ("source_ids_json", "TEXT"), ("replay_injected", "INTEGER"),
            ("error_code", "TEXT"), ("created_at", "TEXT"),
        ),
    }
    optional = {
        "config_revisions": {"parent_config_id", "activated_at"},
        "run_manifests": {"fixture_manifest_sha256"},
        "runs": {"ended_at", "error_code", "briefing_id"},
        "boundary_envelopes": {"response_ref", "response_sha256", "error_code"},
    }
    primary_keys = {
        "config_revisions": "config_id",
        "run_manifests": "manifest_id",
        "runs": "run_id",
        "boundary_envelopes": "boundary_id",
    }
    with database_connection(database) as connection:
        for table, columns in expected.items():
            info = connection.execute(f"PRAGMA table_info({table})").fetchall()
            assert tuple((str(row[1]), str(row[2]).upper()) for row in info) == columns
            assert {row[1] for row in info if row[3] == 0} == optional[table]
            assert tuple(row[1] for row in info if row[5] == 1) == (primary_keys[table],)


def test_fk_dependency_graph_and_blueprint_indexes_are_present(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        fk_rows = {
            table: connection.execute(f"PRAGMA foreign_key_list({table})").fetchall()
            for table in (
                "config_revisions", "run_manifests", "runs",
                "boundary_envelopes", "source_spans",
            )
        }
        index_names = {
            table: {row[1] for row in connection.execute(f"PRAGMA index_list({table})")}
            for table in (
                "config_revisions", "run_manifests", "runs",
                "boundary_envelopes", "source_spans",
            )
        }
        index_columns = {
            (table, str(row[1])): tuple(
                str(item[2])
                for item in connection.execute(f"PRAGMA index_info({row[1]})")
            )
            for table in (
                "config_revisions", "run_manifests", "runs",
                "boundary_envelopes", "source_spans",
            )
            for row in connection.execute(f"PRAGMA index_list({table})")
            if not str(row[1]).startswith("sqlite_autoindex_")
        }
        run_columns = connection.execute("PRAGMA table_info(runs)").fetchall()
    assert {(row[2], row[3], row[4]) for row in fk_rows["config_revisions"]} == {
        ("config_revisions", "parent_config_id", "config_id"),
    }
    assert {(row[2], row[3], row[4]) for row in fk_rows["run_manifests"]} == {
        ("config_revisions", "config_id", "config_id"),
    }
    assert {(row[2], row[3], row[4]) for row in fk_rows["runs"]} == {
        ("principals", "principal_id", "principal_id"),
        ("run_manifests", "manifest_id", "manifest_id"),
    }
    assert {(row[2], row[3], row[4]) for row in fk_rows["boundary_envelopes"]} == {
        ("runs", "run_id", "run_id"),
    }
    assert {
        "config_revisions_activation_created_at_idx" in index_names["config_revisions"],
        "run_manifests_created_at_idx" in index_names["run_manifests"],
        "runs_thread_started_at_idx" in index_names["runs"],
        "runs_status_started_at_idx" in index_names["runs"],
        "boundary_envelopes_kind_adapter_idx" in index_names["boundary_envelopes"],
    } == {True}
    assert index_columns == {
        ("config_revisions", "config_revisions_activation_created_at_idx"):
            ("activation_state", "created_at"),
        ("run_manifests", "run_manifests_created_at_idx"): ("created_at",),
        ("runs", "runs_thread_started_at_idx"): ("thread_id", "started_at"),
        ("runs", "runs_status_started_at_idx"): ("status", "started_at"),
        ("boundary_envelopes", "boundary_envelopes_kind_adapter_idx"):
            ("kind", "adapter_id"),
        ("source_spans", "source_spans_item_start_byte_idx"):
            ("item_id", "start_byte"),
    }
    briefing = next(row for row in run_columns if row[1] == "briefing_id")
    assert briefing[3] == 0
    assert all(row[2] != "briefings" for row in fk_rows["runs"])


def test_valid_self_config_manifest_run_boundary_and_source_span_chain(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        _seed_source_item(connection)
        _insert_config(connection, "config-root", "b" * 64)
        connection.execute(
            """INSERT INTO config_revisions
               (config_id, parent_config_id, layer_set_json, effective_schema_version,
                effective_config_ref, effective_sha256, unsafe_overrides_json,
                activated_at, created_at, activation_state)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "config-child", "config-root", "[]", "sentinel.config.v1",
                "opaque:config-child", "c" * 64, "[]", None,
                "2026-11-03T00:00:01Z", "inactive",
            ),
        )
        _insert_config(connection, "config-r", "d" * 64)
        _insert_manifest(connection)
        _insert_run(connection)
        _insert_boundary(connection, response_sha256="e" * 64)
        connection.execute(
            """INSERT INTO source_spans
               (span_id, item_id, start_byte, end_byte, text_sha256,
                derived_by_boundary_id)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("span-r", "item-r", 0, 4, hashlib.sha256("🙂".encode()).hexdigest(), "boundary-r"),
        )
        stored = connection.execute(
            """SELECT config_id FROM run_manifests WHERE manifest_id = ?""",
            ("manifest-r",),
        ).fetchone()
        verify_integrity(connection)
    assert stored == ("config-r",)


def test_each_required_new_foreign_key_rejects_missing_parent(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        _seed_source_item(connection)
        _insert_config(connection, "config-r", "b" * 64)
        _insert_manifest(connection)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO config_revisions
                   (config_id, parent_config_id, layer_set_json, effective_schema_version,
                    effective_config_ref, effective_sha256, unsafe_overrides_json,
                    created_at, activation_state)
                   VALUES ('config-orphan', 'missing-config', '[]', 'v1', 'opaque:cfg',
                           ?, '[]', '2026-11-03T00:00:00Z', 'inactive')""",
                ("c" * 64,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO runs
                   (run_id, thread_id, principal_id, manifest_id, mode, trigger_kind,
                    started_at, status)
                   VALUES ('run-no-principal', 'thread-r', 'missing-principal',
                           'manifest-r', 'DEMO', 'cli', '2026-11-03T00:00:00Z', 'started')"""
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO runs
                   (run_id, thread_id, principal_id, manifest_id, mode, trigger_kind,
                    started_at, status)
                   VALUES ('run-no-manifest', 'thread-r', 'principal-r',
                           'missing-manifest', 'DEMO', 'cli', '2026-11-03T00:00:00Z', 'started')"""
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO boundary_envelopes
                   (boundary_id, run_id, seq, kind, adapter_id, request_ref,
                    request_sha256, sensitivity, source_ids_json, replay_injected,
                    created_at)
                   VALUES ('boundary-no-run', 'missing-run', 1, 'tool', 'synthetic',
                           'opaque:req', ?, 'PUBLIC', '[]', 0, '2026-11-03T00:00:00Z')""",
                ("a" * 64,),
            )


def test_invalid_parent_references_and_digest_values_fail(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        _seed_source_item(connection)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_config(connection, "config-bad", "not-a-sha256")
        connection.execute(
            """INSERT INTO config_revisions
               (config_id, layer_set_json, effective_schema_version, effective_config_ref,
                effective_sha256, unsafe_overrides_json, created_at, activation_state)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("config-r", "[]", "v1", "opaque:cfg", "f" * 64, "[]", "2026-11-03", "inactive"),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO run_manifests
                   (manifest_id, config_id, policy_sha256, graph_build, plugin_set_sha256,
                    prompt_set_sha256, model_profile_sha256, unsafe_overrides_json,
                    created_at, manifest_sha256)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("manifest-orphan", "missing-config", "a" * 64, "build", "b" * 64,
                 "c" * 64, "d" * 64, "[]", "2026-11-03", "e" * 64),
            )


def test_duplicate_boundary_sequence_and_invalid_replay_or_digest_are_rejected(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        _seed_source_item(connection)
        _insert_config(connection, "config-r", "b" * 64)
        _insert_manifest(connection)
        _insert_run(connection)
        _insert_boundary(connection)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_boundary(connection, boundary_id="boundary-duplicate")
        with pytest.raises(sqlite3.IntegrityError):
            _insert_boundary(
                connection,
                boundary_id="boundary-replay-bad",
                seq=2,
                replay_injected=2,
            )
        with pytest.raises(sqlite3.IntegrityError):
            _insert_boundary(
                connection, boundary_id="boundary-digest-bad", seq=3,
                response_sha256="not-a-sha256",
            )


def test_required_digest_columns_reject_malformed_values(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        _seed_source_item(connection)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_config(connection, "config-bad", "bad-config-digest")
        _insert_config(connection, "config-r", "a" * 64)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO run_manifests
                   (manifest_id, config_id, policy_sha256, graph_build, plugin_set_sha256,
                    prompt_set_sha256, model_profile_sha256, unsafe_overrides_json,
                    created_at, manifest_sha256)
                   VALUES ('manifest-bad', 'config-r', 'bad', 'build', ?, ?, ?, '[]',
                           '2026-11-03T00:00:00Z', ?)""",
                ("b" * 64, "c" * 64, "d" * 64, "e" * 64),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO run_manifests
                   (manifest_id, config_id, policy_sha256, graph_build, plugin_set_sha256,
                    prompt_set_sha256, model_profile_sha256, unsafe_overrides_json,
                    fixture_manifest_sha256, created_at, manifest_sha256)
                   VALUES ('manifest-bad-optional', 'config-r', ?, 'build', ?, ?, ?, '[]',
                           'bad', '2026-11-03T00:00:00Z', ?)""",
                ("5" * 64, "6" * 64, "7" * 64, "8" * 64, "9" * 64),
            )


def test_config_and_manifest_hash_uniqueness_is_enforced(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database_connection(database) as connection:
        _seed_source_item(connection)
        _insert_config(connection, "config-one", "a" * 64)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_config(connection, "config-two", "a" * 64)
        _insert_config(connection, "config-three", "b" * 64)
        _insert_config(connection, "config-r", "c" * 64)
        _insert_manifest(connection, "manifest-one")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO run_manifests
                   (manifest_id, config_id, policy_sha256, graph_build, plugin_set_sha256,
                    prompt_set_sha256, model_profile_sha256, unsafe_overrides_json,
                    created_at, manifest_sha256)
                   VALUES ('manifest-two', 'config-three', ?, 'build', ?, ?, ?, '[]',
                           '2026-11-03T00:00:00Z', ?)""",
                ("5" * 64, "6" * 64, "7" * 64, "8" * 64, "9" * 64),
            )
