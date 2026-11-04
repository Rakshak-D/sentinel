from __future__ import annotations

import pytest
from typer.testing import CliRunner

import sentinel.overview.assembly as assembly
from sentinel.cli import app
from sentinel.content import initialize_public_fixture_store
from sentinel.overview import OverviewError, OverviewErrorCode, build_local_overview
from sentinel.storage.connection import database_connection
from sentinel.tasks import edit_local_task, setup_local_task_operator
from tests.cr1_h1_support import blob_files, initialized_unpromoted_database
from tests.cr1_l_support import AS_OF, add_task, overview_case, persisted_state
from tests.test_cr1_j_support import historical_prefix_database, migration_history

runner = CliRunner()


def test_invalid_as_of_is_rejected_before_any_database_reads(tmp_path, monkeypatch) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("database reads must not occur for an invalid as-of")

    monkeypatch.setattr(assembly, "_read_tasks", forbidden)
    result = runner.invoke(
        app,
        [
            "brief", "local-overview", "--database", str(tmp_path / "missing.db"),
            "--store-root", str(tmp_path / "missing-store"), "--as-of", "2026-11-04T18:00:00",
        ],
    )

    assert result.exit_code != 0
    assert result.stdout == ""
    assert result.stderr == (
        "Local overview failed: as-of must be an ISO-8601 timestamp with an explicit UTC offset.\n"
    )
    assert str(tmp_path) not in result.stderr


@pytest.mark.parametrize(
    "invalid",
    ["not-a-date", "2026-11-04", "2026-11-04T18:00:00", "2026-11-04T18:00:00-00:00"],
)
def test_invalid_as_of_values_fail_closed(invalid: str) -> None:
    from sentinel.overview import parse_as_of_timestamp

    with pytest.raises(OverviewError) as error:
        parse_as_of_timestamp(invalid)
    assert error.value.code is OverviewErrorCode.INVALID_AS_OF
    assert invalid not in str(error.value)


def test_cli_rejects_unknown_format_and_missing_required_options_before_reads(
    tmp_path, monkeypatch
) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("overview must not run for invalid options")

    monkeypatch.setattr(assembly, "_read_tasks", forbidden)
    base = ["brief", "local-overview"]
    missing_database = runner.invoke(
        app,
        [*base, "--store-root", str(tmp_path), "--as-of", "2026-11-04T18:00:00Z"],
    )
    missing_store = runner.invoke(
        app,
        [*base, "--database", str(tmp_path / "db"), "--as-of", "2026-11-04T18:00:00Z"],
    )
    missing_as_of = runner.invoke(
        app,
        [*base, "--database", str(tmp_path / "db"), "--store-root", str(tmp_path)],
    )
    invalid_format = runner.invoke(
        app,
        [
            *base, "--database", str(tmp_path / "db"), "--store-root", str(tmp_path),
            "--as-of", "2026-11-04T18:00:00Z", "--format", "xml",
        ],
    )

    assert missing_database.exit_code != 0 and missing_database.stdout == ""
    assert missing_store.exit_code != 0 and missing_store.stdout == ""
    assert missing_as_of.exit_code != 0 and missing_as_of.stdout == ""
    assert invalid_format.exit_code != 0 and invalid_format.stdout == ""
    assert "Traceback" not in invalid_format.output


def test_historical_and_unpromoted_databases_are_not_repaired_or_promoted(tmp_path) -> None:
    historical = historical_prefix_database(tmp_path / "historical.sqlite3", 3)
    historical_store = tmp_path / "historical-store"
    initialize_public_fixture_store(historical_store)
    history_before = migration_history(historical)
    historical_result = runner.invoke(
        app,
        [
            "brief", "local-overview", "--database", str(historical),
            "--store-root", str(historical_store), "--as-of", "2026-11-04T18:00:00Z",
        ],
    )
    assert historical_result.exit_code != 0 and historical_result.stdout == ""
    assert migration_history(historical) == history_before

    unpromoted = initialized_unpromoted_database(tmp_path / "unpromoted.sqlite3")
    unpromoted_store = tmp_path / "unpromoted-store"
    initialize_public_fixture_store(unpromoted_store)
    setup_local_task_operator(unpromoted)
    rows_before = _source_item_rows(unpromoted)
    blobs_before = blob_files(unpromoted_store)
    unpromoted_result = runner.invoke(
        app,
        [
            "brief", "local-overview", "--database", str(unpromoted),
            "--store-root", str(unpromoted_store), "--as-of", "2026-11-04T18:00:00Z",
        ],
    )
    assert unpromoted_result.exit_code != 0 and unpromoted_result.stdout == ""
    assert _source_item_rows(unpromoted) == rows_before
    assert blob_files(unpromoted_store) == blobs_before == ()


def _source_item_rows(database):
    with database_connection(database) as connection:
        return tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT item_id, content_ref, content_sha256 FROM source_items ORDER BY item_id"
            ).fetchall()
        )


def test_missing_blob_and_corrupt_citation_produce_no_partial_stdout(tmp_path) -> None:
    database, store_root = overview_case(tmp_path, name="missing-blob")
    blob_files(store_root)[0].unlink()
    missing_blob = runner.invoke(
        app,
        [
            "brief", "local-overview", "--database", str(database), "--store-root", str(store_root),
            "--as-of", "2026-11-04T18:00:00Z",
        ],
    )
    assert missing_blob.exit_code != 0
    assert missing_blob.stdout == ""
    assert "failed" in missing_blob.stderr.lower()
    assert str(database) not in missing_blob.stderr
    assert str(store_root) not in missing_blob.stderr

    database2, store_root2 = overview_case(tmp_path, name="corrupt-citation")
    with database_connection(database2) as connection:
        connection.execute(
            "UPDATE source_spans SET text_sha256 = ? WHERE span_id = "
            "(SELECT ss.span_id FROM source_spans AS ss "
            "JOIN source_items AS si ON si.item_id = ss.item_id "
            "WHERE si.provider_item_id = ? LIMIT 1)",
            ("0" * 64, "example-owner/fixture-project#103"),
        )
    late_failure = runner.invoke(
        app,
        [
            "brief", "local-overview", "--database", str(database2),
            "--store-root", str(store_root2),
            "--as-of", "2026-11-04T18:00:00Z",
        ],
    )
    assert late_failure.exit_code != 0
    assert late_failure.stdout == ""
    assert "Traceback" not in late_failure.stderr
    assert str(database2) not in late_failure.stderr
    assert str(store_root2) not in late_failure.stderr


def test_invalid_task_row_rejects_entire_overview_without_title_leak(tmp_path) -> None:
    database, store_root = overview_case(tmp_path, name="task-tamper")
    task = add_task(database, key="canary", title="PRIVATE-TITLE-CANARY")
    with database_connection(database) as connection:
        connection.execute(
            "UPDATE tasks SET title = ? WHERE task_id = ?",
            ("PRIVATE-TITLE-CANARY\x1b", str(task.task_id)),
        )

    result = runner.invoke(
        app,
        [
            "brief", "local-overview", "--database", str(database), "--store-root", str(store_root),
            "--as-of", "2026-11-04T18:00:00Z",
        ],
    )

    assert result.exit_code != 0 and result.stdout == ""
    assert "PRIVATE-TITLE-CANARY" not in result.stderr
    assert str(database) not in result.stderr and str(store_root) not in result.stderr


def test_tampered_cursor_rejects_entire_overview(tmp_path) -> None:
    database, store_root = overview_case(tmp_path, name="cursor-tamper")
    with database_connection(database) as connection:
        connection.execute(
            "UPDATE sync_cursors SET value_cipher_ref = ?",
            ("sentinel-unknown-cursor-v9:sha256:" + "0" * 64,),
        )

    result = runner.invoke(
        app,
        [
            "brief", "local-overview", "--database", str(database),
            "--store-root", str(store_root), "--as-of", "2026-11-04T18:00:00Z",
        ],
    )

    assert result.exit_code != 0 and result.stdout == ""
    assert str(database) not in result.stderr and str(store_root) not in result.stderr


def test_detects_task_mutation_between_component_reads(tmp_path, monkeypatch) -> None:
    database, store_root = overview_case(tmp_path, name="task-race")
    task = add_task(database, key="race-task", title="Before change")
    original = assembly.build_github_fixture_brief
    changed = False

    def mutate_after_evidence(*args, **kwargs):
        nonlocal changed
        briefing = original(*args, **kwargs)
        if not changed:
            changed = True
            edit_local_task(
                database,
                task_id=task.task_id,
                expected_revision=1,
                title="After change",
            )
        return briefing

    monkeypatch.setattr(assembly, "build_github_fixture_brief", mutate_after_evidence)
    with pytest.raises(OverviewError) as error:
        build_local_overview(database, store_root=store_root, as_of=AS_OF)

    assert error.value.code is OverviewErrorCode.STATE_CHANGED
    assert "Before change" not in str(error.value)
    assert "After change" not in str(error.value)


def test_detects_cursor_generation_change_between_component_reads(tmp_path, monkeypatch) -> None:
    from sentinel.sync import advance_incremental_github_fixture

    database, store_root = overview_case(tmp_path, name="cursor-race", generation=0)
    original = assembly.build_github_fixture_brief
    changed = False

    def advance_after_evidence(*args, **kwargs):
        nonlocal changed
        briefing = original(*args, **kwargs)
        if not changed:
            changed = True
            advance_incremental_github_fixture(
                database, store_root=store_root, expected_generation=0
            )
        return briefing

    monkeypatch.setattr(assembly, "build_github_fixture_brief", advance_after_evidence)
    with pytest.raises(OverviewError) as error:
        build_local_overview(database, store_root=store_root, as_of=AS_OF)

    assert error.value.code is OverviewErrorCode.STATE_CHANGED


def test_overview_reads_without_sqlite_or_blob_mutations_and_never_loads_fixture(
    tmp_path, monkeypatch
) -> None:
    database, store_root = overview_case(tmp_path, name="read-only", generation=2)
    before = persisted_state(database, store_root)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("readback must use the pinned body-free expectation manifest")

    monkeypatch.setattr("sentinel.readers.github_fixture.read_packaged_github_fixture", forbidden)
    monkeypatch.setattr("socket.socket", forbidden)
    monkeypatch.setattr("sentinel.gateways.model.ModelGateway.generate", forbidden)
    monkeypatch.setattr("sentinel.gateways.tool.ToolGateway.call", forbidden)

    overview = build_local_overview(database, store_root=store_root, as_of=AS_OF)

    assert overview.sync.generation == 2
    assert persisted_state(database, store_root) == before
