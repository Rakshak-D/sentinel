"""CR1-J schema and migration behavior tests."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest

from sentinel.bootstrap.doctor import run_doctor
from sentinel.storage import migrations as migration_module
from sentinel.storage.connection import database_connection, readonly_database_connection
from sentinel.storage.migrations import (
    Migration,
    MigrationApplyError,
    MigrationIntegrityError,
    initialize_storage,
    inspect_migration_state_readonly,
)
from sentinel.storage.schema import CR1_J_SCHEMA, CR1_J_SCHEMA_DEFINITION_SHA256
from sentinel.storage.writer import acquire_writer_lease
from sentinel.tasks import create_local_task, setup_local_task_operator
from sentinel.tasks.store import LOCAL_TASK_OPERATOR_ID
from tests.test_cr1_j_support import historical_prefix_database, migration_history


def test_registered_migration_adds_task_and_proposal_schema(tmp_path: Path) -> None:
    database = tmp_path / "cr1-j-schema.sqlite3"

    applied = initialize_storage(database, create=True)

    assert applied[-1:] == ("cr1-j-0004-local-tasks",)
    assert migration_module.MIGRATIONS[-1].migration_id == "cr1-j-0004-local-tasks"
    with database_connection(database) as connection:
        objects = {
            (str(kind), str(name))
            for kind, name in connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        }
    assert ("table", "action_proposals") in objects
    assert ("table", "tasks") in objects
    assert ("table", "task_creation_requests") in objects


def test_cr1_j_pins_new_migration_and_complete_checkpoint() -> None:
    migration = migration_module.MIGRATIONS[-1]
    assert migration.migration_id == "cr1-j-0004-local-tasks"
    assert migration.artifact_sha256 == (
        "a75bfcff37255e1fb0cc49eb72254c8e83d049828faa2653a8495ca2f749120a"
    )
    assert migration.schema_after is CR1_J_SCHEMA
    assert CR1_J_SCHEMA.sha256 == (
        "659d0643a9e1c85f839a107d4e8d1d944c38972bb0416d094cd5a73ad355979d"
    )
    assert CR1_J_SCHEMA_DEFINITION_SHA256 == CR1_J_SCHEMA.sha256
    assert [item.migration_id for item in migration_module.MIGRATIONS] == [
        "cr0-c-0001-schema-migrations",
        "cr1-e-0002-source-registry",
        "cr1-f-0003-source-spans",
        "cr1-j-0004-local-tasks",
    ]


def test_task_and_proposal_columns_foreign_keys_and_indexes_match_checkpoint(
    tmp_path: Path,
) -> None:
    database = tmp_path / "task-ddl.sqlite3"
    initialize_storage(database, create=True)
    with database_connection(database) as connection:
        task_columns = connection.execute("PRAGMA table_info(tasks)").fetchall()
        proposal_columns = connection.execute("PRAGMA table_info(action_proposals)").fetchall()
        task_foreign_keys = connection.execute("PRAGMA foreign_key_list(tasks)").fetchall()
        proposal_foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(action_proposals)"
        ).fetchall()
        task_indexes = connection.execute("PRAGMA index_list(tasks)").fetchall()
        proposal_indexes = connection.execute("PRAGMA index_list(action_proposals)").fetchall()
        state = connection.execute("PRAGMA integrity_check").fetchall()
        foreign_state = connection.execute("PRAGMA foreign_key_check").fetchall()

    assert [row[1] for row in task_columns] == [
        "task_id",
        "owner_principal_id",
        "source_item_id",
        "proposal_id",
        "title",
        "body_ref",
        "due_at",
        "status",
        "revision",
        "created_at",
        "updated_at",
        "completed_at",
    ]
    assert [row[1] for row in proposal_columns] == [
        "proposal_id",
        "run_id",
        "principal_id",
        "tool_id",
        "capability",
        "canonical_args_ref",
        "canonical_args_sha256",
        "display_sha256",
        "owner_intent_id",
        "status",
        "created_at",
        "expires_at",
        "credential_alias",
    ]
    assert {row[2] for row in task_foreign_keys} == {
        "principals",
        "source_items",
        "action_proposals",
    }
    assert {row[2] for row in proposal_foreign_keys} == {"runs", "principals"}
    assert {row[1] for row in task_indexes} >= {
        "tasks_status_due_at_idx",
        "tasks_proposal_id_unique_idx",
    }
    assert {row[1] for row in proposal_indexes} >= {"action_proposals_status_expires_at_idx"}
    task_index_flags = {str(row[1]): (int(row[2]), int(row[4])) for row in task_indexes}
    assert task_index_flags["tasks_proposal_id_unique_idx"] == (1, 1)
    assert state == [("ok",)] and foreign_state == []


def test_required_columns_and_sqlite_checks_reject_invalid_task_state(tmp_path: Path) -> None:
    database = tmp_path / "task-checks.sqlite3"
    initialize_storage(database, create=True)
    setup_local_task_operator(database)
    task = create_local_task(database, request_id=uuid4(), title="Valid task").task
    with database_connection(database) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE tasks SET status = 'DRAFT' WHERE task_id = ?", (str(task.task_id),)
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE tasks SET revision = 0 WHERE task_id = ?", (str(task.task_id),)
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO action_proposals
                   (proposal_id, run_id, principal_id, tool_id, capability,
                    canonical_args_ref, canonical_args_sha256, display_sha256,
                    owner_intent_id, status, created_at, expires_at, credential_alias)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL)""",
                (
                    str(uuid4()),
                    "missing-run",
                    str(LOCAL_TASK_OPERATOR_ID),
                    "synthetic",
                    "READ_ONLY",
                    "sha256:" + "a" * 64,
                    "a" * 64,
                    "b" * 64,
                    "PENDING",
                    "2026-11-04T00:00:00.000000Z",
                    "2026-11-05T00:00:00.000000Z",
                ),
            )


def test_tampered_cr1_j_artifact_is_rejected_before_upgrade(tmp_path: Path, monkeypatch) -> None:
    database = historical_prefix_database(tmp_path / "tampered-j.sqlite3", 3)
    before = migration_history(database)
    migration = migration_module.MIGRATIONS[-1]
    changed = Migration(
        migration.migration_id,
        (*migration.statements, "SELECT 1"),
        migration.schema_after,
    )
    monkeypatch.setattr(migration_module, "MIGRATIONS", (*migration_module.MIGRATIONS[:3], changed))
    with pytest.raises(MigrationIntegrityError, match="CR1-J migration artifact digest mismatch"):
        initialize_storage(database)
    assert migration_history(database) == before


@pytest.mark.parametrize("prefix_count", [1, 2, 3])
def test_historical_prefixes_upgrade_to_j_without_rewriting_records(
    tmp_path: Path, prefix_count: int
) -> None:
    database = historical_prefix_database(tmp_path / f"prefix-{prefix_count}.sqlite3", prefix_count)
    before = migration_history(database)
    expected_ids = tuple(m.migration_id for m in migration_module.MIGRATIONS[:prefix_count])
    assert tuple(row[0] for row in before) == expected_ids

    applied = initialize_storage(database)
    assert applied == tuple(m.migration_id for m in migration_module.MIGRATIONS[prefix_count:])
    after = migration_history(database)
    assert after[:prefix_count] == before
    assert tuple(row[0] for row in after) == tuple(
        m.migration_id for m in migration_module.MIGRATIONS
    )
    assert initialize_storage(database) == ()


def test_cr1_j_migration_failure_rolls_back_new_ddl_and_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sentinel.storage.migrations as migration_module

    database = historical_prefix_database(tmp_path / "rollback-j.sqlite3", 3)
    history_before = migration_history(database)
    with database_connection(database) as connection:
        objects_before = set(
            connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
        )

    def fail_integrity(_connection: sqlite3.Connection) -> None:
        raise MigrationIntegrityError("synthetic CR1-J migration failure")

    monkeypatch.setattr(migration_module, "verify_integrity", fail_integrity)
    with pytest.raises(MigrationIntegrityError, match="synthetic CR1-J migration failure"):
        initialize_storage(database)
    assert migration_history(database) == history_before
    with database_connection(database) as connection:
        objects_after = set(
            connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
        )
    assert objects_after == objects_before


def test_current_checkpoint_rejects_extra_schema_object(tmp_path: Path) -> None:
    database = tmp_path / "drift-j.sqlite3"
    initialize_storage(database, create=True)
    with database_connection(database) as connection:
        connection.execute("CREATE TABLE unauthorized_task_aux (value TEXT)")
    with readonly_database_connection(database) as connection:
        with pytest.raises(MigrationIntegrityError):
            inspect_migration_state_readonly(connection)


def test_doctor_and_writer_lease_do_not_apply_pending_task_migration(tmp_path: Path) -> None:
    database = historical_prefix_database(tmp_path / "pending-j.sqlite3", 3)
    before = migration_history(database)

    run_doctor(database)
    with acquire_writer_lease(database):
        pass

    assert migration_history(database) == before
    with database_connection(database) as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='tasks'"
            ).fetchone()
            is None
        )


def test_active_sqlite_transaction_blocks_task_migration_without_partial_ddl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = historical_prefix_database(tmp_path / "active-task-upgrade.sqlite3", 3)
    before = migration_history(database)
    with database_connection(database) as connection:
        objects_before = set(
            connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
        )

    @contextmanager
    def short_timeout_connection(
        target: str | Path, *, create: bool = False
    ) -> Iterator[sqlite3.Connection]:
        assert create is False
        connection = sqlite3.connect(target, timeout=0.02, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
        finally:
            connection.close()

    monkeypatch.setattr(migration_module, "database_connection", short_timeout_connection)
    with acquire_writer_lease(database) as lease:
        with lease.transaction():
            with pytest.raises(MigrationApplyError):
                initialize_storage(database)

    assert migration_history(database) == before
    with database_connection(database) as connection:
        objects_after = set(
            connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
        )
    assert objects_after == objects_before


def test_idle_writer_lease_does_not_arbitrate_task_migration(tmp_path: Path) -> None:
    database = historical_prefix_database(tmp_path / "idle-task-upgrade.sqlite3", 3)
    with acquire_writer_lease(database):
        # Maintenance is still able to migrate while a lease is open but idle.
        assert initialize_storage(database) == ("cr1-j-0004-local-tasks",)
    assert tuple(row[0] for row in migration_history(database)) == tuple(
        migration.migration_id for migration in migration_module.MIGRATIONS
    )
