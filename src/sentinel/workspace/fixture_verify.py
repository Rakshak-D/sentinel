"""Read-only validation of the explicitly selected synthetic workspace."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Final, NoReturn

from sentinel.content import (
    PublicFixtureStoreError,
    PublicFixtureStoreErrorCode,
    read_public_fixture_blob,
)
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.ingestion.blob_readback import read_blob_backed_github_fixture
from sentinel.ingestion.github_fixture import read_persisted_github_fixture
from sentinel.ingestion.types import (
    GithubBlobIntegrationError,
    GithubBlobIntegrationErrorCode,
    GithubFixtureIngestionError,
)
from sentinel.overview import OverviewError, build_local_overview
from sentinel.storage.connection import DatabaseOpenError, readonly_database_connection
from sentinel.storage.migrations import (
    MIGRATIONS,
    MigrationIntegrityError,
    inspect_migration_state_readonly,
    verify_integrity,
)
from sentinel.storage.schema import SchemaIntegrityError
from sentinel.sync import (
    FixtureSyncError,
    IncrementalGithubFixtureState,
    read_incremental_github_fixture_state,
)
from sentinel.sync.github_fixture import INCREMENTAL_CURSOR_ID, INCREMENTAL_SOURCE_ID
from sentinel.tasks import TaskStoreError, TaskStoreErrorCode, list_local_tasks
from sentinel.workspace.types import (
    FixtureGithubState,
    FixtureWorkspaceComponent,
    FixtureWorkspaceError,
    FixtureWorkspaceErrorCode,
    FixtureWorkspaceState,
    FixtureWorkspaceStatus,
    FixtureWorkspaceVerification,
)

_FIXED_AS_OF: Final = datetime(2026, 11, 5, 18, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))


@dataclass(frozen=True, slots=True)
class _Evaluation:
    state: FixtureWorkspaceState
    store_ready: bool
    github_state: FixtureGithubState
    cursor_ready: bool


def _fail(code: FixtureWorkspaceErrorCode) -> NoReturn:
    raise FixtureWorkspaceError(code)


def _selected_path(value: object, *, database: bool) -> Path:
    if isinstance(value, Path):
        path = value
    elif type(value) is str:
        path = Path(value)
    else:
        _fail(FixtureWorkspaceErrorCode.INVALID_PATH)
    if not path.is_absolute():
        _fail(FixtureWorkspaceErrorCode.INVALID_PATH)
    if database and not path.is_file():
        _fail(FixtureWorkspaceErrorCode.DATABASE_UNAVAILABLE)
    return path


def _probe_database(database: Path) -> tuple[bool, bool, bool, int]:
    expected_ids = tuple(migration.migration_id for migration in MIGRATIONS)
    if len(expected_ids) != 4:
        _fail(FixtureWorkspaceErrorCode.INTEGRITY_FAILURE)
    try:
        with readonly_database_connection(database) as connection:
            state = inspect_migration_state_readonly(connection)
            if not state.is_current or state.applied_migration_ids != expected_ids:
                _fail(FixtureWorkspaceErrorCode.SCHEMA_NOT_CURRENT)
            try:
                verify_integrity(connection)
            except (MigrationIntegrityError, sqlite3.Error):
                _fail(FixtureWorkspaceErrorCode.INTEGRITY_FAILURE)
            source_present = (
                connection.execute(
                    "SELECT 1 FROM sources WHERE source_id = ?",
                    (str(EXPECTED_MANIFEST.source_row[0]),),
                ).fetchone()
                is not None
            )
            sync_source_present = (
                connection.execute(
                    "SELECT 1 FROM sources WHERE source_id = ?",
                    (str(INCREMENTAL_SOURCE_ID),),
                ).fetchone()
                is not None
            )
            cursor_present = (
                connection.execute(
                    "SELECT 1 FROM sync_cursors WHERE cursor_id = ?",
                    (str(INCREMENTAL_CURSOR_ID),),
                ).fetchone()
                is not None
            )
            incremental_item_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM source_items WHERE source_id = ?",
                    (str(INCREMENTAL_SOURCE_ID),),
                ).fetchone()[0]
            )
            if sync_source_present != cursor_present:
                _fail(FixtureWorkspaceErrorCode.CURSOR_INVALID)
            return source_present, sync_source_present, cursor_present, incremental_item_count
    except FixtureWorkspaceError:
        raise
    except DatabaseOpenError:
        _fail(FixtureWorkspaceErrorCode.DATABASE_UNAVAILABLE)
    except (MigrationIntegrityError, SchemaIntegrityError):
        _fail(FixtureWorkspaceErrorCode.SCHEMA_NOT_CURRENT)
    except Exception:
        _fail(FixtureWorkspaceErrorCode.INTEGRITY_FAILURE)


def _detect_github_state(
    database: Path,
    store_root: Path,
    source_present: bool,
) -> tuple[FixtureGithubState, int, int]:
    try:
        promoted = read_blob_backed_github_fixture(database, store_root=store_root)
    except GithubBlobIntegrationError as promoted_error:
        if (
            promoted_error.code is GithubBlobIntegrationErrorCode.REGISTRATION_CONFLICT
            and not source_present
        ):
            return FixtureGithubState.ABSENT, 0, 0
        if (
            promoted_error.code is not GithubBlobIntegrationErrorCode.CONTENT_REF_INVALID
            or not source_present
        ):
            if promoted_error.code in {
                GithubBlobIntegrationErrorCode.BLOB_UNAVAILABLE,
                GithubBlobIntegrationErrorCode.BLOB_INVALID,
            }:
                _fail(FixtureWorkspaceErrorCode.STORE_INVALID)
            _fail(FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID)
        try:
            legacy = read_persisted_github_fixture(database)
        except GithubFixtureIngestionError:
            _fail(FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID)
        if (
            legacy.fixture_sha256 != EXPECTED_MANIFEST.fixture_sha256
            or len(legacy.items) != 3
            or sum(len(item.spans) for item in legacy.items) != 9
        ):
            _fail(FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID)
        return FixtureGithubState.LEGACY_COMPLETE, len(legacy.items), 9

    if (
        not source_present
        or promoted.fixture_sha256 != EXPECTED_MANIFEST.fixture_sha256
        or promoted.manifest_sha256 != EXPECTED_MANIFEST.sha256
        or len(promoted.items) != 3
        or sum(len(item.spans) for item in promoted.items) != 9
    ):
        _fail(FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID)
    return FixtureGithubState.PROMOTED_COMPLETE, len(promoted.items), 9


def _inspect_blobs(store_root: Path) -> tuple[bool, int, bool]:
    try:
        if store_root.is_symlink():
            _fail(FixtureWorkspaceErrorCode.STORE_INVALID)
    except FixtureWorkspaceError:
        raise
    except OSError:
        _fail(FixtureWorkspaceErrorCode.STORE_INVALID)

    initialized = True
    valid = 0
    for item in EXPECTED_MANIFEST.items:
        try:
            read_public_fixture_blob(store_root, content_sha256=item.content_sha256)
            valid += 1
        except PublicFixtureStoreError as error:
            if error.code is PublicFixtureStoreErrorCode.STORE_UNINITIALIZED:
                initialized = False
                break
            if error.code is PublicFixtureStoreErrorCode.BLOB_NOT_FOUND:
                continue
            if error.code in {
                PublicFixtureStoreErrorCode.INVALID_ROOT,
                PublicFixtureStoreErrorCode.UNSUPPORTED_FILESYSTEM,
                PublicFixtureStoreErrorCode.STORE_INVALID,
                PublicFixtureStoreErrorCode.BLOB_INVALID,
                PublicFixtureStoreErrorCode.FIXTURE_INVALID,
            }:
                _fail(FixtureWorkspaceErrorCode.STORE_INVALID)
            _fail(FixtureWorkspaceErrorCode.STORE_INVALID)
    return initialized, valid, initialized and valid == 3


def _read_operator(database: Path) -> tuple[bool, int]:
    try:
        return True, len(list_local_tasks(database))
    except TaskStoreError as error:
        if error.code is TaskStoreErrorCode.OPERATOR_NOT_INITIALIZED:
            return False, 0
        _fail(FixtureWorkspaceErrorCode.OPERATOR_INVALID)
    except Exception:
        _fail(FixtureWorkspaceErrorCode.OPERATOR_INVALID)


def _read_cursor(
    database: Path,
    store_root: Path,
    sync_source_present: bool,
    cursor_present: bool,
    github_state: FixtureGithubState,
    incremental_item_count: int,
) -> IncrementalGithubFixtureState | None:
    if not sync_source_present and not cursor_present:
        if incremental_item_count != 0:
            _fail(FixtureWorkspaceErrorCode.CURSOR_INVALID)
        return None
    if github_state is not FixtureGithubState.PROMOTED_COMPLETE:
        _fail(FixtureWorkspaceErrorCode.CURSOR_INVALID)
    try:
        return read_incremental_github_fixture_state(database, store_root=store_root)
    except FixtureSyncError:
        _fail(FixtureWorkspaceErrorCode.CURSOR_INVALID)
    except Exception:
        _fail(FixtureWorkspaceErrorCode.CURSOR_INVALID)


def _evaluate_workspace(database_arg: str | Path, store_arg: str | Path) -> _Evaluation:
    database = _selected_path(database_arg, database=True)
    store_root = _selected_path(store_arg, database=False)
    source_present, sync_source_present, cursor_present, incremental_item_count = _probe_database(
        database
    )
    github_state, item_count, citation_count = _detect_github_state(
        database, store_root, source_present
    )
    if github_state is not FixtureGithubState.PROMOTED_COMPLETE and sync_source_present:
        _fail(FixtureWorkspaceErrorCode.CURSOR_INVALID)

    if github_state is FixtureGithubState.PROMOTED_COMPLETE:
        store_initialized, blob_count, store_ready = True, 3, True
    else:
        store_initialized, blob_count, store_ready = _inspect_blobs(store_root)

    operator_ready, task_count = _read_operator(database)
    cursor = _read_cursor(
        database,
        store_root,
        sync_source_present,
        cursor_present,
        github_state,
        incremental_item_count,
    )

    missing: list[FixtureWorkspaceComponent] = []
    if not store_initialized:
        missing.append(FixtureWorkspaceComponent.PUBLIC_STORE)
    elif not store_ready:
        missing.append(FixtureWorkspaceComponent.PUBLIC_BLOBS)
    if github_state is FixtureGithubState.ABSENT:
        missing.extend(
            (
                FixtureWorkspaceComponent.GITHUB_INGESTION,
                FixtureWorkspaceComponent.H1_PROMOTION,
            )
        )
    elif github_state is FixtureGithubState.LEGACY_COMPLETE:
        missing.append(FixtureWorkspaceComponent.H1_PROMOTION)
    if not operator_ready:
        missing.append(FixtureWorkspaceComponent.TASK_OPERATOR)
    if cursor is None:
        missing.append(FixtureWorkspaceComponent.INCREMENTAL_CURSOR)

    ready = not missing and github_state is FixtureGithubState.PROMOTED_COMPLETE
    if ready:
        try:
            build_local_overview(
                database,
                store_root=store_root,
                as_of=_FIXED_AS_OF,
            )
        except OverviewError:
            _fail(FixtureWorkspaceErrorCode.OVERVIEW_INVALID)
        except Exception:
            _fail(FixtureWorkspaceErrorCode.OVERVIEW_INVALID)

    state = FixtureWorkspaceState(
        status=FixtureWorkspaceStatus.READY if ready else FixtureWorkspaceStatus.INCOMPLETE,
        github_state=github_state,
        github_items=item_count,
        github_citations=citation_count,
        public_blobs=blob_count,
        public_store_initialized=store_initialized,
        task_operator_ready=operator_ready,
        task_count=task_count,
        cursor_generation=None if cursor is None else cursor.generation,
        cursor_status=None if cursor is None else cursor.cursor_status.value,
        missing_components=tuple(missing),
    )
    return _Evaluation(
        state=state,
        store_ready=store_ready,
        github_state=github_state,
        cursor_ready=cursor is not None,
    )


def verify_fixture_workspace(
    database: str | Path,
    *,
    store_root: str | Path,
) -> FixtureWorkspaceVerification:
    """Verify schema, H1 data, blobs, operator, cursor and overview read-only."""

    evaluation = _evaluate_workspace(database, store_root)
    return FixtureWorkspaceVerification(state=evaluation.state)


__all__ = ["verify_fixture_workspace"]
