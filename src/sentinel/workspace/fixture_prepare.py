"""State-aware preparation of the bounded offline synthetic workspace."""

from __future__ import annotations

from pathlib import Path
from typing import NoReturn

from sentinel.content import (
    PublicFixtureStoreError,
    PublicFixtureStoreErrorCode,
    initialize_public_fixture_store,
    store_packaged_github_public_bodies,
)
from sentinel.ingestion.blob_promotion import promote_github_fixture_to_public_blobs
from sentinel.ingestion.github_fixture import ingest_packaged_github_fixture
from sentinel.ingestion.types import (
    GithubBlobIntegrationError,
    GithubBlobIntegrationErrorCode,
    GithubFixtureIngestionError,
    GithubFixtureIngestionErrorCode,
)
from sentinel.sync import (
    FixtureSyncError,
    setup_incremental_github_fixture,
)
from sentinel.tasks import TaskStoreError, setup_local_task_operator
from sentinel.workspace.fixture_verify import _evaluate_workspace
from sentinel.workspace.types import (
    FixtureGithubState,
    FixtureWorkspaceError,
    FixtureWorkspaceErrorCode,
    FixtureWorkspacePrepareDisposition,
    FixtureWorkspacePrepareReport,
    FixtureWorkspaceStatus,
)


def _raise(code: FixtureWorkspaceErrorCode) -> NoReturn:
    raise FixtureWorkspaceError(code)


def _map_store_error(error: PublicFixtureStoreError) -> NoReturn:
    if error.code in {
        PublicFixtureStoreErrorCode.INVALID_ROOT,
        PublicFixtureStoreErrorCode.UNSUPPORTED_FILESYSTEM,
    }:
        _raise(FixtureWorkspaceErrorCode.INVALID_PATH)
    _raise(FixtureWorkspaceErrorCode.STORE_INVALID)


def _map_ingestion_error(error: GithubFixtureIngestionError) -> NoReturn:
    if error.code is GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT:
        _raise(FixtureWorkspaceErrorCode.SCHEMA_NOT_CURRENT)
    if error.code in {
        GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE,
        GithubFixtureIngestionErrorCode.INVALID_PATH,
    }:
        _raise(FixtureWorkspaceErrorCode.DATABASE_UNAVAILABLE)
    _raise(FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID)


def _map_promotion_error(error: GithubBlobIntegrationError) -> NoReturn:
    if error.code is GithubBlobIntegrationErrorCode.SCHEMA_NOT_CURRENT:
        _raise(FixtureWorkspaceErrorCode.SCHEMA_NOT_CURRENT)
    if error.code in {
        GithubBlobIntegrationErrorCode.DATABASE_UNAVAILABLE,
        GithubBlobIntegrationErrorCode.INVALID_PATH,
    }:
        _raise(FixtureWorkspaceErrorCode.DATABASE_UNAVAILABLE)
    if error.code in {
        GithubBlobIntegrationErrorCode.BLOB_UNAVAILABLE,
        GithubBlobIntegrationErrorCode.BLOB_INVALID,
    }:
        _raise(FixtureWorkspaceErrorCode.STORE_INVALID)
    _raise(FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID)


def prepare_fixture_workspace(
    database: str | Path,
    *,
    store_root: str | Path,
) -> FixtureWorkspacePrepareReport:
    """Prepare recognized stages using existing, independently verified APIs.

    Every component retains its existing transaction/publication boundary. A
    failure can leave earlier valid stages committed; retry recognizes them and
    continues without resetting tasks or cursor progress.
    """

    evaluation = _evaluate_workspace(database, store_root)
    if evaluation.state.status is FixtureWorkspaceStatus.READY:
        return FixtureWorkspacePrepareReport(
            disposition=FixtureWorkspacePrepareDisposition.ALREADY_PREPARED,
            state=evaluation.state,
        )

    current = evaluation
    if current.github_state in {
        FixtureGithubState.ABSENT,
        FixtureGithubState.LEGACY_COMPLETE,
    }:
        if not current.state.public_store_initialized:
            try:
                initialize_public_fixture_store(store_root)
            except PublicFixtureStoreError as error:
                _map_store_error(error)
        if current.state.public_blobs != 3:
            try:
                report = store_packaged_github_public_bodies(store_root)
            except PublicFixtureStoreError as error:
                _map_store_error(error)
            if report.inserted_count + report.existing_count != 3 or len(report.blobs) != 3:
                _raise(FixtureWorkspaceErrorCode.STORE_INVALID)

        # Re-read complete source state after filesystem publication. A
        # concurrent preparer may already have ingested or promoted the rows;
        # never invoke legacy ingestion based only on a stale initial probe.
        current = _evaluate_workspace(database, store_root)
        if (
            evaluation.github_state is FixtureGithubState.LEGACY_COMPLETE
            and current.github_state is FixtureGithubState.ABSENT
        ):
            _raise(FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID)

        if (
            evaluation.github_state is FixtureGithubState.ABSENT
            and current.github_state is FixtureGithubState.ABSENT
        ):
            try:
                ingest_packaged_github_fixture(database)
            except GithubFixtureIngestionError as error:
                _map_ingestion_error(error)
            current = _evaluate_workspace(database, store_root)

        if current.github_state is FixtureGithubState.LEGACY_COMPLETE:
            if current.state.public_blobs != 3:
                try:
                    report = store_packaged_github_public_bodies(store_root)
                except PublicFixtureStoreError as error:
                    _map_store_error(error)
                if report.inserted_count + report.existing_count != 3 or len(report.blobs) != 3:
                    _raise(FixtureWorkspaceErrorCode.STORE_INVALID)
                current = _evaluate_workspace(database, store_root)
            if current.github_state is not FixtureGithubState.LEGACY_COMPLETE:
                if current.github_state is not FixtureGithubState.PROMOTED_COMPLETE:
                    _raise(FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID)
            else:
                try:
                    promote_github_fixture_to_public_blobs(database, store_root=store_root)
                except GithubBlobIntegrationError as error:
                    _map_promotion_error(error)
                current = _evaluate_workspace(database, store_root)

        if current.github_state is FixtureGithubState.ABSENT:
            _raise(FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID)

    if not current.state.task_operator_ready:
        try:
            setup_local_task_operator(database)
        except TaskStoreError:
            _raise(FixtureWorkspaceErrorCode.OPERATOR_INVALID)

    if not current.cursor_ready:
        try:
            setup_incremental_github_fixture(database, store_root=store_root)
        except FixtureSyncError:
            _raise(FixtureWorkspaceErrorCode.CURSOR_INVALID)

    final_evaluation = _evaluate_workspace(database, store_root)
    if final_evaluation.state.status is not FixtureWorkspaceStatus.READY:
        _raise(FixtureWorkspaceErrorCode.INTEGRITY_FAILURE)
    return FixtureWorkspacePrepareReport(
        disposition=FixtureWorkspacePrepareDisposition.PREPARED,
        state=final_evaluation.state,
    )


__all__ = ["prepare_fixture_workspace"]
