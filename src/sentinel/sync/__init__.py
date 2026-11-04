"""Synthetic incremental synchronization APIs."""

from sentinel.sync.github_fixture import (
    advance_incremental_github_fixture,
    read_incremental_github_fixture_state,
    setup_incremental_github_fixture,
)
from sentinel.sync.types import (
    FixtureSyncAdvanceReport,
    FixtureSyncAdvanceResult,
    FixtureSyncCursorStatus,
    FixtureSyncError,
    FixtureSyncErrorCode,
    IncrementalGithubFixtureState,
)

__all__ = [
    "FixtureSyncAdvanceReport",
    "FixtureSyncAdvanceResult",
    "FixtureSyncCursorStatus",
    "FixtureSyncError",
    "FixtureSyncErrorCode",
    "IncrementalGithubFixtureState",
    "advance_incremental_github_fixture",
    "read_incremental_github_fixture_state",
    "setup_incremental_github_fixture",
]
