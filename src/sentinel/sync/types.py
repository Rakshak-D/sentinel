"""Typed public results for the fixed incremental fixture replay."""

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class FixtureSyncErrorCode(StrEnum):
    INVALID_INPUT = "invalid_input"
    INVALID_PATH = "invalid_path"
    DATABASE_UNAVAILABLE = "database_unavailable"
    SCHEMA_NOT_CURRENT = "schema_not_current"
    INTEGRITY_FAILURE = "integrity_failure"
    WRITER_UNAVAILABLE = "writer_unavailable"
    FIXTURE_INVALID = "fixture_invalid"
    BLOB_UNAVAILABLE = "blob_unavailable"
    BLOB_INVALID = "blob_invalid"
    SOURCE_CONFLICT = "source_conflict"
    CURSOR_CONFLICT = "cursor_conflict"
    ITEM_CONFLICT = "item_conflict"
    SPAN_CONFLICT = "span_conflict"
    PERSISTENCE_FAILURE = "persistence_failure"


_ERROR_MESSAGES = {
    FixtureSyncErrorCode.INVALID_INPUT: "Synthetic fixture synchronization input is invalid.",
    FixtureSyncErrorCode.INVALID_PATH: "Explicit absolute database and store paths are required.",
    FixtureSyncErrorCode.DATABASE_UNAVAILABLE: "The selected Sentinel database is unavailable.",
    FixtureSyncErrorCode.SCHEMA_NOT_CURRENT: (
        "The database does not have the current registered Sentinel schema."
    ),
    FixtureSyncErrorCode.INTEGRITY_FAILURE: (
        "The selected Sentinel database failed integrity verification."
    ),
    FixtureSyncErrorCode.WRITER_UNAVAILABLE: (
        "Cooperating Sentinel writer ownership is unavailable."
    ),
    FixtureSyncErrorCode.FIXTURE_INVALID: (
        "The pinned synthetic GitHub fixture could not be verified."
    ),
    FixtureSyncErrorCode.BLOB_UNAVAILABLE: "A required PUBLIC fixture blob is unavailable.",
    FixtureSyncErrorCode.BLOB_INVALID: "A required PUBLIC fixture blob failed verification.",
    FixtureSyncErrorCode.SOURCE_CONFLICT: (
        "Synthetic incremental source registration conflicts with stored metadata."
    ),
    FixtureSyncErrorCode.CURSOR_CONFLICT: (
        "Synthetic incremental cursor state conflicts with the expected sequence."
    ),
    FixtureSyncErrorCode.ITEM_CONFLICT: (
        "Synthetic incremental item state conflicts with the expected fixture page."
    ),
    FixtureSyncErrorCode.SPAN_CONFLICT: (
        "Synthetic incremental citation state conflicts with the expected fixture page."
    ),
    FixtureSyncErrorCode.PERSISTENCE_FAILURE: (
        "Synthetic incremental page operation failed and was rolled back."
    ),
}


class FixtureSyncError(RuntimeError):
    """Fixed-message error with no database path, SQL or fixture text."""

    def __init__(self, code: FixtureSyncErrorCode) -> None:
        if type(code) is not FixtureSyncErrorCode:
            raise TypeError("fixture sync error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


class FixtureSyncAdvanceResult(StrEnum):
    APPLIED = "APPLIED"
    ALREADY_APPLIED = "ALREADY_APPLIED"
    COMPLETE = "COMPLETE"
    STALE = "STALE"
    OUT_OF_ORDER = "OUT_OF_ORDER"


class FixtureSyncCursorStatus(StrEnum):
    READY = "READY"
    COMPLETE = "COMPLETE"


@dataclass(frozen=True, slots=True)
class IncrementalGithubFixtureState:
    source_id: UUID
    cursor_id: UUID
    generation: int
    completed_pages: int
    total_pages: int
    item_count: int
    span_count: int
    cursor_status: FixtureSyncCursorStatus
    fixture_version: str
    fixture_sha256: str


@dataclass(frozen=True, slots=True)
class FixtureSyncAdvanceReport:
    result: FixtureSyncAdvanceResult
    state: IncrementalGithubFixtureState


__all__ = [
    "FixtureSyncAdvanceReport",
    "FixtureSyncAdvanceResult",
    "FixtureSyncCursorStatus",
    "FixtureSyncError",
    "FixtureSyncErrorCode",
    "IncrementalGithubFixtureState",
]
