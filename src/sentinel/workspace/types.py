"""Immutable, body-free public results for fixture-workspace orchestration."""

from dataclasses import dataclass
from enum import StrEnum


class FixtureWorkspaceStatus(StrEnum):
    READY = "READY"
    INCOMPLETE = "INCOMPLETE"


class FixtureGithubState(StrEnum):
    ABSENT = "ABSENT"
    LEGACY_COMPLETE = "LEGACY_COMPLETE"
    PROMOTED_COMPLETE = "PROMOTED_COMPLETE"


class FixtureWorkspaceComponent(StrEnum):
    PUBLIC_STORE = "PUBLIC_STORE"
    PUBLIC_BLOBS = "PUBLIC_BLOBS"
    GITHUB_INGESTION = "GITHUB_INGESTION"
    H1_PROMOTION = "H1_PROMOTION"
    TASK_OPERATOR = "TASK_OPERATOR"
    INCREMENTAL_CURSOR = "INCREMENTAL_CURSOR"


@dataclass(frozen=True, slots=True)
class FixtureWorkspaceState:
    status: FixtureWorkspaceStatus
    github_state: FixtureGithubState
    github_items: int
    github_citations: int
    public_blobs: int
    public_store_initialized: bool
    task_operator_ready: bool
    task_count: int
    cursor_generation: int | None
    cursor_status: str | None
    missing_components: tuple[FixtureWorkspaceComponent, ...]


class FixtureWorkspaceErrorCode(StrEnum):
    INVALID_PATH = "invalid_path"
    DATABASE_UNAVAILABLE = "database_unavailable"
    SCHEMA_NOT_CURRENT = "schema_not_current"
    STORE_INVALID = "store_invalid"
    GITHUB_STATE_INVALID = "github_state_invalid"
    OPERATOR_INVALID = "operator_invalid"
    CURSOR_INVALID = "cursor_invalid"
    OVERVIEW_INVALID = "overview_invalid"
    INTEGRITY_FAILURE = "integrity_failure"


_ERROR_MESSAGES = {
    FixtureWorkspaceErrorCode.INVALID_PATH: (
        "Explicit absolute database and store paths are required."
    ),
    FixtureWorkspaceErrorCode.DATABASE_UNAVAILABLE: (
        "The selected Sentinel database is unavailable."
    ),
    FixtureWorkspaceErrorCode.SCHEMA_NOT_CURRENT: (
        "The database does not have the current registered schema."
    ),
    FixtureWorkspaceErrorCode.STORE_INVALID: "The PUBLIC fixture store is unavailable or invalid.",
    FixtureWorkspaceErrorCode.GITHUB_STATE_INVALID: (
        "Synthetic GitHub fixture state conflicts with the expected workspace."
    ),
    FixtureWorkspaceErrorCode.OPERATOR_INVALID: (
        "The local task operator state is unavailable or conflicting."
    ),
    FixtureWorkspaceErrorCode.CURSOR_INVALID: (
        "The synthetic fixture cursor state is unavailable or conflicting."
    ),
    FixtureWorkspaceErrorCode.OVERVIEW_INVALID: (
        "The verified local overview could not be constructed."
    ),
    FixtureWorkspaceErrorCode.INTEGRITY_FAILURE: "Workspace integrity verification failed.",
}


class FixtureWorkspaceError(RuntimeError):
    """Fixed-message workspace failure without paths or source content."""

    def __init__(self, code: FixtureWorkspaceErrorCode) -> None:
        if type(code) is not FixtureWorkspaceErrorCode:
            raise TypeError("workspace error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


class FixtureWorkspacePrepareDisposition(StrEnum):
    PREPARED = "PREPARED"
    ALREADY_PREPARED = "ALREADY_PREPARED"


@dataclass(frozen=True, slots=True)
class FixtureWorkspacePrepareReport:
    disposition: FixtureWorkspacePrepareDisposition
    state: FixtureWorkspaceState


@dataclass(frozen=True, slots=True)
class FixtureWorkspaceVerification:
    state: FixtureWorkspaceState
