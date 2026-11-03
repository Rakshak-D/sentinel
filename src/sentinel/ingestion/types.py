"""Immutable, body-free results for the synthetic GitHub ingestion API."""

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class GithubFixtureIngestionErrorCode(StrEnum):
    """Bounded public error categories that never include paths or content."""

    INVALID_PATH = "invalid_path"
    DATABASE_UNAVAILABLE = "database_unavailable"
    WRITER_UNAVAILABLE = "writer_unavailable"
    SCHEMA_NOT_CURRENT = "schema_not_current"
    INTEGRITY_FAILURE = "integrity_failure"
    FIXTURE_INVALID = "fixture_invalid"
    REGISTRATION_CONFLICT = "registration_conflict"
    ITEM_CONFLICT = "item_conflict"
    SPAN_CONFLICT = "span_conflict"
    PERSISTENCE_FAILURE = "persistence_failure"
    CONTENT_UNAVAILABLE = "content_unavailable"
    MULTIPLE_HARD_LINKS = "multiple_hard_links"


_ERROR_MESSAGES = {
    GithubFixtureIngestionErrorCode.INVALID_PATH: (
        "An explicit absolute Sentinel database path is required."
    ),
    GithubFixtureIngestionErrorCode.DATABASE_UNAVAILABLE: (
        "The selected Sentinel database is unavailable."
    ),
    GithubFixtureIngestionErrorCode.WRITER_UNAVAILABLE: (
        "Cooperating Sentinel writer ownership is unavailable."
    ),
    GithubFixtureIngestionErrorCode.SCHEMA_NOT_CURRENT: (
        "The database does not have the current registered Sentinel schema."
    ),
    GithubFixtureIngestionErrorCode.INTEGRITY_FAILURE: (
        "The selected Sentinel database failed integrity verification."
    ),
    GithubFixtureIngestionErrorCode.FIXTURE_INVALID: (
        "The pinned synthetic GitHub fixture could not be verified."
    ),
    GithubFixtureIngestionErrorCode.REGISTRATION_CONFLICT: (
        "Synthetic GitHub source registration conflicts with stored metadata."
    ),
    GithubFixtureIngestionErrorCode.ITEM_CONFLICT: (
        "Synthetic GitHub item metadata conflicts with stored data."
    ),
    GithubFixtureIngestionErrorCode.SPAN_CONFLICT: (
        "Synthetic GitHub citation metadata conflicts with stored data."
    ),
    GithubFixtureIngestionErrorCode.PERSISTENCE_FAILURE: (
        "Synthetic GitHub fixture ingestion failed and was rolled back."
    ),
    GithubFixtureIngestionErrorCode.CONTENT_UNAVAILABLE: (
        "Pinned synthetic source content is unavailable for verification."
    ),
    GithubFixtureIngestionErrorCode.MULTIPLE_HARD_LINKS: (
        "Database paths with multiple hard links are not supported for this operation."
    ),
}


class GithubFixtureIngestionError(RuntimeError):
    """Fixed-message persistence error with no raw SQLite or path details."""

    def __init__(self, code: GithubFixtureIngestionErrorCode) -> None:
        if type(code) is not GithubFixtureIngestionErrorCode:
            raise TypeError("ingestion error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class PersistedGithubSpan:
    """Persisted citation identity and byte metadata, never cited text."""

    span_id: UUID
    in_memory_span_id: UUID
    start_byte: int
    end_byte: int
    text_sha256: str


@dataclass(frozen=True, slots=True)
class PersistedGithubItem:
    """Persisted revision metadata; source body bytes are intentionally absent."""

    item_id: UUID
    provider_item_id: str
    source_envelope_id: UUID
    content_sha256: str
    spans: tuple[PersistedGithubSpan, ...]


@dataclass(frozen=True, slots=True)
class GithubFixtureIngestionReport:
    """Deterministic per-call insertion counts and fixed source provenance."""

    registry_source_id: UUID
    fixture_sha256: str
    inserted_items: int
    existing_items: int
    inserted_spans: int
    existing_spans: int
    items: tuple[PersistedGithubItem, ...]


@dataclass(frozen=True, slots=True)
class PersistedGithubFixture:
    """Body-free result of restart-time verification against the pinned fixture."""

    registry_source_id: UUID
    fixture_version: str
    fixture_sha256: str
    items: tuple[PersistedGithubItem, ...]
