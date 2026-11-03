"""Immutable results and bounded errors for synthetic source fixtures."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from sentinel.normalization.types import NormalizedPlainTextSource, SourceBoundCitation


class GithubFixtureErrorCode(StrEnum):
    """Non-sensitive error categories for the packaged issue fixture reader."""

    FIXTURE_UNAVAILABLE = "fixture_unavailable"
    FIXTURE_HASH_MISMATCH = "fixture_hash_mismatch"
    INVALID_FIXTURE = "invalid_fixture"
    INVALID_OBSERVED_AT = "invalid_observed_at"
    INVALID_SOURCE = "invalid_source"
    INVALID_CITATION = "invalid_citation"


_ERROR_MESSAGES = {
    GithubFixtureErrorCode.FIXTURE_UNAVAILABLE: "The packaged issue fixture is unavailable.",
    GithubFixtureErrorCode.FIXTURE_HASH_MISMATCH: (
        "The packaged issue fixture failed integrity verification."
    ),
    GithubFixtureErrorCode.INVALID_FIXTURE: "The synthetic issue fixture is invalid.",
    GithubFixtureErrorCode.INVALID_OBSERVED_AT: "The trusted observation timestamp is invalid.",
    GithubFixtureErrorCode.INVALID_SOURCE: "A synthetic issue source is invalid.",
    GithubFixtureErrorCode.INVALID_CITATION: "A synthetic issue citation is invalid.",
}


class GithubFixtureError(ValueError):
    """Fixed-message reader failure that does not expose fixture values."""

    def __init__(self, code: GithubFixtureErrorCode) -> None:
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class GithubFixtureIssue:
    """Fictional provider metadata kept beside, not inside, normalized body text."""

    repository: str
    issue_number: int
    updated_at: datetime
    title: str
    normalized_source: NormalizedPlainTextSource
    citations: tuple[SourceBoundCitation, ...]

    @property
    def source_id(self) -> UUID:
        return self.normalized_source.envelope.source_id

    @property
    def body_text(self) -> str:
        """Explicit internal access to the exact decoded body text."""

        return self.normalized_source.text


@dataclass(frozen=True, slots=True)
class GithubFixtureRead:
    """Immutable result for the fixed versioned package fixture."""

    fixture_version: str
    fixture_sha256: str
    issues: tuple[GithubFixtureIssue, ...]
