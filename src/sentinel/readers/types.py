"""Immutable results and bounded errors for synthetic source fixtures."""

from dataclasses import dataclass, field
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


class GmailFixtureErrorCode(StrEnum):
    """Fixed, non-sensitive error categories for the synthetic Gmail reader."""

    FIXTURE_UNAVAILABLE = "fixture_unavailable"
    FIXTURE_HASH_MISMATCH = "fixture_hash_mismatch"
    INVALID_FIXTURE = "invalid_fixture"
    INVALID_BASE64URL = "invalid_base64url"
    INVALID_BODY = "invalid_body"
    INVALID_OBSERVED_AT = "invalid_observed_at"
    INVALID_CITATION = "invalid_citation"


_GMAIL_ERROR_MESSAGES = {
    GmailFixtureErrorCode.FIXTURE_UNAVAILABLE: "The packaged Gmail fixture is unavailable.",
    GmailFixtureErrorCode.FIXTURE_HASH_MISMATCH: (
        "The packaged Gmail fixture failed integrity verification."
    ),
    GmailFixtureErrorCode.INVALID_FIXTURE: "The synthetic Gmail fixture is invalid.",
    GmailFixtureErrorCode.INVALID_BASE64URL: "A synthetic message body encoding is invalid.",
    GmailFixtureErrorCode.INVALID_BODY: "A synthetic message body is invalid.",
    GmailFixtureErrorCode.INVALID_OBSERVED_AT: "The trusted observation timestamp is invalid.",
    GmailFixtureErrorCode.INVALID_CITATION: "A synthetic message citation is invalid.",
}


class GmailFixtureError(ValueError):
    """Bounded public error that never includes mail metadata or body content."""

    def __init__(self, code: GmailFixtureErrorCode) -> None:
        self.code = code
        super().__init__(_GMAIL_ERROR_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class GmailFixtureMessage:
    """Immutable message result; mail subject and normalized content stay out of repr."""

    mailbox_alias: str
    message_id: str
    thread_id: str
    internal_date: datetime
    subject: str = field(repr=False)
    normalized_source: NormalizedPlainTextSource = field(repr=False)
    citations: tuple[SourceBoundCitation, ...]

    @property
    def source_id(self) -> UUID:
        return self.normalized_source.envelope.source_id

    @property
    def body_text(self) -> str:
        """Explicit access to decoded body text for trusted internal callers."""

        return self.normalized_source.text

    @property
    def body_bytes(self) -> bytes:
        """Explicit access to the original decoded body bytes."""

        return self.normalized_source.original_bytes


@dataclass(frozen=True, slots=True)
class GmailFixtureRead:
    """Immutable read result for the single pinned synthetic Gmail collection."""

    mailbox_alias: str
    fixture_version: str
    fixture_sha256: str
    messages: tuple[GmailFixtureMessage, ...]
