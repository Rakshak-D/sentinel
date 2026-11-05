"""Immutable, body-conscious types for bounded job-alert extraction."""

from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization.types import NormalizedPlainTextSource, SourceBoundCitation


class JobAlertStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    INCOMPLETE = "INCOMPLETE"
    AMBIGUOUS = "AMBIGUOUS"
    NO_MATCH = "NO_MATCH"


class JobAlertFieldName(StrEnum):
    COMPANY = "company"
    ROLE = "role"
    LOCATION = "location"
    APPLICATION_URL = "application_url"
    DEADLINE = "deadline"


class JobAlertFieldState(StrEnum):
    PRESENT = "present"
    MISSING = "missing"
    INVALID = "invalid"
    AMBIGUOUS = "ambiguous"


class JobAlertErrorCode(StrEnum):
    INVALID_SOURCE = "invalid_source"
    SOURCE_TOO_LARGE = "source_too_large"
    INPUT_TOO_COMPLEX = "input_too_complex"
    INVALID_CITATION = "invalid_citation"


_ERROR_MESSAGES = {
    JobAlertErrorCode.INVALID_SOURCE: "The selected job-alert source could not be verified.",
    JobAlertErrorCode.SOURCE_TOO_LARGE: "The job-alert source exceeds the 64 KiB parsing limit.",
    JobAlertErrorCode.INPUT_TOO_COMPLEX: "The job-alert source exceeds a parsing bound.",
    JobAlertErrorCode.INVALID_CITATION: "An extracted field citation could not be verified.",
}


class JobAlertError(ValueError):
    """Fixed-message failure that never includes source text or path details."""

    def __init__(self, code: JobAlertErrorCode) -> None:
        if type(code) is not JobAlertErrorCode:
            raise TypeError("job-alert error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class JobAlertEvidence:
    field_id: JobAlertFieldName
    source_id: UUID
    content_sha256: str
    span_id: UUID
    start_byte: int
    end_byte: int
    text_sha256: str
    bound_citation: SourceBoundCitation


@dataclass(frozen=True, slots=True)
class JobAlertField:
    field_id: JobAlertFieldName
    state: JobAlertFieldState
    value: str | None = field(default=None, repr=False)
    evidence: JobAlertEvidence | None = None


@dataclass(frozen=True, slots=True)
class JobAlertParseResult:
    status: JobAlertStatus
    synthetic_data: bool
    provider_id: str
    source_id: UUID
    content_sha256: str
    byte_length: int
    trust: TrustLabel
    sensitivity: SensitivityLabel
    fields: tuple[JobAlertField, ...]
    normalized_source: NormalizedPlainTextSource = field(repr=False)
