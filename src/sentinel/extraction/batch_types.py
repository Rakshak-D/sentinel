"""Immutable, privacy-conscious types for bounded job-alert batch review."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal
from uuid import UUID

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.extraction.types import JobAlertParseResult, JobAlertStatus


class JobAlertReviewErrorCode(StrEnum):
    INVALID_SELECTION = "invalid_selection"
    TOO_MANY_FILES = "too_many_files"
    DUPLICATE_FILE = "duplicate_file"
    SOURCE_INVALID = "source_invalid"
    SOURCE_CHANGED = "source_changed"
    OUTPUT_TOO_LARGE = "output_too_large"


_ERROR_MESSAGES = {
    JobAlertReviewErrorCode.INVALID_SELECTION: "Select one to eight valid local job-alert files.",
    JobAlertReviewErrorCode.TOO_MANY_FILES: "Select no more than eight job-alert files.",
    JobAlertReviewErrorCode.DUPLICATE_FILE: "The same local file was selected more than once.",
    JobAlertReviewErrorCode.SOURCE_INVALID: "A selected job-alert source could not be verified.",
    JobAlertReviewErrorCode.SOURCE_CHANGED: "A selected source changed during batch verification.",
    JobAlertReviewErrorCode.OUTPUT_TOO_LARGE: (
        "The complete job-alert review exceeds its output limit."
    ),
}


class JobAlertReviewError(RuntimeError):
    """A bounded batch-review error that never includes a path or source value."""

    def __init__(self, code: JobAlertReviewErrorCode) -> None:
        if type(code) is not JobAlertReviewErrorCode:
            raise TypeError("job-alert review error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


class JobAlertCorrelationKind(StrEnum):
    EXACT_SOURCE_CONTENT = "EXACT_SOURCE_CONTENT"
    SHARED_APPLICATION_URL = "SHARED_APPLICATION_URL"


@dataclass(frozen=True, slots=True)
class JobAlertClassificationCounts:
    candidate: int
    incomplete: int
    ambiguous: int
    no_match: int


@dataclass(frozen=True, slots=True)
class JobAlertReviewedFile:
    ordinal: int
    result: JobAlertParseResult = field(repr=False)

    @property
    def source_id(self) -> UUID:
        return self.result.source_id

    @property
    def content_sha256(self) -> str:
        return self.result.content_sha256

    @property
    def byte_length(self) -> int:
        return self.result.byte_length

    @property
    def status(self) -> JobAlertStatus:
        return self.result.status


@dataclass(frozen=True, slots=True)
class JobAlertCorrelationGroup:
    group_id: str
    kind: JobAlertCorrelationKind
    member_file_ordinals: tuple[int, ...]
    member_source_ids: tuple[str, ...]
    member_count: int
    content_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class JobAlertBatchReview:
    schema_version: Literal["sentinel.job-alert-batch-review.v1"]
    review_mode: Literal["explicit_local_job_alert_batch"]
    synthetic_data: Literal[False]
    trust: TrustLabel
    sensitivity: SensitivityLabel
    selected_file_count: int
    classification_counts: JobAlertClassificationCounts
    verified_field_count: int
    citation_count: int
    files_with_application_url: int
    files_with_explicit_deadline: int
    files: tuple[JobAlertReviewedFile, ...]
    correlation_groups: tuple[JobAlertCorrelationGroup, ...]


__all__ = [
    "JobAlertBatchReview",
    "JobAlertClassificationCounts",
    "JobAlertCorrelationGroup",
    "JobAlertCorrelationKind",
    "JobAlertReviewError",
    "JobAlertReviewErrorCode",
    "JobAlertReviewedFile",
]
