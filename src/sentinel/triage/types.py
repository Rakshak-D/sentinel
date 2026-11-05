"""Immutable types for cited, deterministic job-alert triage."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal
from uuid import UUID

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.extraction.types import (
    JobAlertFieldName,
    JobAlertFieldState,
    JobAlertParseResult,
    JobAlertStatus,
)


class JobAlertTriageErrorCode(StrEnum):
    INVALID_SELECTION = "invalid_selection"
    TOO_MANY_FILES = "too_many_files"
    SOURCE_INVALID = "source_invalid"
    INVALID_RESULT = "invalid_result"
    OUTPUT_TOO_LARGE = "output_too_large"


_ERROR_MESSAGES = {
    JobAlertTriageErrorCode.INVALID_SELECTION: "Select one to eight valid local job-alert files.",
    JobAlertTriageErrorCode.TOO_MANY_FILES: "Select no more than eight job-alert files.",
    JobAlertTriageErrorCode.SOURCE_INVALID: "A selected job-alert source could not be verified.",
    JobAlertTriageErrorCode.INVALID_RESULT: "The complete job-alert triage result is invalid.",
    JobAlertTriageErrorCode.OUTPUT_TOO_LARGE: (
        "The complete job-alert triage exceeds its output limit."
    ),
}


class JobAlertTriageError(RuntimeError):
    """Fixed-category failure without source values, paths, or raw exceptions."""

    def __init__(self, code: JobAlertTriageErrorCode) -> None:
        if type(code) is not JobAlertTriageErrorCode:
            raise TypeError("job-alert triage error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


class JobAlertTriageOutcome(StrEnum):
    EVIDENCE_PRESENT = "EVIDENCE_PRESENT"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    NO_SIGNAL = "NO_SIGNAL"


class JobAlertSignalKind(StrEnum):
    JOB_ALERT_CANDIDATE = "JOB_ALERT_CANDIDATE"
    APPLICATION_URL_DECLARED = "APPLICATION_URL_DECLARED"
    DEADLINE_DATE_DECLARED = "DEADLINE_DATE_DECLARED"


class JobAlertTriageReviewReason(StrEnum):
    INCOMPLETE_OR_INVALID_FIELDS = "INCOMPLETE_OR_INVALID_FIELDS"
    AMBIGUOUS_FIELDS_OR_LISTINGS = "AMBIGUOUS_FIELDS_OR_LISTINGS"


@dataclass(frozen=True, slots=True)
class JobAlertTriageFieldIssue:
    field_id: JobAlertFieldName
    state: JobAlertFieldState


@dataclass(frozen=True, slots=True)
class JobAlertTriageEvidence:
    field_id: JobAlertFieldName
    source_id: UUID
    content_sha256: str
    span_id: UUID
    start_byte: int
    end_byte: int
    text_sha256: str
    source_trust: TrustLabel = TrustLabel.T4_EXTERNAL
    source_sensitivity: SensitivityLabel = SensitivityLabel.PRIVATE


@dataclass(frozen=True, slots=True)
class JobAlertTriageSignal:
    signal_id: UUID
    kind: JobAlertSignalKind
    source_id: UUID
    content_sha256: str
    evidence: tuple[JobAlertTriageEvidence, ...]
    trust: TrustLabel = TrustLabel.T3_DERIVED
    sensitivity: SensitivityLabel = SensitivityLabel.PRIVATE


@dataclass(frozen=True, slots=True)
class JobAlertTriageItem:
    ordinal: int
    classification: JobAlertStatus
    outcome: JobAlertTriageOutcome
    review_reason: JobAlertTriageReviewReason | None
    field_issues: tuple[JobAlertTriageFieldIssue, ...]
    signals: tuple[JobAlertTriageSignal, ...]
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


@dataclass(frozen=True, slots=True)
class JobAlertClassificationCounts:
    candidate: int
    incomplete: int
    ambiguous: int
    no_match: int


@dataclass(frozen=True, slots=True)
class JobAlertOutcomeCounts:
    evidence_present: int
    review_required: int
    no_signal: int


@dataclass(frozen=True, slots=True)
class JobAlertSignalCounts:
    job_alert_candidate: int
    application_url_declared: int
    deadline_date_declared: int


@dataclass(frozen=True, slots=True)
class JobAlertTriage:
    schema_version: Literal["sentinel.job-alert-triage.v1"]
    triage_mode: Literal["deterministic_cited_field_projection"]
    selected_file_count: int
    classification_counts: JobAlertClassificationCounts
    outcome_counts: JobAlertOutcomeCounts
    signal_counts: JobAlertSignalCounts
    items: tuple[JobAlertTriageItem, ...]
    trust: TrustLabel = TrustLabel.T4_EXTERNAL
    sensitivity: SensitivityLabel = SensitivityLabel.PRIVATE


@dataclass(frozen=True, slots=True)
class JobAlertExpectedSignal:
    kind: JobAlertSignalKind
    evidence_fields: tuple[JobAlertFieldName, ...]


@dataclass(frozen=True, slots=True)
class JobAlertEvaluationLabel:
    case_id: str
    expected_classification: JobAlertStatus | None
    expected_signals: tuple[JobAlertExpectedSignal, ...]
    expected_error_code: str | None = None


@dataclass(frozen=True, slots=True)
class JobAlertEvaluationObservation:
    case_id: str
    triage: JobAlertTriage | None = field(repr=False)
    failure_code: str | None = None


@dataclass(frozen=True, slots=True)
class JobAlertMetric:
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float


@dataclass(frozen=True, slots=True)
class JobAlertConfusionRow:
    expected: JobAlertStatus
    predicted_counts: tuple[int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class JobAlertPerSignalMetric:
    kind: JobAlertSignalKind
    metric: JobAlertMetric


@dataclass(frozen=True, slots=True)
class JobAlertEvaluationReport:
    schema_version: Literal["sentinel.job-alert-triage-evaluation.v1"]
    evaluation_version: str
    dataset_id: Literal["development", "holdout"]
    case_count: int
    classified_case_count: int
    rejected_case_count: int
    classification_accuracy: float
    classification_confusion: tuple[JobAlertConfusionRow, ...]
    candidate_signal_metric: JobAlertMetric
    per_signal_metrics: tuple[JobAlertPerSignalMetric, ...]
    micro_signal_metric: JobAlertMetric
    macro_signal_f1: float
    false_positive_candidate_count: int
    false_negative_candidate_count: int
    incorrect_abstention_count: int
    missing_evidence_count: int
    verified_citation_count: int
    invalid_citation_count: int
    cross_source_evidence_error_count: int
    unexpected_failure_count: int
    zero_denominator_convention: Literal["metric_is_zero"] = "metric_is_zero"
    exact_signal_rule: Literal[
        "case_local_kind_and_required_field_ids"
    ] = "case_local_kind_and_required_field_ids"


__all__ = [
    "JobAlertClassificationCounts",
    "JobAlertConfusionRow",
    "JobAlertEvaluationLabel",
    "JobAlertEvaluationObservation",
    "JobAlertEvaluationReport",
    "JobAlertExpectedSignal",
    "JobAlertMetric",
    "JobAlertOutcomeCounts",
    "JobAlertPerSignalMetric",
    "JobAlertSignalCounts",
    "JobAlertSignalKind",
    "JobAlertTriage",
    "JobAlertTriageError",
    "JobAlertTriageErrorCode",
    "JobAlertTriageEvidence",
    "JobAlertTriageFieldIssue",
    "JobAlertTriageItem",
    "JobAlertTriageOutcome",
    "JobAlertTriageReviewReason",
    "JobAlertTriageSignal",
]
