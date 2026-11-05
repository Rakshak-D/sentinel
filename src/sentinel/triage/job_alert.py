"""Deterministic source-grounded projection of verified local job alerts."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn
from uuid import NAMESPACE_URL, uuid5

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.extraction import (
    JobAlertError,
    JobAlertField,
    JobAlertFieldName,
    JobAlertFieldState,
    JobAlertParseResult,
    JobAlertReviewError,
    JobAlertReviewErrorCode,
    JobAlertStatus,
    format_json_job_alert,
    review_selected_job_alerts,
)
from sentinel.triage.types import (
    JobAlertClassificationCounts,
    JobAlertOutcomeCounts,
    JobAlertSignalCounts,
    JobAlertSignalKind,
    JobAlertTriage,
    JobAlertTriageError,
    JobAlertTriageErrorCode,
    JobAlertTriageEvidence,
    JobAlertTriageFieldIssue,
    JobAlertTriageItem,
    JobAlertTriageOutcome,
    JobAlertTriageReviewReason,
    JobAlertTriageSignal,
)

_SIGNAL_ORDER = (
    JobAlertSignalKind.JOB_ALERT_CANDIDATE,
    JobAlertSignalKind.APPLICATION_URL_DECLARED,
    JobAlertSignalKind.DEADLINE_DATE_DECLARED,
)
_FIELD_REQUIREMENTS: dict[JobAlertSignalKind, tuple[JobAlertFieldName, ...]] = {
    JobAlertSignalKind.JOB_ALERT_CANDIDATE: (
        JobAlertFieldName.COMPANY,
        JobAlertFieldName.ROLE,
    ),
    JobAlertSignalKind.APPLICATION_URL_DECLARED: (JobAlertFieldName.APPLICATION_URL,),
    JobAlertSignalKind.DEADLINE_DATE_DECLARED: (JobAlertFieldName.DEADLINE,),
}


def _fail(code: JobAlertTriageErrorCode) -> NoReturn:
    raise JobAlertTriageError(code) from None


def _field(result: JobAlertParseResult, name: JobAlertFieldName) -> JobAlertField:
    matches = tuple(field for field in result.fields if field.field_id is name)
    if len(matches) != 1:
        _fail(JobAlertTriageErrorCode.INVALID_RESULT)
    return matches[0]


def _evidence(result: JobAlertParseResult, field: JobAlertField) -> JobAlertTriageEvidence:
    evidence = field.evidence
    if (
        field.state is not JobAlertFieldState.PRESENT
        or evidence is None
        or evidence.field_id is not field.field_id
        or evidence.source_id != result.source_id
        or evidence.content_sha256 != result.content_sha256
        or evidence.start_byte < 0
        or evidence.end_byte <= evidence.start_byte
        or evidence.end_byte > result.byte_length
        or len(evidence.text_sha256) != 64
        or hashlib.sha256(
            result.normalized_source.original_bytes[evidence.start_byte : evidence.end_byte]
        ).hexdigest()
        != evidence.text_sha256
    ):
        _fail(JobAlertTriageErrorCode.INVALID_RESULT)
    return JobAlertTriageEvidence(
        field_id=field.field_id,
        source_id=evidence.source_id,
        content_sha256=evidence.content_sha256,
        span_id=evidence.span_id,
        start_byte=evidence.start_byte,
        end_byte=evidence.end_byte,
        text_sha256=evidence.text_sha256,
    )


def _signal(
    result: JobAlertParseResult,
    kind: JobAlertSignalKind,
    evidence: tuple[JobAlertTriageEvidence, ...],
) -> JobAlertTriageSignal:
    ordered_fields = _FIELD_REQUIREMENTS[kind]
    if tuple(item.field_id for item in evidence) != ordered_fields:
        _fail(JobAlertTriageErrorCode.INVALID_RESULT)
    span_key = ":".join(str(item.span_id) for item in evidence)
    signal_id = uuid5(
        NAMESPACE_URL,
        f"sentinel:job-alert-triage-signal:v1:{result.source_id}:{kind.value}:{span_key}",
    )
    return JobAlertTriageSignal(
        signal_id=signal_id,
        kind=kind,
        source_id=result.source_id,
        content_sha256=result.content_sha256,
        evidence=evidence,
    )


def _derive_item(ordinal: int, result: JobAlertParseResult) -> JobAlertTriageItem:
    if (
        type(result) is not JobAlertParseResult
        or type(result.status) is not JobAlertStatus
        or result.provider_id != "local.file"
        or result.synthetic_data is not False
        or result.trust is not TrustLabel.T4_EXTERNAL
        or result.sensitivity is not SensitivityLabel.PRIVATE
    ):
        _fail(JobAlertTriageErrorCode.INVALID_RESULT)
    signals: list[JobAlertTriageSignal] = []
    issues: list[JobAlertTriageFieldIssue] = []
    review_reason: JobAlertTriageReviewReason | None = None

    if result.status is JobAlertStatus.CANDIDATE:
        company = _field(result, JobAlertFieldName.COMPANY)
        role = _field(result, JobAlertFieldName.ROLE)
        if (
            company.state is not JobAlertFieldState.PRESENT
            or role.state is not JobAlertFieldState.PRESENT
        ):
            _fail(JobAlertTriageErrorCode.INVALID_RESULT)
        signals.append(
            _signal(
                result,
                JobAlertSignalKind.JOB_ALERT_CANDIDATE,
                (_evidence(result, company), _evidence(result, role)),
            )
        )
        for kind, field_name in (
            (JobAlertSignalKind.APPLICATION_URL_DECLARED, JobAlertFieldName.APPLICATION_URL),
            (JobAlertSignalKind.DEADLINE_DATE_DECLARED, JobAlertFieldName.DEADLINE),
        ):
            selected = _field(result, field_name)
            if selected.state is JobAlertFieldState.PRESENT:
                signals.append(_signal(result, kind, (_evidence(result, selected),)))
        outcome = JobAlertTriageOutcome.EVIDENCE_PRESENT
    elif result.status in {JobAlertStatus.INCOMPLETE, JobAlertStatus.AMBIGUOUS}:
        issues.extend(
            JobAlertTriageFieldIssue(field_id=item.field_id, state=item.state)
            for item in result.fields
            if item.state is not JobAlertFieldState.PRESENT
        )
        if result.status is JobAlertStatus.INCOMPLETE:
            outcome = JobAlertTriageOutcome.REVIEW_REQUIRED
            review_reason = JobAlertTriageReviewReason.INCOMPLETE_OR_INVALID_FIELDS
        else:
            outcome = JobAlertTriageOutcome.REVIEW_REQUIRED
            review_reason = JobAlertTriageReviewReason.AMBIGUOUS_FIELDS_OR_LISTINGS
    else:
        outcome = JobAlertTriageOutcome.NO_SIGNAL

    if tuple(signal.kind for signal in signals) != tuple(
        kind for kind in _SIGNAL_ORDER if any(signal.kind is kind for signal in signals)
    ):
        _fail(JobAlertTriageErrorCode.INVALID_RESULT)
    return JobAlertTriageItem(
        ordinal=ordinal,
        classification=result.status,
        outcome=outcome,
        review_reason=review_reason,
        field_issues=tuple(issues),
        signals=tuple(signals),
        result=result,
    )


def _build_triage(results: tuple[JobAlertParseResult, ...]) -> JobAlertTriage:
    items = tuple(_derive_item(index, result) for index, result in enumerate(results, start=1))
    classes = {status: 0 for status in JobAlertStatus}
    outcomes = {outcome: 0 for outcome in JobAlertTriageOutcome}
    signals = {kind: 0 for kind in _SIGNAL_ORDER}
    for item in items:
        classes[item.classification] += 1
        outcomes[item.outcome] += 1
        for signal in item.signals:
            signals[signal.kind] += 1
    return JobAlertTriage(
        schema_version="sentinel.job-alert-triage.v1",
        triage_mode="deterministic_cited_field_projection",
        selected_file_count=len(items),
        classification_counts=JobAlertClassificationCounts(
            candidate=classes[JobAlertStatus.CANDIDATE],
            incomplete=classes[JobAlertStatus.INCOMPLETE],
            ambiguous=classes[JobAlertStatus.AMBIGUOUS],
            no_match=classes[JobAlertStatus.NO_MATCH],
        ),
        outcome_counts=JobAlertOutcomeCounts(
            evidence_present=outcomes[JobAlertTriageOutcome.EVIDENCE_PRESENT],
            review_required=outcomes[JobAlertTriageOutcome.REVIEW_REQUIRED],
            no_signal=outcomes[JobAlertTriageOutcome.NO_SIGNAL],
        ),
        signal_counts=JobAlertSignalCounts(
            job_alert_candidate=signals[JobAlertSignalKind.JOB_ALERT_CANDIDATE],
            application_url_declared=signals[JobAlertSignalKind.APPLICATION_URL_DECLARED],
            deadline_date_declared=signals[JobAlertSignalKind.DEADLINE_DATE_DECLARED],
        ),
        items=items,
    )


def triage_selected_job_alerts(
    *,
    allowed_root: str | Path,
    file_paths: Sequence[str | Path],
) -> JobAlertTriage:
    """Project verified CR1-O fields into bounded cited signals; never calls a model."""
    try:
        review = review_selected_job_alerts(allowed_root=allowed_root, file_paths=file_paths)
        results = tuple(item.result for item in review.files)
        return _build_triage(results)
    except JobAlertTriageError:
        raise
    except JobAlertReviewError as exc:
        if exc.code is JobAlertReviewErrorCode.TOO_MANY_FILES:
            code = JobAlertTriageErrorCode.TOO_MANY_FILES
        elif exc.code is JobAlertReviewErrorCode.INVALID_SELECTION:
            code = JobAlertTriageErrorCode.INVALID_SELECTION
        else:
            code = JobAlertTriageErrorCode.SOURCE_INVALID
        _fail(code)
    except (JobAlertError, OSError, TypeError, ValueError):
        _fail(JobAlertTriageErrorCode.SOURCE_INVALID)
    except Exception:
        _fail(JobAlertTriageErrorCode.SOURCE_INVALID)


def validate_job_alert_triage(value: object) -> JobAlertTriage:
    """Revalidate an immutable result, parser citations, derived signals, and counts."""
    if (
        type(value) is not JobAlertTriage
        or value.schema_version != "sentinel.job-alert-triage.v1"
        or value.triage_mode != "deterministic_cited_field_projection"
        or type(value.items) is not tuple
        or not 1 <= len(value.items) <= 8
        or type(value.selected_file_count) is not int
        or value.selected_file_count != len(value.items)
        or value.trust is not TrustLabel.T4_EXTERNAL
        or value.sensitivity is not SensitivityLabel.PRIVATE
    ):
        _fail(JobAlertTriageErrorCode.INVALID_RESULT)
    count_records = (
        (value.classification_counts, JobAlertClassificationCounts),
        (value.outcome_counts, JobAlertOutcomeCounts),
        (value.signal_counts, JobAlertSignalCounts),
    )
    if any(type(record) is not expected_type for record, expected_type in count_records):
        _fail(JobAlertTriageErrorCode.INVALID_RESULT)
    count_values = (
        value.classification_counts.candidate,
        value.classification_counts.incomplete,
        value.classification_counts.ambiguous,
        value.classification_counts.no_match,
        value.outcome_counts.evidence_present,
        value.outcome_counts.review_required,
        value.outcome_counts.no_signal,
        value.signal_counts.job_alert_candidate,
        value.signal_counts.application_url_declared,
        value.signal_counts.deadline_date_declared,
    )
    if any(type(count) is not int or count < 0 for count in count_values):
        _fail(JobAlertTriageErrorCode.INVALID_RESULT)
    expected_results: list[JobAlertParseResult] = []
    try:
        for ordinal, item in enumerate(value.items, start=1):
            if (
                type(item) is not JobAlertTriageItem
                or type(item.ordinal) is not int
                or item.ordinal != ordinal
            ):
                _fail(JobAlertTriageErrorCode.INVALID_RESULT)
            # CR1-O's strict formatter checks body digest, field identity, and every byte citation.
            format_json_job_alert(item.result, show_fields=False)
            expected = _derive_item(ordinal, item.result)
            if (
                item.classification is not expected.classification
                or item.outcome is not expected.outcome
                or item.review_reason is not expected.review_reason
                or item.field_issues != expected.field_issues
                or item.signals != expected.signals
            ):
                _fail(JobAlertTriageErrorCode.INVALID_RESULT)
            expected_results.append(item.result)
        expected_triage = _build_triage(tuple(expected_results))
        if (
            value.classification_counts != expected_triage.classification_counts
            or value.outcome_counts != expected_triage.outcome_counts
            or value.signal_counts != expected_triage.signal_counts
        ):
            _fail(JobAlertTriageErrorCode.INVALID_RESULT)
    except JobAlertTriageError:
        raise
    except Exception:
        _fail(JobAlertTriageErrorCode.INVALID_RESULT)
    return value


__all__ = ["triage_selected_job_alerts", "validate_job_alert_triage"]
