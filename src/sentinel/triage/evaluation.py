"""Exact, deterministic evaluation for the frozen fictional CR1-U corpus."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from typing import Final, Literal, NoReturn, cast

from sentinel.extraction import format_json_job_alert
from sentinel.extraction.types import JobAlertFieldName, JobAlertParseResult, JobAlertStatus
from sentinel.triage.job_alert import validate_job_alert_triage
from sentinel.triage.types import (
    JobAlertConfusionRow,
    JobAlertEvaluationLabel,
    JobAlertEvaluationObservation,
    JobAlertEvaluationReport,
    JobAlertExpectedSignal,
    JobAlertMetric,
    JobAlertPerSignalMetric,
    JobAlertSignalKind,
    JobAlertTriage,
    JobAlertTriageError,
    JobAlertTriageErrorCode,
    JobAlertTriageEvidence,
    JobAlertTriageItem,
    JobAlertTriageSignal,
)

_DATASETS: Final = {"development", "holdout"}
_CLASSES: Final = (
    JobAlertStatus.CANDIDATE,
    JobAlertStatus.INCOMPLETE,
    JobAlertStatus.AMBIGUOUS,
    JobAlertStatus.NO_MATCH,
)
_SIGNALS: Final = (
    JobAlertSignalKind.JOB_ALERT_CANDIDATE,
    JobAlertSignalKind.APPLICATION_URL_DECLARED,
    JobAlertSignalKind.DEADLINE_DATE_DECLARED,
)
_REQUIRED_FIELDS: Final = {
    JobAlertSignalKind.JOB_ALERT_CANDIDATE: (
        JobAlertFieldName.COMPANY,
        JobAlertFieldName.ROLE,
    ),
    JobAlertSignalKind.APPLICATION_URL_DECLARED: (JobAlertFieldName.APPLICATION_URL,),
    JobAlertSignalKind.DEADLINE_DATE_DECLARED: (JobAlertFieldName.DEADLINE,),
}
_FAILURE_CODES: Final = frozenset(code.value for code in JobAlertTriageErrorCode)
_CASE_ID_CHARS: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-")


def _fail() -> NoReturn:
    raise JobAlertTriageError(JobAlertTriageErrorCode.INVALID_RESULT) from None


def _metric(tp: int, fp: int, fn: int) -> JobAlertMetric:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return JobAlertMetric(tp, fp, fn, precision, recall, f1)


def _valid_case_id(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and value.isascii()
        and value[0] in "abcdefghijklmnopqrstuvwxyz0123456789"
        and all(character in _CASE_ID_CHARS for character in value)
    )


def _label_signals(label: JobAlertEvaluationLabel) -> Counter[tuple[str, tuple[str, ...]]]:
    if type(label.expected_signals) is not tuple:
        _fail()
    output: Counter[tuple[str, tuple[str, ...]]] = Counter()
    seen_kinds: set[JobAlertSignalKind] = set()
    for signal in label.expected_signals:
        if (
            type(signal) is not JobAlertExpectedSignal
            or type(signal.kind) is not JobAlertSignalKind
            or signal.kind not in _SIGNALS
            or type(signal.evidence_fields) is not tuple
            or any(type(field) is not JobAlertFieldName for field in signal.evidence_fields)
            or signal.kind in seen_kinds
        ):
            _fail()
        expected_fields = _REQUIRED_FIELDS[signal.kind]
        if signal.evidence_fields != expected_fields:
            _fail()
        seen_kinds.add(signal.kind)
        output[(signal.kind.value, tuple(field.value for field in signal.evidence_fields))] += 1
    return output


def _invalid_reference_counts(
    value: object,
) -> tuple[int, int, int, int]:
    """Diagnose references after rejection without allowing them scoring credit."""
    if type(value) is not JobAlertTriage or type(value.items) is not tuple:
        return 0, 0, 0, 1
    verified = invalid = cross_source = missing = 0
    try:
        for item in value.items:
            if type(item) is not JobAlertTriageItem or type(item.result) is not JobAlertParseResult:
                missing += 1
                continue
            try:
                # Reuse CR1-O's strict validation of its source and bound field citations.
                format_json_job_alert(item.result, show_fields=False)
                source_valid = True
            except Exception:
                source_valid = False
            if type(item.signals) is not tuple:
                missing += 1
                continue
            for signal in item.signals:
                if type(signal) is not JobAlertTriageSignal or type(signal.evidence) is not tuple:
                    missing += 1
                    continue
                if not signal.evidence:
                    missing += 1
                    continue
                for evidence in signal.evidence:
                    if type(evidence) is not JobAlertTriageEvidence:
                        invalid += 1
                        continue
                    if (
                        evidence.source_id != item.result.source_id
                        or evidence.content_sha256 != item.result.content_sha256
                    ):
                        cross_source += 1
                        invalid += 1
                        continue
                    if type(evidence.field_id) is not JobAlertFieldName:
                        invalid += 1
                        continue
                    field = next(
                        (
                            candidate
                            for candidate in item.result.fields
                            if candidate.field_id is evidence.field_id
                        ),
                        None,
                    )
                    if field is None:
                        missing += 1
                        continue
                    if field.evidence is None:
                        invalid += 1
                        continue
                    source_evidence = field.evidence
                    if (
                        not source_valid
                        or field.state.value != "present"
                        or evidence.source_id != source_evidence.source_id
                        or evidence.content_sha256 != source_evidence.content_sha256
                        or evidence.span_id != source_evidence.span_id
                        or evidence.start_byte != source_evidence.start_byte
                        or evidence.end_byte != source_evidence.end_byte
                        or evidence.text_sha256 != source_evidence.text_sha256
                    ):
                        invalid += 1
                    else:
                        verified += 1
    except Exception:
        return verified, invalid + 1, cross_source, missing
    return verified, invalid, cross_source, missing


def _predicted_signals(
    triage: JobAlertTriage,
) -> tuple[Counter[tuple[str, tuple[str, ...]]], int]:
    """Return only a strictly validated, single-source case prediction."""
    if len(triage.items) != 1:
        _fail()
    item = triage.items[0]
    predictions: Counter[tuple[str, tuple[str, ...]]] = Counter()
    verified = 0
    for signal in item.signals:
        fields = tuple(evidence.field_id.value for evidence in signal.evidence)
        predictions[(signal.kind.value, fields)] += 1
        verified += len(signal.evidence)
    return predictions, verified


def evaluate_job_alert_triage(
    *,
    dataset_id: str,
    labels: Sequence[JobAlertEvaluationLabel],
    observations: Sequence[JobAlertEvaluationObservation],
) -> JobAlertEvaluationReport:
    """Score exact typed signals, matching each prediction only within its case."""
    if (
        dataset_id not in _DATASETS
        or type(labels) not in (tuple, list)
        or type(observations) not in (tuple, list)
        or not labels
        or len(labels) != len(observations)
        or any(type(label) is not JobAlertEvaluationLabel for label in labels)
        or any(
            type(observation) is not JobAlertEvaluationObservation for observation in observations
        )
    ):
        _fail()
    case_ids = [label.case_id for label in labels]
    if (
        any(not _valid_case_id(case_id) for case_id in case_ids)
        or len(set(case_ids)) != len(case_ids)
        or any(not _valid_case_id(observation.case_id) for observation in observations)
        or [observation.case_id for observation in observations] != case_ids
    ):
        _fail()

    confusion: dict[JobAlertStatus, Counter[JobAlertStatus | None]] = {
        expected: Counter() for expected in _CLASSES
    }
    classification_correct = 0
    classified_count = 0
    rejected_count = 0
    unexpected_failures = 0
    incorrect_abstentions = 0
    signal_totals: dict[JobAlertSignalKind, list[int]] = {
        kind: [0, 0, 0] for kind in _SIGNALS
    }
    total_verified = total_invalid = total_cross = total_missing = 0

    for label, observation in zip(labels, observations, strict=True):
        if (
            type(label) is not JobAlertEvaluationLabel
            or type(observation) is not JobAlertEvaluationObservation
            or (
                label.expected_classification is not None
                and type(label.expected_classification) is not JobAlertStatus
            )
            or (
                label.expected_error_code is not None
                and (
                    type(label.expected_error_code) is not str
                    or label.expected_error_code not in _FAILURE_CODES
                )
            )
            or (
                observation.failure_code is not None
                and (
                    type(observation.failure_code) is not str
                    or observation.failure_code not in _FAILURE_CODES
                )
            )
            or (observation.triage is not None and observation.failure_code is not None)
        ):
            _fail()
        gold = _label_signals(label)
        if label.expected_classification is None:
            if label.expected_error_code is None or gold:
                _fail()
        else:
            if (
                label.expected_error_code is not None
                or label.expected_classification not in _CLASSES
            ):
                _fail()
            candidate_key = (
                JobAlertSignalKind.JOB_ALERT_CANDIDATE.value,
                tuple(
                    field.value
                    for field in _REQUIRED_FIELDS[JobAlertSignalKind.JOB_ALERT_CANDIDATE]
                ),
            )
            if (
                (
                    label.expected_classification is JobAlertStatus.CANDIDATE
                    and gold[candidate_key] != 1
                )
                or (
                    label.expected_classification is not JobAlertStatus.CANDIDATE and gold
                )
            ):
                _fail()
            classified_count += 1

        predicted_class: JobAlertStatus | None = None
        predicted: Counter[tuple[str, tuple[str, ...]]] = Counter()
        verified = invalid = cross = missing = 0
        if observation.triage is None:
            rejected_count += 1
            if (
                label.expected_classification is not None
                or observation.failure_code != label.expected_error_code
            ):
                unexpected_failures += 1
        else:
            try:
                triage = validate_job_alert_triage(observation.triage)
                predicted, verified = _predicted_signals(triage)
                predicted_class = triage.items[0].classification
            except JobAlertTriageError:
                verified, invalid, cross, missing = _invalid_reference_counts(
                    observation.triage
                )
                rejected_count += 1
                unexpected_failures += 1
            else:
                if label.expected_classification is None:
                    # A valid result for a gold rejection is an unexpected acceptance;
                    # its signals remain false positives in this same case.
                    unexpected_failures += 1
        if label.expected_classification is not None:
            confusion[label.expected_classification][predicted_class] += 1
            if predicted_class is label.expected_classification:
                classification_correct += 1

        # Match this case's exact signals before accumulating aggregate totals.
        for kind in _SIGNALS:
            case_gold = Counter({key: count for key, count in gold.items() if key[0] == kind.value})
            case_predicted = Counter(
                {key: count for key, count in predicted.items() if key[0] == kind.value}
            )
            true_positive = sum(
                min(count, case_predicted[key]) for key, count in case_gold.items()
            )
            signal_counts = signal_totals[kind]
            signal_counts[0] += true_positive
            signal_counts[1] += sum(case_predicted.values()) - true_positive
            signal_counts[2] += sum(case_gold.values()) - true_positive
        total_verified += verified
        total_invalid += invalid
        total_cross += cross
        total_missing += missing
        if gold and not predicted:
            incorrect_abstentions += 1

    per_signal = tuple(
        JobAlertPerSignalMetric(
            kind=kind,
            metric=_metric(*signal_totals[kind]),
        )
        for kind in _SIGNALS
    )
    micro = _metric(
        sum(counts[0] for counts in signal_totals.values()),
        sum(counts[1] for counts in signal_totals.values()),
        sum(counts[2] for counts in signal_totals.values()),
    )
    macro_f1 = sum(metric.metric.f1 for metric in per_signal) / len(per_signal)
    rows_list: list[JobAlertConfusionRow] = []
    for expected in _CLASSES:
        counts: tuple[int, int, int, int, int] = (
            confusion[expected][_CLASSES[0]],
            confusion[expected][_CLASSES[1]],
            confusion[expected][_CLASSES[2]],
            confusion[expected][_CLASSES[3]],
            confusion[expected][None],
        )
        rows_list.append(JobAlertConfusionRow(expected=expected, predicted_counts=counts))
    rows = tuple(rows_list)
    candidate_metric = _metric(*signal_totals[JobAlertSignalKind.JOB_ALERT_CANDIDATE])
    return JobAlertEvaluationReport(
        schema_version="sentinel.job-alert-triage-evaluation.v1",
        evaluation_version="cr1-u-job-alert-triage-v1",
        dataset_id=cast(Literal["development", "holdout"], dataset_id),
        case_count=len(labels),
        classified_case_count=classified_count,
        rejected_case_count=rejected_count,
        classification_accuracy=classification_correct / classified_count
        if classified_count
        else 0.0,
        classification_confusion=rows,
        candidate_signal_metric=candidate_metric,
        per_signal_metrics=per_signal,
        micro_signal_metric=micro,
        macro_signal_f1=macro_f1,
        false_positive_candidate_count=candidate_metric.false_positive,
        false_negative_candidate_count=candidate_metric.false_negative,
        incorrect_abstention_count=incorrect_abstentions,
        missing_evidence_count=total_missing,
        verified_citation_count=total_verified,
        invalid_citation_count=total_invalid,
        cross_source_evidence_error_count=total_cross,
        unexpected_failure_count=unexpected_failures,
    )


def _metric_document(metric: JobAlertMetric) -> dict[str, int | float]:
    return {
        "true_positive": metric.true_positive,
        "false_positive": metric.false_positive,
        "false_negative": metric.false_negative,
        "precision": metric.precision,
        "recall": metric.recall,
        "f1": metric.f1,
    }


def format_json_job_alert_evaluation(report: JobAlertEvaluationReport) -> str:
    """Render metrics with stable keys; results describe only the pinned fictional corpus."""
    if (
        type(report) is not JobAlertEvaluationReport
        or report.schema_version != "sentinel.job-alert-triage-evaluation.v1"
        or report.evaluation_version != "cr1-u-job-alert-triage-v1"
        or report.dataset_id not in _DATASETS
        or type(report.classification_confusion) is not tuple
        or type(report.per_signal_metrics) is not tuple
        or len(report.per_signal_metrics) != len(_SIGNALS)
        or report.zero_denominator_convention != "metric_is_zero"
        or report.exact_signal_rule != "case_local_kind_and_required_field_ids"
    ):
        _fail()
    document: dict[str, object] = {
        "schema_version": report.schema_version,
        "evaluation_version": report.evaluation_version,
        "dataset_id": report.dataset_id,
        "case_count": report.case_count,
        "classified_case_count": report.classified_case_count,
        "rejected_case_count": report.rejected_case_count,
        "classification_accuracy": report.classification_accuracy,
        "classification_confusion": [
            {
                "expected": row.expected.value,
                "predicted_counts": list(row.predicted_counts),
                "predicted_order": [status.value for status in _CLASSES] + ["INPUT_REJECTED"],
            }
            for row in report.classification_confusion
        ],
        "candidate_signal_metric": _metric_document(report.candidate_signal_metric),
        "per_signal_metrics": [
            {"kind": entry.kind.value, **_metric_document(entry.metric)}
            for entry in report.per_signal_metrics
        ],
        "micro_signal_metric": _metric_document(report.micro_signal_metric),
        "macro_signal_f1": report.macro_signal_f1,
        "false_positive_candidate_count": report.false_positive_candidate_count,
        "false_negative_candidate_count": report.false_negative_candidate_count,
        "incorrect_abstention_count": report.incorrect_abstention_count,
        "missing_evidence_count": report.missing_evidence_count,
        "verified_citation_count": report.verified_citation_count,
        "invalid_citation_count": report.invalid_citation_count,
        "cross_source_evidence_error_count": report.cross_source_evidence_error_count,
        "unexpected_failure_count": report.unexpected_failure_count,
        "zero_denominator_convention": report.zero_denominator_convention,
        "exact_signal_rule": report.exact_signal_rule,
    }
    try:
        return json.dumps(
            document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        )
    except (TypeError, ValueError):
        _fail()


__all__ = ["evaluate_job_alert_triage", "format_json_job_alert_evaluation"]
