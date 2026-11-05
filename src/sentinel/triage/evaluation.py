"""Exact, deterministic evaluation for the frozen fictional CR1-U corpus."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from typing import Final, Literal, NoReturn, cast

from sentinel.extraction.types import JobAlertFieldName, JobAlertStatus
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
    JobAlertTriageError,
    JobAlertTriageErrorCode,
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


def _fail() -> NoReturn:
    raise JobAlertTriageError(JobAlertTriageErrorCode.INVALID_RESULT) from None


def _metric(tp: int, fp: int, fn: int) -> JobAlertMetric:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return JobAlertMetric(tp, fp, fn, precision, recall, f1)


def _label_signals(label: JobAlertEvaluationLabel) -> Counter[tuple[str, tuple[str, ...]]]:
    output: Counter[tuple[str, tuple[str, ...]]] = Counter()
    for signal in label.expected_signals:
        if type(signal) is not JobAlertExpectedSignal or signal.kind not in _SIGNALS:
            _fail()
        expected_fields = _REQUIRED_FIELDS[signal.kind]
        if signal.evidence_fields != expected_fields:
            _fail()
        output[(signal.kind.value, tuple(field.value for field in signal.evidence_fields))] += 1
    return output


def _predicted_signals(
    observation: JobAlertEvaluationObservation,
) -> tuple[Counter[tuple[str, tuple[str, ...]]], int, int, int, int]:
    if observation.triage is None:
        return Counter(), 0, 0, 0, 0
    triage = validate_job_alert_triage(observation.triage)
    predictions: Counter[tuple[str, tuple[str, ...]]] = Counter()
    verified = 0
    invalid = 0
    cross_source = 0
    missing = 0
    for item in triage.items:
        for signal in item.signals:
            if not signal.evidence:
                missing += 1
                continue
            fields: list[str] = []
            valid_signal = True
            for evidence in signal.evidence:
                fields.append(evidence.field_id.value)
                field = next(
                    (
                        candidate
                        for candidate in item.result.fields
                        if candidate.field_id is evidence.field_id
                    ),
                    None,
                )
                if (
                    evidence.source_id != item.source_id
                    or evidence.content_sha256 != item.content_sha256
                ):
                    cross_source += 1
                if field is None or field.evidence is None:
                    missing += 1
                    valid_signal = False
                    continue
                if (
                    evidence.source_id != field.evidence.source_id
                    or evidence.content_sha256 != field.evidence.content_sha256
                    or evidence.span_id != field.evidence.span_id
                    or evidence.start_byte != field.evidence.start_byte
                    or evidence.end_byte != field.evidence.end_byte
                    or evidence.text_sha256 != field.evidence.text_sha256
                    or field.state.value != "present"
                ):
                    invalid += 1
                    valid_signal = False
                else:
                    verified += 1
            if valid_signal:
                predictions[(signal.kind.value, tuple(fields))] += 1
    return predictions, verified, invalid, cross_source, missing


def evaluate_job_alert_triage(
    *,
    dataset_id: str,
    labels: Sequence[JobAlertEvaluationLabel],
    observations: Sequence[JobAlertEvaluationObservation],
) -> JobAlertEvaluationReport:
    """Score actual typed projections with exact signal-kind/field-set matches."""
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
        any(type(case_id) is not str or not case_id or len(case_id) > 128 for case_id in case_ids)
        or len(set(case_ids)) != len(case_ids)
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
    candidate_gold: Counter[tuple[str, tuple[str, ...]]] = Counter()
    candidate_pred: Counter[tuple[str, tuple[str, ...]]] = Counter()
    all_gold: Counter[tuple[str, tuple[str, ...]]] = Counter()
    all_pred: Counter[tuple[str, tuple[str, ...]]] = Counter()
    total_verified = total_invalid = total_cross = total_missing = 0

    for label, observation in zip(labels, observations, strict=True):
        if (
            type(label) is not JobAlertEvaluationLabel
            or type(observation) is not JobAlertEvaluationObservation
            or (
                label.expected_classification is not None
                and label.expected_classification not in _CLASSES
            )
            or type(label.expected_signals) is not tuple
        ):
            _fail()
        gold = _label_signals(label)
        all_gold.update(gold)
        candidate_gold.update(
            {
                key: count
                for key, count in gold.items()
                if key[0] == JobAlertSignalKind.JOB_ALERT_CANDIDATE.value
            }
        )
        if label.expected_classification is None:
            if label.expected_error_code is None or gold:
                _fail()
            if observation.triage is None:
                rejected_count += 1
                if observation.failure_code != label.expected_error_code:
                    unexpected_failures += 1
            else:
                # An unexpectedly accepted out-of-contract input has no gold signals;
                # any produced signal is scored as a false positive below.
                unexpected_failures += 1
            predicted_class: JobAlertStatus | None = None
        else:
            classified_count += 1
            predicted_class = None
        if observation.triage is None:
            if label.expected_classification is not None:
                rejected_count += 1
                unexpected_failures += 1
        else:
            try:
                triage = validate_job_alert_triage(observation.triage)
            except JobAlertTriageError:
                predicted_class = None
                rejected_count += 1
                unexpected_failures += 1
            else:
                if len(triage.items) != 1:
                    predicted_class = None
                    rejected_count += 1
                    unexpected_failures += 1
                else:
                    predicted_class = triage.items[0].classification
        if label.expected_classification is not None:
            confusion[label.expected_classification][predicted_class] += 1
            if predicted_class is label.expected_classification:
                classification_correct += 1
        if observation.triage is None:
            predicted: Counter[tuple[str, tuple[str, ...]]] = Counter()
            verified = invalid = cross = missing = 0
        else:
            try:
                predicted, verified, invalid, cross, missing = _predicted_signals(observation)
            except JobAlertTriageError:
                predicted = Counter()
                verified = 0
                invalid = 0
                cross = 0
                missing = 1
                unexpected_failures += 1
        all_pred.update(predicted)
        candidate_pred.update(
            {
                key: count
                for key, count in predicted.items()
                if key[0] == JobAlertSignalKind.JOB_ALERT_CANDIDATE.value
            }
        )
        total_verified += verified
        total_invalid += invalid
        total_cross += cross
        total_missing += missing
        if gold and not predicted:
            incorrect_abstentions += 1

    def scored(
        gold: Counter[tuple[str, tuple[str, ...]]], pred: Counter[tuple[str, tuple[str, ...]]]
    ) -> JobAlertMetric:
        tp = sum(min(count, pred[key]) for key, count in gold.items())
        fp = sum(pred.values()) - tp
        fn = sum(gold.values()) - tp
        return _metric(tp, fp, fn)

    per_signal = tuple(
        JobAlertPerSignalMetric(
            kind=kind,
            metric=scored(
                Counter({key: count for key, count in all_gold.items() if key[0] == kind.value}),
                Counter({key: count for key, count in all_pred.items() if key[0] == kind.value}),
            ),
        )
        for kind in _SIGNALS
    )
    micro = scored(all_gold, all_pred)
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
    candidate_metric = scored(candidate_gold, candidate_pred)
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
