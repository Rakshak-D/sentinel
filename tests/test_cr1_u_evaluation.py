from __future__ import annotations

import json

import pytest

from sentinel.extraction.types import JobAlertFieldName, JobAlertStatus
from sentinel.triage.evaluation import evaluate_job_alert_triage, format_json_job_alert_evaluation
from sentinel.triage.job_alert import triage_selected_job_alerts
from sentinel.triage.types import (
    JobAlertEvaluationLabel,
    JobAlertEvaluationObservation,
    JobAlertExpectedSignal,
    JobAlertSignalKind,
    JobAlertTriageError,
)
from tests.cr1_u_corpus import decode_corpus_case, load_cr1_u_corpus


def _build_split(dataset_id, corpus, manifest, tmp_path):
    labels_by_id = {entry["case_id"]: entry for entry in manifest[dataset_id]}
    root = tmp_path / dataset_id
    root.mkdir()
    labels = []
    observations = []
    for case in corpus["cases"]:
        label = labels_by_id[case["case_id"]]
        expected = label["expected_classification"]
        expected_status = None if expected == "INPUT_REJECTED" else JobAlertStatus(expected)
        expected_signals = tuple(
            JobAlertExpectedSignal(
                kind=JobAlertSignalKind[signal["kind"]],
                evidence_fields=tuple(
                    JobAlertFieldName(field) for field in signal["evidence_fields"]
                ),
            )
            for signal in label["expected_signals"]
        )
        labels.append(
            JobAlertEvaluationLabel(
                case_id=case["case_id"],
                expected_classification=expected_status,
                expected_signals=expected_signals,
                expected_error_code=label.get("expected_error_code"),
            )
        )
        path = root / f"{case['case_id']}.txt"
        path.write_bytes(decode_corpus_case(case))
        try:
            result = triage_selected_job_alerts(allowed_root=root, file_paths=(path,))
        except JobAlertTriageError as error:
            observations.append(
                JobAlertEvaluationObservation(
                    case_id=case["case_id"], triage=None, failure_code=error.code.value
                )
            )
        else:
            observations.append(
                JobAlertEvaluationObservation(case_id=case["case_id"], triage=result)
            )
    return tuple(labels), tuple(observations)


def test_fixed_development_and_holdout_evaluation_uses_actual_triage(tmp_path) -> None:
    development, holdout, manifest = load_cr1_u_corpus()
    assert len(development["cases"]) == 24
    assert len(holdout["cases"]) == 30

    results = {}
    for dataset_id, corpus in (("development", development), ("holdout", holdout)):
        labels, observations = _build_split(dataset_id, corpus, manifest, tmp_path)
        report = evaluate_job_alert_triage(
            dataset_id=dataset_id, labels=labels, observations=observations
        )
        output = format_json_job_alert_evaluation(report)
        results[dataset_id] = json.loads(output)
        assert format_json_job_alert_evaluation(report) == output
        assert results[dataset_id]["case_count"] == len(corpus["cases"])
        assert results[dataset_id]["invalid_citation_count"] == 0
        assert results[dataset_id]["cross_source_evidence_error_count"] == 0
        assert results[dataset_id]["verified_citation_count"] > 0
        assert (
            results[dataset_id]["exact_signal_rule"]
            == "case_local_kind_and_required_field_ids"
        )
        for row in report.classification_confusion:
            expected_row_count = sum(
                label.expected_classification is row.expected for label in labels
            )
            assert sum(row.predicted_counts) == expected_row_count

    holdout_report = results["holdout"]
    assert holdout_report["candidate_signal_metric"]["true_positive"] == 12
    assert holdout_report["false_negative_candidate_count"] == 2
    assert holdout_report["incorrect_abstention_count"] == 2
    assert holdout_report["missing_evidence_count"] == 0
    assert holdout_report["candidate_signal_metric"]["precision"] == 1.0
    assert holdout_report["candidate_signal_metric"]["recall"] == 12 / 14
    assert holdout_report["candidate_signal_metric"]["f1"] == pytest.approx(12 / 13)
    assert holdout_report["classification_accuracy"] == 26 / 28
    assert holdout_report["false_positive_candidate_count"] == 0
    assert holdout_report["per_signal_metrics"][1]["f1"] == 1.0
    assert holdout_report["per_signal_metrics"][2]["f1"] == 1.0
    assert holdout_report["micro_signal_metric"]["f1"] < 1.0


def test_evaluator_counts_an_unexpectedly_accepted_invalid_case_as_false_positive(tmp_path) -> None:
    root = tmp_path / "alerts"
    root.mkdir()
    path = root / "accepted.txt"
    path.write_text("Company: Fictional\nRole: Analyst\n", encoding="utf-8")
    actual = triage_selected_job_alerts(allowed_root=root, file_paths=(path,))
    labels = (
        JobAlertEvaluationLabel(
            case_id="invalid-case",
            expected_classification=None,
            expected_signals=(),
            expected_error_code="source_invalid",
        ),
    )
    observations = (JobAlertEvaluationObservation(case_id="invalid-case", triage=actual),)
    report = evaluate_job_alert_triage(
        dataset_id="holdout", labels=labels, observations=observations
    )
    assert report.unexpected_failure_count == 1
    assert report.false_positive_candidate_count == 1
