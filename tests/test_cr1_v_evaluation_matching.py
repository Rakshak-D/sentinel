from __future__ import annotations

from dataclasses import replace

import pytest

from sentinel.extraction.types import JobAlertFieldName, JobAlertStatus
from sentinel.triage.evaluation import evaluate_job_alert_triage
from sentinel.triage.job_alert import triage_selected_job_alerts
from sentinel.triage.types import (
    JobAlertEvaluationLabel,
    JobAlertEvaluationObservation,
    JobAlertExpectedSignal,
    JobAlertSignalKind,
    JobAlertTriageError,
)


def _read_triage(tmp_path, case_id: str, *, url: bool = False, deadline: bool = False,
                 unrelated: bool = False):
    root = tmp_path / "sources"
    root.mkdir(exist_ok=True)
    path = root / f"{case_id}.txt"
    if unrelated:
        body = "A fictional package update.\n"
    else:
        lines = [f"Company: Company {case_id}", f"Role: Analyst {case_id}"]
        if url:
            lines.append(f"Apply URL: https://jobs.{case_id}.example.test/apply")
        if deadline:
            lines.append("Deadline: 2027-04-30")
        body = "\n".join(lines) + "\n"
    path.write_text(body, encoding="utf-8", newline="")
    return triage_selected_job_alerts(allowed_root=root, file_paths=(path,))


def _signal(kind: JobAlertSignalKind) -> JobAlertExpectedSignal:
    fields = {
        JobAlertSignalKind.JOB_ALERT_CANDIDATE: (
            JobAlertFieldName.COMPANY,
            JobAlertFieldName.ROLE,
        ),
        JobAlertSignalKind.APPLICATION_URL_DECLARED: (JobAlertFieldName.APPLICATION_URL,),
        JobAlertSignalKind.DEADLINE_DATE_DECLARED: (JobAlertFieldName.DEADLINE,),
    }
    return JobAlertExpectedSignal(kind=kind, evidence_fields=fields[kind])


def _label(
    case_id: str,
    classification: JobAlertStatus | None,
    *signals: JobAlertSignalKind,
    error_code: str | None = None,
) -> JobAlertEvaluationLabel:
    return JobAlertEvaluationLabel(
        case_id=case_id,
        expected_classification=classification,
        expected_signals=tuple(_signal(kind) for kind in signals),
        expected_error_code=error_code,
    )


def _observation(case_id: str, triage) -> JobAlertEvaluationObservation:
    return JobAlertEvaluationObservation(case_id=case_id, triage=triage)


def _evaluate(labels, observations):
    return evaluate_job_alert_triage(
        dataset_id="holdout", labels=tuple(labels), observations=tuple(observations)
    )


def _metric(report, kind: JobAlertSignalKind):
    return next(entry.metric for entry in report.per_signal_metrics if entry.kind is kind)


def test_url_swap_between_cases_does_not_receive_cross_case_true_positive(tmp_path) -> None:
    expected_url = JobAlertSignalKind.APPLICATION_URL_DECLARED
    candidate = JobAlertSignalKind.JOB_ALERT_CANDIDATE
    labels = (
        _label("case-a", JobAlertStatus.CANDIDATE, candidate, expected_url),
        _label("case-b", JobAlertStatus.CANDIDATE, candidate),
    )
    observations = (
        _observation("case-a", _read_triage(tmp_path, "case-a")),
        _observation("case-b", _read_triage(tmp_path, "case-b", url=True)),
    )

    report = _evaluate(labels, observations)

    url_metric = _metric(report, expected_url)
    assert (url_metric.true_positive, url_metric.false_positive, url_metric.false_negative) == (
        0,
        1,
        1,
    )
    assert (url_metric.precision, url_metric.recall, url_metric.f1) == (0.0, 0.0, 0.0)


def test_candidate_swap_between_cases_does_not_receive_cross_case_credit(tmp_path) -> None:
    candidate = JobAlertSignalKind.JOB_ALERT_CANDIDATE
    labels = (
        _label("candidate-a", JobAlertStatus.CANDIDATE, candidate),
        _label("candidate-b", JobAlertStatus.NO_MATCH),
    )
    observations = (
        _observation("candidate-a", _read_triage(tmp_path, "candidate-a", unrelated=True)),
        _observation("candidate-b", _read_triage(tmp_path, "candidate-b")),
    )

    report = _evaluate(labels, observations)

    metric = report.candidate_signal_metric
    assert (metric.true_positive, metric.false_positive, metric.false_negative) == (0, 1, 1)
    assert report.classification_confusion[0].predicted_counts == (0, 0, 0, 1, 0)
    assert report.classification_confusion[3].predicted_counts == (1, 0, 0, 0, 0)
    assert sum(report.classification_confusion[0].predicted_counts) == 1
    assert sum(report.classification_confusion[3].predicted_counts) == 1


def test_deadline_swap_between_cases_does_not_receive_cross_case_credit(tmp_path) -> None:
    candidate = JobAlertSignalKind.JOB_ALERT_CANDIDATE
    deadline = JobAlertSignalKind.DEADLINE_DATE_DECLARED
    labels = (
        _label("deadline-a", JobAlertStatus.CANDIDATE, candidate, deadline),
        _label("deadline-b", JobAlertStatus.CANDIDATE, candidate),
    )
    observations = (
        _observation("deadline-a", _read_triage(tmp_path, "deadline-a")),
        _observation("deadline-b", _read_triage(tmp_path, "deadline-b", deadline=True)),
    )

    report = _evaluate(labels, observations)

    metric = _metric(report, deadline)
    assert (metric.true_positive, metric.false_positive, metric.false_negative) == (0, 1, 1)


def test_exact_case_local_matches_and_partial_matches_score_independently(tmp_path) -> None:
    candidate = JobAlertSignalKind.JOB_ALERT_CANDIDATE
    url = JobAlertSignalKind.APPLICATION_URL_DECLARED
    deadline = JobAlertSignalKind.DEADLINE_DATE_DECLARED
    labels = (
        _label("all-signals", JobAlertStatus.CANDIDATE, candidate, url, deadline),
        _label("partial", JobAlertStatus.CANDIDATE, candidate, url),
    )
    observations = (
        _observation(
            "all-signals", _read_triage(tmp_path, "all-signals", url=True, deadline=True)
        ),
        _observation("partial", _read_triage(tmp_path, "partial")),
    )

    report = _evaluate(labels, observations)

    assert (report.candidate_signal_metric.true_positive,
            report.candidate_signal_metric.false_positive,
            report.candidate_signal_metric.false_negative) == (2, 0, 0)
    assert (_metric(report, url).true_positive, _metric(report, url).false_positive,
            _metric(report, url).false_negative) == (1, 0, 1)
    assert (_metric(report, deadline).true_positive, _metric(report, deadline).false_positive,
            _metric(report, deadline).false_negative) == (1, 0, 0)
    assert (report.micro_signal_metric.true_positive,
            report.micro_signal_metric.false_positive,
            report.micro_signal_metric.false_negative) == (4, 0, 1)
    assert report.micro_signal_metric.f1 == pytest.approx(8 / 9)
    assert report.macro_signal_f1 == pytest.approx(
        (1.0 + 2 / 3 + 1.0) / 3
    )
    assert report.exact_signal_rule == "case_local_kind_and_required_field_ids"
    assert report.incorrect_abstention_count == 0


def test_unexpected_acceptance_is_false_positive_and_unexpected_rejection_is_false_negative(
    tmp_path,
) -> None:
    candidate = JobAlertSignalKind.JOB_ALERT_CANDIDATE
    accepted = _read_triage(tmp_path, "unexpectedly-accepted")
    accepted_report = _evaluate(
        (_label("unexpectedly-accepted", None, error_code="source_invalid"),),
        (_observation("unexpectedly-accepted", accepted),),
    )
    assert accepted_report.unexpected_failure_count == 1
    assert (accepted_report.candidate_signal_metric.true_positive,
            accepted_report.candidate_signal_metric.false_positive,
            accepted_report.candidate_signal_metric.false_negative) == (0, 1, 0)

    rejected_report = _evaluate(
        (_label("unexpectedly-rejected", JobAlertStatus.CANDIDATE, candidate),),
        (JobAlertEvaluationObservation(
            case_id="unexpectedly-rejected", triage=None, failure_code="source_invalid"
        ),),
    )
    assert rejected_report.unexpected_failure_count == 1
    assert rejected_report.rejected_case_count == 1
    assert rejected_report.false_negative_candidate_count == 1
    assert rejected_report.classification_confusion[0].predicted_counts == (0, 0, 0, 0, 1)


def test_no_positive_split_uses_zero_denominator_convention(tmp_path) -> None:
    triage = _read_triage(tmp_path, "no-positive", unrelated=True)
    report = _evaluate(
        (_label("no-positive", JobAlertStatus.NO_MATCH),),
        (_observation("no-positive", triage),),
    )

    assert report.candidate_signal_metric.f1 == 0.0
    assert report.micro_signal_metric.f1 == 0.0
    assert report.macro_signal_f1 == 0.0
    assert all(entry.metric.f1 == 0.0 for entry in report.per_signal_metrics)
    assert report.classification_accuracy == 1.0


def test_together_reordering_preserves_metrics_but_misalignment_is_rejected(tmp_path) -> None:
    candidate = JobAlertSignalKind.JOB_ALERT_CANDIDATE
    labels = (
        _label("ordered-a", JobAlertStatus.CANDIDATE, candidate),
        _label("ordered-b", JobAlertStatus.NO_MATCH),
    )
    observations = (
        _observation("ordered-a", _read_triage(tmp_path, "ordered-a")),
        _observation("ordered-b", _read_triage(tmp_path, "ordered-b", unrelated=True)),
    )
    original = _evaluate(labels, observations)
    reordered = _evaluate(labels[::-1], observations[::-1])

    assert original.candidate_signal_metric == reordered.candidate_signal_metric
    assert original.micro_signal_metric == reordered.micro_signal_metric
    assert original.macro_signal_f1 == reordered.macro_signal_f1
    with pytest.raises(JobAlertTriageError):
        _evaluate(labels, observations[::-1])


@pytest.mark.parametrize("case_id", ["duplicate", "bad case", "bad\ncase", "é-case"])
def test_duplicate_or_malformed_case_ids_are_rejected(tmp_path, case_id: str) -> None:
    triage = _read_triage(tmp_path, "identity")
    label = _label(case_id, JobAlertStatus.CANDIDATE, JobAlertSignalKind.JOB_ALERT_CANDIDATE)
    observation = _observation(case_id, triage)
    labels = (label, label) if case_id == "duplicate" else (label,)
    observations = (observation, observation) if case_id == "duplicate" else (observation,)

    with pytest.raises(JobAlertTriageError):
        _evaluate(labels, observations)


def test_duplicate_expected_signal_kind_is_rejected(tmp_path) -> None:
    triage = _read_triage(tmp_path, "duplicate-label")
    candidate = JobAlertSignalKind.JOB_ALERT_CANDIDATE
    with pytest.raises(JobAlertTriageError):
        _evaluate(
            (_label("duplicate-label", JobAlertStatus.CANDIDATE, candidate, candidate),),
            (_observation("duplicate-label", triage),),
        )


def test_wrong_expected_signal_field_grammar_is_rejected(tmp_path) -> None:
    triage = _read_triage(tmp_path, "wrong-field")
    candidate = JobAlertSignalKind.JOB_ALERT_CANDIDATE
    malformed = replace(
        _signal(candidate), evidence_fields=(JobAlertFieldName.ROLE,)
    )
    label = replace(
        _label("wrong-field", JobAlertStatus.CANDIDATE, candidate),
        expected_signals=(malformed,),
    )

    with pytest.raises(JobAlertTriageError):
        _evaluate((label,), (_observation("wrong-field", triage),))


def test_tampered_citation_never_receives_positive_signal_credit(tmp_path) -> None:
    candidate = JobAlertSignalKind.JOB_ALERT_CANDIDATE
    triage = _read_triage(tmp_path, "tampered")
    item = triage.items[0]
    signal = item.signals[0]
    invalid_evidence = replace(signal.evidence[0], text_sha256="0" * 64)
    invalid_signal = replace(signal, evidence=(invalid_evidence, *signal.evidence[1:]))
    tampered = replace(triage, items=(replace(item, signals=(invalid_signal,)),))

    report = _evaluate(
        (_label("tampered", JobAlertStatus.CANDIDATE, candidate),),
        (_observation("tampered", tampered),),
    )

    assert report.candidate_signal_metric.true_positive == 0
    assert report.candidate_signal_metric.false_negative == 1
    assert report.verified_citation_count == 1
    assert report.invalid_citation_count == 1
    assert report.missing_evidence_count == 0


def test_cross_source_citation_is_invalid_and_never_scores(tmp_path) -> None:
    candidate = JobAlertSignalKind.JOB_ALERT_CANDIDATE
    triage = _read_triage(tmp_path, "cross-source")
    other = _read_triage(tmp_path, "other-source")
    item = triage.items[0]
    signal = item.signals[0]
    foreign = replace(
        signal.evidence[0],
        source_id=other.items[0].source_id,
        content_sha256=other.items[0].content_sha256,
    )
    tampered = replace(
        triage,
        items=(
            replace(
                item,
                signals=(replace(signal, evidence=(foreign, *signal.evidence[1:])),),
            ),
        ),
    )

    report = _evaluate(
        (_label("cross-source", JobAlertStatus.CANDIDATE, candidate),),
        (_observation("cross-source", tampered),),
    )

    assert report.candidate_signal_metric.true_positive == 0
    assert report.candidate_signal_metric.false_negative == 1
    assert report.cross_source_evidence_error_count == 1
    assert report.invalid_citation_count == 1


def test_wrong_actual_signal_field_grammar_is_unscored(tmp_path) -> None:
    candidate = JobAlertSignalKind.JOB_ALERT_CANDIDATE
    triage = _read_triage(tmp_path, "wrong-actual-field")
    item = triage.items[0]
    signal = item.signals[0]
    invalid_field = replace(signal.evidence[0], field_id=JobAlertFieldName.DEADLINE)
    tampered = replace(
        triage,
        items=(
            replace(
                item,
                signals=(replace(signal, evidence=(invalid_field, *signal.evidence[1:])),),
            ),
        ),
    )

    report = _evaluate(
        (_label("wrong-actual-field", JobAlertStatus.CANDIDATE, candidate),),
        (_observation("wrong-actual-field", tampered),),
    )

    assert report.candidate_signal_metric.true_positive == 0
    assert report.candidate_signal_metric.false_negative == 1
    assert report.invalid_citation_count == 1


def test_multifile_triage_cannot_be_scored_as_one_evaluation_case(tmp_path) -> None:
    root = tmp_path / "multiple"
    root.mkdir()
    first = root / "first.txt"
    second = root / "second.txt"
    first.write_text("Company: First Co\nRole: Analyst\n", encoding="utf-8")
    second.write_text("Company: Second Co\nRole: Designer\n", encoding="utf-8")
    triage = triage_selected_job_alerts(allowed_root=root, file_paths=(first, second))
    candidate = JobAlertSignalKind.JOB_ALERT_CANDIDATE

    report = _evaluate(
        (_label("one-case", JobAlertStatus.CANDIDATE, candidate),),
        (_observation("one-case", triage),),
    )

    assert report.candidate_signal_metric.true_positive == 0
    assert report.candidate_signal_metric.false_positive == 0
    assert report.candidate_signal_metric.false_negative == 1
    assert report.rejected_case_count == 1
    assert report.unexpected_failure_count == 1
    assert report.classification_confusion[0].predicted_counts == (0, 0, 0, 0, 1)
