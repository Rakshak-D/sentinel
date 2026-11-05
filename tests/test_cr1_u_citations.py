from __future__ import annotations

from dataclasses import replace
from uuid import UUID

import pytest

from sentinel.extraction.types import JobAlertFieldName
from sentinel.triage.formatters import format_json_job_alert_triage
from sentinel.triage.job_alert import triage_selected_job_alerts
from sentinel.triage.types import (
    JobAlertTriageError,
    JobAlertTriageErrorCode,
)


def test_tampered_or_cross_source_signal_evidence_is_rejected(tmp_path) -> None:
    root = tmp_path / "alerts"
    root.mkdir()
    first = root / "first.txt"
    second = root / "second.txt"
    first.write_text("Company: Aster\nRole: Engineer\n", encoding="utf-8")
    second.write_text("Company: Comet\nRole: Analyst\n", encoding="utf-8")
    triage = triage_selected_job_alerts(allowed_root=root, file_paths=(first, second))
    signal = triage.items[0].signals[0]
    forged_evidence = replace(signal.evidence[0], source_id=triage.items[1].source_id)
    forged_signal = replace(signal, evidence=(forged_evidence, *signal.evidence[1:]))
    forged_item = replace(triage.items[0], signals=(forged_signal,))
    forged = replace(triage, items=(forged_item, triage.items[1]))

    with pytest.raises(JobAlertTriageError) as error:
        format_json_job_alert_triage(forged)

    assert error.value.code in {
        JobAlertTriageErrorCode.INVALID_RESULT,
        JobAlertTriageErrorCode.SOURCE_INVALID,
    }
    assert str(root) not in str(error.value)


def test_field_kind_mismatch_cannot_support_a_positive_signal(tmp_path) -> None:
    root = tmp_path / "alerts"
    root.mkdir()
    path = root / "candidate.txt"
    path.write_text("Company: Aster\nRole: Engineer\n", encoding="utf-8")
    triage = triage_selected_job_alerts(allowed_root=root, file_paths=(path,))
    signal = triage.items[0].signals[0]
    wrong_field = replace(signal.evidence[0], field_id=JobAlertFieldName.DEADLINE)
    forged = replace(
        triage,
        items=(
            replace(
                triage.items[0],
                signals=(replace(signal, evidence=(wrong_field, *signal.evidence[1:])),),
            ),
        ),
    )

    with pytest.raises(JobAlertTriageError):
        format_json_job_alert_triage(forged)


def test_forged_signal_identity_and_unknown_classification_are_rejected(tmp_path) -> None:
    root = tmp_path / "alerts"
    root.mkdir()
    path = root / "candidate.txt"
    path.write_text("Company: Aster\nRole: Engineer\n", encoding="utf-8")
    triage = triage_selected_job_alerts(allowed_root=root, file_paths=(path,))
    item = triage.items[0]
    signal = item.signals[0]

    forged_signal = replace(signal, signal_id=UUID(int=0))
    with pytest.raises(JobAlertTriageError):
        format_json_job_alert_triage(
            replace(triage, items=(replace(item, signals=(forged_signal,)),))
        )

    with pytest.raises(JobAlertTriageError):
        format_json_job_alert_triage(
            replace(triage, items=(replace(item, classification="candidate"),))
        )
