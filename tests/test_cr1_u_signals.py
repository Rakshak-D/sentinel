from __future__ import annotations

from sentinel.briefing.formatters import escape_display_text
from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.extraction.types import JobAlertFieldName, JobAlertStatus
from sentinel.triage.job_alert import triage_selected_job_alerts
from sentinel.triage.types import JobAlertSignalKind


def test_signal_provenance_and_utf8_citations_are_source_bound(tmp_path) -> None:
    root = tmp_path / "alerts"
    root.mkdir()
    body = (
        "Company: 星の研究室 🚀\r\n"
        "Role: 東京のデータ担当\r\n"
        "Apply URL: https://jobs.sakura.example.test/role\r\n"
        "Deadline: 2028-03-01\r\n"
    )
    path = root / "unicode.txt"
    path.write_bytes(body.encode("utf-8"))

    result = triage_selected_job_alerts(allowed_root=root, file_paths=(path,))
    item = result.items[0]
    assert item.classification is JobAlertStatus.CANDIDATE
    assert item.result.trust is TrustLabel.T4_EXTERNAL
    assert item.result.sensitivity is SensitivityLabel.PRIVATE

    for signal in item.signals:
        assert signal.trust is TrustLabel.T3_DERIVED
        assert signal.sensitivity is SensitivityLabel.PRIVATE
        for evidence in signal.evidence:
            assert evidence.source_trust is TrustLabel.T4_EXTERNAL
            assert evidence.source_sensitivity is SensitivityLabel.PRIVATE
            assert evidence.source_id == item.result.source_id
            assert evidence.content_sha256 == item.result.content_sha256
            field = next(
                field for field in item.result.fields if field.field_id is evidence.field_id
            )
            assert field.evidence is not None
            assert evidence.span_id == field.evidence.span_id
            assert evidence.start_byte == field.evidence.start_byte
            assert evidence.end_byte == field.evidence.end_byte
            assert evidence.text_sha256 == field.evidence.text_sha256
            assert (
                item.result.normalized_source.original_bytes[
                    evidence.start_byte : evidence.end_byte
                ].decode("utf-8")
                == field.value
            )
            assert evidence.end_byte > evidence.start_byte

    company = next(
        field for field in item.result.fields if field.field_id is JobAlertFieldName.COMPANY
    )
    assert company.value == "星の研究室 🚀"
    assert JobAlertSignalKind.JOB_ALERT_CANDIDATE in [signal.kind for signal in item.signals]
    assert escape_display_text(company.value) == company.value


def test_candidate_signal_ids_bind_source_kind_and_span_set(tmp_path) -> None:
    root = tmp_path / "alerts"
    root.mkdir()
    source = root / "candidate.txt"
    source.write_text("Company: Aster\nRole: Engineer\n", encoding="utf-8")
    original = triage_selected_job_alerts(allowed_root=root, file_paths=(source,))
    original_signal = original.items[0].signals[0]
    source.write_text("Company: Aster\nRole: Designer\n", encoding="utf-8")
    changed = triage_selected_job_alerts(allowed_root=root, file_paths=(source,))
    assert original_signal.kind is JobAlertSignalKind.JOB_ALERT_CANDIDATE
    assert original_signal.signal_id != changed.items[0].signals[0].signal_id
