from __future__ import annotations

import pytest

from sentinel.extraction.batch import review_selected_job_alerts
from sentinel.extraction.batch_types import JobAlertReviewError, JobAlertReviewErrorCode
from tests.test_cr1_p_batch import _candidate, _selected_files


def test_no_files_ninth_file_and_same_file_alias_are_rejected(tmp_path) -> None:
    root, paths = _selected_files(tmp_path, [_candidate("A", "B") for _ in range(9)])
    with pytest.raises(JobAlertReviewError) as empty:
        review_selected_job_alerts(allowed_root=root, file_paths=[])
    assert empty.value.code is JobAlertReviewErrorCode.INVALID_SELECTION
    with pytest.raises(JobAlertReviewError) as ninth:
        review_selected_job_alerts(allowed_root=root, file_paths=paths)
    assert ninth.value.code is JobAlertReviewErrorCode.TOO_MANY_FILES
    alias = paths[0].with_name(paths[0].name.upper())
    with pytest.raises(JobAlertReviewError) as duplicate:
        review_selected_job_alerts(allowed_root=root, file_paths=[paths[0], alias])
    assert duplicate.value.code is JobAlertReviewErrorCode.DUPLICATE_FILE


def test_file_policy_and_parser_limits_reject_whole_batch(tmp_path) -> None:
    root, paths = _selected_files(tmp_path, [_candidate("A", "B")])
    outside = tmp_path / "outside.txt"
    outside.write_text(_candidate("Outside", "File"), encoding="utf-8")
    unsupported = root / "alert.csv"
    unsupported.write_text("Company: A\nRole: B", encoding="utf-8")
    invalid_utf8 = root / "invalid.txt"
    invalid_utf8.write_bytes(b"Company: A\nRole: \xff")
    oversized = root / "large.txt"
    oversized.write_bytes(b"x" * 65_537)
    for selected in ([outside], [unsupported], [invalid_utf8], [oversized]):
        with pytest.raises(JobAlertReviewError):
            review_selected_job_alerts(allowed_root=root, file_paths=selected)
    with pytest.raises(JobAlertReviewError):
        review_selected_job_alerts(allowed_root=root, file_paths=[paths[0], "relative.txt"])


def test_whole_batch_rejects_parser_citation_tampering(monkeypatch, tmp_path) -> None:
    from dataclasses import replace

    from sentinel.extraction import batch

    root, paths = _selected_files(tmp_path, [_candidate("Aster", "Engineer")])
    valid = batch.parse_local_job_alert(allowed_root=root, file_path=paths[0])
    field = valid.fields[0]
    evidence = replace(field.evidence, end_byte=field.evidence.end_byte + 1)
    invalid_field = replace(field, evidence=evidence)
    invalid = replace(valid, fields=(invalid_field, *valid.fields[1:]))
    monkeypatch.setattr(batch, "parse_local_job_alert", lambda **_kwargs: invalid)
    with pytest.raises(JobAlertReviewError) as error:
        review_selected_job_alerts(allowed_root=root, file_paths=paths)
    assert error.value.code is JobAlertReviewErrorCode.SOURCE_INVALID


def test_failure_errors_are_bounded_and_do_not_echo_paths_or_content(tmp_path) -> None:
    root, paths = _selected_files(tmp_path, [_candidate("PRIVATE_SOURCE_CANARY", "Engineer")])
    with pytest.raises(JobAlertReviewError) as error:
        review_selected_job_alerts(allowed_root=root, file_paths=[paths[0], root / "missing.txt"])
    assert str(root) not in str(error.value)
    assert "PRIVATE_SOURCE_CANARY" not in str(error.value)
