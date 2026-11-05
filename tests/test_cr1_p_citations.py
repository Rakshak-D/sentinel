from __future__ import annotations

from dataclasses import replace

import pytest

from sentinel.extraction import batch
from sentinel.extraction.batch import review_selected_job_alerts
from sentinel.extraction.batch_types import JobAlertReviewError
from sentinel.extraction.types import JobAlertFieldState
from tests.test_cr1_p_batch import _candidate, _selected_files


def test_each_present_field_preserves_original_source_and_span_evidence(tmp_path) -> None:
    body = _candidate("東京技師 🚀", "Senior Engineer")
    root, paths = _selected_files(tmp_path, [body])
    result = review_selected_job_alerts(allowed_root=root, file_paths=paths)
    parsed = result.files[0].result
    raw = body.encode("utf-8")
    present = [field for field in parsed.fields if field.state is JobAlertFieldState.PRESENT]
    assert len(present) == 2
    for field in present:
        assert field.value is not None and field.evidence is not None
        evidence = field.evidence
        assert evidence.source_id == parsed.source_id
        assert evidence.content_sha256 == parsed.content_sha256
        assert raw[evidence.start_byte : evidence.end_byte].decode("utf-8") == field.value


def test_tampered_field_span_and_cross_source_citation_fail_closed(monkeypatch, tmp_path) -> None:
    root, paths = _selected_files(
        tmp_path,
        [_candidate("Aster", "Engineer"), _candidate("Comet", "Analyst")],
    )
    originals = batch.parse_local_job_alert
    parsed = [originals(allowed_root=root, file_path=path) for path in paths]
    company = parsed[1].fields[0]
    forged_evidence = replace(company.evidence, source_id=parsed[0].source_id)
    forged_field = replace(company, evidence=forged_evidence)
    forged_result = replace(parsed[1], fields=(forged_field, *parsed[1].fields[1:]))
    calls = 0

    def forged_parser(*, allowed_root, file_path):
        nonlocal calls
        calls += 1
        return forged_result if calls == 1 else parsed[1]

    monkeypatch.setattr(batch, "parse_local_job_alert", forged_parser)
    with pytest.raises(JobAlertReviewError):
        review_selected_job_alerts(allowed_root=root, file_paths=[paths[1]])
