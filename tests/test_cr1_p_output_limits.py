from __future__ import annotations

import pytest

from sentinel.extraction import batch_formatters
from sentinel.extraction.batch import review_selected_job_alerts
from sentinel.extraction.batch_types import JobAlertReviewError, JobAlertReviewErrorCode
from tests.test_cr1_p_batch import _candidate, _selected_files


def test_formatter_rejects_result_above_fixed_output_byte_limit(monkeypatch, tmp_path) -> None:
    root, paths = _selected_files(tmp_path, [_candidate("Aster", "Engineer")])
    review = review_selected_job_alerts(allowed_root=root, file_paths=paths)
    monkeypatch.setattr(batch_formatters, "MAX_RENDERED_OUTPUT_BYTES", 32)
    with pytest.raises(JobAlertReviewError) as error:
        batch_formatters.format_json_job_alert_batch(review)
    assert error.value.code is JobAlertReviewErrorCode.OUTPUT_TOO_LARGE
