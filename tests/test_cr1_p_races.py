from __future__ import annotations

from sentinel.extraction.batch import review_selected_job_alerts
from sentinel.extraction.batch_types import JobAlertReviewError, JobAlertReviewErrorCode
from tests.test_cr1_p_batch import _candidate, _selected_files


def test_mutation_between_parse_and_final_reread_is_rejected(monkeypatch, tmp_path) -> None:
    from sentinel.extraction import batch
    from sentinel.readers import local_text as local_reader

    root, paths = _selected_files(tmp_path, [_candidate("Aster", "Engineer")])
    real_read = local_reader.read_allowlisted_local_text
    count = 0

    def changing_read(*, allowed_root, file_path):
        nonlocal count
        count += 1
        if count == 2:
            file_path.write_text(_candidate("Comet", "Analyst"), encoding="utf-8")
        return real_read(allowed_root=allowed_root, file_path=file_path)

    monkeypatch.setattr(batch, "read_allowlisted_local_text", changing_read)
    try:
        review_selected_job_alerts(allowed_root=root, file_paths=paths)
    except JobAlertReviewError as error:
        assert error.code is JobAlertReviewErrorCode.SOURCE_CHANGED
    else:
        raise AssertionError("changed file must invalidate the complete batch")
