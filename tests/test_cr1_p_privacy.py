from __future__ import annotations

import json
import sqlite3

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.extraction.batch import review_selected_job_alerts
from sentinel.extraction.batch_formatters import format_json_job_alert_batch
from tests.test_cr1_p_batch import _candidate, _selected_files


def test_default_metadata_has_no_values_paths_or_filename_and_opt_in_escapes(
    monkeypatch, tmp_path
) -> None:
    root, paths = _selected_files(
        tmp_path,
        [_candidate("PRIVATE_EMPLOYER_CANARY", "Private Analyst", "https://apply.example.test/a")],
    )
    before = tuple(sorted(path.name for path in root.iterdir()))
    sqlite_calls = 0

    def forbid_sqlite(*_args, **_kwargs):
        nonlocal sqlite_calls
        sqlite_calls += 1
        raise AssertionError("SQLite must not be used by batch review")

    monkeypatch.setattr(sqlite3, "connect", forbid_sqlite)
    result = review_selected_job_alerts(allowed_root=root, file_paths=paths)
    hidden = format_json_job_alert_batch(result)
    shown = format_json_job_alert_batch(result, show_fields=True)
    assert "PRIVATE_EMPLOYER_CANARY" not in hidden
    assert str(root) not in hidden and paths[0].name not in hidden
    assert "PRIVATE_EMPLOYER_CANARY" in shown
    document = json.loads(hidden)
    assert document["trust"] == TrustLabel.T4_EXTERNAL.value
    assert document["sensitivity"] == SensitivityLabel.PRIVATE.value
    assert document["synthetic_data"] is False
    assert document["values_included"] is False
    assert sqlite_calls == 0
    assert tuple(sorted(path.name for path in root.iterdir())) == before
