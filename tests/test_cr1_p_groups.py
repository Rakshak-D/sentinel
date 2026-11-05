from __future__ import annotations

from dataclasses import replace

import pytest

from sentinel.extraction.batch import review_selected_job_alerts
from sentinel.extraction.batch_formatters import format_json_job_alert_batch
from sentinel.extraction.batch_types import (
    JobAlertCorrelationKind,
    JobAlertReviewError,
)


def _write(root, name: str, content: str):
    path = root / name
    path.write_bytes(content.encode("utf-8"))
    return path


def test_shared_application_url_is_exact_and_does_not_merge_distinct_roles(tmp_path) -> None:
    root = tmp_path / "sources"
    root.mkdir()
    url = "https://apply.example.test/form?position=one"
    first = _write(root, "one.txt", f"Company: Aster\nRole: Engineer\nApply URL: {url}\n")
    second = _write(root, "two.txt", f"Company: Aster\nRole: Analyst\nApply URL: {url}\n")
    third = _write(
        root,
        "three.txt",
        f"Company: Aster\nRole: Engineer\nApply URL: {url.upper()}\n",
    )

    result = review_selected_job_alerts(allowed_root=root, file_paths=[first, second, third])
    groups = [
        group
        for group in result.correlation_groups
        if group.kind is JobAlertCorrelationKind.SHARED_APPLICATION_URL
    ]
    assert len(groups) == 1
    assert groups[0].member_file_ordinals == (1, 2)
    assert len(result.files) == 3
    assert [item.ordinal for item in result.files] == [1, 2, 3]


def test_invalid_or_missing_urls_do_not_form_shared_url_groups(tmp_path) -> None:
    root = tmp_path / "sources"
    root.mkdir()
    no_url = _write(root, "one.txt", "Company: Aster\nRole: Engineer\n")
    invalid_url = _write(
        root, "two.txt", "Company: Comet\nRole: Analyst\nApply URL: javascript:alert(1)\n"
    )
    result = review_selected_job_alerts(allowed_root=root, file_paths=[no_url, invalid_url])
    assert not any(
        group.kind is JobAlertCorrelationKind.SHARED_APPLICATION_URL
        for group in result.correlation_groups
    )


def test_eight_selected_files_keep_argument_order_and_zero_matches(tmp_path) -> None:
    root = tmp_path / "sources"
    root.mkdir()
    paths = [_write(root, f"{index}.md", f"No alert marker {index}\n") for index in range(8)]
    result = review_selected_job_alerts(allowed_root=root, file_paths=paths)
    assert result.selected_file_count == 8
    assert [item.ordinal for item in result.files] == list(range(1, 9))
    assert all(item.status.value == "NO_MATCH" for item in result.files)
    assert result.classification_counts.no_match == 8
    assert result.citation_count == 0


def test_formatter_rejects_fabricated_or_missing_correlation_group(tmp_path) -> None:
    root = tmp_path / "sources"
    root.mkdir()
    url = "https://apply.example.test/form"
    paths = [
        _write(root, "one.txt", f"Company: Aster\nRole: Engineer\nApply URL: {url}\n"),
        _write(root, "two.txt", f"Company: Comet\nRole: Analyst\nApply URL: {url}\n"),
    ]
    result = review_selected_job_alerts(allowed_root=root, file_paths=paths)
    tampered = replace(result, correlation_groups=())
    with pytest.raises(JobAlertReviewError):
        format_json_job_alert_batch(tampered)
