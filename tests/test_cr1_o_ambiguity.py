from __future__ import annotations

import pytest

from sentinel.extraction import JobAlertStatus, parse_gmail_fixture_job_alert
from tests.cr1_o_support import gmail_message


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("Company: A\nEmployer: A\nRole: X\n", JobAlertStatus.AMBIGUOUS),
        ("Company: A\nRole: X\nPosition: Y\n", JobAlertStatus.AMBIGUOUS),
        ("Company: A\nRole: X\nLocation: one\nLocation: two\n", JobAlertStatus.AMBIGUOUS),
        (
            "Job opportunity\nCompany: A\nRole: X\nJob opportunity\nCompany: B\nRole: Y\n",
            JobAlertStatus.AMBIGUOUS,
        ),
        ("Company: A\nProse between fields.\nRole: X\n", JobAlertStatus.AMBIGUOUS),
        ("Company: A\n\nRole: X\n", JobAlertStatus.AMBIGUOUS),
        ("> Company: A\n> Role: X\n", JobAlertStatus.NO_MATCH),
        ("A company might be A and the role could be X.\n", JobAlertStatus.NO_MATCH),
        ("Salary: 100 credits\nEmployer: A\nPosition: X\n", JobAlertStatus.CANDIDATE),
        ("Job opportunity\nNo fields yet.\n", JobAlertStatus.INCOMPLETE),
    ],
)
def test_duplicate_multiple_and_unstructured_content_abstains(body, expected) -> None:
    result = parse_gmail_fixture_job_alert(gmail_message(body))
    assert result.status is expected
    if expected is JobAlertStatus.AMBIGUOUS:
        assert all(field.value is None and field.evidence is None for field in result.fields)
