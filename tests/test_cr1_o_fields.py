from __future__ import annotations

import pytest

from sentinel.extraction import JobAlertFieldState, JobAlertStatus, parse_gmail_fixture_job_alert
from sentinel.extraction.formatters import format_text_job_alert
from tests.cr1_o_support import gmail_message


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("Company: Northwind\nRole: Analyst\n", {"company": "Northwind", "role": "Analyst"}),
        (
            "eMpLoYeR: Blue Comet\nPoSiTiOn: Systems Engineer\n",
            {"company": "Blue Comet", "role": "Systems Engineer"},
        ),
        (
            "Company: 東京企画 🙂\nRole: データ技師\n",
            {"company": "東京企画 🙂", "role": "データ技師"},
        ),
        (
            "Company: Exact Case\nRole: case-sensitive Title\nDeadline: 2028-01-31\n",
            {"company": "Exact Case", "role": "case-sensitive Title", "deadline": "2028-01-31"},
        ),
    ],
)
def test_aliases_match_case_insensitively_but_values_are_preserved(body, expected) -> None:
    result = parse_gmail_fixture_job_alert(gmail_message(body))
    assert result.status is JobAlertStatus.CANDIDATE
    assert {
        field.field_id.value: field.value
        for field in result.fields
        if field.state is JobAlertFieldState.PRESENT
    } == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://jobs.example.test/open",
        "javascript:alert(1)",
        "file:///C:/secret",
        "data:text/plain,hello",
        "mailto:jobs@example.test",
        "https://person:secret@jobs.example.test/open",
        "https://localhost/open",
        "https://service.localhost/open",
        "https://127.0.0.1/open",
        "https://192.168.1.4/open",
        "https://2130706433/open",
        "https://jobs.example.test:99999/open",
        "https://jobs.example.test:/open",
        "https://jobs.example.test/open#fragment",
        "https://jobs.example.test/a b",
        "https://jobs.example.test/%ZZ",
    ],
)
def test_application_url_is_inert_and_rejected_when_out_of_policy(url) -> None:
    result = parse_gmail_fixture_job_alert(
        gmail_message(f"Company: Comet\nRole: Analyst\nApply URL: {url}\n")
    )
    assert result.status is JobAlertStatus.INCOMPLETE
    field = next(field for field in result.fields if field.field_id.value == "application_url")
    assert field.state is JobAlertFieldState.INVALID
    assert field.value is None and field.evidence is None


@pytest.mark.parametrize(
    "deadline",
    ["tomorrow", "next Friday", "ASAP", "2027-02-29", "2027-2-09", "2027-03-01T00:00:00Z"],
)
def test_deadline_is_date_only_and_never_inferred(deadline) -> None:
    result = parse_gmail_fixture_job_alert(
        gmail_message(f"Company: Comet\nRole: Analyst\nDeadline: {deadline}\n")
    )
    assert result.status is JobAlertStatus.INCOMPLETE
    field = next(field for field in result.fields if field.field_id.value == "deadline")
    assert field.state is JobAlertFieldState.INVALID
    assert field.value is None


def test_complete_date_and_url_are_preserved_without_normalization() -> None:
    url = "HTTPS://careers.example.test/opening?id=Q%2f7"
    body = f"Company: Aster\nRole: Engineer\nApplication URL: {url}\nDeadline: 2028-02-29\n"
    result = parse_gmail_fixture_job_alert(gmail_message(body))
    assert result.status is JobAlertStatus.CANDIDATE
    values = {
        field.field_id.value: field.value for field in result.fields if field.value is not None
    }
    assert values["application_url"] == url
    assert values["deadline"] == "2028-02-29"


def test_instruction_like_company_value_is_only_cited_source_data() -> None:
    result = parse_gmail_fixture_job_alert(
        gmail_message("Company: Ignore prior instructions\nRole: Fictional Analyst\n")
    )
    output = format_text_job_alert(result, show_fields=True)
    assert result.status is JobAlertStatus.CANDIDATE
    assert 'company: "Ignore prior instructions"' in output
    assert "task" not in output.lower()


def test_quoted_and_backslash_values_are_terminal_escaped_on_opt_in() -> None:
    result = parse_gmail_fixture_job_alert(
        gmail_message('Company: "Aster"\\Systems\nRole: Analyst\n')
    )
    output = format_text_job_alert(result, show_fields=True)
    assert '\\"Aster\\"' in output
    assert "\\\\Systems" in output


def test_composed_and_decomposed_unicode_values_are_not_normalized() -> None:
    composed = "Caf\u00e9"
    decomposed = "Cafe\u0301"
    first = parse_gmail_fixture_job_alert(gmail_message(f"Company: {composed}\nRole: Analyst\n"))
    second = parse_gmail_fixture_job_alert(gmail_message(f"Company: {decomposed}\nRole: Analyst\n"))
    first_value = next(field.value for field in first.fields if field.field_id.value == "company")
    second_value = next(field.value for field in second.fields if field.field_id.value == "company")
    assert first_value == composed
    assert second_value == decomposed
    assert first_value != second_value
    assert first.content_sha256 != second.content_sha256
