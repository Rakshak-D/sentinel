from __future__ import annotations

import hashlib

from sentinel.extraction import JobAlertFieldState, parse_gmail_fixture_job_alert
from sentinel.normalization import verify_bound_citation
from tests.cr1_o_support import gmail_message


def test_each_present_field_has_exact_source_bound_byte_evidence() -> None:
    body = (
        "Job opportunity\r\n"
        "Company: 🚀 Kumo Labs\r\n"
        "Role: 日本語データ技師\r\n"
        "Location: 東京\r\n"
        "Apply URL: https://jobs.kumo.example.test/open\r\n"
        "Deadline: 2027-09-30\r\n"
    )
    result = parse_gmail_fixture_job_alert(gmail_message(body))
    raw = body.encode("utf-8")
    for field in result.fields:
        if field.state is not JobAlertFieldState.PRESENT:
            continue
        assert field.value is not None and field.evidence is not None
        evidence = field.evidence
        assert evidence.source_id == result.source_id
        assert evidence.content_sha256 == hashlib.sha256(raw).hexdigest()
        assert raw[evidence.start_byte : evidence.end_byte].decode("utf-8") == field.value
        assert evidence.text_sha256 == hashlib.sha256(field.value.encode("utf-8")).hexdigest()
        assert (
            verify_bound_citation(
                result.normalized_source,
                evidence.bound_citation,
                original_bytes=raw,
                expected_text=field.value,
            )
            == field.value
        )


def test_same_field_value_at_distinct_byte_ranges_has_distinct_span_ids() -> None:
    body = "Company: Repeated\r\nRole: Repeated\r\n"
    result = parse_gmail_fixture_job_alert(gmail_message(body))
    company = next(field for field in result.fields if field.field_id.value == "company")
    role = next(field for field in result.fields if field.field_id.value == "role")
    assert company.value == role.value == "Repeated"
    assert company.evidence.text_sha256 == role.evidence.text_sha256
    assert company.evidence.start_byte != role.evidence.start_byte
    assert company.evidence.span_id != role.evidence.span_id


def test_field_span_uuid_is_stable_and_domain_separated_by_field() -> None:
    message = gmail_message("Company: Generalist\nRole: Generalist\n")
    first = parse_gmail_fixture_job_alert(message)
    second = parse_gmail_fixture_job_alert(message)
    first_by_name = {field.field_id.value: field for field in first.fields}
    second_by_name = {field.field_id.value: field for field in second.fields}
    assert first_by_name["company"].evidence.span_id == second_by_name["company"].evidence.span_id
    assert first_by_name["role"].evidence.span_id == second_by_name["role"].evidence.span_id
    assert first_by_name["company"].evidence.span_id != first_by_name["role"].evidence.span_id
