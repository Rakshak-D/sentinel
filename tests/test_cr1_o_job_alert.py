from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

import pytest

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.extraction import (
    JobAlertError,
    JobAlertErrorCode,
    JobAlertFieldState,
    JobAlertStatus,
    parse_gmail_fixture_job_alert,
)
from sentinel.normalization import (
    PlainTextSourceDescriptor,
    normalize_plain_text,
    verify_bound_citation,
)
from sentinel.readers import read_packaged_gmail_fixture
from sentinel.readers.types import GmailFixtureMessage
from tests.cr1_o_corpus import CASES
from tests.cr1_o_support import gmail_message


def _field_map(result) -> dict[str, object]:
    return {field.field_id.value: field for field in result.fields}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.case_id)
def test_labeled_synthetic_corpus_has_exact_expected_classification_and_values(case) -> None:
    try:
        result = parse_gmail_fixture_job_alert(
            gmail_message(case.body, message_id=f"case-{case.case_id}")
        )
    except JobAlertError as exc:
        assert case.expected_status == f"ERROR:{exc.code.name}"
        return

    assert result.status.value == case.expected_status
    fields = _field_map(result)
    actual = {
        name: field.value
        for name, field in fields.items()
        if field.state is JobAlertFieldState.PRESENT
    }
    assert actual == dict(case.expected_values)
    assert result.provider_id == "gmail.fixture"
    assert result.synthetic_data is True
    assert result.trust is TrustLabel.T4_EXTERNAL
    assert result.sensitivity is SensitivityLabel.PRIVATE
    for field in result.fields:
        if field.state is JobAlertFieldState.PRESENT:
            assert field.value is not None
            assert field.evidence is not None
            cited = verify_bound_citation(
                result.normalized_source,
                field.evidence.bound_citation,
                expected_text=field.value,
            )
            assert cited == field.value
            raw = result.normalized_source.original_bytes
            assert raw[field.evidence.start_byte : field.evidence.end_byte] == field.value.encode()


def test_existing_pinned_gmail_collection_is_not_misclassified_from_subjects() -> None:
    parsed = tuple(
        parse_gmail_fixture_job_alert(message) for message in read_packaged_gmail_fixture().messages
    )
    assert len(parsed) == 3
    assert all(result.status is JobAlertStatus.NO_MATCH for result in parsed)


def test_repeated_parse_keeps_field_span_identity_stable_and_different_fields_distinct() -> None:
    message = gmail_message("Company: Same\nRole: Same\n")
    first = parse_gmail_fixture_job_alert(message)
    second = parse_gmail_fixture_job_alert(message)
    first_fields = _field_map(first)
    second_fields = _field_map(second)
    company_id = first_fields["company"].evidence.span_id
    role_id = first_fields["role"].evidence.span_id
    assert company_id == second_fields["company"].evidence.span_id
    assert role_id == second_fields["role"].evidence.span_id
    assert company_id != role_id
    assert first_fields["company"].evidence.text_sha256 == hashlib.sha256(b"Same").hexdigest()
    assert first_fields["company"].evidence.start_byte != first_fields["role"].evidence.start_byte


def test_crlf_and_multibyte_values_use_original_utf8_byte_offsets() -> None:
    body = "Job opportunity\r\nCompany: 🚀 Orbit\r\nRole: 東京技師\r\n"
    raw = body.encode()
    result = parse_gmail_fixture_job_alert(gmail_message(body))
    fields = _field_map(result)
    for name, value in {"company": "🚀 Orbit", "role": "東京技師"}.items():
        field = fields[name]
        assert raw[field.evidence.start_byte : field.evidence.end_byte].decode() == value
        assert field.evidence.text_sha256 == hashlib.sha256(value.encode()).hexdigest()
    assert b"\r\n" in raw


def test_invalid_source_labels_identity_digest_and_utf8_fail_closed() -> None:
    valid = gmail_message("Company: Aster\nRole: Engineer\n")
    source = valid.normalized_source
    bad_source_id = normalize_plain_text(
        PlainTextSourceDescriptor(
            source_id=uuid5(NAMESPACE_URL, "wrong-id"),
            provider_id="gmail.fixture",
            observed_at=datetime(2026, 11, 5, tzinfo=UTC),
            trust=TrustLabel.T4_EXTERNAL,
            sensitivity=SensitivityLabel.PRIVATE,
        ),
        source.original_bytes,
        "text/plain; charset=utf-8",
    )
    with pytest.raises(JobAlertError) as error:
        parse_gmail_fixture_job_alert(
            GmailFixtureMessage(
                mailbox_alias=valid.mailbox_alias,
                message_id=valid.message_id,
                thread_id=valid.thread_id,
                internal_date=valid.internal_date,
                subject="do not use",
                normalized_source=bad_source_id,
                citations=(),
            )
        )
    assert error.value.code is JobAlertErrorCode.INVALID_SOURCE


def test_result_repr_does_not_expose_private_field_or_subject_canaries() -> None:
    result = parse_gmail_fixture_job_alert(
        gmail_message(
            "Company: PRIVATE_COMPANY_CANARY\nRole: PRIVATE_ROLE_CANARY\n",
            subject="PRIVATE_SUBJECT_CANARY",
        )
    )
    rendered = repr(result)
    assert "PRIVATE_COMPANY_CANARY" not in rendered
    assert "PRIVATE_ROLE_CANARY" not in rendered
    assert "PRIVATE_SUBJECT_CANARY" not in rendered
    assert "Company:" not in rendered


def test_corpus_evaluation_reports_actual_synthetic_metrics(capsys) -> None:
    actual_counts = {status.value: 0 for status in JobAlertStatus}
    bounded_errors: dict[str, int] = {}
    exact_fields = 0
    expected_fields = 0
    citation_count = 0
    classified_cases = classification_correct = 0
    false_positives = false_negatives = 0
    for case in CASES:
        try:
            result = parse_gmail_fixture_job_alert(
                gmail_message(case.body, message_id=f"eval-{case.case_id}")
            )
        except JobAlertError as exc:
            assert case.expected_status == f"ERROR:{exc.code.name}"
            bounded_errors[exc.code.name] = bounded_errors.get(exc.code.name, 0) + 1
            continue
        classified_cases += 1
        actual_counts[result.status.value] += 1
        classification_correct += result.status.value == case.expected_status
        false_positives += (
            result.status is JobAlertStatus.CANDIDATE and case.expected_status != "CANDIDATE"
        )
        false_negatives += (
            case.expected_status == "CANDIDATE" and result.status is not JobAlertStatus.CANDIDATE
        )
        field_map = _field_map(result)
        actual = {
            name: field.value
            for name, field in field_map.items()
            if field.state is JobAlertFieldState.PRESENT
        }
        expected = dict(case.expected_values)
        expected_fields += len(expected)
        exact_fields += sum(actual.get(name) == value for name, value in expected.items())
        for field in result.fields:
            if field.state is JobAlertFieldState.PRESENT:
                assert field.value is not None and field.evidence is not None
                cited = verify_bound_citation(
                    result.normalized_source,
                    field.evidence.bound_citation,
                    original_bytes=result.normalized_source.original_bytes,
                    expected_text=field.value,
                )
                assert cited == field.value
                citation_count += 1
    print(
        "CORPUS_METRICS "
        + json.dumps(
            {
                "cases": len(CASES),
                "classified_cases": classified_cases,
                "classification_correct": classification_correct,
                "classification_accuracy": classification_correct / classified_cases,
                "counts": actual_counts,
                "bounded_errors": bounded_errors,
                "field_exact_match": exact_fields,
                "field_expected": expected_fields,
                "verified_present_field_citations": citation_count,
                "false_positives": false_positives,
                "false_negatives": false_negatives,
            },
            sort_keys=True,
        )
    )
    captured = capsys.readouterr()
    assert "CORPUS_METRICS" in captured.out
    assert classification_correct == classified_cases == len(CASES) - sum(bounded_errors.values())
    print(captured.out, end="")
