from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

import pytest

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.extraction import (
    JobAlertError,
    JobAlertErrorCode,
    JobAlertStatus,
    parse_gmail_fixture_job_alert,
)
from sentinel.normalization import (
    NormalizedPlainTextSource,
    PlainTextSourceDescriptor,
    normalize_plain_text,
)
from sentinel.readers import read_packaged_gmail_fixture
from tests.cr1_o_support import gmail_message


def test_gmail_body_is_parsed_but_subject_is_never_an_evidence_source() -> None:
    body_only_non_job = gmail_message(
        "A note about a role may arrive later.\n", subject="AI Intern Opening"
    )
    result = parse_gmail_fixture_job_alert(body_only_non_job)
    assert result.status is JobAlertStatus.NO_MATCH
    assert result.fields[0].value is None


def test_existing_gmail_fixture_messages_are_not_a_job_alert_corpus() -> None:
    read = read_packaged_gmail_fixture()
    parsed = tuple(parse_gmail_fixture_job_alert(message) for message in read.messages)
    assert len(parsed) == 3
    assert all(result.status is JobAlertStatus.NO_MATCH for result in parsed)


@pytest.mark.parametrize(
    ("trust", "sensitivity", "provider"),
    [
        (TrustLabel.T3_DERIVED, SensitivityLabel.PRIVATE, "gmail.fixture"),
        (TrustLabel.T4_EXTERNAL, SensitivityLabel.PUBLIC, "gmail.fixture"),
        (TrustLabel.T4_EXTERNAL, SensitivityLabel.PRIVATE, "other.provider"),
    ],
)
def test_gmail_message_cannot_choose_provider_trust_or_sensitivity(
    trust, sensitivity, provider
) -> None:
    message = gmail_message("Company: A\nRole: B\n")
    raw = message.body_bytes
    normalized = normalize_plain_text(
        PlainTextSourceDescriptor(
            source_id=uuid5(NAMESPACE_URL, "sentinel:gmail.fixture:synthetic-test#test-alert-001"),
            provider_id=provider,
            observed_at=datetime(2026, 11, 5, tzinfo=UTC),
            trust=trust,
            sensitivity=sensitivity,
        ),
        raw,
        "text/plain; charset=utf-8",
    )
    altered = replace(message, normalized_source=normalized)
    with pytest.raises(JobAlertError) as error:
        parse_gmail_fixture_job_alert(altered)
    assert error.value.code is JobAlertErrorCode.INVALID_SOURCE


def test_wrong_gmail_source_identity_is_rejected() -> None:
    message = gmail_message("Company: A\nRole: B\n")
    normalized = normalize_plain_text(
        PlainTextSourceDescriptor(
            source_id=uuid5(NAMESPACE_URL, "not-the-message-identity"),
            provider_id="gmail.fixture",
            observed_at=datetime(2026, 11, 5, tzinfo=UTC),
            trust=TrustLabel.T4_EXTERNAL,
            sensitivity=SensitivityLabel.PRIVATE,
        ),
        message.body_bytes,
        "text/plain; charset=utf-8",
    )
    with pytest.raises(JobAlertError) as error:
        parse_gmail_fixture_job_alert(replace(message, normalized_source=normalized))
    assert error.value.code is JobAlertErrorCode.INVALID_SOURCE


def test_tampered_normalized_digest_is_rejected_without_body_disclosure() -> None:
    message = gmail_message("Company: Aster\nRole: Engineer\n")
    source = message.normalized_source
    damaged = NormalizedPlainTextSource(
        envelope=source.envelope,
        text=source.text,
        original_bytes=source.original_bytes,
        payload_sha256="0" * 64,
        declared_mime_type=source.declared_mime_type,
        mime_type=source.mime_type,
        charset=source.charset,
        charset_was_defaulted=source.charset_was_defaulted,
    )
    with pytest.raises(JobAlertError) as error:
        parse_gmail_fixture_job_alert(replace(message, normalized_source=damaged))
    assert error.value.code is JobAlertErrorCode.INVALID_SOURCE
    assert "Aster" not in str(error.value)


def test_cross_source_existing_citation_is_rejected() -> None:
    first = parse_gmail_fixture_job_alert(gmail_message("Company: Aster\nRole: Engineer\n"))
    second = gmail_message("Company: Comet\nRole: Analyst\n", message_id="different-message")
    company_citation = next(field for field in first.fields if field.field_id.value == "company")
    assert company_citation.evidence is not None
    with pytest.raises(JobAlertError) as error:
        parse_gmail_fixture_job_alert(
            replace(second, citations=(company_citation.evidence.bound_citation,))
        )
    assert error.value.code is JobAlertErrorCode.INVALID_SOURCE
