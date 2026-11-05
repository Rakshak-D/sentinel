from __future__ import annotations

from dataclasses import replace

import pytest

from sentinel.readers.source_status import (
    build_source_status_report,
    format_json_source_status,
    is_source_status_healthy,
)
from sentinel.readers.source_status_types import (
    AccountCheckState,
    CredentialBackendState,
    CredentialCheckState,
    ReviewGateState,
    SafeDefaultsState,
    SourceCapabilityId,
    SourceReadinessCode,
    SourceStatusError,
)

EXPECTED_IDS = (
    SourceCapabilityId.GMAIL_FIXTURE,
    SourceCapabilityId.GITHUB_FIXTURE,
    SourceCapabilityId.CALENDAR_FIXTURE,
    SourceCapabilityId.LOCAL_TEXT_FILE,
    SourceCapabilityId.LOCAL_LITERAL_SEARCH,
    SourceCapabilityId.LOCAL_JOB_ALERT_EXTRACTION,
    SourceCapabilityId.LOCAL_JOB_ALERT_REVIEW,
    SourceCapabilityId.GMAIL_LIVE_READ,
    SourceCapabilityId.GITHUB_LIVE_READ,
    SourceCapabilityId.CALENDAR_LIVE_READ,
    SourceCapabilityId.GREENHOUSE_PUBLIC_FEED,
    SourceCapabilityId.LEVER_PUBLIC_FEED,
    SourceCapabilityId.LINKEDIN_OWNER_EXPORT,
    SourceCapabilityId.PRODUCTION_CREDENTIAL_BACKEND,
)


def test_inventory_is_complete_unique_and_stably_ordered() -> None:
    report = build_source_status_report()
    ids = tuple(item.capability_id for item in report.capabilities)
    assert report.schema_version == "sentinel.source-capability-status.v1"
    assert ids == EXPECTED_IDS
    assert len(set(ids)) == len(EXPECTED_IDS)
    assert report.safe_defaults_state is SafeDefaultsState.VERIFIED


def test_fixtures_local_workflows_live_adapters_and_terms_are_distinguished() -> None:
    report = build_source_status_report()
    capabilities = {item.capability_id: item for item in report.capabilities}
    for capability_id in EXPECTED_IDS[:3]:
        assert capabilities[capability_id].readiness is SourceReadinessCode.FIXTURE_READY
    for capability_id in EXPECTED_IDS[3:7]:
        assert capabilities[capability_id].readiness is SourceReadinessCode.EXPLICIT_LOCAL_ONLY
    for capability_id in EXPECTED_IDS[7:10]:
        item = capabilities[capability_id]
        assert item.readiness is SourceReadinessCode.NOT_IMPLEMENTED
        assert item.account_check_state is AccountCheckState.NOT_CHECKED
        assert item.credential_backend_state is CredentialBackendState.UNAVAILABLE
    for capability_id in EXPECTED_IDS[10:12]:
        item = capabilities[capability_id]
        assert item.readiness is SourceReadinessCode.TERMS_REVIEW_REQUIRED
        assert item.terms_review_state is ReviewGateState.REQUIRED_NOT_COMPLETED
    assert capabilities[SourceCapabilityId.LINKEDIN_OWNER_EXPORT].readiness is (
        SourceReadinessCode.NOT_IMPLEMENTED
    )
    broker = capabilities[SourceCapabilityId.PRODUCTION_CREDENTIAL_BACKEND]
    assert broker.readiness is SourceReadinessCode.CREDENTIAL_BACKEND_UNAVAILABLE
    assert broker.credential_backend_state is CredentialBackendState.UNAVAILABLE


def test_report_records_bounded_non_sensitive_explanations() -> None:
    report = build_source_status_report()
    assert all(
        isinstance(item.explanation, str) and item.explanation for item in report.capabilities
    )
    rendered_explanations = " ".join(item.explanation for item in report.capabilities)
    assert "@" not in rendered_explanations
    assert "C:\\" not in rendered_explanations


def test_unexpected_runtime_enum_or_inconsistent_state_is_rejected() -> None:
    report = build_source_status_report()
    invalid_item = replace(report.capabilities[0], readiness="READY")
    invalid_report = replace(report, capabilities=(invalid_item, *report.capabilities[1:]))
    with pytest.raises(SourceStatusError, match="could not be validated"):
        format_json_source_status(invalid_report)

    inconsistent_live = replace(
        report.capabilities[7],
        credential_backend_state=CredentialBackendState.AVAILABLE,
    )
    invalid_report = replace(
        report,
        capabilities=(
            *report.capabilities[:7],
            inconsistent_live,
            *report.capabilities[8:],
        ),
    )
    with pytest.raises(SourceStatusError, match="could not be validated"):
        format_json_source_status(invalid_report)


def test_missing_explicit_local_api_is_reported_unavailable_and_unhealthy(monkeypatch) -> None:
    from sentinel.readers import source_status

    monkeypatch.setattr(source_status, "read_allowlisted_local_text", None)
    report = build_source_status_report()
    item = next(
        row
        for row in report.capabilities
        if row.capability_id is SourceCapabilityId.LOCAL_TEXT_FILE
    )
    assert item.readiness is SourceReadinessCode.UNAVAILABLE
    assert is_source_status_healthy(report) is False

    # A known enum value in the wrong source class is still invalid.
    invalid_live = replace(report.capabilities[7], readiness=SourceReadinessCode.FIXTURE_READY)
    invalid_report = replace(
        report,
        capabilities=(*report.capabilities[:7], invalid_live, *report.capabilities[8:]),
    )
    with pytest.raises(SourceStatusError, match="could not be validated"):
        format_json_source_status(invalid_report)

    invalid_linkedin = replace(
        report.capabilities[12],
        credential_check_state=CredentialCheckState.NOT_CHECKED,
    )
    invalid_report = replace(
        report,
        capabilities=(
            *report.capabilities[:12],
            invalid_linkedin,
            report.capabilities[13],
        ),
    )
    with pytest.raises(SourceStatusError, match="could not be validated"):
        is_source_status_healthy(invalid_report)
