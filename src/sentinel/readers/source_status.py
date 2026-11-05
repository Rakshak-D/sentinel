"""Read-only, credential-free status for Sentinel's registered source capabilities."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TypeVar

from sentinel.config.defaults import load_bundled_defaults
from sentinel.config.schema import SentinelConfig
from sentinel.credentials import CredentialBroker
from sentinel.credentials.types import BackendAvailability
from sentinel.extraction import parse_local_job_alert, review_selected_job_alerts
from sentinel.readers import calendar_fixture, github_fixture, gmail_fixture
from sentinel.readers.calendar_types import CalendarFixtureRead
from sentinel.readers.local_search import search_selected_local_text_files
from sentinel.readers.local_text import read_allowlisted_local_text
from sentinel.readers.source_status_types import (
    AccountCheckState,
    ActivationState,
    CredentialBackendState,
    CredentialCheckState,
    ImplementationState,
    ReviewGateState,
    SafeDefaultsState,
    SourceCapabilityId,
    SourceCapabilityReport,
    SourceKind,
    SourceReadinessCode,
    SourceStatusError,
    SourceStatusErrorCode,
    SourceStatusExplanation,
    SourceStatusReport,
)
from sentinel.readers.types import GithubFixtureRead, GmailFixtureRead

SOURCE_STATUS_SCHEMA_VERSION = "sentinel.source-capability-status.v1"

_CAPABILITY_ORDER = (
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

_EXPLANATION_BY_ID = {
    SourceCapabilityId.GMAIL_FIXTURE: SourceStatusExplanation.GMAIL_FIXTURE_VALID,
    SourceCapabilityId.GITHUB_FIXTURE: SourceStatusExplanation.GITHUB_FIXTURE_VALID,
    SourceCapabilityId.CALENDAR_FIXTURE: SourceStatusExplanation.CALENDAR_FIXTURE_VALID,
    SourceCapabilityId.LOCAL_TEXT_FILE: SourceStatusExplanation.LOCAL_TEXT_EXPLICIT,
    SourceCapabilityId.LOCAL_LITERAL_SEARCH: SourceStatusExplanation.LOCAL_SEARCH_EXPLICIT,
    SourceCapabilityId.LOCAL_JOB_ALERT_EXTRACTION: SourceStatusExplanation.LOCAL_JOB_ALERT_EXPLICIT,
    SourceCapabilityId.LOCAL_JOB_ALERT_REVIEW: SourceStatusExplanation.LOCAL_JOB_REVIEW_EXPLICIT,
    SourceCapabilityId.GMAIL_LIVE_READ: SourceStatusExplanation.LIVE_ADAPTER_ABSENT,
    SourceCapabilityId.GITHUB_LIVE_READ: SourceStatusExplanation.LIVE_ADAPTER_ABSENT,
    SourceCapabilityId.CALENDAR_LIVE_READ: SourceStatusExplanation.LIVE_ADAPTER_ABSENT,
    SourceCapabilityId.GREENHOUSE_PUBLIC_FEED: SourceStatusExplanation.PUBLIC_FEED_TERMS_CLOSED,
    SourceCapabilityId.LEVER_PUBLIC_FEED: SourceStatusExplanation.PUBLIC_FEED_TERMS_CLOSED,
    SourceCapabilityId.LINKEDIN_OWNER_EXPORT: SourceStatusExplanation.LINKEDIN_IMPORT_ABSENT,
    SourceCapabilityId.PRODUCTION_CREDENTIAL_BACKEND: (
        SourceStatusExplanation.CREDENTIAL_BACKEND_UNAVAILABLE
    ),
}

_FIXTURE_INVALID_EXPLANATION_BY_ID = {
    SourceCapabilityId.GMAIL_FIXTURE: SourceStatusExplanation.GMAIL_FIXTURE_INVALID,
    SourceCapabilityId.GITHUB_FIXTURE: SourceStatusExplanation.GITHUB_FIXTURE_INVALID,
    SourceCapabilityId.CALENDAR_FIXTURE: SourceStatusExplanation.CALENDAR_FIXTURE_INVALID,
}

_EXPLANATIONS = {
    SourceStatusExplanation.GMAIL_FIXTURE_VALID: (
        "Pinned synthetic Gmail fixture validated offline."
    ),
    SourceStatusExplanation.GMAIL_FIXTURE_INVALID: (
        "Pinned synthetic Gmail fixture is missing or failed validation."
    ),
    SourceStatusExplanation.GITHUB_FIXTURE_VALID: (
        "Pinned synthetic GitHub fixture validated offline."
    ),
    SourceStatusExplanation.GITHUB_FIXTURE_INVALID: (
        "Pinned synthetic GitHub fixture is missing or failed validation."
    ),
    SourceStatusExplanation.CALENDAR_FIXTURE_VALID: (
        "Pinned synthetic Calendar fixture validated offline."
    ),
    SourceStatusExplanation.CALENDAR_FIXTURE_INVALID: (
        "Pinned synthetic Calendar fixture is missing or failed validation."
    ),
    SourceStatusExplanation.LOCAL_TEXT_EXPLICIT: (
        "Explicit allowlisted local text selection; no discovery or persistence."
    ),
    SourceStatusExplanation.LOCAL_SEARCH_EXPLICIT: (
        "Explicit selected-file literal search; no scanning or indexing."
    ),
    SourceStatusExplanation.LOCAL_JOB_ALERT_EXPLICIT: (
        "Explicit local parsing; no mailbox access or automatic tasks."
    ),
    SourceStatusExplanation.LOCAL_JOB_REVIEW_EXPLICIT: (
        "Explicit local-file review; source text remains untrusted."
    ),
    SourceStatusExplanation.LOCAL_API_UNAVAILABLE: (
        "Expected explicit local source API is unavailable in this installation."
    ),
    SourceStatusExplanation.LIVE_ADAPTER_ABSENT: (
        "No live provider adapter; account state was not checked."
    ),
    SourceStatusExplanation.PUBLIC_FEED_TERMS_CLOSED: (
        "No feed reader; source-specific terms review is required and incomplete."
    ),
    SourceStatusExplanation.LINKEDIN_IMPORT_ABSENT: (
        "Owner-export import is absent; source review remains required."
    ),
    SourceStatusExplanation.CREDENTIAL_BACKEND_UNAVAILABLE: (
        "No verified production credential backend; real credentials were not inspected."
    ),
}

_Capability = TypeVar("_Capability", GmailFixtureRead, GithubFixtureRead, CalendarFixtureRead)


def _bundled_defaults_are_safe() -> bool:
    try:
        config = load_bundled_defaults()
        return (
            type(config) is SentinelConfig
            and config.schema_version == "sentinel.config.v1"
            and config.profile.name == "local-only"
            and config.profile.timezone == "UTC"
            and config.data.storage_path is None
            and config.sources.enabled == ()
            and config.sources.host_allowlist == ()
            and config.models.egress.internal_cloud_consent is False
            and config.security.external_writes.gmail_draft.enabled is False
            and config.security.external_writes.gmail_send.enabled is False
            and config.security.external_writes.github_comment.enabled is False
            and config.security.external_writes.github_label.enabled is False
            and config.security.allowed_email_recipients == ()
            and config.security.github_allowlisted_repos == ()
        )
    except Exception:
        return False


def _backend_state() -> BackendAvailability:
    try:
        availability = CredentialBroker().backend_availability
    except Exception:
        return BackendAvailability.UNAVAILABLE
    if availability is BackendAvailability.AVAILABLE:
        return BackendAvailability.AVAILABLE
    return BackendAvailability.UNAVAILABLE


def _fixture_is_valid(
    reader: Callable[[], _Capability],
    *,
    expected_type: type[_Capability],
    version: str,
    digest: str,
    count_attribute: str,
    expected_count: int,
) -> bool:
    try:
        value = reader()
        if type(value) is not expected_type:
            return False
        if getattr(value, "fixture_version", None) != version:
            return False
        if getattr(value, "fixture_sha256", None) != digest:
            return False
        records = getattr(value, count_attribute, None)
        return type(records) is tuple and len(records) == expected_count
    except Exception:
        return False


def _make_capability(
    capability_id: SourceCapabilityId,
    source_kind: SourceKind,
    readiness: SourceReadinessCode,
    implementation_state: ImplementationState,
    activation_state: ActivationState,
    credential_check_state: CredentialCheckState,
    credential_backend_state: CredentialBackendState,
    account_check_state: AccountCheckState,
    source_review_state: ReviewGateState,
    terms_review_state: ReviewGateState,
    explanation: SourceStatusExplanation,
) -> SourceCapabilityReport:
    return SourceCapabilityReport(
        capability_id=capability_id,
        source_kind=source_kind,
        readiness=readiness,
        implementation_state=implementation_state,
        activation_state=activation_state,
        credential_check_state=credential_check_state,
        credential_backend_state=credential_backend_state,
        account_check_state=account_check_state,
        source_review_state=source_review_state,
        terms_review_state=terms_review_state,
        explanation=explanation,
    )


def _base_fields() -> dict[str, object]:
    return {
        "credential_check_state": CredentialCheckState.NOT_REQUIRED,
        "credential_backend_state": CredentialBackendState.NOT_REQUIRED,
        "account_check_state": AccountCheckState.NOT_APPLICABLE,
        "source_review_state": ReviewGateState.NOT_REQUIRED,
        "terms_review_state": ReviewGateState.NOT_REQUIRED,
    }


def build_source_status_report() -> SourceStatusReport:
    """Validate fixed fixtures and report source capability without probing accounts."""

    defaults = (
        SafeDefaultsState.VERIFIED if _bundled_defaults_are_safe() else SafeDefaultsState.INVALID
    )
    backend = _backend_state()
    capabilities: list[SourceCapabilityReport] = []

    fixture_specs: tuple[
        tuple[
            SourceCapabilityId,
            SourceKind,
            bool,
            SourceStatusExplanation,
        ],
        ...,
    ] = (
        (
            SourceCapabilityId.GMAIL_FIXTURE,
            SourceKind.PACKAGED_FIXTURE,
            _fixture_is_valid(
                gmail_fixture.read_packaged_gmail_fixture,
                expected_type=GmailFixtureRead,
                version=gmail_fixture.GMAIL_FIXTURE_SCHEMA_VERSION,
                digest=gmail_fixture.GMAIL_FIXTURE_SHA256,
                count_attribute="messages",
                expected_count=3,
            ),
            SourceStatusExplanation.GMAIL_FIXTURE_VALID,
        ),
        (
            SourceCapabilityId.GITHUB_FIXTURE,
            SourceKind.PACKAGED_FIXTURE,
            _fixture_is_valid(
                github_fixture.read_packaged_github_fixture,
                expected_type=GithubFixtureRead,
                version=github_fixture.FIXTURE_SCHEMA_VERSION,
                digest=github_fixture.FIXTURE_SHA256,
                count_attribute="issues",
                expected_count=3,
            ),
            SourceStatusExplanation.GITHUB_FIXTURE_VALID,
        ),
        (
            SourceCapabilityId.CALENDAR_FIXTURE,
            SourceKind.PACKAGED_FIXTURE,
            _fixture_is_valid(
                calendar_fixture.read_packaged_calendar_fixture,
                expected_type=CalendarFixtureRead,
                version=calendar_fixture.CALENDAR_FIXTURE_VERSION,
                digest=calendar_fixture.CALENDAR_FIXTURE_SHA256,
                count_attribute="events",
                expected_count=4,
            ),
            SourceStatusExplanation.CALENDAR_FIXTURE_VALID,
        ),
    )
    for capability_id, kind, valid, explanation in fixture_specs:
        fields = _base_fields()
        capabilities.append(
            _make_capability(
                capability_id,
                kind,
                SourceReadinessCode.FIXTURE_READY if valid else SourceReadinessCode.FIXTURE_INVALID,
                ImplementationState.IMPLEMENTED,
                ActivationState.FIXTURE_ONLY,
                **fields,  # type: ignore[arg-type]
                explanation=(
                    explanation
                    if valid
                    else _FIXTURE_INVALID_EXPLANATION_BY_ID[capability_id]
                ),
            )
        )

    local_specs = (
        (
            SourceCapabilityId.LOCAL_TEXT_FILE,
            callable(read_allowlisted_local_text),
            SourceStatusExplanation.LOCAL_TEXT_EXPLICIT,
        ),
        (
            SourceCapabilityId.LOCAL_LITERAL_SEARCH,
            callable(search_selected_local_text_files),
            SourceStatusExplanation.LOCAL_SEARCH_EXPLICIT,
        ),
        (
            SourceCapabilityId.LOCAL_JOB_ALERT_EXTRACTION,
            callable(parse_local_job_alert),
            SourceStatusExplanation.LOCAL_JOB_ALERT_EXPLICIT,
        ),
        (
            SourceCapabilityId.LOCAL_JOB_ALERT_REVIEW,
            callable(review_selected_job_alerts),
            SourceStatusExplanation.LOCAL_JOB_REVIEW_EXPLICIT,
        ),
    )
    for capability_id, implemented, explanation in local_specs:
        capabilities.append(
            _make_capability(
                capability_id,
                SourceKind.EXPLICIT_LOCAL,
                SourceReadinessCode.EXPLICIT_LOCAL_ONLY
                if implemented
                else SourceReadinessCode.UNAVAILABLE,
                ImplementationState.IMPLEMENTED
                if implemented
                else ImplementationState.NOT_IMPLEMENTED,
                ActivationState.EXPLICIT_INVOCATION_ONLY,
                **_base_fields(),  # type: ignore[arg-type]
                explanation=(
                    explanation if implemented else SourceStatusExplanation.LOCAL_API_UNAVAILABLE
                ),
            )
        )

    live_specs = (
        SourceCapabilityId.GMAIL_LIVE_READ,
        SourceCapabilityId.GITHUB_LIVE_READ,
        SourceCapabilityId.CALENDAR_LIVE_READ,
    )
    for capability_id in live_specs:
        capabilities.append(
            _make_capability(
                capability_id,
                SourceKind.LIVE_PROVIDER,
                SourceReadinessCode.NOT_IMPLEMENTED,
                ImplementationState.NOT_IMPLEMENTED,
                ActivationState.DISABLED
                if defaults is SafeDefaultsState.VERIFIED
                else ActivationState.CONFIGURATION_INVALID,
                CredentialCheckState.NOT_CHECKED,
                CredentialBackendState(backend.value),
                AccountCheckState.NOT_CHECKED,
                ReviewGateState.NOT_REQUIRED,
                ReviewGateState.NOT_REQUIRED,
                SourceStatusExplanation.LIVE_ADAPTER_ABSENT,
            )
        )

    for capability_id in (
        SourceCapabilityId.GREENHOUSE_PUBLIC_FEED,
        SourceCapabilityId.LEVER_PUBLIC_FEED,
    ):
        capabilities.append(
            _make_capability(
                capability_id,
                SourceKind.PUBLIC_FEED,
                SourceReadinessCode.TERMS_REVIEW_REQUIRED,
                ImplementationState.NOT_IMPLEMENTED,
                ActivationState.TERMS_GATED,
                CredentialCheckState.NOT_REQUIRED,
                CredentialBackendState.NOT_REQUIRED,
                AccountCheckState.NOT_APPLICABLE,
                ReviewGateState.NOT_ASSESSED,
                ReviewGateState.REQUIRED_NOT_COMPLETED,
                SourceStatusExplanation.PUBLIC_FEED_TERMS_CLOSED,
            )
        )

    capabilities.append(
        _make_capability(
            SourceCapabilityId.LINKEDIN_OWNER_EXPORT,
            SourceKind.OWNER_EXPORT,
            SourceReadinessCode.NOT_IMPLEMENTED,
            ImplementationState.NOT_IMPLEMENTED,
            ActivationState.SOURCE_REVIEW_GATED,
            CredentialCheckState.NOT_REQUIRED,
            CredentialBackendState.NOT_REQUIRED,
            AccountCheckState.NOT_APPLICABLE,
            ReviewGateState.REQUIRED_NOT_COMPLETED,
            ReviewGateState.NOT_ASSESSED,
            SourceStatusExplanation.LINKEDIN_IMPORT_ABSENT,
        )
    )
    capabilities.append(
        _make_capability(
            SourceCapabilityId.PRODUCTION_CREDENTIAL_BACKEND,
            SourceKind.CREDENTIAL_BACKEND,
            SourceReadinessCode.CREDENTIAL_BACKEND_UNAVAILABLE
            if backend is BackendAvailability.UNAVAILABLE
            else SourceReadinessCode.UNAVAILABLE,
            ImplementationState.NOT_IMPLEMENTED,
            ActivationState.DISABLED,
            CredentialCheckState.NOT_CHECKED,
            CredentialBackendState.UNAVAILABLE
            if backend is BackendAvailability.UNAVAILABLE
            else CredentialBackendState.AVAILABLE,
            AccountCheckState.NOT_APPLICABLE,
            ReviewGateState.NOT_REQUIRED,
            ReviewGateState.NOT_REQUIRED,
            SourceStatusExplanation.CREDENTIAL_BACKEND_UNAVAILABLE,
        )
    )

    return SourceStatusReport(
        schema_version=SOURCE_STATUS_SCHEMA_VERSION,
        safe_defaults_state=defaults,
        capabilities=tuple(capabilities),
    )


def _validate_report(report: object) -> SourceStatusReport:
    if (
        type(report) is not SourceStatusReport
        or report.schema_version != SOURCE_STATUS_SCHEMA_VERSION
        or type(report.safe_defaults_state) is not SafeDefaultsState
        or type(report.capabilities) is not tuple
        or len(report.capabilities) != len(_CAPABILITY_ORDER)
    ):
        raise SourceStatusError(SourceStatusErrorCode.INVALID_STATUS_REPORT)
    for expected_id, capability in zip(_CAPABILITY_ORDER, report.capabilities, strict=True):
        if (
            type(capability) is not SourceCapabilityReport
            or type(capability.capability_id) is not SourceCapabilityId
            or capability.capability_id is not expected_id
            or type(capability.source_kind) is not SourceKind
            or type(capability.readiness) is not SourceReadinessCode
            or type(capability.implementation_state) is not ImplementationState
            or type(capability.activation_state) is not ActivationState
            or type(capability.credential_check_state) is not CredentialCheckState
            or type(capability.credential_backend_state) is not CredentialBackendState
            or type(capability.account_check_state) is not AccountCheckState
            or type(capability.source_review_state) is not ReviewGateState
            or type(capability.terms_review_state) is not ReviewGateState
            or type(capability.explanation) is not SourceStatusExplanation
        ):
            raise SourceStatusError(SourceStatusErrorCode.INVALID_STATUS_REPORT)
        expected_explanation = _EXPLANATION_BY_ID[expected_id]
        if (
            expected_id in _CAPABILITY_ORDER[:3]
            and capability.readiness is SourceReadinessCode.FIXTURE_INVALID
        ):
            expected_explanation = _FIXTURE_INVALID_EXPLANATION_BY_ID[expected_id]
        elif (
            expected_id in _CAPABILITY_ORDER[3:7]
            and capability.readiness is SourceReadinessCode.UNAVAILABLE
        ):
            expected_explanation = SourceStatusExplanation.LOCAL_API_UNAVAILABLE
        if capability.explanation is not expected_explanation:
            raise SourceStatusError(SourceStatusErrorCode.INVALID_STATUS_REPORT)
        if expected_id in _CAPABILITY_ORDER[:3]:
            valid = (
                capability.source_kind is SourceKind.PACKAGED_FIXTURE
                and capability.implementation_state is ImplementationState.IMPLEMENTED
                and capability.activation_state is ActivationState.FIXTURE_ONLY
                and capability.readiness
                in {SourceReadinessCode.FIXTURE_READY, SourceReadinessCode.FIXTURE_INVALID}
                and capability.credential_check_state is CredentialCheckState.NOT_REQUIRED
                and capability.credential_backend_state is CredentialBackendState.NOT_REQUIRED
                and capability.account_check_state is AccountCheckState.NOT_APPLICABLE
                and capability.source_review_state is ReviewGateState.NOT_REQUIRED
                and capability.terms_review_state is ReviewGateState.NOT_REQUIRED
            )
        elif expected_id in _CAPABILITY_ORDER[3:7]:
            valid = (
                capability.source_kind is SourceKind.EXPLICIT_LOCAL
                and capability.activation_state is ActivationState.EXPLICIT_INVOCATION_ONLY
                and capability.readiness
                in {SourceReadinessCode.EXPLICIT_LOCAL_ONLY, SourceReadinessCode.UNAVAILABLE}
                and capability.implementation_state
                is (
                    ImplementationState.IMPLEMENTED
                    if capability.readiness is SourceReadinessCode.EXPLICIT_LOCAL_ONLY
                    else ImplementationState.NOT_IMPLEMENTED
                )
                and capability.credential_check_state is CredentialCheckState.NOT_REQUIRED
                and capability.credential_backend_state is CredentialBackendState.NOT_REQUIRED
                and capability.account_check_state is AccountCheckState.NOT_APPLICABLE
                and capability.source_review_state is ReviewGateState.NOT_REQUIRED
                and capability.terms_review_state is ReviewGateState.NOT_REQUIRED
            )
        elif expected_id in _CAPABILITY_ORDER[7:10]:
            expected_activation = (
                ActivationState.DISABLED
                if report.safe_defaults_state is SafeDefaultsState.VERIFIED
                else ActivationState.CONFIGURATION_INVALID
            )
            valid = (
                capability.source_kind is SourceKind.LIVE_PROVIDER
                and capability.readiness is SourceReadinessCode.NOT_IMPLEMENTED
                and capability.implementation_state is ImplementationState.NOT_IMPLEMENTED
                and capability.activation_state is expected_activation
                and capability.credential_check_state is CredentialCheckState.NOT_CHECKED
                and capability.credential_backend_state
                in {CredentialBackendState.AVAILABLE, CredentialBackendState.UNAVAILABLE}
                and capability.account_check_state is AccountCheckState.NOT_CHECKED
                and capability.source_review_state is ReviewGateState.NOT_REQUIRED
                and capability.terms_review_state is ReviewGateState.NOT_REQUIRED
            )
        elif expected_id in _CAPABILITY_ORDER[10:12]:
            valid = (
                capability.source_kind is SourceKind.PUBLIC_FEED
                and capability.readiness is SourceReadinessCode.TERMS_REVIEW_REQUIRED
                and capability.implementation_state is ImplementationState.NOT_IMPLEMENTED
                and capability.activation_state is ActivationState.TERMS_GATED
                and capability.terms_review_state is ReviewGateState.REQUIRED_NOT_COMPLETED
                and capability.source_review_state is ReviewGateState.NOT_ASSESSED
                and capability.credential_check_state is CredentialCheckState.NOT_REQUIRED
                and capability.credential_backend_state is CredentialBackendState.NOT_REQUIRED
                and capability.account_check_state is AccountCheckState.NOT_APPLICABLE
            )
        elif expected_id is SourceCapabilityId.LINKEDIN_OWNER_EXPORT:
            valid = (
                capability.source_kind is SourceKind.OWNER_EXPORT
                and capability.readiness is SourceReadinessCode.NOT_IMPLEMENTED
                and capability.implementation_state is ImplementationState.NOT_IMPLEMENTED
                and capability.activation_state is ActivationState.SOURCE_REVIEW_GATED
                and capability.source_review_state is ReviewGateState.REQUIRED_NOT_COMPLETED
                and capability.terms_review_state is ReviewGateState.NOT_ASSESSED
                and capability.credential_check_state is CredentialCheckState.NOT_REQUIRED
                and capability.credential_backend_state is CredentialBackendState.NOT_REQUIRED
                and capability.account_check_state is AccountCheckState.NOT_APPLICABLE
            )
        else:
            expected_backend_state = (
                CredentialBackendState.AVAILABLE
                if capability.credential_backend_state is CredentialBackendState.AVAILABLE
                else CredentialBackendState.UNAVAILABLE
            )
            expected_readiness = (
                SourceReadinessCode.UNAVAILABLE
                if expected_backend_state is CredentialBackendState.AVAILABLE
                else SourceReadinessCode.CREDENTIAL_BACKEND_UNAVAILABLE
            )
            valid = (
                capability.source_kind is SourceKind.CREDENTIAL_BACKEND
                and capability.readiness is expected_readiness
                and capability.implementation_state is ImplementationState.NOT_IMPLEMENTED
                and capability.activation_state is ActivationState.DISABLED
                and capability.credential_check_state is CredentialCheckState.NOT_CHECKED
                and capability.credential_backend_state is expected_backend_state
                and capability.account_check_state is AccountCheckState.NOT_APPLICABLE
                and capability.source_review_state is ReviewGateState.NOT_REQUIRED
                and capability.terms_review_state is ReviewGateState.NOT_REQUIRED
            )
        if not valid:
            raise SourceStatusError(SourceStatusErrorCode.INVALID_STATUS_REPORT)
    production_backend = report.capabilities[-1].credential_backend_state
    if any(
        capability.credential_backend_state is not production_backend
        for capability in report.capabilities[7:10]
    ):
        raise SourceStatusError(SourceStatusErrorCode.INVALID_STATUS_REPORT)
    return report


def is_source_status_healthy(report: object) -> bool:
    """Validate a complete report and indicate whether integrity checks passed."""

    return _report_is_healthy(_validate_report(report))


def _report_is_healthy(report: SourceStatusReport) -> bool:
    return report.safe_defaults_state is SafeDefaultsState.VERIFIED and all(
        item.readiness
        in {
            SourceReadinessCode.FIXTURE_READY,
            SourceReadinessCode.EXPLICIT_LOCAL_ONLY,
        }
        for item in report.capabilities
        if item.source_kind in {SourceKind.PACKAGED_FIXTURE, SourceKind.EXPLICIT_LOCAL}
    )


def _capability_document(capability: SourceCapabilityReport) -> dict[str, str]:
    return {
        "capability_id": capability.capability_id.value,
        "source_kind": capability.source_kind.value,
        "readiness": capability.readiness.value,
        "implementation_state": capability.implementation_state.value,
        "activation_state": capability.activation_state.value,
        "credential_check_state": capability.credential_check_state.value,
        "credential_backend_state": capability.credential_backend_state.value,
        "account_check_state": capability.account_check_state.value,
        "source_review_state": capability.source_review_state.value,
        "terms_review_state": capability.terms_review_state.value,
        "explanation": _EXPLANATIONS[capability.explanation],
    }


def format_json_source_status(report: SourceStatusReport) -> str:
    """Return a stable, closed-schema JSON status document."""

    checked = _validate_report(report)
    document = {
        "schema_version": checked.schema_version,
        "validation": "VALID" if _report_is_healthy(checked) else "FAILED",
        "safe_defaults_state": checked.safe_defaults_state.value,
        "live_sources_enabled": (
            False if checked.safe_defaults_state is SafeDefaultsState.VERIFIED else None
        ),
        "external_writes_enabled": (
            False if checked.safe_defaults_state is SafeDefaultsState.VERIFIED else None
        ),
        "capabilities": [_capability_document(item) for item in checked.capabilities],
    }
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def format_text_source_status(report: SourceStatusReport) -> str:
    """Return a concise deterministic text view of the complete inventory."""

    checked = _validate_report(report)
    by_id = {item.capability_id: item for item in checked.capabilities}
    lines = [
        "Sentinel - Source capabilities",
        f"Validation: {'PASS' if _report_is_healthy(checked) else 'FAIL'}",
        (
            "Bundled defaults: VERIFIED (no live sources or external writes enabled)"
            if checked.safe_defaults_state is SafeDefaultsState.VERIFIED
            else "Bundled defaults: INVALID (activation state cannot be confirmed)"
        ),
        "Synthetic fixtures do not indicate a linked real provider account.",
        "Offline fixtures",
    ]
    labels = {
        SourceCapabilityId.GMAIL_FIXTURE: "Gmail fixture",
        SourceCapabilityId.GITHUB_FIXTURE: "GitHub fixture",
        SourceCapabilityId.CALENDAR_FIXTURE: "Calendar fixture",
    }
    for capability_id, label in labels.items():
        lines.append(f"  {label:<22} {by_id[capability_id].readiness.value.replace('_', ' ')}")
    lines.append(
        "Local access requires explicit paths; there is no discovery, background scan, "
        "or PRIVATE persistence."
    )
    lines.append("Explicit local workflows")
    labels = {
        SourceCapabilityId.LOCAL_TEXT_FILE: "Text files",
        SourceCapabilityId.LOCAL_LITERAL_SEARCH: "Literal search",
        SourceCapabilityId.LOCAL_JOB_ALERT_EXTRACTION: "Job-alert extraction",
        SourceCapabilityId.LOCAL_JOB_ALERT_REVIEW: "Job-alert review",
    }
    for capability_id, label in labels.items():
        lines.append(f"  {label:<22} {by_id[capability_id].readiness.value.replace('_', ' ')}")
    lines.append("Live integrations")
    labels = {
        SourceCapabilityId.GMAIL_LIVE_READ: "Gmail read-only",
        SourceCapabilityId.GITHUB_LIVE_READ: "GitHub repository",
        SourceCapabilityId.CALENDAR_LIVE_READ: "Calendar read-only",
    }
    for capability_id, label in labels.items():
        item = by_id[capability_id]
        lines.append(
            f"  {label:<22} {item.readiness.value.replace('_', ' ')}; credential backend "
            f"{item.credential_backend_state.value}; account {item.account_check_state.value}; "
            f"activation {item.activation_state.value}"
        )
    lines.append("Public job feeds")
    for capability_id, label in (
        (SourceCapabilityId.GREENHOUSE_PUBLIC_FEED, "Greenhouse"),
        (SourceCapabilityId.LEVER_PUBLIC_FEED, "Lever"),
    ):
        item = by_id[capability_id]
        lines.append(
            f"  {label:<22} {item.readiness.value.replace('_', ' ')}; "
            "source-specific terms review not completed"
        )
    linkedin = by_id[SourceCapabilityId.LINKEDIN_OWNER_EXPORT]
    lines.append(
        "LinkedIn owner export\n"
        f"  {linkedin.readiness.value.replace('_', ' ')}; source review not completed"
    )
    broker = by_id[SourceCapabilityId.PRODUCTION_CREDENTIAL_BACKEND]
    lines.extend(
        (
            "Credential broker",
            f"  Production backend  {broker.credential_backend_state.value}",
            "  Real account credentials NOT_CHECKED",
            "No account was connected or probed. This is not a production-readiness result.",
        )
    )
    return "\n".join(lines)


__all__ = [
    "SOURCE_STATUS_SCHEMA_VERSION",
    "build_source_status_report",
    "format_json_source_status",
    "format_text_source_status",
    "is_source_status_healthy",
]
