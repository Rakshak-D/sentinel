"""Immutable vocabulary for the bounded source-capability diagnostic."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SourceCapabilityId(StrEnum):
    GMAIL_FIXTURE = "gmail.fixture"
    GITHUB_FIXTURE = "github.fixture"
    CALENDAR_FIXTURE = "calendar.fixture"
    LOCAL_TEXT_FILE = "local.text_file"
    LOCAL_LITERAL_SEARCH = "local.literal_search"
    LOCAL_JOB_ALERT_EXTRACTION = "local.job_alert_extraction"
    LOCAL_JOB_ALERT_REVIEW = "local.job_alert_batch_review"
    GMAIL_LIVE_READ = "gmail.live_read"
    GITHUB_LIVE_READ = "github.live_repository_read"
    CALENDAR_LIVE_READ = "calendar.live_read"
    GREENHOUSE_PUBLIC_FEED = "jobs.greenhouse_public_feed"
    LEVER_PUBLIC_FEED = "jobs.lever_public_feed"
    LINKEDIN_OWNER_EXPORT = "linkedin.owner_export_import"
    PRODUCTION_CREDENTIAL_BACKEND = "credentials.production_backend"


class SourceKind(StrEnum):
    PACKAGED_FIXTURE = "PACKAGED_FIXTURE"
    EXPLICIT_LOCAL = "EXPLICIT_LOCAL"
    LIVE_PROVIDER = "LIVE_PROVIDER"
    PUBLIC_FEED = "PUBLIC_FEED"
    OWNER_EXPORT = "OWNER_EXPORT"
    CREDENTIAL_BACKEND = "CREDENTIAL_BACKEND"


class SourceReadinessCode(StrEnum):
    FIXTURE_READY = "FIXTURE_READY"
    EXPLICIT_LOCAL_ONLY = "EXPLICIT_LOCAL_ONLY"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    CREDENTIAL_BACKEND_UNAVAILABLE = "CREDENTIAL_BACKEND_UNAVAILABLE"
    TERMS_REVIEW_REQUIRED = "TERMS_REVIEW_REQUIRED"
    FIXTURE_INVALID = "FIXTURE_INVALID"
    UNAVAILABLE = "UNAVAILABLE"


class ImplementationState(StrEnum):
    IMPLEMENTED = "IMPLEMENTED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


class ActivationState(StrEnum):
    FIXTURE_ONLY = "FIXTURE_ONLY"
    EXPLICIT_INVOCATION_ONLY = "EXPLICIT_INVOCATION_ONLY"
    DISABLED = "DISABLED"
    TERMS_GATED = "TERMS_GATED"
    SOURCE_REVIEW_GATED = "SOURCE_REVIEW_GATED"
    CONFIGURATION_INVALID = "CONFIGURATION_INVALID"


class CredentialCheckState(StrEnum):
    NOT_REQUIRED = "NOT_REQUIRED"
    NOT_CHECKED = "NOT_CHECKED"


class CredentialBackendState(StrEnum):
    NOT_REQUIRED = "NOT_REQUIRED"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_CHECKED = "NOT_CHECKED"


class AccountCheckState(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_CHECKED = "NOT_CHECKED"


class ReviewGateState(StrEnum):
    NOT_REQUIRED = "NOT_REQUIRED"
    REQUIRED_NOT_COMPLETED = "REQUIRED_NOT_COMPLETED"
    NOT_ASSESSED = "NOT_ASSESSED"


class SafeDefaultsState(StrEnum):
    VERIFIED = "VERIFIED"
    INVALID = "INVALID"


class SourceStatusExplanation(StrEnum):
    GMAIL_FIXTURE_VALID = "GMAIL_FIXTURE_VALID"
    GMAIL_FIXTURE_INVALID = "GMAIL_FIXTURE_INVALID"
    GITHUB_FIXTURE_VALID = "GITHUB_FIXTURE_VALID"
    GITHUB_FIXTURE_INVALID = "GITHUB_FIXTURE_INVALID"
    CALENDAR_FIXTURE_VALID = "CALENDAR_FIXTURE_VALID"
    CALENDAR_FIXTURE_INVALID = "CALENDAR_FIXTURE_INVALID"
    LOCAL_TEXT_EXPLICIT = "LOCAL_TEXT_EXPLICIT"
    LOCAL_SEARCH_EXPLICIT = "LOCAL_SEARCH_EXPLICIT"
    LOCAL_JOB_ALERT_EXPLICIT = "LOCAL_JOB_ALERT_EXPLICIT"
    LOCAL_JOB_REVIEW_EXPLICIT = "LOCAL_JOB_REVIEW_EXPLICIT"
    LOCAL_API_UNAVAILABLE = "LOCAL_API_UNAVAILABLE"
    LIVE_ADAPTER_ABSENT = "LIVE_ADAPTER_ABSENT"
    PUBLIC_FEED_TERMS_CLOSED = "PUBLIC_FEED_TERMS_CLOSED"
    LINKEDIN_IMPORT_ABSENT = "LINKEDIN_IMPORT_ABSENT"
    CREDENTIAL_BACKEND_UNAVAILABLE = "CREDENTIAL_BACKEND_UNAVAILABLE"


class SourceStatusErrorCode(StrEnum):
    INVALID_STATUS_REPORT = "invalid_status_report"


class SourceStatusError(RuntimeError):
    """Fixed-message failure for an invalid capability-status record."""

    def __init__(self, code: SourceStatusErrorCode) -> None:
        self.code = (
            code
            if type(code) is SourceStatusErrorCode
            else SourceStatusErrorCode.INVALID_STATUS_REPORT
        )
        super().__init__("Source capability status could not be validated.")


@dataclass(frozen=True, slots=True)
class SourceCapabilityReport:
    capability_id: SourceCapabilityId
    source_kind: SourceKind
    readiness: SourceReadinessCode
    implementation_state: ImplementationState
    activation_state: ActivationState
    credential_check_state: CredentialCheckState
    credential_backend_state: CredentialBackendState
    account_check_state: AccountCheckState
    source_review_state: ReviewGateState
    terms_review_state: ReviewGateState
    explanation: SourceStatusExplanation


@dataclass(frozen=True, slots=True)
class SourceStatusReport:
    schema_version: str
    safe_defaults_state: SafeDefaultsState
    capabilities: tuple[SourceCapabilityReport, ...]


__all__ = [
    "AccountCheckState",
    "ActivationState",
    "CredentialBackendState",
    "CredentialCheckState",
    "ImplementationState",
    "ReviewGateState",
    "SafeDefaultsState",
    "SourceCapabilityId",
    "SourceCapabilityReport",
    "SourceKind",
    "SourceReadinessCode",
    "SourceStatusError",
    "SourceStatusErrorCode",
    "SourceStatusExplanation",
    "SourceStatusReport",
]
