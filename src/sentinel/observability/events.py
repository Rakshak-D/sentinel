"""Fixed-schema diagnostic event types; no raw content or dynamic messages."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, field_validator

from sentinel.contracts.labels import SensitivityLabel


class DiagnosticEventCode(StrEnum):
    """Stable event vocabulary for future CLI, storage, gateway, and logger diagnostics."""

    CLI_OPERATION_RESULT = "cli.operation_result"
    STORAGE_OPERATION_RESULT = "storage.operation_result"
    GATEWAY_OPERATION_RESULT = "gateway.operation_result"
    BOUNDARY_OPERATION_RESULT = "boundary.operation_result"
    DIAGNOSTIC_FAILURE = "diagnostic.failure"


class DiagnosticSeverity(StrEnum):
    """Bounded severity labels independent of authorization decisions."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class DiagnosticOutcome(StrEnum):
    """Bounded operation outcomes; none of these values grants capability."""

    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    FAILURE = "FAILURE"
    UNAVAILABLE = "UNAVAILABLE"


class DiagnosticComponent(StrEnum):
    """Fixed component vocabulary; arbitrary subsystem names are not accepted."""

    CLI = "cli"
    STORAGE = "storage"
    MODEL_GATEWAY = "model_gateway"
    TOOL_GATEWAY = "tool_gateway"
    OBSERVABILITY = "observability"


class DiagnosticErrorCode(StrEnum):
    """Safe registered failure reasons, without exception or provider text."""

    INVALID_INPUT = "invalid_input"
    OPERATION_DENIED = "operation_denied"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    STORAGE_UNAVAILABLE = "storage_unavailable"
    ADAPTER_FAILED = "adapter_failed"
    INTERNAL_ERROR = "internal_error"


class DiagnosticValidationError(ValueError):
    """Non-sensitive event validation failure with no echoed input values."""


class DiagnosticEvent(BaseModel):
    """Immutable event containing only registered codes and bounded typed metadata.

    There is deliberately no free-form message or metadata dictionary. The optional
    sensitivity value is absent as ``None`` when not supplied; it never defaults to
    PUBLIC. This record is diagnostic only and is not an audit receipt or policy result.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    event_code: DiagnosticEventCode
    timestamp: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
    severity: DiagnosticSeverity
    outcome: DiagnosticOutcome
    run_id: UUID | None = None
    boundary_id: UUID | None = None
    component: DiagnosticComponent | None = None
    sensitivity: SensitivityLabel | None = None
    error_code: DiagnosticErrorCode | None = None

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except ValidationError:
            raise DiagnosticValidationError("Diagnostic event is invalid.") from None

    def __setattr__(self, name: str, value: Any) -> None:
        try:
            super().__setattr__(name, value)
        except ValidationError:
            raise DiagnosticValidationError("Diagnostic event is immutable.") from None

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp_to_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)
