"""Safe, structured diagnostic events for Sentinel."""

from sentinel.observability.events import (
    DiagnosticComponent,
    DiagnosticErrorCode,
    DiagnosticEvent,
    DiagnosticEventCode,
    DiagnosticOutcome,
    DiagnosticSeverity,
    DiagnosticValidationError,
)
from sentinel.observability.logging import (
    DiagnosticSinkError,
    JsonLinesDiagnosticLogger,
    encode_event,
    stderr_logger,
)

__all__ = [
    "DiagnosticComponent",
    "DiagnosticErrorCode",
    "DiagnosticEvent",
    "DiagnosticEventCode",
    "DiagnosticOutcome",
    "DiagnosticSeverity",
    "DiagnosticSinkError",
    "DiagnosticValidationError",
    "JsonLinesDiagnosticLogger",
    "encode_event",
    "stderr_logger",
]
