"""JSON Lines output for validated, allowlisted Sentinel diagnostic events."""

from __future__ import annotations

import json
import sys
from datetime import UTC
from threading import Lock
from typing import TextIO

from sentinel.observability.events import (
    DiagnosticEvent,
    DiagnosticValidationError,
)

_EVENT_FIELDS = (
    "event_code",
    "timestamp",
    "severity",
    "outcome",
    "run_id",
    "boundary_id",
    "component",
    "sensitivity",
    "error_code",
)


class DiagnosticSinkError(OSError):
    """Non-sensitive error indicating the configured diagnostic sink failed."""


def _revalidate_event(event: DiagnosticEvent) -> DiagnosticEvent:
    if type(event) is not DiagnosticEvent:
        raise DiagnosticValidationError("Diagnostic event is invalid.")

    try:
        instance_fields = object.__getattribute__(event, "__dict__")
        if type(instance_fields) is not dict or len(instance_fields) != len(_EVENT_FIELDS):
            raise DiagnosticValidationError("Diagnostic event is invalid.")
        if any(type(key) is not str for key in instance_fields):
            raise DiagnosticValidationError("Diagnostic event is invalid.")
        if any(field not in instance_fields for field in _EVENT_FIELDS):
            raise DiagnosticValidationError("Diagnostic event is invalid.")
        extras = object.__getattribute__(event, "__pydantic_extra__")
        if extras is not None:
            raise DiagnosticValidationError("Diagnostic event is invalid.")
        values = {field: instance_fields[field] for field in _EVENT_FIELDS}
        return DiagnosticEvent(**values)
    except DiagnosticValidationError:
        raise
    except Exception:
        raise DiagnosticValidationError("Diagnostic event is invalid.") from None


def encode_event(event: DiagnosticEvent) -> str:
    """Encode one revalidated event as deterministic, single-line JSON text."""

    validated = _revalidate_event(event)
    timestamp = validated.timestamp.astimezone(UTC)
    record = {
        "event_code": validated.event_code.value,
        "timestamp": timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "severity": validated.severity.value,
        "outcome": validated.outcome.value,
        "run_id": str(validated.run_id) if validated.run_id is not None else None,
        "boundary_id": (
            str(validated.boundary_id) if validated.boundary_id is not None else None
        ),
        "component": validated.component.value if validated.component is not None else None,
        "sensitivity": (
            validated.sensitivity.value if validated.sensitivity is not None else None
        ),
        "error_code": validated.error_code.value if validated.error_code is not None else None,
    }
    return json.dumps(
        record,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


class JsonLinesDiagnosticLogger:
    """Write allowlisted events to a caller-selected text sink, one line per event.

    The sink is explicitly supplied by trusted application setup. This logger does
    not configure Python's global logging system, retain records, or select stdout.
    """

    def __init__(self, sink: TextIO) -> None:
        if sink is sys.stdout:
            raise DiagnosticSinkError(
                "Standard output is reserved for command or protocol output."
            )
        self._sink = sink
        self._lock = Lock()

    def emit(self, event: DiagnosticEvent) -> None:
        """Write one validated event; sink failures propagate as a safe fixed error."""

        record = encode_event(event) + "\n"
        with self._lock:
            try:
                written = self._sink.write(record)
                if written != len(record):
                    raise OSError
                self._sink.flush()
            except Exception:
                raise DiagnosticSinkError("Diagnostic output failed.") from None


def stderr_logger() -> JsonLinesDiagnosticLogger:
    """Return a logger explicitly bound to the current standard error stream."""

    return JsonLinesDiagnosticLogger(sys.stderr)
