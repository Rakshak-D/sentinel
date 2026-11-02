from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest


def _event_api():
    from sentinel.observability import events

    return events


def _valid_event(**overrides: object):
    api = _event_api()
    values: dict[str, object] = {
        "event_code": api.DiagnosticEventCode.GATEWAY_OPERATION_RESULT,
        "timestamp": datetime(2026, 11, 2, 10, 11, 12, tzinfo=UTC),
        "severity": api.DiagnosticSeverity.INFO,
        "outcome": api.DiagnosticOutcome.SUCCESS,
        "run_id": uuid4(),
        "boundary_id": None,
        "component": api.DiagnosticComponent.MODEL_GATEWAY,
        "sensitivity": None,
        "error_code": None,
    }
    values.update(overrides)
    return api.DiagnosticEvent(**values)


def test_event_requires_registered_code_and_uses_safe_validation_errors() -> None:
    api = _event_api()

    event = _valid_event()
    assert event.event_code is api.DiagnosticEventCode.GATEWAY_OPERATION_RESULT

    with pytest.raises(api.DiagnosticValidationError) as exc_info:
        _valid_event(event_code="unregistered.synthetic.secret")

    assert str(exc_info.value) == "Diagnostic event is invalid."


def test_event_has_fixed_typed_metadata_and_no_public_sensitivity_default() -> None:
    api = _event_api()
    from sentinel.contracts.labels import SensitivityLabel

    event = _valid_event()
    assert event.sensitivity is None
    assert event.component is api.DiagnosticComponent.MODEL_GATEWAY
    assert event.outcome is api.DiagnosticOutcome.SUCCESS
    assert event.severity is api.DiagnosticSeverity.INFO

    classified = _valid_event(sensitivity=SensitivityLabel.PRIVATE)
    assert classified.sensitivity is SensitivityLabel.PRIVATE


@pytest.mark.parametrize(
    "field,value",
    [
        ("severity", "LOUD"),
        ("outcome", "AUTHORIZED"),
        ("sensitivity", "PUBLIC"),
        ("component", "arbitrary-component"),
    ],
)
def test_invalid_enum_metadata_is_rejected_without_echoing_input(
    field: str, value: str
) -> None:
    api = _event_api()

    with pytest.raises(api.DiagnosticValidationError) as exc_info:
        _valid_event(**{field: value})

    assert str(exc_info.value) == "Diagnostic event is invalid."
    assert value not in str(exc_info.value)


@pytest.mark.parametrize(
    "field",
    [
        "message",
        "prompt",
        "email_body",
        "source_document",
        "authorization",
        "authorization_decision",
        "approval",
        "approved",
        "owner_intent",
        "trust",
        "bearer_token",
        "refresh_token",
        "cookie",
        "arbitrary_metadata",
    ],
)
def test_unapproved_fields_are_rejected_without_serializing_canaries(field: str) -> None:
    api = _event_api()
    canary = "SYNTHETIC-PRIVATE-CANARY-9e2a"

    with pytest.raises(api.DiagnosticValidationError) as exc_info:
        _valid_event(**{field: canary})

    assert str(exc_info.value) == "Diagnostic event is invalid."
    assert canary not in str(exc_info.value)


def test_untrusted_stringification_is_never_used_as_event_metadata() -> None:
    api = _event_api()

    class UntrustedValue:
        def __str__(self) -> str:
            raise AssertionError("__str__ must not be called")

        def __repr__(self) -> str:
            raise AssertionError("__repr__ must not be called")

    with pytest.raises(api.DiagnosticValidationError) as exc_info:
        _valid_event(component=UntrustedValue())

    assert str(exc_info.value) == "Diagnostic event is invalid."


def test_event_is_frozen_and_requires_an_aware_timestamp() -> None:
    api = _event_api()
    event = _valid_event()

    with pytest.raises(api.DiagnosticValidationError):
        event.outcome = api.DiagnosticOutcome.FAILURE

    with pytest.raises(api.DiagnosticValidationError):
        _valid_event(timestamp=datetime(2026, 11, 2, 10, 11, 12))


def test_unknown_fields_cannot_be_added_through_unvalidated_model_instances() -> None:
    api = _event_api()
    event = _valid_event()
    event.__dict__["prompt"] = "SYNTHETIC-CANARY"

    from sentinel.observability.logging import encode_event

    with pytest.raises(api.DiagnosticValidationError):
        encode_event(event)
