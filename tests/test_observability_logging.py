from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta, timezone
from io import StringIO
from uuid import uuid4

import pytest


def _api():
    from sentinel.observability import events, logging

    return events, logging


def _event(**overrides: object):
    events, _ = _api()
    fields: dict[str, object] = {
        "event_code": events.DiagnosticEventCode.GATEWAY_OPERATION_RESULT,
        "timestamp": datetime(2026, 11, 2, 10, 11, 12, tzinfo=UTC),
        "severity": events.DiagnosticSeverity.INFO,
        "outcome": events.DiagnosticOutcome.SUCCESS,
        "run_id": uuid4(),
        "boundary_id": uuid4(),
        "component": events.DiagnosticComponent.MODEL_GATEWAY,
        "sensitivity": None,
        "error_code": None,
    }
    fields.update(overrides)
    return events.DiagnosticEvent(**fields)


def test_emit_writes_one_json_line_to_the_configured_sink_only(capsys) -> None:
    _, logging = _api()
    sink = StringIO()
    logger = logging.JsonLinesDiagnosticLogger(sink)

    logger.emit(_event())

    record = json.loads(sink.getvalue())
    assert record["event_code"] == "gateway.operation_result"
    assert record["severity"] == "INFO"
    assert record["outcome"] == "SUCCESS"
    assert len(sink.getvalue().splitlines()) == 1
    assert capsys.readouterr().out == ""
    assert capsys.readouterr().err == ""


def test_record_contains_typed_correlations_and_utc_timestamp() -> None:
    _, logging = _api()
    run_id = uuid4()
    boundary_id = uuid4()
    sink = StringIO()
    event = _event(
        timestamp=datetime(
            2026,
            11,
            2,
            15,
            41,
            12,
            tzinfo=timezone(timedelta(hours=5, minutes=30)),
        ),
        run_id=run_id,
        boundary_id=boundary_id,
    )

    logging.JsonLinesDiagnosticLogger(sink).emit(event)
    record = json.loads(sink.getvalue())

    assert record["run_id"] == str(run_id)
    assert record["boundary_id"] == str(boundary_id)
    assert record["timestamp"] == "2026-11-02T10:11:12.000000Z"


def test_fixed_event_has_deterministic_json_representation() -> None:
    _, logging = _api()
    fixed_id = uuid4()
    first = _event(run_id=fixed_id, boundary_id=None)
    second = _event(run_id=fixed_id, boundary_id=None)

    assert logging.encode_event(first) == logging.encode_event(second)
    assert logging.encode_event(first).startswith('{"boundary_id":null,')


def test_multiple_records_are_independently_parseable() -> None:
    events, logging = _api()
    sink = StringIO()
    logger = logging.JsonLinesDiagnosticLogger(sink)
    logger.emit(_event())
    logger.emit(_event(outcome=events.DiagnosticOutcome.DENIED))

    lines = sink.getvalue().splitlines()
    assert len(lines) == 2
    assert all(isinstance(json.loads(line), dict) for line in lines)


def test_synthetic_exception_uses_safe_code_and_never_emits_exception_text() -> None:
    events, logging = _api()
    sink = StringIO()
    canary = "SYNTHETIC-EXCEPTION-SECRET-71c4"

    try:
        raise RuntimeError(canary)
    except RuntimeError:
        event = _event(
            event_code=events.DiagnosticEventCode.DIAGNOSTIC_FAILURE,
            severity=events.DiagnosticSeverity.ERROR,
            outcome=events.DiagnosticOutcome.FAILURE,
            component=events.DiagnosticComponent.OBSERVABILITY,
            error_code=events.DiagnosticErrorCode.INTERNAL_ERROR,
        )
        logging.JsonLinesDiagnosticLogger(sink).emit(event)

    record = json.loads(sink.getvalue())
    assert record["error_code"] == "internal_error"
    assert canary not in sink.getvalue()


def test_newline_and_control_injection_cannot_create_a_forged_record() -> None:
    events, _ = _api()
    sink = StringIO()

    with pytest.raises(events.DiagnosticValidationError) as exc_info:
        _event(event_code="gateway.operation_result\n{\"forged\":true}")

    assert sink.getvalue() == ""
    assert "forged" not in str(exc_info.value)


def test_sensitive_payload_and_credential_fields_are_not_serializable() -> None:
    events, _ = _api()
    sink = StringIO()
    canaries = {
        "prompt": "SYNTHETIC-PROMPT-CANARY",
        "authorization": "Bearer SYNTHETIC-TOKEN-CANARY",
        "cookie": "SYNTHETIC-COOKIE-CANARY",
        "email_body": "SYNTHETIC-EMAIL-CANARY",
        "source_document": "SYNTHETIC-SOURCE-CANARY",
    }

    for field, value in canaries.items():
        with pytest.raises(events.DiagnosticValidationError) as exc_info:
            _event(**{field: value})
        assert value not in str(exc_info.value)

    assert sink.getvalue() == ""
    assert all(canary not in sink.getvalue() for canary in canaries.values())


def test_logger_revalidates_unchecked_models_before_writing() -> None:
    events, logging = _api()
    event = _event()
    malformed_values = event.model_dump()
    malformed_values["event_code"] = "arbitrary\nsecret"
    malformed = events.DiagnosticEvent.model_construct(**malformed_values)
    sink = StringIO()

    with pytest.raises(events.DiagnosticValidationError):
        logging.JsonLinesDiagnosticLogger(sink).emit(malformed)

    assert sink.getvalue() == ""


def test_stderr_factory_uses_stderr_and_sink_errors_are_not_silent(capsys) -> None:
    _, logging = _api()
    logging.stderr_logger().emit(_event())
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["event_code"] == "gateway.operation_result"

    class BrokenSink:
        def write(self, value: str) -> int:
            raise OSError("SYNTHETIC-SINK-PATH-CANARY")

        def flush(self) -> None:
            return None

    with pytest.raises(logging.DiagnosticSinkError) as exc_info:
        logging.JsonLinesDiagnosticLogger(BrokenSink()).emit(_event())
    assert str(exc_info.value) == "Diagnostic output failed."
    assert "SYNTHETIC-SINK-PATH-CANARY" not in str(exc_info.value)


def test_standard_output_cannot_be_selected_as_a_diagnostic_sink() -> None:
    _, logging = _api()

    with pytest.raises(logging.DiagnosticSinkError) as exc_info:
        logging.JsonLinesDiagnosticLogger(sys.stdout)

    assert str(exc_info.value) == "Standard output is reserved for command or protocol output."
