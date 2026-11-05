"""Deterministic, privacy-conscious output for the Calendar fixture."""

from __future__ import annotations

import json
from datetime import UTC
from typing import Final, cast

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization import NormalizationError, verify_bound_citation
from sentinel.readers.calendar_fixture import read_packaged_calendar_fixture
from sentinel.readers.calendar_types import (
    CalendarFixtureError,
    CalendarFixtureErrorCode,
    CalendarFixtureEvent,
    CalendarFixtureEventStatus,
    CalendarFixtureRead,
    CalendarFixtureTimedRange,
)

MAX_CALENDAR_OUTPUT_BYTES: Final = 128 * 1024
_SCHEMA_VERSION: Final = "sentinel.calendar-fixture-inspection.v1"


def _escape_display_text(value: str) -> str:
    # The reader package is imported while ingestion loads the legacy fixture
    # adapters. Resolve this shared formatter lazily to avoid a briefing import
    # cycle, while retaining the established escaping behavior.
    from sentinel.briefing.formatters import escape_display_text

    return escape_display_text(value)


def _fail(code: CalendarFixtureErrorCode = CalendarFixtureErrorCode.INVALID_FIXTURE) -> None:
    raise CalendarFixtureError(code) from None


def _same_event(actual: object, expected: CalendarFixtureEvent) -> bool:
    if type(actual) is not CalendarFixtureEvent:
        return False
    event = actual
    source = event.normalized_description
    expected_source = expected.normalized_description
    return (
        event.event_id == expected.event_id
        and event.status is expected.status
        and event.summary == expected.summary
        and event.time_range == expected.time_range
        and event.source_id == expected.source_id
        and event.description_sha256 == expected.description_sha256
        and event.description_byte_length == expected.description_byte_length
        and event.description_bytes == expected.description_bytes
        and event.description_text == expected.description_text
        and source.envelope.model_dump(mode="python")
        == expected_source.envelope.model_dump(mode="python")
        and source.mime_type == expected_source.mime_type
        and source.charset == expected_source.charset
        and source.declared_mime_type == expected_source.declared_mime_type
        and source.charset_was_defaulted is expected_source.charset_was_defaulted
        and event.citations == expected.citations
    )


def _trusted_fixture(fixture: CalendarFixtureRead) -> CalendarFixtureRead:
    if type(fixture) is not CalendarFixtureRead or type(fixture.events) is not tuple:
        _fail()
    trusted = read_packaged_calendar_fixture()
    if (
        fixture.fixture_version != trusted.fixture_version
        or fixture.calendar_alias != trusted.calendar_alias
        or fixture.fixture_sha256 != trusted.fixture_sha256
        or len(fixture.events) != len(trusted.events)
        or any(not _same_event(actual, expected) for actual, expected in zip(
            fixture.events, trusted.events, strict=True
        ))
    ):
        _fail()
    return trusted


def _citation_documents(event: CalendarFixtureEvent) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for citation in event.citations:
        try:
            cited_text = verify_bound_citation(
                event.normalized_description,
                citation,
                original_bytes=event.description_bytes,
            )
        except (NormalizationError, TypeError, ValueError):
            _fail(CalendarFixtureErrorCode.INVALID_CITATION)
        result.append(
            {
                "span_id": str(citation.span.span_id),
                "start_byte": citation.span.start_byte,
                "end_byte": citation.span.end_byte,
                "text_sha256": citation.span.text_sha256,
                "cited_text": _escape_display_text(cited_text),
            }
        )
    return result


def _event_document(event: CalendarFixtureEvent, *, show_details: bool) -> dict[str, object]:
    document: dict[str, object] = {
        "event_id": event.event_id,
        "status": event.status.value,
        "event_kind": "all_day" if event.is_all_day else "timed",
        "source_id": str(event.source_id),
        "description_sha256": event.description_sha256,
        "description_byte_length": event.description_byte_length,
        "citation_count": len(event.citations),
        "trust": TrustLabel.T4_EXTERNAL.value,
        "sensitivity": SensitivityLabel.PRIVATE.value,
    }
    if not show_details:
        return document

    document["summary"] = _escape_display_text(event.summary)
    if isinstance(event.time_range, CalendarFixtureTimedRange):
        timed_range = event.time_range
        if (
            timed_range.start_utc.tzinfo is not UTC
            or timed_range.end_utc.tzinfo is not UTC
            or timed_range.end_utc <= timed_range.start_utc
        ):
            _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)
        document["time_range"] = {
            "kind": "timed",
            "start": timed_range.start_text,
            "end": timed_range.end_text,
            "start_utc": timed_range.start_utc.isoformat().replace("+00:00", "Z"),
            "end_utc": timed_range.end_utc.isoformat().replace("+00:00", "Z"),
            "duration_seconds": timed_range.duration_seconds,
        }
    else:
        date_range = event.time_range
        if date_range.end_date_exclusive <= date_range.start_date:
            _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)
        document["time_range"] = {
            "kind": "all_day",
            "start_date": date_range.start_date.isoformat(),
            "end_date_exclusive": date_range.end_date_exclusive.isoformat(),
            "end_semantics": "exclusive",
        }
    document["description_citations"] = _citation_documents(event)
    return document


def _document(fixture: CalendarFixtureRead, *, show_details: bool) -> dict[str, object]:
    trusted = _trusted_fixture(fixture)
    if (
        trusted.fixture_version != "sentinel.calendar-events-fixture.v1"
        or len(trusted.events) != 4
        or any(
            event.normalized_description.envelope.provider_id != "calendar.fixture"
            or event.normalized_description.envelope.trust is not TrustLabel.T4_EXTERNAL
            or event.normalized_description.envelope.sensitivity is not SensitivityLabel.PRIVATE
            for event in trusted.events
        )
    ):
        _fail()
    confirmed_count = sum(
        event.status is CalendarFixtureEventStatus.CONFIRMED for event in trusted.events
    )
    cancelled_count = sum(
        event.status is CalendarFixtureEventStatus.CANCELLED for event in trusted.events
    )
    return {
        "schema_version": _SCHEMA_VERSION,
        "synthetic_data": True,
        "fixture_version": trusted.fixture_version,
        "fixture_sha256": trusted.fixture_sha256,
        "calendar_alias": trusted.calendar_alias,
        "event_count": len(trusted.events),
        "status_counts": {"confirmed": confirmed_count, "cancelled": cancelled_count},
        "trust": TrustLabel.T4_EXTERNAL.value,
        "sensitivity": SensitivityLabel.PRIVATE.value,
        "details_included": show_details,
        "disclaimer": (
            "Fictional packaged Calendar fixture only; not the user's actual Calendar. "
            "Fixture metadata is not authenticated provider data."
        ),
        "events": [
            _event_document(event, show_details=show_details) for event in trusted.events
        ],
    }


def _bounded_output(value: str) -> str:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail()
    if len(encoded) > MAX_CALENDAR_OUTPUT_BYTES:
        _fail(CalendarFixtureErrorCode.OUTPUT_TOO_LARGE)
    return value


def format_json_calendar_fixture(
    fixture: CalendarFixtureRead,
    *,
    show_details: bool = False,
) -> str:
    """Render full verified fixture metadata as deterministic versioned JSON."""

    payload = _document(fixture, show_details=show_details)
    try:
        output = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        _fail()
    return _bounded_output(output)


def format_text_calendar_fixture(
    fixture: CalendarFixtureRead,
    *,
    show_details: bool = False,
) -> str:
    """Render a body-free Calendar fixture index with explicit detail disclosure."""

    payload = _document(fixture, show_details=show_details)
    status_counts = cast(dict[str, int], payload["status_counts"])
    lines = [
        "Sentinel - Synthetic Calendar fixture",
        "Data: fictional packaged fixture; not the user's actual Calendar",
        f"Fixture: {payload['fixture_version']} | SHA-256 {payload['fixture_sha256']}",
        f"Calendar alias: {payload['calendar_alias']}",
        f"Events: {payload['event_count']} | Confirmed: {status_counts['confirmed']} | "
        f"Cancelled: {status_counts['cancelled']}",
        "Trust: T4 EXTERNAL | Sensitivity: PRIVATE",
        "Event metadata is synthetic and not authenticated provider data.",
        f"Details included: {'yes' if show_details else 'no'}",
    ]
    for event in cast(list[dict[str, object]], payload["events"]):
        lines.extend(
            [
                "",
                f"Event: {event['event_id']} | {event['status']} | {event['event_kind']}",
                f"  Source UUID: {event['source_id']}",
                f"  Description SHA-256: {event['description_sha256']} "
                f"({event['description_byte_length']} bytes)",
                f"  Verified description citations: {event['citation_count']}",
            ]
        )
        if not show_details:
            continue
        lines.append(f"  Summary: {event['summary']}")
        time_range = cast(dict[str, object], event["time_range"])
        if time_range["kind"] == "timed":
            lines.extend(
                [
                    f"  Start: {time_range['start']} (UTC {time_range['start_utc']})",
                    f"  End: {time_range['end']} (UTC {time_range['end_utc']})",
                    f"  Duration: {time_range['duration_seconds']} seconds",
                ]
            )
        else:
            lines.extend(
                [
                    f"  All-day start: {time_range['start_date']}",
                    f"  End date (exclusive): {time_range['end_date_exclusive']}",
                ]
            )
        lines.append("  Verified description citations:")
        for citation in cast(list[dict[str, object]], event["description_citations"]):
            lines.append(
                f"    [bytes {citation['start_byte']}:{citation['end_byte']}) "
                f"span {citation['span_id']} sha256 {citation['text_sha256']}: "
                f'"{citation["cited_text"]}"'
            )
    return _bounded_output("\n".join(lines))


__all__ = [
    "MAX_CALENDAR_OUTPUT_BYTES",
    "format_json_calendar_fixture",
    "format_text_calendar_fixture",
]
