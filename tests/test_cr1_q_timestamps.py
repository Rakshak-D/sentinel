from __future__ import annotations

import json
from datetime import UTC, datetime
from importlib.resources import files

import pytest

from sentinel.readers.calendar_fixture import _parse_calendar_fixture_bytes
from sentinel.readers.calendar_types import CalendarFixtureError, CalendarFixtureErrorCode
from tests.test_cr1_q_calendar_reader import CALENDAR_FIXTURE_SHA256


def _document() -> dict[str, object]:
    raw = files("sentinel.readers").joinpath("fixtures", "calendar-events-v1.json").read_bytes()
    assert __import__("hashlib").sha256(raw).hexdigest() == CALENDAR_FIXTURE_SHA256
    return json.loads(raw)


def _parse(document: dict[str, object]):
    return _parse_calendar_fixture_bytes(
        json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )


def test_utc_z_and_explicit_plus_0530_are_normalized_to_utc_instants() -> None:
    fixture = _parse(_document())
    utc_event, offset_event = fixture.events[:2]
    assert utc_event.time_range.start_utc == datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
    assert utc_event.time_range.end_utc == datetime(2026, 11, 5, 9, 30, tzinfo=UTC)
    assert offset_event.time_range.start_text == "2026-11-06T18:00:00+05:30"
    assert offset_event.time_range.start_utc == datetime(2026, 11, 6, 12, 30, tzinfo=UTC)
    assert offset_event.time_range.end_utc == datetime(2026, 11, 6, 13, 45, tzinfo=UTC)


def test_equivalent_explicit_offsets_compare_as_equal_instants() -> None:
    baseline = _parse(_document()).events[0].time_range
    document = _document()
    event = document["events"][0]
    event["start"] = {"dateTime": "2026-11-05T14:30:00+05:30"}
    event["end"] = {"dateTime": "2026-11-05T15:00:00+05:30"}
    equivalent = _parse(document).events[0].time_range
    assert equivalent.start_text.endswith("+05:30")
    assert equivalent.start_utc == baseline.start_utc
    assert equivalent.end_utc == baseline.end_utc


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-11-05T09:00:00",
        "2026-02-30T09:00:00Z",
        "2026-11-05T09:00:60Z",
        "2026-11-05 09:00:00Z",
        "2026-11-05T09:00:00+24:00",
        "2026-11-05T09:00:00+05:60",
        "2026-11-05T09:00:00-00:00",
    ],
)
def test_noncanonical_or_invalid_timestamps_are_rejected(timestamp: str) -> None:
    document = _document()
    document["events"][0]["start"] = {"dateTime": timestamp}
    with pytest.raises(CalendarFixtureError) as error:
        _parse(document)
    assert error.value.code is CalendarFixtureErrorCode.INVALID_EVENT_TIME


@pytest.mark.parametrize(
    ("start", "end"),
    [
        ("2026-11-05T09:00:00Z", "2026-11-05T09:00:00Z"),
        ("2026-11-05T10:00:00Z", "2026-11-05T09:00:00Z"),
        ("2026-11-01T00:00:00Z", "2026-11-09T00:00:00Z"),
    ],
)
def test_timed_end_must_follow_start_within_seven_days(start: str, end: str) -> None:
    document = _document()
    document["events"][0]["start"] = {"dateTime": start}
    document["events"][0]["end"] = {"dateTime": end}
    with pytest.raises(CalendarFixtureError) as error:
        _parse(document)
    assert error.value.code is CalendarFixtureErrorCode.INVALID_EVENT_TIME
