from __future__ import annotations

import json
from datetime import date
from importlib.resources import files

import pytest

from sentinel.readers.calendar_fixture import _parse_calendar_fixture_bytes
from sentinel.readers.calendar_types import CalendarFixtureError, CalendarFixtureErrorCode


def _mutated(**changes):
    raw = files("sentinel.readers").joinpath("fixtures", "calendar-events-v1.json").read_bytes()
    document = json.loads(raw)
    event = document["events"][2]
    event.update(changes)
    return _parse_calendar_fixture_bytes(
        json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )


def test_all_day_end_date_is_exclusive_and_remains_a_date_interval() -> None:
    fixture = _mutated()
    all_day = fixture.events[2].time_range
    assert all_day.start_date == date(2026, 11, 10)
    assert all_day.end_date_exclusive == date(2026, 11, 12)
    assert all_day.duration_days == 2


@pytest.mark.parametrize(
    ("start", "end"),
    [
        ({"date": "2026-11-10"}, {"dateTime": "2026-11-12T00:00:00Z"}),
        ({"dateTime": "2026-11-10T00:00:00Z"}, {"date": "2026-11-12"}),
        ({"date": "2026-11-10", "dateTime": "2026-11-10T00:00:00Z"}, {"date": "2026-11-12"}),
        ({"date": "2026-11-10"}, {"date": "2026-11-10"}),
        ({"date": "2026-11-12"}, {"date": "2026-11-10"}),
        ({"date": "2026-11-10"}, {"date": "2026-12-12"}),
        ({"date": "2026-02-30"}, {"date": "2026-03-01"}),
    ],
)
def test_invalid_all_day_shapes_or_ranges_are_rejected(start, end) -> None:
    raw = files("sentinel.readers").joinpath("fixtures", "calendar-events-v1.json").read_bytes()
    document = json.loads(raw)
    document["events"][2]["start"] = start
    document["events"][2]["end"] = end
    with pytest.raises(CalendarFixtureError) as error:
        _parse_calendar_fixture_bytes(
            json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
    assert error.value.code is CalendarFixtureErrorCode.INVALID_EVENT_TIME


def test_all_day_time_zone_is_not_accepted_or_inferred() -> None:
    raw = files("sentinel.readers").joinpath("fixtures", "calendar-events-v1.json").read_bytes()
    document = json.loads(raw)
    document["events"][2]["start"]["timeZone"] = "Asia/Tokyo"
    with pytest.raises(CalendarFixtureError) as error:
        _parse_calendar_fixture_bytes(
            json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
    assert error.value.code is CalendarFixtureErrorCode.INVALID_FIXTURE
