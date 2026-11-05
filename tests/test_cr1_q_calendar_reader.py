from __future__ import annotations

import hashlib
import json
from importlib.resources import files

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization import verify_bound_citation
from sentinel.readers import (
    CALENDAR_FIXTURE_SCHEMA_VERSION,
    CALENDAR_FIXTURE_SHA256,
    CalendarFixtureDateRange,
    CalendarFixtureTimedRange,
    read_packaged_calendar_fixture,
)


def test_packaged_calendar_fixture_is_pinned_and_has_four_stable_events() -> None:
    raw = files("sentinel.readers").joinpath("fixtures", "calendar-events-v1.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CALENDAR_FIXTURE_SHA256
    fixture = read_packaged_calendar_fixture()
    assert fixture.fixture_version == CALENDAR_FIXTURE_SCHEMA_VERSION
    assert fixture.fixture_sha256 == CALENDAR_FIXTURE_SHA256
    assert fixture.calendar_alias == "sentinel-fictional-calendar-v1"
    assert len(fixture.events) == 4
    assert len({event.event_id for event in fixture.events}) == 4
    repeated = read_packaged_calendar_fixture()
    assert tuple(event.event_id for event in fixture.events) == tuple(
        event.event_id for event in repeated.events
    )
    assert tuple(event.source_id for event in fixture.events) == tuple(
        event.source_id for event in repeated.events
    )
    assert tuple(event.description_sha256 for event in fixture.events) == tuple(
        event.description_sha256 for event in repeated.events
    )
    assert len({event.source_id for event in fixture.events}) == 4


def test_event_descriptions_keep_exact_bytes_labels_and_distinct_source_identity() -> None:
    fixture = read_packaged_calendar_fixture()
    assert all(
        event.normalized_description.envelope.provider_id == "calendar.fixture"
        for event in fixture.events
    )
    for event in fixture.events:
        source = event.normalized_description
        assert source.envelope.trust is TrustLabel.T4_EXTERNAL
        assert source.envelope.sensitivity is SensitivityLabel.PRIVATE
        assert source.original_bytes == event.description_text.encode("utf-8")
        assert hashlib.sha256(source.original_bytes).hexdigest() == event.description_sha256
        assert event.description_byte_length == len(source.original_bytes)
        assert b"\r\n" in source.original_bytes or b"\n" in source.original_bytes
        assert len(event.citations) > 0
        for citation in event.citations:
            cited = verify_bound_citation(
                source, citation, original_bytes=source.original_bytes
            )
            encoded = cited.encode("utf-8")
            assert source.original_bytes[citation.span.start_byte:citation.span.end_byte] == encoded
            assert hashlib.sha256(encoded).hexdigest() == citation.span.text_sha256


def test_timed_and_all_day_records_remain_distinct_typed_ranges() -> None:
    fixture = read_packaged_calendar_fixture()
    assert isinstance(fixture.events[0].time_range, CalendarFixtureTimedRange)
    assert isinstance(fixture.events[1].time_range, CalendarFixtureTimedRange)
    assert isinstance(fixture.events[2].time_range, CalendarFixtureDateRange)
    assert isinstance(fixture.events[3].time_range, CalendarFixtureTimedRange)
    all_day = fixture.events[2].time_range
    assert all_day.end_date_exclusive.isoformat() == "2026-11-12"
    assert all_day.duration_days == 2


def test_private_metadata_and_description_are_hidden_from_result_repr() -> None:
    fixture = read_packaged_calendar_fixture()
    rendered = repr(fixture)
    assert "Synthetic focus review" not in rendered
    assert "Focus review" not in rendered
    assert "ignore previous instructions" not in rendered


def test_distinct_event_ids_produce_distinct_sources_even_for_identical_descriptions() -> None:
    from sentinel.readers.calendar_fixture import (
        _event_source_id,
        _parse_calendar_fixture_bytes,
        _span_id,
    )

    raw = files("sentinel.readers").joinpath("fixtures", "calendar-events-v1.json").read_bytes()
    document = json.loads(raw)
    first, second = document["events"][:2]
    first["description"] = dict(second["description"])
    first["evidence_spans"] = [dict(span) for span in second["evidence_spans"]]
    first["id"] = "same-body-event-a"
    second["id"] = "same-body-event-b"
    for event in (first, second):
        for span in event["evidence_spans"]:
            span["span_id"] = str(
                _span_id(
                    document["calendar_alias"],
                    event["id"],
                    span["start_byte"],
                    span["end_byte"],
                )
            )
    parsed = _parse_calendar_fixture_bytes(
        json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )
    assert parsed.events[0].description_sha256 == parsed.events[1].description_sha256
    assert parsed.events[0].source_id != parsed.events[1].source_id
    assert _event_source_id(document["calendar_alias"], first["id"]) != _event_source_id(
        document["calendar_alias"], second["id"]
    )
