from __future__ import annotations

import hashlib
import json
from importlib.resources import files

import pytest

from sentinel.normalization import NormalizationError, verify_bound_citation
from sentinel.readers import read_packaged_calendar_fixture
from sentinel.readers.calendar_fixture import _parse_calendar_fixture_bytes
from sentinel.readers.calendar_types import CalendarFixtureError, CalendarFixtureErrorCode


def test_description_citations_verify_exact_utf8_bytes_and_source_association() -> None:
    fixture = read_packaged_calendar_fixture()
    for event in fixture.events:
        raw = event.description_bytes
        for citation in event.citations:
            cited = verify_bound_citation(
                event.normalized_description,
                citation,
                original_bytes=raw,
            )
            encoded = cited.encode("utf-8")
            assert raw[citation.span.start_byte:citation.span.end_byte] == encoded
            assert citation.source_id == event.source_id
            assert citation.content_sha256 == event.description_sha256
            assert hashlib.sha256(encoded).hexdigest() == citation.span.text_sha256


def test_repeated_description_phrase_keeps_distinct_byte_ranges_and_span_ids() -> None:
    event = read_packaged_calendar_fixture().events[0]
    repeated = [
        citation
        for citation in event.citations
        if verify_bound_citation(event.normalized_description, citation) == "blue notebook"
    ]
    assert len(repeated) == 2
    assert repeated[0].span.start_byte != repeated[1].span.start_byte
    assert repeated[0].span.span_id != repeated[1].span.span_id


def test_cross_event_citation_and_wrong_expected_text_are_rejected() -> None:
    fixture = read_packaged_calendar_fixture()
    with pytest.raises(NormalizationError):
        verify_bound_citation(
            fixture.events[1].normalized_description,
            fixture.events[0].citations[0],
        )

    raw = files("sentinel.readers").joinpath("fixtures", "calendar-events-v1.json").read_bytes()
    document = json.loads(raw)
    document["events"][0]["evidence_spans"][0]["expected_text"] = "wrong excerpt"
    with pytest.raises(CalendarFixtureError) as error:
        _parse_calendar_fixture_bytes(
            json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
    assert error.value.code is CalendarFixtureErrorCode.INVALID_CITATION


def test_japanese_emoji_crlf_and_lf_bytes_are_preserved() -> None:
    fixture = read_packaged_calendar_fixture()
    offset_event = fixture.events[1]
    assert "東京の庭" in offset_event.description_text
    assert "🌱" in offset_event.description_text
    assert b"\n" in offset_event.description_bytes
    assert b"\r\n" in offset_event.description_bytes
    for citation in offset_event.citations:
        verify_bound_citation(offset_event.normalized_description, citation)


def test_fixture_pins_each_citation_slice_digest_and_rejects_digest_tampering() -> None:
    raw = files("sentinel.readers").joinpath("fixtures", "calendar-events-v1.json").read_bytes()
    document = json.loads(raw)
    event = read_packaged_calendar_fixture().events[0]
    body = event.description_bytes
    for expected, citation in zip(
        document["events"][0]["evidence_spans"], event.citations, strict=True
    ):
        cited = body[citation.span.start_byte:citation.span.end_byte]
        assert expected["text_sha256"] == hashlib.sha256(cited).hexdigest()
        assert expected["text_sha256"] == citation.span.text_sha256

    document["events"][0]["evidence_spans"][0]["text_sha256"] = "0" * 64
    with pytest.raises(CalendarFixtureError) as error:
        _parse_calendar_fixture_bytes(
            json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
    assert error.value.code is CalendarFixtureErrorCode.INVALID_CITATION
