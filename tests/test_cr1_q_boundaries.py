from __future__ import annotations

import base64
import json
from importlib.resources import files
from uuid import uuid4

import pytest

from sentinel.readers import CalendarFixtureError, CalendarFixtureErrorCode, calendar_fixture


def _raw_fixture() -> bytes:
    return files("sentinel.readers").joinpath("fixtures", "calendar-events-v1.json").read_bytes()


def _document():
    return json.loads(_raw_fixture())


def _parse(document):
    return calendar_fixture._parse_calendar_fixture_bytes(
        json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )


def _set_body(event, raw: bytes, *, expected_text: str = "") -> None:
    event["description"] = {
        "encoding": "base64url-utf8",
        "size": len(raw),
        "data": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
    }
    event["evidence_spans"] = [] if not expected_text else [
        {
            "span_id": str(uuid4()),
            "start_byte": 0,
            "end_byte": len(expected_text.encode("utf-8")),
            "expected_text": expected_text,
        }
    ]


def _expect_invalid(document, code: CalendarFixtureErrorCode) -> None:
    with pytest.raises(CalendarFixtureError) as error:
        _parse(document)
    assert error.value.code is code


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc.update(unexpected=True),
        lambda doc: doc["events"][0].update(unexpected=True),
        lambda doc: doc["events"][0]["description"].update(unexpected=True),
        lambda doc: doc["events"][0]["start"].update(timeZone="UTC"),
        lambda doc: doc["events"][0].update(status="tentative"),
        lambda doc: doc["events"][0].update(id="event id with spaces"),
        lambda doc: doc["events"][0].update(summary="é" * 257),
        lambda doc: doc["events"][0].update(evidence_spans=[{"span_id": "bad"}]),
    ],
)
def test_unknown_or_invalid_schema_fields_fail_closed(mutate) -> None:
    document = _document()
    mutate(document)
    _expect_invalid(document, CalendarFixtureErrorCode.INVALID_FIXTURE)


def test_duplicate_json_keys_are_rejected() -> None:
    duplicated = _raw_fixture().replace(
        b'"calendar_alias":',
        b'"calendar_alias":"shadow", "calendar_alias":',
        1,
    )
    with pytest.raises(CalendarFixtureError) as error:
        calendar_fixture._parse_calendar_fixture_bytes(duplicated)
    assert error.value.code is CalendarFixtureErrorCode.INVALID_FIXTURE


def test_duplicate_event_ids_are_rejected() -> None:
    document = _document()
    document["events"][1]["id"] = document["events"][0]["id"]
    _expect_invalid(document, CalendarFixtureErrorCode.INVALID_FIXTURE)


@pytest.mark.parametrize("bad_data", ["!!!!", "A", "abcd=", "abc+"])
def test_noncanonical_base64url_is_rejected(bad_data: str) -> None:
    document = _document()
    document["events"][0]["description"]["data"] = bad_data
    _expect_invalid(document, CalendarFixtureErrorCode.INVALID_DESCRIPTION)


def test_invalid_utf8_and_oversized_description_are_rejected() -> None:
    document = _document()
    _set_body(document["events"][0], b"\xff")
    _expect_invalid(document, CalendarFixtureErrorCode.INVALID_DESCRIPTION)

    document = _document()
    _set_body(document["events"][0], b"x" * (16 * 1024 + 1))
    _expect_invalid(document, CalendarFixtureErrorCode.INVALID_DESCRIPTION)


def test_out_of_range_split_or_wrong_citation_is_rejected() -> None:
    document = _document()
    document["events"][0]["evidence_spans"][0]["end_byte"] = 1_000_000
    _expect_invalid(document, CalendarFixtureErrorCode.INVALID_CITATION)

    document = _document()
    document["events"][1]["evidence_spans"][0]["start_byte"] += 1
    _expect_invalid(document, CalendarFixtureErrorCode.INVALID_CITATION)

    document = _document()
    document["events"][0]["evidence_spans"][0]["expected_text"] = "not the cited bytes"
    _expect_invalid(document, CalendarFixtureErrorCode.INVALID_CITATION)


def test_duplicate_span_ids_and_excessive_event_or_citation_counts_are_rejected() -> None:
    document = _document()
    duplicate = document["events"][0]["evidence_spans"][0]
    document["events"][0]["evidence_spans"].append(dict(duplicate))
    _expect_invalid(document, CalendarFixtureErrorCode.INVALID_FIXTURE)

    document = _document()
    document["events"].extend(document["events"] * 2)
    _expect_invalid(document, CalendarFixtureErrorCode.INVALID_FIXTURE)

    document = _document()
    document["events"][0]["evidence_spans"] *= 6
    _expect_invalid(document, CalendarFixtureErrorCode.INVALID_FIXTURE)


def test_public_reader_rejects_missing_resource_and_hash_mismatch(monkeypatch) -> None:
    def raise_os_error() -> bytes:
        raise OSError

    with monkeypatch.context() as context:
        context.setattr(calendar_fixture, "_read_calendar_fixture_resource", raise_os_error)
        with pytest.raises(CalendarFixtureError) as error:
            calendar_fixture.read_packaged_calendar_fixture()
        assert error.value.code is CalendarFixtureErrorCode.FIXTURE_UNAVAILABLE

    with monkeypatch.context() as context:
        context.setattr(
            calendar_fixture,
            "_read_calendar_fixture_resource",
            lambda: _raw_fixture() + b" ",
        )
        with pytest.raises(CalendarFixtureError) as error:
            calendar_fixture.read_packaged_calendar_fixture()
        assert error.value.code is CalendarFixtureErrorCode.FIXTURE_HASH_MISMATCH


def test_oversized_fixture_resource_is_rejected() -> None:
    with pytest.raises(CalendarFixtureError) as error:
        calendar_fixture._parse_calendar_fixture_bytes(b" " * (64 * 1024 + 1))
    assert error.value.code is CalendarFixtureErrorCode.INVALID_FIXTURE
