"""Strict, credential-free reader for one pinned fictional Calendar collection."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import UTC, date, datetime, timedelta
from importlib.resources import files
from typing import Annotated, Final, Literal, NoReturn
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization import (
    NormalizationError,
    PlainTextSourceDescriptor,
    add_citation,
    bind_citation,
    normalize_plain_text,
    verify_bound_citation,
)
from sentinel.readers.calendar_types import (
    CalendarFixtureDateRange,
    CalendarFixtureError,
    CalendarFixtureErrorCode,
    CalendarFixtureEvent,
    CalendarFixtureEventStatus,
    CalendarFixtureRead,
    CalendarFixtureTimedRange,
)

CALENDAR_FIXTURE_SCHEMA_VERSION: Final = "sentinel.calendar-events-fixture.v1"
CALENDAR_FIXTURE_VERSION: Final = CALENDAR_FIXTURE_SCHEMA_VERSION
CALENDAR_FIXTURE_SHA256: Final = "e879838ea32430497160bacbdedde1c4ffd98b1906bcdddc1c77c776f756575a"
CALENDAR_FIXTURE_OBSERVED_AT: Final = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)

MAX_CALENDAR_FIXTURE_BYTES: Final = 64 * 1024
MAX_CALENDAR_EVENTS: Final = 8
MAX_CALENDAR_DESCRIPTION_BYTES: Final = 16 * 1024
MAX_CALENDAR_DESCRIPTION_ENCODED_CHARS: Final = ((MAX_CALENDAR_DESCRIPTION_BYTES + 2) // 3) * 4
MAX_CALENDAR_SUMMARY_BYTES: Final = 512
MAX_CALENDAR_EVENT_ID_BYTES: Final = 128
MAX_CALENDAR_ALIAS_BYTES: Final = 64
MAX_CALENDAR_SPANS_PER_EVENT: Final = 16
MAX_CALENDAR_SPAN_TEXT_BYTES: Final = 4 * 1024
MAX_CALENDAR_TIMED_DURATION: Final = timedelta(days=7)
MAX_CALENDAR_ALL_DAY_DURATION_DAYS: Final = 30

_EVENT_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_-]{5,128}")
_CALENDAR_ALIAS_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9-]{1,62}[a-z0-9]")
_BASE64URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_-]*")
_DATE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_DATETIME_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{1,6})?"
    r"(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


def _fail(code: CalendarFixtureErrorCode) -> NoReturn:
    raise CalendarFixtureError(code) from None


class _FrozenStrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class _CalendarEndpoint(_FrozenStrictModel):
    date: StrictStr | None = None
    dateTime: StrictStr | None = None


class _Description(_FrozenStrictModel):
    encoding: Literal["base64url-utf8"]
    size: Annotated[StrictInt, Field(ge=0)]
    data: StrictStr


class _EvidenceSpan(_FrozenStrictModel):
    span_id: UUID
    start_byte: Annotated[StrictInt, Field(ge=0)]
    end_byte: Annotated[StrictInt, Field(gt=0)]
    text_sha256: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
    expected_text: Annotated[
        StrictStr,
        Field(min_length=1, max_length=MAX_CALENDAR_SPAN_TEXT_BYTES),
    ]

    @model_validator(mode="after")
    def validate_range_order(self) -> _EvidenceSpan:
        if self.end_byte <= self.start_byte:
            raise ValueError("invalid evidence range")
        return self


class _CalendarEvent(_FrozenStrictModel):
    id: Annotated[StrictStr, Field(min_length=5, max_length=MAX_CALENDAR_EVENT_ID_BYTES)]
    status: Literal["confirmed", "cancelled"]
    summary: StrictStr
    start: _CalendarEndpoint
    end: _CalendarEndpoint
    description: _Description
    evidence_spans: tuple[_EvidenceSpan, ...] = Field(max_length=MAX_CALENDAR_SPANS_PER_EVENT)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not value.isascii() or _EVENT_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("invalid event ID")
        return value

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise ValueError("invalid summary") from None
        if len(encoded) > MAX_CALENDAR_SUMMARY_BYTES:
            raise ValueError("summary too large")
        return value

    @model_validator(mode="after")
    def validate_unique_span_ids(self) -> _CalendarEvent:
        span_ids = [item.span_id for item in self.evidence_spans]
        if len(span_ids) != len(set(span_ids)):
            raise ValueError("duplicate description citation ID")
        return self


class _CalendarFixtureDocument(_FrozenStrictModel):
    fixture_version: Literal["sentinel.calendar-events-fixture.v1"]
    calendar_alias: Annotated[
        StrictStr,
        Field(min_length=3, max_length=MAX_CALENDAR_ALIAS_BYTES),
    ]
    events: tuple[_CalendarEvent, ...] = Field(min_length=1, max_length=MAX_CALENDAR_EVENTS)

    @field_validator("calendar_alias")
    @classmethod
    def validate_calendar_alias(cls, value: str) -> str:
        if not value.isascii() or _CALENDAR_ALIAS_PATTERN.fullmatch(value) is None:
            raise ValueError("invalid synthetic Calendar alias")
        return value

    @model_validator(mode="after")
    def reject_duplicate_event_ids(self) -> _CalendarFixtureDocument:
        event_ids = [event.id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("duplicate event ID")
        return self


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> NoReturn:
    raise ValueError("non-standard JSON constant")


def _read_calendar_fixture_resource() -> bytes:
    """Read only the fixed package resource; callers cannot select a path."""

    resource = files("sentinel.readers").joinpath("fixtures", "calendar-events-v1.json")
    with resource.open("rb") as stream:
        return stream.read(MAX_CALENDAR_FIXTURE_BYTES + 1)


def _event_source_id(calendar_alias: str, event_id: str) -> UUID:
    return uuid5(
        NAMESPACE_URL,
        f"sentinel:calendar.fixture:v1:{calendar_alias}#{event_id}",
    )


def _span_id(calendar_alias: str, event_id: str, start_byte: int, end_byte: int) -> UUID:
    return uuid5(
        NAMESPACE_URL,
        f"sentinel:calendar.fixture:v1:{calendar_alias}#{event_id}:span:{start_byte}:{end_byte}",
    )


def _decode_description(description: _Description) -> bytes:
    encoded = description.data
    if (
        type(encoded) is not str
        or description.size > MAX_CALENDAR_DESCRIPTION_BYTES
        or len(encoded) > MAX_CALENDAR_DESCRIPTION_ENCODED_CHARS
        or _BASE64URL_PATTERN.fullmatch(encoded) is None
        or len(encoded) % 4 == 1
    ):
        _fail(CalendarFixtureErrorCode.INVALID_DESCRIPTION)
    try:
        ascii_data = encoded.encode("ascii", errors="strict")
        raw = base64.b64decode(
            ascii_data + b"=" * (-len(ascii_data) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError):
        _fail(CalendarFixtureErrorCode.INVALID_DESCRIPTION)
    if base64.urlsafe_b64encode(raw).rstrip(b"=") != ascii_data:
        _fail(CalendarFixtureErrorCode.INVALID_DESCRIPTION)
    if len(raw) > MAX_CALENDAR_DESCRIPTION_BYTES or len(raw) != description.size:
        _fail(CalendarFixtureErrorCode.INVALID_DESCRIPTION)
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail(CalendarFixtureErrorCode.INVALID_DESCRIPTION)
    return raw


def _parse_datetime(value: str) -> datetime:
    if (
        type(value) is not str
        or len(value) > 40
        or _DATETIME_PATTERN.fullmatch(value) is None
        or value.endswith("-00:00")
    ):
        _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError):
        _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)


def _parse_date(value: str) -> date:
    if type(value) is not str or _DATE_PATTERN.fullmatch(value) is None:
        _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)
    if parsed.isoformat() != value:
        _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)
    return parsed


def _parse_event_range(
    event: _CalendarEvent,
) -> CalendarFixtureTimedRange | CalendarFixtureDateRange:
    start_fields = event.start.model_fields_set
    end_fields = event.end.model_fields_set
    valid_shapes = ({"dateTime"}, {"date"})
    if (
        start_fields not in valid_shapes
        or end_fields not in valid_shapes
        or start_fields != end_fields
    ):
        _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)
    if start_fields == {"dateTime"}:
        if event.start.dateTime is None or event.end.dateTime is None:
            _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)
        start_text = event.start.dateTime
        end_text = event.end.dateTime
        start_utc = _parse_datetime(start_text)
        end_utc = _parse_datetime(end_text)
        if end_utc <= start_utc or end_utc - start_utc > MAX_CALENDAR_TIMED_DURATION:
            _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)
        return CalendarFixtureTimedRange(
            start_text=start_text,
            end_text=end_text,
            start_utc=start_utc,
            end_utc=end_utc,
        )

    if event.start.date is None or event.end.date is None:
        _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)
    start_date = _parse_date(event.start.date)
    end_date = _parse_date(event.end.date)
    duration = (end_date - start_date).days
    if duration <= 0 or duration > MAX_CALENDAR_ALL_DAY_DURATION_DAYS:
        _fail(CalendarFixtureErrorCode.INVALID_EVENT_TIME)
    return CalendarFixtureDateRange(start_date=start_date, end_date_exclusive=end_date)


def _parse_calendar_fixture_bytes(raw_json: bytes) -> CalendarFixtureRead:
    """Private strict parser for mutation tests; package entry always checks the pin."""

    if type(raw_json) is not bytes or len(raw_json) > MAX_CALENDAR_FIXTURE_BYTES:
        _fail(CalendarFixtureErrorCode.INVALID_FIXTURE)
    try:
        decoded_json = raw_json.decode("utf-8", errors="strict")
        json.loads(
            decoded_json,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
        document = _CalendarFixtureDocument.model_validate_json(raw_json, strict=True)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
        ValidationError,
    ):
        _fail(CalendarFixtureErrorCode.INVALID_FIXTURE)

    events: list[CalendarFixtureEvent] = []
    for event in document.events:
        time_range = _parse_event_range(event)
        body_bytes = _decode_description(event.description)
        try:
            source_id = _event_source_id(document.calendar_alias, event.id)
            normalized = normalize_plain_text(
                PlainTextSourceDescriptor(
                    source_id=source_id,
                    provider_id="calendar.fixture",
                    observed_at=CALENDAR_FIXTURE_OBSERVED_AT,
                    trust=TrustLabel.T4_EXTERNAL,
                    sensitivity=SensitivityLabel.PRIVATE,
                ),
                body_bytes,
                "text/plain; charset=utf-8",
            )
        except (NormalizationError, TypeError, ValueError):
            _fail(CalendarFixtureErrorCode.INVALID_DESCRIPTION)

        citations = []
        try:
            for evidence in event.evidence_spans:
                expected_bytes = evidence.expected_text.encode("utf-8", errors="strict")
                if len(expected_bytes) > MAX_CALENDAR_SPAN_TEXT_BYTES:
                    _fail(CalendarFixtureErrorCode.INVALID_CITATION)
                cited_bytes = body_bytes[evidence.start_byte:evidence.end_byte]
                if hashlib.sha256(cited_bytes).hexdigest() != evidence.text_sha256:
                    _fail(CalendarFixtureErrorCode.INVALID_CITATION)
                if evidence.span_id != _span_id(
                    document.calendar_alias,
                    event.id,
                    evidence.start_byte,
                    evidence.end_byte,
                ):
                    _fail(CalendarFixtureErrorCode.INVALID_CITATION)
                normalized = add_citation(
                    normalized,
                    span_id=evidence.span_id,
                    start_byte=evidence.start_byte,
                    end_byte=evidence.end_byte,
                    expected_text=evidence.expected_text,
                )
                span = next(
                    item
                    for item in normalized.envelope.byte_spans
                    if item.span_id == evidence.span_id
                )
                bound = bind_citation(normalized, span)
                if verify_bound_citation(
                    normalized,
                    bound,
                    original_bytes=body_bytes,
                    expected_text=evidence.expected_text,
                ) != evidence.expected_text:
                    _fail(CalendarFixtureErrorCode.INVALID_CITATION)
                citations.append(bound)
        except CalendarFixtureError:
            raise
        except (NormalizationError, StopIteration, UnicodeEncodeError, TypeError, ValueError):
            _fail(CalendarFixtureErrorCode.INVALID_CITATION)

        events.append(
            CalendarFixtureEvent(
                event_id=event.id,
                status=CalendarFixtureEventStatus(event.status),
                summary=event.summary,
                time_range=time_range,
                normalized_description=normalized,
                citations=tuple(citations),
            )
        )

    return CalendarFixtureRead(
        fixture_version=document.fixture_version,
        calendar_alias=document.calendar_alias,
        fixture_sha256=hashlib.sha256(raw_json).hexdigest(),
        events=tuple(events),
    )


def read_packaged_calendar_fixture() -> CalendarFixtureRead:
    """Read, hash-check, and validate the one fixed packaged Calendar fixture."""

    try:
        raw_json = _read_calendar_fixture_resource()
    except Exception:
        _fail(CalendarFixtureErrorCode.FIXTURE_UNAVAILABLE)
    if type(raw_json) is not bytes or len(raw_json) > MAX_CALENDAR_FIXTURE_BYTES:
        _fail(CalendarFixtureErrorCode.INVALID_FIXTURE)
    if hashlib.sha256(raw_json).hexdigest() != CALENDAR_FIXTURE_SHA256:
        _fail(CalendarFixtureErrorCode.FIXTURE_HASH_MISMATCH)
    return _parse_calendar_fixture_bytes(raw_json)


__all__ = [
    "CALENDAR_FIXTURE_OBSERVED_AT",
    "CALENDAR_FIXTURE_SCHEMA_VERSION",
    "CALENDAR_FIXTURE_SHA256",
    "CALENDAR_FIXTURE_VERSION",
    "MAX_CALENDAR_ALIAS_BYTES",
    "MAX_CALENDAR_DESCRIPTION_BYTES",
    "MAX_CALENDAR_EVENTS",
    "MAX_CALENDAR_EVENT_ID_BYTES",
    "MAX_CALENDAR_FIXTURE_BYTES",
    "MAX_CALENDAR_SPAN_TEXT_BYTES",
    "MAX_CALENDAR_SPANS_PER_EVENT",
    "MAX_CALENDAR_SUMMARY_BYTES",
    "MAX_CALENDAR_TIMED_DURATION",
    "read_packaged_calendar_fixture",
]
