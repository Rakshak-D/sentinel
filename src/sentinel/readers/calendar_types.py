"""Immutable results and bounded failures for the Calendar fixture reader."""

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum
from typing import TypeAlias
from uuid import UUID

from sentinel.normalization.types import NormalizedPlainTextSource, SourceBoundCitation


class CalendarFixtureErrorCode(StrEnum):
    FIXTURE_UNAVAILABLE = "fixture_unavailable"
    FIXTURE_HASH_MISMATCH = "fixture_hash_mismatch"
    INVALID_FIXTURE = "invalid_fixture"
    INVALID_EVENT_TIME = "invalid_event_time"
    INVALID_DESCRIPTION = "invalid_description"
    INVALID_CITATION = "invalid_citation"
    OUTPUT_TOO_LARGE = "output_too_large"


_ERROR_MESSAGES = {
    CalendarFixtureErrorCode.FIXTURE_UNAVAILABLE: "The packaged Calendar fixture is unavailable.",
    CalendarFixtureErrorCode.FIXTURE_HASH_MISMATCH: (
        "The packaged Calendar fixture failed integrity verification."
    ),
    CalendarFixtureErrorCode.INVALID_FIXTURE: "The synthetic Calendar fixture is invalid.",
    CalendarFixtureErrorCode.INVALID_EVENT_TIME: "A synthetic Calendar event time is invalid.",
    CalendarFixtureErrorCode.INVALID_DESCRIPTION: "A synthetic Calendar description is invalid.",
    CalendarFixtureErrorCode.INVALID_CITATION: (
        "A synthetic Calendar description citation is invalid."
    ),
    CalendarFixtureErrorCode.OUTPUT_TOO_LARGE: (
        "The complete Calendar fixture inspection exceeds its output limit."
    ),
}


class CalendarFixtureError(ValueError):
    """Fixed, non-sensitive error for the packaged Calendar fixture reader."""

    def __init__(self, code: CalendarFixtureErrorCode) -> None:
        if type(code) is not CalendarFixtureErrorCode:
            raise TypeError("calendar fixture error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


class CalendarFixtureEventStatus(StrEnum):
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class CalendarFixtureTimedRange:
    start_text: str = field(repr=False)
    end_text: str = field(repr=False)
    start_utc: datetime = field(repr=False)
    end_utc: datetime = field(repr=False)

    @property
    def duration_seconds(self) -> float:
        return (self.end_utc - self.start_utc).total_seconds()


@dataclass(frozen=True, slots=True)
class CalendarFixtureDateRange:
    start_date: date = field(repr=False)
    end_date_exclusive: date = field(repr=False)

    @property
    def duration_days(self) -> int:
        return (self.end_date_exclusive - self.start_date).days


CalendarFixtureRange: TypeAlias = CalendarFixtureTimedRange | CalendarFixtureDateRange


@dataclass(frozen=True, slots=True)
class CalendarFixtureEvent:
    event_id: str
    status: CalendarFixtureEventStatus
    summary: str = field(repr=False)
    time_range: CalendarFixtureRange
    normalized_description: NormalizedPlainTextSource = field(repr=False)
    citations: tuple[SourceBoundCitation, ...]

    @property
    def source_id(self) -> UUID:
        return self.normalized_description.envelope.source_id

    @property
    def description_sha256(self) -> str:
        return self.normalized_description.payload_sha256

    @property
    def description_byte_length(self) -> int:
        return len(self.normalized_description.original_bytes)

    @property
    def description_text(self) -> str:
        """Explicit trusted access to decoded description text."""

        return self.normalized_description.text

    @property
    def description_bytes(self) -> bytes:
        """Explicit trusted access to the exact decoded description bytes."""

        return self.normalized_description.original_bytes

    @property
    def is_all_day(self) -> bool:
        return isinstance(self.time_range, CalendarFixtureDateRange)


@dataclass(frozen=True, slots=True)
class CalendarFixtureRead:
    fixture_version: str
    calendar_alias: str
    fixture_sha256: str
    events: tuple[CalendarFixtureEvent, ...]


__all__ = [
    "CalendarFixtureDateRange",
    "CalendarFixtureError",
    "CalendarFixtureErrorCode",
    "CalendarFixtureEvent",
    "CalendarFixtureEventStatus",
    "CalendarFixtureRange",
    "CalendarFixtureRead",
    "CalendarFixtureTimedRange",
]
