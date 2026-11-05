"""Credential-free readers for fixtures and explicitly selected local sources."""

from sentinel.readers.calendar_fixture import (
    CALENDAR_FIXTURE_SCHEMA_VERSION,
    CALENDAR_FIXTURE_SHA256,
    CALENDAR_FIXTURE_VERSION,
    read_packaged_calendar_fixture,
)
from sentinel.readers.calendar_formatters import (
    format_json_calendar_fixture,
    format_text_calendar_fixture,
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
from sentinel.readers.github_fixture import (
    FIXTURE_OBSERVED_AT,
    FIXTURE_SCHEMA_VERSION,
    FIXTURE_SHA256,
    GithubFixtureError,
    GithubFixtureErrorCode,
    read_packaged_github_fixture,
)
from sentinel.readers.gmail_fixture import (
    GMAIL_FIXTURE_OBSERVED_AT,
    GMAIL_FIXTURE_SCHEMA_VERSION,
    GMAIL_FIXTURE_SHA256,
    GmailFixtureError,
    GmailFixtureErrorCode,
    read_packaged_gmail_fixture,
)
from sentinel.readers.local_search import (
    format_json_local_file_search,
    format_text_local_file_search,
    search_selected_local_text_files,
)
from sentinel.readers.local_search_types import (
    LocalFileMatch,
    LocalFilePreview,
    LocalFileSearch,
    LocalFileSearchFile,
    LocalSearchError,
    LocalSearchErrorCode,
)
from sentinel.readers.local_text import read_allowlisted_local_text, verify_local_text_span
from sentinel.readers.local_text_types import (
    LocalFileMetadata,
    LocalTextCitation,
    LocalTextError,
    LocalTextErrorCode,
    LocalTextFormat,
    LocalTextRead,
)
from sentinel.readers.types import (
    GithubFixtureIssue,
    GithubFixtureRead,
    GmailFixtureMessage,
    GmailFixtureRead,
)

__all__ = [
    "CALENDAR_FIXTURE_SCHEMA_VERSION",
    "CALENDAR_FIXTURE_SHA256",
    "CALENDAR_FIXTURE_VERSION",
    "CalendarFixtureDateRange",
    "CalendarFixtureError",
    "CalendarFixtureErrorCode",
    "CalendarFixtureEvent",
    "CalendarFixtureEventStatus",
    "CalendarFixtureRead",
    "CalendarFixtureTimedRange",
    "FIXTURE_OBSERVED_AT",
    "FIXTURE_SCHEMA_VERSION",
    "FIXTURE_SHA256",
    "GithubFixtureError",
    "GithubFixtureErrorCode",
    "GithubFixtureIssue",
    "GithubFixtureRead",
    "GMAIL_FIXTURE_OBSERVED_AT",
    "GMAIL_FIXTURE_SCHEMA_VERSION",
    "GMAIL_FIXTURE_SHA256",
    "GmailFixtureError",
    "GmailFixtureErrorCode",
    "GmailFixtureMessage",
    "GmailFixtureRead",
    "LocalFileMetadata",
    "LocalFileMatch",
    "LocalFilePreview",
    "LocalFileSearch",
    "LocalFileSearchFile",
    "LocalSearchError",
    "LocalSearchErrorCode",
    "LocalTextCitation",
    "LocalTextError",
    "LocalTextErrorCode",
    "LocalTextFormat",
    "LocalTextRead",
    "read_packaged_gmail_fixture",
    "read_packaged_github_fixture",
    "read_packaged_calendar_fixture",
    "read_allowlisted_local_text",
    "verify_local_text_span",
    "search_selected_local_text_files",
    "format_text_local_file_search",
    "format_json_local_file_search",
    "format_json_calendar_fixture",
    "format_text_calendar_fixture",
]
