"""Credential-free, packaged source fixture readers."""

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
from sentinel.readers.types import (
    GithubFixtureIssue,
    GithubFixtureRead,
    GmailFixtureMessage,
    GmailFixtureRead,
)

__all__ = [
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
    "read_packaged_gmail_fixture",
    "read_packaged_github_fixture",
]
