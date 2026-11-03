"""Narrow persistence APIs for fixed, synthetic reader inputs."""

from sentinel.ingestion.github_fixture import (
    ingest_packaged_github_fixture,
    read_persisted_github_fixture,
    verify_persisted_github_citation,
)
from sentinel.ingestion.types import (
    GithubFixtureIngestionError,
    GithubFixtureIngestionErrorCode,
    GithubFixtureIngestionReport,
    PersistedGithubFixture,
    PersistedGithubItem,
    PersistedGithubSpan,
)

__all__ = [
    "GithubFixtureIngestionError",
    "GithubFixtureIngestionErrorCode",
    "GithubFixtureIngestionReport",
    "PersistedGithubFixture",
    "PersistedGithubItem",
    "PersistedGithubSpan",
    "ingest_packaged_github_fixture",
    "read_persisted_github_fixture",
    "verify_persisted_github_citation",
]
