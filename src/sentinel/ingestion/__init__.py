"""Narrow persistence APIs for fixed, synthetic reader inputs."""

from sentinel.ingestion.blob_promotion import promote_github_fixture_to_public_blobs
from sentinel.ingestion.blob_readback import (
    read_blob_backed_github_body,
    read_blob_backed_github_fixture,
    verify_blob_backed_github_citation,
)
from sentinel.ingestion.github_fixture import (
    ingest_packaged_github_fixture,
    read_persisted_github_fixture,
    verify_persisted_github_citation,
)
from sentinel.ingestion.types import (
    BlobBackedGithubFixture,
    GithubBlobIntegrationError,
    GithubBlobIntegrationErrorCode,
    GithubBlobPromotionReport,
    GithubFixtureIngestionError,
    GithubFixtureIngestionErrorCode,
    GithubFixtureIngestionReport,
    PersistedGithubFixture,
    PersistedGithubItem,
    PersistedGithubSpan,
)

__all__ = [
    "BlobBackedGithubFixture",
    "GithubBlobIntegrationError",
    "GithubBlobIntegrationErrorCode",
    "GithubBlobPromotionReport",
    "GithubFixtureIngestionError",
    "GithubFixtureIngestionErrorCode",
    "GithubFixtureIngestionReport",
    "PersistedGithubFixture",
    "PersistedGithubItem",
    "PersistedGithubSpan",
    "ingest_packaged_github_fixture",
    "promote_github_fixture_to_public_blobs",
    "read_blob_backed_github_body",
    "read_blob_backed_github_fixture",
    "read_persisted_github_fixture",
    "verify_persisted_github_citation",
    "verify_blob_backed_github_citation",
]
