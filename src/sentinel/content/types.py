"""Immutable public-fixture content-store result types."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PublicFixtureBlob:
    content_sha256: str
    payload_byte_length: int


@dataclass(frozen=True, slots=True)
class PublicFixtureStoreReport:
    format_version: str
    fixture_version: str
    fixture_sha256: str
    inserted_count: int
    existing_count: int
    blobs: tuple[PublicFixtureBlob, ...]
