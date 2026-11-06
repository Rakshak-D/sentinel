"""Trusted, body-free lineage binding for the fixed synthetic GitHub fixture."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Literal, cast
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from sentinel.contracts import ByteSpan, SensitivityLabel, SourceEnvelope, TrustLabel
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST, MANIFEST_VERSION
from sentinel.ingestion.blob_readback import read_blob_backed_github_evidence
from sentinel.ingestion.types import VerifiedBlobBackedGithubEvidence

_SHA256 = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64)]
_BINDING_DOMAIN = b"sentinel.verified-public-source-binding.v1\x00"
SOURCE_BINDING_SCHEMA: Literal["sentinel.verified-public-source-binding.v1"] = (
    "sentinel.verified-public-source-binding.v1"
)


class PublicCitationBinding(BaseModel):
    """Citation identity and byte provenance; never includes excerpt text."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always"
    )

    span_id: UUID
    start_byte: Annotated[int, Field(ge=0)]
    end_byte: Annotated[int, Field(gt=0)]
    text_sha256: _SHA256

    @model_validator(mode="after")
    def require_nonempty_byte_range(self) -> PublicCitationBinding:
        if self.end_byte <= self.start_byte:
            raise ValueError("citation byte range must be nonempty")
        return self


class PublicSourceBinding(BaseModel):
    """Body-free exact metadata for one verified source in the pinned fixture."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always"
    )

    source_id: UUID
    item_id: UUID
    provider_item_id: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]
    content_sha256: _SHA256
    trust: TrustLabel
    sensitivity: SensitivityLabel
    citations: Annotated[tuple[PublicCitationBinding, ...], Field(min_length=1, max_length=16)]

    @field_validator("citations")
    @classmethod
    def require_unique_citation_ids(
        cls, value: tuple[PublicCitationBinding, ...]
    ) -> tuple[PublicCitationBinding, ...]:
        span_ids = tuple(item.span_id for item in value)
        if len(span_ids) != len(set(span_ids)):
            raise ValueError("citation identities must be unique within a source")
        return value


class VerifiedPublicSourceSet(BaseModel):
    """Canonical source-set identity derived only after pinned readback validation."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always"
    )

    schema_version: Literal["sentinel.verified-public-source-binding.v1"] = SOURCE_BINDING_SCHEMA
    provider_id: Literal["github.fixture"] = "github.fixture"
    fixture_version: Literal["sentinel.github-issues-fixture.v1"]
    fixture_sha256: _SHA256
    manifest_version: Literal["sentinel.github-fixture-persistence-manifest.v1"] = MANIFEST_VERSION
    manifest_sha256: _SHA256
    registry_source_id: UUID
    sources: Annotated[tuple[PublicSourceBinding, ...], Field(min_length=3, max_length=3)]
    source_set_sha256: _SHA256

    @field_validator("sources")
    @classmethod
    def require_unique_source_ids(
        cls, value: tuple[PublicSourceBinding, ...]
    ) -> tuple[PublicSourceBinding, ...]:
        source_ids = tuple(item.source_id for item in value)
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("source identities must be unique within the binding")
        return value


class PublicReadBindingError(ValueError):
    """Bounded validation failure; messages never include source data or paths."""

    def __init__(self) -> None:
        super().__init__("Verified public source evidence is unavailable.")


_VERIFIED_READ_SEAL = object()


class VerifiedGithubPublicRead:
    """Internal one-operation result with no mutable body and a resolver-only seal.

    The verified citations are retained separately for the existing briefing
    formatter. The policy binding contains only identifiers, hashes, labels and
    byte ranges. This seal protects the application-level API boundary; it is
    not process isolation or a cryptographic signature.
    """

    __slots__ = ("_evidence", "_binding", "_source_envelopes", "_seal")
    _evidence: VerifiedBlobBackedGithubEvidence
    _binding: VerifiedPublicSourceSet
    _source_envelopes: tuple[SourceEnvelope, ...]
    _seal: object

    def __init__(
        self,
        *,
        evidence: VerifiedBlobBackedGithubEvidence,
        binding: VerifiedPublicSourceSet,
        source_envelopes: tuple[SourceEnvelope, ...],
        _seal: object,
    ) -> None:
        if _seal is not _VERIFIED_READ_SEAL:
            raise TypeError("verified public read values are resolver-created")
        object.__setattr__(self, "_evidence", evidence)
        object.__setattr__(self, "_binding", binding)
        object.__setattr__(self, "_source_envelopes", source_envelopes)
        object.__setattr__(self, "_seal", _seal)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("verified public read values are immutable")

    def __repr__(self) -> str:
        return "VerifiedGithubPublicRead(<verified metadata omitted>)"

    @property
    def evidence(self) -> VerifiedBlobBackedGithubEvidence:
        """Verified excerpts for the fixed briefing path only."""
        return self._evidence

    @property
    def binding(self) -> VerifiedPublicSourceSet:
        return self._binding

    @property
    def source_envelopes(self) -> tuple[SourceEnvelope, ...]:
        return self._source_envelopes


def canonical_source_binding_bytes(binding: VerifiedPublicSourceSet) -> bytes:
    """Return stable UTF-8 JSON for exact body-free binding metadata."""
    if type(binding) is not VerifiedPublicSourceSet:
        raise TypeError("source binding must use the registered verified schema")
    validated = VerifiedPublicSourceSet.model_validate(
        binding.model_dump(mode="python"), strict=True
    )
    if validated != binding:
        raise ValueError("source binding is not canonical")
    payload = validated.model_dump(mode="json", exclude={"source_set_sha256"})
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def source_binding_sha256(binding: VerifiedPublicSourceSet) -> str:
    """Identify canonical source-set bytes; this digest is not authentication."""
    return hashlib.sha256(_BINDING_DOMAIN + canonical_source_binding_bytes(binding)).hexdigest()


def _expected_binding_sources(
    evidence: VerifiedBlobBackedGithubEvidence,
) -> tuple[tuple[PublicSourceBinding, ...], tuple[SourceEnvelope, ...]]:
    if type(evidence) is not VerifiedBlobBackedGithubEvidence:
        raise PublicReadBindingError
    if (
        evidence.provider_id != "github.fixture"
        or evidence.fixture_version != EXPECTED_MANIFEST.fixture_version
        or evidence.fixture_sha256 != EXPECTED_MANIFEST.fixture_sha256
        or evidence.manifest_sha256 != EXPECTED_MANIFEST.sha256
        or len(evidence.items) != len(EXPECTED_MANIFEST.items)
    ):
        raise PublicReadBindingError

    expected_by_id = {item.item_id: item for item in EXPECTED_MANIFEST.items}
    actual_ids = tuple(item.item_id for item in evidence.items)
    if len(actual_ids) != len(set(actual_ids)) or set(actual_ids) != set(expected_by_id):
        raise PublicReadBindingError

    bindings: list[PublicSourceBinding] = []
    envelopes: list[SourceEnvelope] = []
    seen_sources: set[UUID] = set()
    for item in evidence.items:
        expected = expected_by_id.get(item.item_id)
        if expected is None or item.source_envelope_id != expected.source_envelope_id:
            raise PublicReadBindingError
        if (
            item.provider_item_id != expected.provider_item_id
            or item.content_sha256 != expected.content_sha256
            or item.trust is not TrustLabel.T4_EXTERNAL
            or item.sensitivity is not SensitivityLabel.PUBLIC
            or item.source_envelope_id in seen_sources
            or len(item.citations) != len(expected.spans)
        ):
            raise PublicReadBindingError
        seen_sources.add(item.source_envelope_id)

        bound_citations: list[PublicCitationBinding] = []
        byte_spans: list[ByteSpan] = []
        for actual, expected_span in zip(item.citations, expected.spans, strict=True):
            if (
                actual.span_id != expected_span.span_id
                or actual.start_byte != expected_span.start_byte
                or actual.end_byte != expected_span.end_byte
                or actual.text_sha256 != expected_span.text_sha256
                or expected_span.source_id != expected.source_envelope_id
                or expected_span.content_sha256 != expected.content_sha256
            ):
                raise PublicReadBindingError
            try:
                cited_bytes = actual.cited_text.encode("utf-8", errors="strict")
            except (AttributeError, UnicodeEncodeError):
                raise PublicReadBindingError from None
            if (
                len(cited_bytes) != expected_span.end_byte - expected_span.start_byte
                or hashlib.sha256(cited_bytes).hexdigest() != expected_span.text_sha256
            ):
                raise PublicReadBindingError
            bound_citations.append(
                PublicCitationBinding(
                    span_id=actual.span_id,
                    start_byte=actual.start_byte,
                    end_byte=actual.end_byte,
                    text_sha256=actual.text_sha256,
                )
            )
            byte_spans.append(
                ByteSpan(
                    span_id=actual.span_id,
                    start_byte=actual.start_byte,
                    end_byte=actual.end_byte,
                    text_sha256=actual.text_sha256,
                )
            )
        bindings.append(
            PublicSourceBinding(
                source_id=item.source_envelope_id,
                item_id=item.item_id,
                provider_item_id=item.provider_item_id,
                content_sha256=item.content_sha256,
                trust=item.trust,
                sensitivity=item.sensitivity,
                citations=tuple(bound_citations),
            )
        )
        envelopes.append(
            SourceEnvelope(
                source_id=item.source_envelope_id,
                provider_id="github.fixture",
                content_sha256=item.content_sha256,
                observed_at=item.observed_at,
                trust=item.trust,
                sensitivity=item.sensitivity,
                parent_ids=(),
                byte_spans=tuple(byte_spans),
            )
        )
    return tuple(bindings), tuple(envelopes)


def resolve_github_fixture_public_read(
    database: str | Path,
    *,
    store_root: str | Path,
) -> VerifiedGithubPublicRead:
    """Resolve one complete pinned blob-backed snapshot, with no fixture fallback."""
    try:
        evidence = read_blob_backed_github_evidence(database, store_root=store_root)
        sources, envelopes = _expected_binding_sources(evidence)
        binding = VerifiedPublicSourceSet(
            fixture_version=cast(
                Literal["sentinel.github-issues-fixture.v1"], evidence.fixture_version
            ),
            fixture_sha256=evidence.fixture_sha256,
            manifest_sha256=evidence.manifest_sha256,
            registry_source_id=UUID(str(EXPECTED_MANIFEST.source_row[0])),
            sources=sources,
            source_set_sha256="0" * 64,
        )
        binding = binding.model_copy(
            update={"source_set_sha256": source_binding_sha256(binding)}
        )
        return VerifiedGithubPublicRead(
            evidence=evidence,
            binding=binding,
            source_envelopes=envelopes,
            _seal=_VERIFIED_READ_SEAL,
        )
    except PublicReadBindingError:
        raise
    except Exception:
        raise PublicReadBindingError from None


def validate_verified_github_public_read(value: object) -> bool:
    """Validate resolver seal, pinned metadata, envelopes and source-set digest."""
    if type(value) is not VerifiedGithubPublicRead or value._seal is not _VERIFIED_READ_SEAL:
        return False
    try:
        evidence = value.evidence
        expected_sources, expected_envelopes = _expected_binding_sources(evidence)
        binding = value.binding
        validated = VerifiedPublicSourceSet.model_validate(
            binding.model_dump(mode="python"), strict=True
        )
        if validated != binding or binding.sources != expected_sources:
            return False
        if value.source_envelopes != expected_envelopes:
            return False
        return (
            binding.source_set_sha256 == source_binding_sha256(binding)
            and binding.fixture_sha256 == EXPECTED_MANIFEST.fixture_sha256
            and binding.manifest_sha256 == EXPECTED_MANIFEST.sha256
            and binding.registry_source_id == UUID(str(EXPECTED_MANIFEST.source_row[0]))
        )
    except Exception:
        return False


__all__ = [
    "PublicCitationBinding",
    "PublicReadBindingError",
    "PublicSourceBinding",
    "VerifiedGithubPublicRead",
    "VerifiedPublicSourceSet",
    "canonical_source_binding_bytes",
    "resolve_github_fixture_public_read",
    "source_binding_sha256",
    "validate_verified_github_public_read",
]
