"""Immutable, passive source and model/tool boundary envelope contracts."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from sentinel.contracts.labels import BoundaryKind, SensitivityLabel, TrustLabel

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CONTENT_REF_PATTERN = rf"^sha256:{_SHA256_PATTERN[1:-1]}$"
_IDENTIFIER_PATTERN = r"^[a-z][a-z0-9_.:-]{0,127}$"
_ERROR_CODE_PATTERN = r"^[a-z][a-z0-9_.:-]{0,63}$"

Sha256Digest = Annotated[str, StringConstraints(strict=True, pattern=_SHA256_PATTERN)]
ContentReference = Annotated[
    str,
    StringConstraints(strict=True, pattern=_CONTENT_REF_PATTERN, max_length=71),
]
ContractIdentifier = Annotated[
    str,
    StringConstraints(strict=True, pattern=_IDENTIFIER_PATTERN, max_length=128),
]
ErrorCode = Annotated[
    str,
    StringConstraints(strict=True, pattern=_ERROR_CODE_PATTERN, max_length=64),
]


class _FrozenContract(BaseModel):
    """Shared frozen configuration; collection fields are immutable tuples."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ByteSpan(_FrozenContract):
    """A source byte range and its digest, analogous to the §10 source_spans row.

    The containing SourceEnvelope supplies the source identity, so item_id is not
    duplicated here. The blueprint does not provide a source byte-length field;
    upper-bound validation against the complete body therefore belongs to the
    future normalization layer. This contract enforces 0 <= start < end.
    """

    span_id: UUID
    start_byte: Annotated[StrictInt, Field(ge=0)]
    end_byte: Annotated[StrictInt, Field(gt=0)]
    text_sha256: Sha256Digest
    context_ref: ContentReference | None = None
    derived_by_boundary_id: UUID | None = None

    @model_validator(mode="after")
    def validate_nonempty_ordered_range(self) -> "ByteSpan":
        if self.end_byte <= self.start_byte:
            raise ValueError("byte span must satisfy start_byte < end_byte")
        return self


class SourceEnvelope(_FrozenContract):
    """Typed source metadata only; raw source text and credentials stay external."""

    source_id: UUID
    provider_id: ContractIdentifier
    content_sha256: Sha256Digest
    observed_at: AwareDatetime
    trust: TrustLabel
    sensitivity: SensitivityLabel
    parent_ids: tuple[UUID, ...]
    byte_spans: tuple[ByteSpan, ...]

    @field_validator("observed_at")
    @classmethod
    def normalize_observed_at_to_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator("parent_ids")
    @classmethod
    def reject_duplicate_parents(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(value) != len(set(value)):
            raise ValueError("parent_ids must not contain duplicates")
        return value

    @model_validator(mode="after")
    def reject_self_parent(self) -> "SourceEnvelope":
        if self.source_id in self.parent_ids:
            raise ValueError("source_id cannot be its own parent")
        return self


class BoundaryEnvelope(_FrozenContract):
    """Typed references and digests for one model/tool boundary crossing.

    This model is a record shape, not a dispatch instruction or authorization.
    Request/response bodies, provider credentials, and tool handlers are not
    represented. A response reference and response digest must be present or
    absent together.
    """

    boundary_id: UUID
    run_id: UUID
    seq: Annotated[StrictInt, Field(ge=1)]
    kind: BoundaryKind
    adapter_id: ContractIdentifier
    request_ref: ContentReference
    response_ref: ContentReference | None
    request_sha256: Sha256Digest
    response_sha256: Sha256Digest | None
    sensitivity: SensitivityLabel
    source_ids: tuple[UUID, ...]
    replay_injected: StrictBool
    error_code: ErrorCode | None
    created_at: AwareDatetime

    @field_validator("created_at")
    @classmethod
    def normalize_created_at_to_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator("source_ids")
    @classmethod
    def reject_duplicate_sources(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(value) != len(set(value)):
            raise ValueError("source_ids must not contain duplicates")
        return value

    @model_validator(mode="after")
    def validate_response_pair_and_references(self) -> "BoundaryEnvelope":
        if (self.response_ref is None) != (self.response_sha256 is None):
            raise ValueError("response_ref and response_sha256 must be present together")
        if self.request_ref != f"sha256:{self.request_sha256}":
            raise ValueError("request_ref digest must match request_sha256")
        if self.response_ref is not None and self.response_ref != f"sha256:{self.response_sha256}":
            raise ValueError("response_ref digest must match response_sha256")
        return self
