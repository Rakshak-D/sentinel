"""Typed descriptor and immutable in-memory normalization result."""

from typing import Any
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, ValidationError, field_validator

from sentinel.contracts.envelopes import (
    ByteSpan,
    ContractIdentifier,
    Sha256Digest,
    SourceEnvelope,
)
from sentinel.contracts.labels import SensitivityLabel, TrustLabel


class PlainTextSourceDescriptor(BaseModel):
    """Caller-supplied metadata; labels do not authenticate the caller."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    source_id: UUID
    provider_id: ContractIdentifier
    observed_at: AwareDatetime
    trust: TrustLabel
    sensitivity: SensitivityLabel

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except (TypeError, ValueError):
            raise ValueError("Source descriptor is invalid.") from None


class NormalizedPlainTextSource:
    """Immutable internal source value; default repr omits all source content."""

    __slots__ = (
        "_envelope",
        "_text",
        "_original_bytes",
        "_payload_sha256",
        "_declared_mime_type",
        "_mime_type",
        "_charset",
        "_charset_was_defaulted",
    )

    _envelope: SourceEnvelope
    _text: str
    _original_bytes: bytes
    _payload_sha256: str
    _declared_mime_type: str
    _mime_type: str
    _charset: str
    _charset_was_defaulted: bool

    def __init__(
        self,
        *,
        envelope: SourceEnvelope,
        text: str,
        original_bytes: bytes,
        payload_sha256: str,
        declared_mime_type: str,
        mime_type: str,
        charset: str,
        charset_was_defaulted: bool,
    ) -> None:
        object.__setattr__(self, "_envelope", envelope)
        object.__setattr__(self, "_text", text)
        object.__setattr__(self, "_original_bytes", original_bytes)
        object.__setattr__(self, "_payload_sha256", payload_sha256)
        object.__setattr__(self, "_declared_mime_type", declared_mime_type)
        object.__setattr__(self, "_mime_type", mime_type)
        object.__setattr__(self, "_charset", charset)
        object.__setattr__(self, "_charset_was_defaulted", charset_was_defaulted)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("NormalizedPlainTextSource is immutable.")

    @property
    def envelope(self) -> SourceEnvelope:
        return self._envelope

    @property
    def text(self) -> str:
        """Return exact decoded content to an explicit trusted internal caller."""
        return self._text

    @property
    def original_bytes(self) -> bytes:
        """Return the exact original bytes to an explicit trusted internal caller."""
        return self._original_bytes

    @property
    def payload_sha256(self) -> str:
        return self._payload_sha256

    @property
    def declared_mime_type(self) -> str:
        return self._declared_mime_type

    @property
    def mime_type(self) -> str:
        return self._mime_type

    @property
    def charset(self) -> str:
        return self._charset

    @property
    def charset_was_defaulted(self) -> bool:
        return self._charset_was_defaulted

    @property
    def citations(self) -> tuple[ByteSpan, ...]:
        """Return the source's typed byte spans, without a raw-body serializer."""
        return self.envelope.byte_spans


class SourceBoundCitation(BaseModel):
    """Immutable source identity, full content digest, and existing byte-span record."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    source_id: UUID
    content_sha256: Sha256Digest
    span: ByteSpan

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except (TypeError, ValueError):
            raise ValueError("Source-bound citation is invalid.") from None

    @field_validator("span", mode="before")
    @classmethod
    def revalidate_span(cls, value: object) -> ByteSpan:
        if type(value) is ByteSpan:
            candidate: object = value.model_dump(mode="python")
        elif type(value) is dict:
            candidate = value
        else:
            raise ValueError("Source-bound citation span is invalid.")
        try:
            return ByteSpan.model_validate(candidate)
        except (TypeError, ValidationError):
            raise ValueError("Source-bound citation span is invalid.") from None
