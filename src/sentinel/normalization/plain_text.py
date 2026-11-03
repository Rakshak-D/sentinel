"""Strict, in-memory plain-text normalization with byte-accurate citations."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Final
from uuid import UUID

from pydantic import ValidationError

from sentinel.contracts.envelopes import ByteSpan, SourceEnvelope
from sentinel.normalization.types import NormalizedPlainTextSource, PlainTextSourceDescriptor

MAX_PLAIN_TEXT_BYTES = 1_048_576
_UTF8_MIME_TYPE: Final = "text/plain; charset=utf-8"
_MIME_TOKEN: Final = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_MIME_PATTERN: Final = re.compile(
    rf"[ \t]*(?P<type>{_MIME_TOKEN})[ \t]*/[ \t]*(?P<subtype>{_MIME_TOKEN})"
    rf"[ \t]*(?:;[ \t]*(?P<name>{_MIME_TOKEN})[ \t]*=[ \t]*(?P<value>{_MIME_TOKEN})[ \t]*)?"
)


class NormalizationErrorCode(StrEnum):
    """Fixed non-sensitive error categories from the normalization boundary."""

    INVALID_DESCRIPTOR = "invalid_descriptor"
    INVALID_BYTES = "invalid_bytes"
    INVALID_MIME = "invalid_mime"
    UNSUPPORTED_MIME = "unsupported_mime"
    UNSUPPORTED_CHARSET = "unsupported_charset"
    TOO_LARGE = "too_large"
    INVALID_UTF8 = "invalid_utf8"
    INVALID_CITATION = "invalid_citation"
    INVALID_BOUND_CITATION = "invalid_bound_citation"
    SOURCE_DIGEST_MISMATCH = "source_digest_mismatch"
    CITATION_DIGEST_MISMATCH = "citation_digest_mismatch"
    CITATION_SOURCE_MISMATCH = "citation_source_mismatch"
    CITED_TEXT_MISMATCH = "cited_text_mismatch"
    INVALID_NORMALIZED_SOURCE = "invalid_normalized_source"


_ERROR_MESSAGES: Final[dict[NormalizationErrorCode, str]] = {
    NormalizationErrorCode.INVALID_DESCRIPTOR: "Source descriptor is invalid.",
    NormalizationErrorCode.INVALID_BYTES: "Source content must be bytes.",
    NormalizationErrorCode.INVALID_MIME: "MIME type is invalid.",
    NormalizationErrorCode.UNSUPPORTED_MIME: "MIME type is unsupported.",
    NormalizationErrorCode.UNSUPPORTED_CHARSET: "Character set is unsupported.",
    NormalizationErrorCode.TOO_LARGE: "Source content exceeds the configured size limit.",
    NormalizationErrorCode.INVALID_UTF8: "Source content is not valid UTF-8.",
    NormalizationErrorCode.INVALID_CITATION: "Citation byte range or identifier is invalid.",
    NormalizationErrorCode.INVALID_BOUND_CITATION: "Source-bound citation is invalid.",
    NormalizationErrorCode.SOURCE_DIGEST_MISMATCH: "Source content digest does not match.",
    NormalizationErrorCode.CITATION_DIGEST_MISMATCH: (
        "Citation digest does not match its source bytes."
    ),
    NormalizationErrorCode.CITATION_SOURCE_MISMATCH: "Citation is not attached to this source.",
    NormalizationErrorCode.CITED_TEXT_MISMATCH: (
        "Expected cited text does not match the source range."
    ),
    NormalizationErrorCode.INVALID_NORMALIZED_SOURCE: "Normalized source data is invalid.",
}


class NormalizationError(ValueError):
    """Bounded failure that never embeds source text or arbitrary exception details."""

    def __init__(self, code: NormalizationErrorCode) -> None:
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


def _normalize_descriptor(
    descriptor: PlainTextSourceDescriptor,
) -> PlainTextSourceDescriptor:
    if type(descriptor) is not PlainTextSourceDescriptor:
        raise NormalizationError(NormalizationErrorCode.INVALID_DESCRIPTOR)
    try:
        return PlainTextSourceDescriptor.model_validate(descriptor.model_dump(mode="python"))
    except (TypeError, ValidationError):
        raise NormalizationError(NormalizationErrorCode.INVALID_DESCRIPTOR) from None


def _parse_mime_type(mime_type: str) -> tuple[str, bool]:
    if type(mime_type) is not str or not mime_type or len(mime_type) > 128:
        raise NormalizationError(NormalizationErrorCode.INVALID_MIME)
    match = _MIME_PATTERN.fullmatch(mime_type)
    if match is None:
        raise NormalizationError(NormalizationErrorCode.INVALID_MIME)
    if match.group("type").lower() != "text" or match.group("subtype").lower() != "plain":
        raise NormalizationError(NormalizationErrorCode.UNSUPPORTED_MIME)

    parameter_name = match.group("name")
    parameter_value = match.group("value")
    if parameter_name is None:
        return _UTF8_MIME_TYPE, True
    if parameter_name.lower() != "charset":
        raise NormalizationError(NormalizationErrorCode.UNSUPPORTED_MIME)
    if parameter_value is None or parameter_value.lower() != "utf-8":
        raise NormalizationError(NormalizationErrorCode.UNSUPPORTED_CHARSET)
    return _UTF8_MIME_TYPE, False


def _decode_utf8(raw_content: bytes) -> str:
    try:
        return raw_content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise NormalizationError(NormalizationErrorCode.INVALID_UTF8) from None


def _validated_envelope(envelope: object) -> SourceEnvelope:
    if type(envelope) is not SourceEnvelope:
        raise NormalizationError(NormalizationErrorCode.INVALID_NORMALIZED_SOURCE)
    try:
        return SourceEnvelope.model_validate(envelope.model_dump(mode="python"))
    except (TypeError, ValidationError):
        raise NormalizationError(NormalizationErrorCode.INVALID_NORMALIZED_SOURCE) from None


def _validate_span_range(raw_content: bytes, span: ByteSpan) -> str:
    if span.start_byte < 0 or span.end_byte <= span.start_byte or span.end_byte > len(raw_content):
        raise NormalizationError(NormalizationErrorCode.INVALID_CITATION)
    try:
        raw_content[: span.start_byte].decode("utf-8", errors="strict")
        raw_content[: span.end_byte].decode("utf-8", errors="strict")
        cited_text = raw_content[span.start_byte : span.end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise NormalizationError(NormalizationErrorCode.INVALID_CITATION) from None
    if hashlib.sha256(raw_content[span.start_byte : span.end_byte]).hexdigest() != span.text_sha256:
        raise NormalizationError(NormalizationErrorCode.CITATION_DIGEST_MISMATCH)
    return cited_text


def _validate_normalized_source(source: NormalizedPlainTextSource) -> tuple[SourceEnvelope, bytes]:
    if type(source) is not NormalizedPlainTextSource:
        raise NormalizationError(NormalizationErrorCode.INVALID_NORMALIZED_SOURCE)
    if type(source.original_bytes) is not bytes or type(source.text) is not str:
        raise NormalizationError(NormalizationErrorCode.INVALID_NORMALIZED_SOURCE)
    if (
        type(source.payload_sha256) is not str
        or type(source.declared_mime_type) is not str
        or type(source.mime_type) is not str
        or type(source.charset) is not str
        or type(source.charset_was_defaulted) is not bool
    ):
        raise NormalizationError(NormalizationErrorCode.INVALID_NORMALIZED_SOURCE)
    if len(source.original_bytes) > MAX_PLAIN_TEXT_BYTES:
        raise NormalizationError(NormalizationErrorCode.INVALID_NORMALIZED_SOURCE)

    envelope = _validated_envelope(source.envelope)
    actual_digest = hashlib.sha256(source.original_bytes).hexdigest()
    if source.payload_sha256 != actual_digest or envelope.content_sha256 != actual_digest:
        raise NormalizationError(NormalizationErrorCode.SOURCE_DIGEST_MISMATCH)
    if _decode_utf8(source.original_bytes) != source.text:
        raise NormalizationError(NormalizationErrorCode.INVALID_NORMALIZED_SOURCE)
    canonical_mime, defaulted = _parse_mime_type(source.declared_mime_type)
    if (
        source.mime_type != canonical_mime
        or source.charset != "utf-8"
        or type(source.charset_was_defaulted) is not bool
        or source.charset_was_defaulted is not defaulted
    ):
        raise NormalizationError(NormalizationErrorCode.INVALID_NORMALIZED_SOURCE)

    span_ids: set[UUID] = set()
    for candidate in envelope.byte_spans:
        try:
            span = ByteSpan.model_validate(candidate.model_dump(mode="python"))
        except (TypeError, ValidationError):
            raise NormalizationError(NormalizationErrorCode.INVALID_CITATION) from None
        if span.span_id in span_ids:
            raise NormalizationError(NormalizationErrorCode.INVALID_CITATION)
        span_ids.add(span.span_id)
        _validate_span_range(source.original_bytes, span)
    return envelope, source.original_bytes


def normalize_plain_text(
    descriptor: PlainTextSourceDescriptor,
    raw_content: bytes,
    mime_type: str,
) -> NormalizedPlainTextSource:
    """Validate and decode a bounded UTF-8 text/plain payload without transforming it."""
    normalized_descriptor = _normalize_descriptor(descriptor)
    if type(raw_content) is not bytes:
        raise NormalizationError(NormalizationErrorCode.INVALID_BYTES)
    if len(raw_content) > MAX_PLAIN_TEXT_BYTES:
        raise NormalizationError(NormalizationErrorCode.TOO_LARGE)
    normalized_mime, charset_was_defaulted = _parse_mime_type(mime_type)
    decoded_text = _decode_utf8(raw_content)
    payload_sha256 = hashlib.sha256(raw_content).hexdigest()
    try:
        envelope = SourceEnvelope.model_validate(
            {
                "source_id": normalized_descriptor.source_id,
                "provider_id": normalized_descriptor.provider_id,
                "content_sha256": payload_sha256,
                "observed_at": normalized_descriptor.observed_at,
                "trust": normalized_descriptor.trust,
                "sensitivity": normalized_descriptor.sensitivity,
                "parent_ids": (),
                "byte_spans": (),
            }
        )
    except (TypeError, ValidationError):
        raise NormalizationError(NormalizationErrorCode.INVALID_DESCRIPTOR) from None
    return NormalizedPlainTextSource(
        envelope=envelope,
        text=decoded_text,
        original_bytes=raw_content,
        payload_sha256=payload_sha256,
        declared_mime_type=mime_type,
        mime_type=normalized_mime,
        charset="utf-8",
        charset_was_defaulted=charset_was_defaulted,
    )


def add_citation(
    source: NormalizedPlainTextSource,
    *,
    span_id: UUID,
    start_byte: int,
    end_byte: int,
    expected_text: str | None = None,
) -> NormalizedPlainTextSource:
    """Return a new normalized result with one verified half-open UTF-8 byte span."""
    envelope, raw_content = _validate_normalized_source(source)
    if type(span_id) is not UUID or type(start_byte) is not int or type(end_byte) is not int:
        raise NormalizationError(NormalizationErrorCode.INVALID_CITATION)
    if expected_text is not None and type(expected_text) is not str:
        raise NormalizationError(NormalizationErrorCode.CITED_TEXT_MISMATCH)
    if any(span.span_id == span_id for span in envelope.byte_spans):
        raise NormalizationError(NormalizationErrorCode.INVALID_CITATION)

    if 0 <= start_byte < end_byte <= len(raw_content):
        text_sha256 = hashlib.sha256(raw_content[start_byte:end_byte]).hexdigest()
    else:
        text_sha256 = "0" * 64
    try:
        candidate = ByteSpan.model_validate(
            {
                "span_id": span_id,
                "start_byte": start_byte,
                "end_byte": end_byte,
                "text_sha256": text_sha256,
            }
        )
    except (TypeError, ValidationError):
        raise NormalizationError(NormalizationErrorCode.INVALID_CITATION) from None
    cited_text = _validate_span_range(raw_content, candidate)
    if expected_text is not None and expected_text != cited_text:
        raise NormalizationError(NormalizationErrorCode.CITED_TEXT_MISMATCH)

    try:
        updated_envelope = SourceEnvelope.model_validate(
            {
                **envelope.model_dump(mode="python"),
                "byte_spans": (*envelope.byte_spans, candidate),
            }
        )
    except (TypeError, ValidationError):
        raise NormalizationError(NormalizationErrorCode.INVALID_NORMALIZED_SOURCE) from None
    return NormalizedPlainTextSource(
        envelope=updated_envelope,
        text=source.text,
        original_bytes=source.original_bytes,
        payload_sha256=source.payload_sha256,
        declared_mime_type=source.declared_mime_type,
        mime_type=source.mime_type,
        charset=source.charset,
        charset_was_defaulted=source.charset_was_defaulted,
    )


def verify_citation(
    source: NormalizedPlainTextSource,
    citation: ByteSpan,
    *,
    original_bytes: bytes | None = None,
    expected_text: str | None = None,
) -> str:
    """Recheck the source digest, association, UTF-8 boundaries and cited-byte digest."""
    envelope, _ = _validate_normalized_source(source)
    if original_bytes is None:
        verified_bytes = source.original_bytes
    elif type(original_bytes) is bytes:
        verified_bytes = original_bytes
    else:
        raise NormalizationError(NormalizationErrorCode.INVALID_BYTES)
    if len(verified_bytes) > MAX_PLAIN_TEXT_BYTES:
        raise NormalizationError(NormalizationErrorCode.TOO_LARGE)
    source_digest = hashlib.sha256(verified_bytes).hexdigest()
    if source_digest != envelope.content_sha256 or source_digest != source.payload_sha256:
        raise NormalizationError(NormalizationErrorCode.SOURCE_DIGEST_MISMATCH)
    if type(citation) is not ByteSpan:
        raise NormalizationError(NormalizationErrorCode.INVALID_CITATION)
    try:
        validated_citation = ByteSpan.model_validate(citation.model_dump(mode="python"))
    except (TypeError, ValidationError):
        raise NormalizationError(NormalizationErrorCode.INVALID_CITATION) from None
    if validated_citation not in envelope.byte_spans:
        raise NormalizationError(NormalizationErrorCode.CITATION_SOURCE_MISMATCH)
    cited_text = _validate_span_range(verified_bytes, validated_citation)
    if expected_text is not None:
        if type(expected_text) is not str or expected_text != cited_text:
            raise NormalizationError(NormalizationErrorCode.CITED_TEXT_MISMATCH)
    return cited_text
