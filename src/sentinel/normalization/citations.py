"""Explicit byte-range and source-bound citation APIs."""

import hashlib

from pydantic import ValidationError

from sentinel.contracts.envelopes import ByteSpan
from sentinel.normalization.plain_text import (
    MAX_PLAIN_TEXT_BYTES,
    NormalizationError,
    NormalizationErrorCode,
    _validate_normalized_source,
    _validate_span_range,
    add_citation,
    verify_citation,
)
from sentinel.normalization.types import NormalizedPlainTextSource, SourceBoundCitation


def _validate_citation(citation: ByteSpan) -> ByteSpan:
    if type(citation) is not ByteSpan:
        raise NormalizationError(NormalizationErrorCode.INVALID_CITATION)
    try:
        return ByteSpan.model_validate(citation.model_dump(mode="python"))
    except (TypeError, ValidationError):
        raise NormalizationError(NormalizationErrorCode.INVALID_CITATION) from None


def _validate_bound_citation(citation: SourceBoundCitation) -> SourceBoundCitation:
    if type(citation) is not SourceBoundCitation:
        raise NormalizationError(NormalizationErrorCode.INVALID_BOUND_CITATION)
    try:
        data = citation.model_dump(mode="python")
        return SourceBoundCitation.model_validate(data)
    except (TypeError, ValueError):
        raise NormalizationError(NormalizationErrorCode.INVALID_BOUND_CITATION) from None


def bind_citation(
    source: NormalizedPlainTextSource,
    citation: ByteSpan,
) -> SourceBoundCitation:
    """Bind a member span to a validated source ID and complete content digest."""
    envelope, raw_content = _validate_normalized_source(source)
    validated_span = _validate_citation(citation)
    if validated_span not in envelope.byte_spans:
        raise NormalizationError(NormalizationErrorCode.CITATION_SOURCE_MISMATCH)
    _validate_span_range(raw_content, validated_span)
    try:
        return SourceBoundCitation(
            source_id=envelope.source_id,
            content_sha256=envelope.content_sha256,
            span=validated_span,
        )
    except (TypeError, ValueError):
        raise NormalizationError(NormalizationErrorCode.INVALID_BOUND_CITATION) from None


def verify_bound_citation(
    source: NormalizedPlainTextSource,
    bound_citation: SourceBoundCitation,
    *,
    original_bytes: bytes | None = None,
    expected_text: str | None = None,
) -> str:
    """Revalidate source identity, content bytes, span membership and cited bytes."""
    envelope, _ = _validate_normalized_source(source)
    citation = _validate_bound_citation(bound_citation)
    if citation.source_id != envelope.source_id:
        raise NormalizationError(NormalizationErrorCode.CITATION_SOURCE_MISMATCH)
    if citation.content_sha256 != envelope.content_sha256:
        raise NormalizationError(NormalizationErrorCode.SOURCE_DIGEST_MISMATCH)

    if original_bytes is None:
        verified_bytes = source.original_bytes
    elif type(original_bytes) is bytes:
        verified_bytes = original_bytes
    else:
        raise NormalizationError(NormalizationErrorCode.INVALID_BYTES)
    if len(verified_bytes) > MAX_PLAIN_TEXT_BYTES:
        raise NormalizationError(NormalizationErrorCode.TOO_LARGE)
    actual_digest = hashlib.sha256(verified_bytes).hexdigest()
    if actual_digest != envelope.content_sha256 or actual_digest != citation.content_sha256:
        raise NormalizationError(NormalizationErrorCode.SOURCE_DIGEST_MISMATCH)
    if citation.span not in envelope.byte_spans:
        raise NormalizationError(NormalizationErrorCode.CITATION_SOURCE_MISMATCH)

    cited_text = _validate_span_range(verified_bytes, citation.span)
    if expected_text is not None:
        if type(expected_text) is not str or expected_text != cited_text:
            raise NormalizationError(NormalizationErrorCode.CITED_TEXT_MISMATCH)
    return cited_text


__all__ = [
    "ByteSpan",
    "SourceBoundCitation",
    "add_citation",
    "bind_citation",
    "verify_bound_citation",
    "verify_citation",
]
