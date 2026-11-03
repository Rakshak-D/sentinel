"""Plain-text source normalization and citation helpers."""

from sentinel.normalization.citations import bind_citation, verify_bound_citation
from sentinel.normalization.plain_text import (
    MAX_PLAIN_TEXT_BYTES,
    NormalizationError,
    NormalizationErrorCode,
    add_citation,
    normalize_plain_text,
    verify_citation,
)
from sentinel.normalization.types import (
    NormalizedPlainTextSource,
    PlainTextSourceDescriptor,
    SourceBoundCitation,
)

__all__ = [
    "MAX_PLAIN_TEXT_BYTES",
    "NormalizationError",
    "NormalizationErrorCode",
    "NormalizedPlainTextSource",
    "PlainTextSourceDescriptor",
    "SourceBoundCitation",
    "add_citation",
    "bind_citation",
    "normalize_plain_text",
    "verify_bound_citation",
    "verify_citation",
]
