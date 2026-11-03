"""Plain-text source normalization and citation helpers."""

from sentinel.normalization.plain_text import (
    MAX_PLAIN_TEXT_BYTES,
    NormalizationError,
    NormalizationErrorCode,
    add_citation,
    normalize_plain_text,
    verify_citation,
)
from sentinel.normalization.types import NormalizedPlainTextSource, PlainTextSourceDescriptor

__all__ = [
    "MAX_PLAIN_TEXT_BYTES",
    "NormalizationError",
    "NormalizationErrorCode",
    "NormalizedPlainTextSource",
    "PlainTextSourceDescriptor",
    "add_citation",
    "normalize_plain_text",
    "verify_citation",
]
