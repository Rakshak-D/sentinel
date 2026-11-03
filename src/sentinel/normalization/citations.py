"""Explicit byte-range citation API."""

from sentinel.contracts.envelopes import ByteSpan
from sentinel.normalization.plain_text import add_citation, verify_citation

__all__ = ["ByteSpan", "add_citation", "verify_citation"]
