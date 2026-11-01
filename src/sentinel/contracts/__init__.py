"""Immutable data contracts for Sentinel's source and execution boundaries.

These types validate structure only. They do not authenticate owner intent,
authorize an operation, or execute a model or tool call.
"""

from sentinel.contracts.canonical import canonical_json_bytes, canonical_sha256
from sentinel.contracts.envelopes import BoundaryEnvelope, ByteSpan, SourceEnvelope
from sentinel.contracts.labels import BoundaryKind, SensitivityLabel, TrustLabel

__all__ = [
    "BoundaryEnvelope",
    "BoundaryKind",
    "ByteSpan",
    "SensitivityLabel",
    "SourceEnvelope",
    "TrustLabel",
    "canonical_json_bytes",
    "canonical_sha256",
]
