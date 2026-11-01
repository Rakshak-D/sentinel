"""Deterministic JSON representation for Sentinel's typed contracts only.

This is not the future approval-digest or audit-chain algorithm.
"""

import hashlib
import json

from sentinel.contracts.envelopes import BoundaryEnvelope, SourceEnvelope


def canonical_json_bytes(value: SourceEnvelope | BoundaryEnvelope) -> bytes:
    """Serialize one exact contract type as sorted, compact UTF-8 JSON bytes."""
    if type(value) not in (SourceEnvelope, BoundaryEnvelope):
        raise TypeError("canonical serialization accepts only SourceEnvelope or BoundaryEnvelope")

    raw_value = value.model_dump(mode="python")
    validated: SourceEnvelope | BoundaryEnvelope
    if type(value) is SourceEnvelope:
        validated = SourceEnvelope.model_validate(raw_value)
    else:
        validated = BoundaryEnvelope.model_validate(raw_value)
    payload = validated.model_dump(mode="json")
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: SourceEnvelope | BoundaryEnvelope) -> str:
    """Return a deterministic SHA-256 hex digest for a typed contract."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
