"""Shared deterministic identities for bounded source-bound policy routes."""

from __future__ import annotations

import hashlib
import json
from uuid import UUID

_PREVIEW_ID_DOMAIN = b"sentinel.synthetic-proposal-preview.identity.v1\x00"


def proposal_preview_identity(source_item_id: UUID, source_binding_sha256: str) -> str:
    """Identify the fixed preview template and exact selected verified source set."""
    if type(source_item_id) is not UUID or type(source_binding_sha256) is not str:
        raise TypeError("proposal preview identity inputs are invalid")
    if len(source_binding_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in source_binding_sha256
    ):
        raise ValueError("proposal preview identity inputs are invalid")
    payload = {
        "domain": "sentinel.synthetic-proposal-preview.identity.v1",
        "source_item_id": str(source_item_id),
        "source_binding_sha256": source_binding_sha256,
        "proposal_kind": "REVIEW_SOURCE",
        "template_version": "v1",
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")
    return hashlib.sha256(_PREVIEW_ID_DOMAIN + canonical).hexdigest()


__all__ = ["proposal_preview_identity"]
