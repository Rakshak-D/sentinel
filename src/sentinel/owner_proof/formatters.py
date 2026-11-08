"""Deterministic, body-free owner-proof status formatters."""

from __future__ import annotations

import json

from sentinel.owner_proof.types import OwnerProofStatus

_MAX_OUTPUT_BYTES = 8192


def _validate(report: OwnerProofStatus) -> OwnerProofStatus:
    if type(report) is not OwnerProofStatus:
        raise ValueError("owner-proof status must use the registered model")
    checked = OwnerProofStatus.model_validate(report.model_dump(mode="python"), strict=True)
    if checked != report:
        raise ValueError("owner-proof status is not canonical")
    return checked


def format_json_owner_proof_status(report: OwnerProofStatus) -> str:
    """Format one deterministic status record without paths or credential material."""
    checked = _validate(report)
    value = json.dumps(
        checked.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(value.encode("utf-8", errors="strict")) > _MAX_OUTPUT_BYTES:
        raise ValueError("owner-proof status output exceeds its fixed limit")
    return value


def format_text_owner_proof_status(report: OwnerProofStatus) -> str:
    """Return compact operational status without implying owner authentication."""
    checked = _validate(report)
    text = "\n".join(
        (
            "Sentinel owner-proof verification",
            f"WebAuthn verifier: {checked.backend_state}",
            f"Authentication schema: {checked.schema_state}",
            f"Synthetic test credentials: {checked.synthetic_test_credentials}",
            "Production owner verification: UNAVAILABLE",
            "Authorization and execution: unavailable",
        )
    )
    if len(text.encode("utf-8", errors="strict")) > _MAX_OUTPUT_BYTES:
        raise ValueError("owner-proof status output exceeds its fixed limit")
    return text


__all__ = ["format_json_owner_proof_status", "format_text_owner_proof_status"]
