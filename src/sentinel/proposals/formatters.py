"""Deterministic, bounded, body-free proposal preview formatters."""

from __future__ import annotations

import json

from sentinel.briefing.formatters import escape_display_text
from sentinel.proposals.types import SyntheticProposalPreview, _is_verified_preview

MAX_PREVIEW_OUTPUT_BYTES = 64 * 1024


def _validate_preview(preview: SyntheticProposalPreview) -> SyntheticProposalPreview:
    if not _is_verified_preview(preview):
        raise ValueError("proposal formatter requires a locally verified preview")
    return SyntheticProposalPreview.model_validate(preview.model_dump(mode="python"), strict=True)


def _bounded(output: str) -> str:
    if len(output.encode("utf-8", errors="strict")) > MAX_PREVIEW_OUTPUT_BYTES:
        raise ValueError("preview output exceeds the fixed output limit")
    return output


def format_json_proposal_preview(preview: SyntheticProposalPreview) -> str:
    validated = _validate_preview(preview)
    return _bounded(
        json.dumps(
            validated.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def format_text_proposal_preview(preview: SyntheticProposalPreview) -> str:
    validated = _validate_preview(preview)
    return _bounded(
        "\n".join(
            (
                "Synthetic GitHub proposal preview",
                f"Title: {escape_display_text(validated.proposal_title)}",
                "Status: PREVIEW_ONLY",
                "Disclaimer: " + escape_display_text(validated.disclaimer),
                f"Selected issue: {escape_display_text(validated.provider_item_id)}",
                f"Preview ID: {validated.preview_id}",
                f"Source item UUID: {validated.source_item_id}",
                f"Source envelope UUID: {validated.source_envelope_id}",
                f"Source content SHA-256: {validated.source_content_sha256}",
                f"Source binding SHA-256: {validated.source_binding_sha256}",
                "Verified citation spans: "
                + ", ".join(str(span_id) for span_id in validated.evidence_span_ids),
                f"Source: {validated.source_trust.value} / {validated.source_sensitivity.value}",
                f"Derived preview: {validated.derived_trust.value} / "
                f"{validated.derived_sensitivity.value}",
                f"Capability: {validated.proposed_capability.value}",
                f"Policy: {validated.policy_rule_id.value} ALLOW (preview construction only)",
                f"Policy request SHA-256: {validated.policy_request_sha256}",
                f"Policy SHA-256: {validated.policy_sha256}",
                f"Registry SHA-256: {validated.registry_sha256}",
                "No task, proposal, approval, grant or external action was created.",
            )
        )
    )


__all__ = [
    "MAX_PREVIEW_OUTPUT_BYTES",
    "format_json_proposal_preview",
    "format_text_proposal_preview",
]
