"""Bounded deterministic formatting for read-only proposal review checks."""

from __future__ import annotations

import json

from sentinel.briefing.formatters import escape_display_text
from sentinel.proposals.review_types import ProposalReviewCheck

MAX_PROPOSAL_REVIEW_OUTPUT_BYTES = 65_536


def _validated(report: ProposalReviewCheck) -> ProposalReviewCheck:
    if type(report) is not ProposalReviewCheck:
        raise TypeError("proposal review formatter requires the registered report type")
    validated = ProposalReviewCheck.model_validate(report.model_dump(mode="python"), strict=True)
    if validated != report:
        raise ValueError("proposal review report is not canonical")
    return validated


def format_json_proposal_review(report: ProposalReviewCheck) -> str:
    validated = _validated(report)
    output = json.dumps(
        validated.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    _require_bound(output)
    return output


def format_text_proposal_review(report: ProposalReviewCheck) -> str:
    validated = _validated(report)
    lines = (
        "Synthetic pending proposal review check",
        f"Proposal ID: {validated.proposal_id}",
        f"Stored status: {validated.stored_status}",
        f"Review readiness: {validated.review_readiness.value}",
        f"Source item UUID: {validated.source_item_id}",
        f"Source content SHA-256: {validated.source_content_sha256}",
        f"Source binding SHA-256: {validated.source_binding_sha256}",
        f"Verified citation spans: {validated.evidence_span_count}",
        f"Created at: {validated.created_at.isoformat(timespec='microseconds')}",
        f"Expires at: {validated.expires_at.isoformat(timespec='microseconds')}",
        f"Checked at: {validated.checked_at.isoformat(timespec='microseconds')}",
        f"Reason: {validated.reason_code.value}",
        f"Owner verified: {'yes' if validated.owner_verified else 'no'}",
        f"Executable: {'yes' if validated.executable else 'no'}",
        "This is read-only review readiness, not approval or task authorization.",
    )
    output = "\n".join(escape_display_text(line) for line in lines)
    _require_bound(output)
    return output


def _require_bound(output: str) -> None:
    if len(output.encode("utf-8", errors="strict")) > MAX_PROPOSAL_REVIEW_OUTPUT_BYTES:
        raise ValueError("proposal review output exceeds the fixed output limit")


__all__ = [
    "MAX_PROPOSAL_REVIEW_OUTPUT_BYTES",
    "format_json_proposal_review",
    "format_text_proposal_review",
]
