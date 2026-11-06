"""Bounded, deterministic presentations for pending proposal metadata."""

from __future__ import annotations

import json
from typing import TypeVar

from pydantic import BaseModel

from sentinel.briefing.formatters import escape_display_text
from sentinel.proposals.persistence_types import ProposalListReport, ProposalSaveReport

MAX_PROPOSAL_OUTPUT_BYTES = 65_536
ModelT = TypeVar("ModelT", bound=BaseModel)


def _validate(value: object, model_type: type[ModelT]) -> ModelT:
    if type(value) is not model_type:
        raise TypeError("proposal formatter requires the exact registered result type")
    return model_type.model_validate(value.model_dump(mode="python"), strict=True)


def format_json_proposal_save(report: ProposalSaveReport) -> str:
    validated = _validate(report, ProposalSaveReport)
    output = json.dumps(
        validated.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    _require_output_bound(output)
    return output


def format_text_proposal_save(report: ProposalSaveReport) -> str:
    validated = _validate(report, ProposalSaveReport)
    proposal = validated.proposal
    title = escape_display_text(proposal.proposal_title)
    lines = [
        "Synthetic GitHub review proposal",
        f"Result: {validated.disposition}",
        f"Proposal ID: {proposal.proposal_id}",
        f"Issue: {proposal.provider_item_id}",
        f"Title: {title}",
        f"Status: {proposal.status}",
        f"Evidence citations: {len(proposal.evidence_span_ids)}",
        "Authorization: pending review only; no task, approval, or execution.",
    ]
    output = "\n".join(lines)
    _require_output_bound(output)
    return output


def format_json_proposal_list(report: ProposalListReport) -> str:
    validated = _validate(report, ProposalListReport)
    output = json.dumps(
        validated.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    _require_output_bound(output)
    return output


def format_text_proposal_list(report: ProposalListReport) -> str:
    validated = _validate(report, ProposalListReport)
    lines = [f"Pending synthetic proposals: {validated.proposal_count}"]
    for proposal in validated.proposals:
        lines.extend(
            (
                f"{proposal.proposal_id}  {proposal.status}  {proposal.provider_item_id}",
                f"  Title: {escape_display_text(proposal.proposal_title)}",
                f"  Evidence citations: {len(proposal.evidence_span_ids)}",
            )
        )
    if validated.proposals:
        lines.append("Pending review is metadata only; it is not approval or execution authority.")
    output = "\n".join(lines)
    _require_output_bound(output)
    return output


def _require_output_bound(output: str) -> None:
    if len(output.encode("utf-8", errors="strict")) > MAX_PROPOSAL_OUTPUT_BYTES:
        raise ValueError("proposal output exceeds the registered limit")


__all__ = [
    "MAX_PROPOSAL_OUTPUT_BYTES",
    "format_json_proposal_list",
    "format_json_proposal_save",
    "format_text_proposal_list",
    "format_text_proposal_save",
]
