"""Immutable metadata contracts for bounded pending synthetic proposals."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)

from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.policy.types import Capability

_SHA256 = Annotated[
    StrictStr,
    StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64),
]
_ISO_TIME = datetime


class _FrozenProposalModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
        hide_input_in_errors=True,
    )


class SyntheticPendingProposal(_FrozenProposalModel):
    """Body-free pending proposal metadata; never an approval or execution receipt."""

    schema_version: Literal["sentinel.synthetic-pending-proposal.v1"] = (
        "sentinel.synthetic-pending-proposal.v1"
    )
    proposal_id: _SHA256
    run_id: UUID
    principal_id: UUID
    tool_id: Literal["sentinel.synthetic.proposal.persist"]
    capability: Literal[Capability.C2_WRITE_LOCAL_PROPOSAL] = Capability.C2_WRITE_LOCAL_PROPOSAL
    proposal_kind: Literal["REVIEW_SOURCE"] = "REVIEW_SOURCE"
    issue_number: Annotated[StrictInt, Field(ge=101, le=103)]
    proposal_title: Annotated[StrictStr, Field(min_length=1, max_length=80)]
    source_item_id: UUID
    source_envelope_id: UUID
    preview_id: _SHA256
    provider_item_id: Annotated[
        StrictStr,
        StringConstraints(
            strict=True,
            pattern=r"^example-owner/fixture-project#(?:101|102|103)$",
            max_length=40,
        ),
    ]
    source_content_sha256: _SHA256
    source_binding_sha256: _SHA256
    source_manifest_sha256: _SHA256
    evidence_span_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=5)]
    canonical_args_ref: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    canonical_args_sha256: _SHA256
    display_sha256: _SHA256
    policy_request_sha256: _SHA256
    policy_sha256: _SHA256
    registry_sha256: _SHA256
    config_sha256: _SHA256
    policy_rule_id: Literal["P06"] = "P06"
    status: Literal["PENDING_REVIEW"] = "PENDING_REVIEW"
    created_at: _ISO_TIME
    expires_at: _ISO_TIME
    owner_intent_id: Literal[None] = None
    credential_alias: Literal[None] = None
    source_trust: Literal[TrustLabel.T4_EXTERNAL] = TrustLabel.T4_EXTERNAL
    source_sensitivity: Literal[SensitivityLabel.PUBLIC] = SensitivityLabel.PUBLIC
    derived_trust: Literal[TrustLabel.T3_DERIVED] = TrustLabel.T3_DERIVED
    derived_sensitivity: Literal[SensitivityLabel.PUBLIC] = SensitivityLabel.PUBLIC
    executable: Literal[False] = False

    @field_validator("created_at", "expires_at")
    @classmethod
    def require_canonical_utc(cls, value: datetime) -> datetime:
        offset = value.utcoffset()
        if (
            value.tzinfo is None
            or offset is None
            or offset.total_seconds() != 0
        ):
            raise ValueError("proposal timestamps must be canonical aware UTC values")
        return value

    @model_validator(mode="after")
    def enforce_pending_contract(self) -> SyntheticPendingProposal:
        if (
            self.provider_item_id != f"example-owner/fixture-project#{self.issue_number}"
            or self.proposal_title != f"Review synthetic GitHub issue #{self.issue_number}"
            or self.expires_at <= self.created_at
            or len(self.evidence_span_ids) != len(set(self.evidence_span_ids))
            or self.canonical_args_ref != f"sha256:{self.canonical_args_sha256}"
        ):
            raise ValueError("pending proposal metadata is invalid")
        return self


class ProposalSaveReport(_FrozenProposalModel):
    schema_version: Literal["sentinel.synthetic-pending-proposal-save.v1"] = (
        "sentinel.synthetic-pending-proposal-save.v1"
    )
    disposition: Literal["CREATED", "ALREADY_EXISTS"]
    proposal: SyntheticPendingProposal


class ProposalListReport(_FrozenProposalModel):
    schema_version: Literal["sentinel.synthetic-pending-proposal-list.v1"] = (
        "sentinel.synthetic-pending-proposal-list.v1"
    )
    proposal_count: Annotated[StrictInt, Field(ge=0, le=1000)]
    proposals: Annotated[tuple[SyntheticPendingProposal, ...], Field(max_length=1000)]

    @model_validator(mode="after")
    def require_count_match(self) -> ProposalListReport:
        if self.proposal_count != len(self.proposals):
            raise ValueError("proposal count does not match the result list")
        if tuple(sorted(item.proposal_id for item in self.proposals)) != tuple(
            item.proposal_id for item in self.proposals
        ):
            raise ValueError("proposals must be ordered by stable identity")
        return self


__all__ = ["ProposalListReport", "ProposalSaveReport", "SyntheticPendingProposal"]
