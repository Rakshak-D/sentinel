"""Strict metadata-only contract for one synthetic source review preview."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_validator,
)

from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.policy.types import Capability, PolicyRuleId

_SHA256 = Annotated[
    StrictStr,
    StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64),
]
_ProviderItemId = Annotated[
    StrictStr,
    StringConstraints(
        strict=True,
        pattern=r"^example-owner/fixture-project#(?:101|102|103)$",
        max_length=40,
    ),
]
_PREVIEW_VERIFICATION_SEAL = object()


class SyntheticProposalPreview(BaseModel):
    """Immutable preview metadata; source body, authority and execution are absent."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
        hide_input_in_errors=True,
    )
    _verification_seal: object = PrivateAttr(default=None)

    schema_version: Literal["sentinel.synthetic-proposal-preview.v1"] = (
        "sentinel.synthetic-proposal-preview.v1"
    )
    synthetic_data: Literal[True] = True
    preview_id: _SHA256
    proposal_kind: Literal["REVIEW_SOURCE"] = "REVIEW_SOURCE"
    proposal_title: Annotated[StrictStr, Field(min_length=1, max_length=80)]
    issue_number: Annotated[StrictInt, Field(ge=101, le=103)]
    source_item_id: UUID
    source_envelope_id: UUID
    provider_item_id: _ProviderItemId
    source_content_sha256: _SHA256
    source_binding_sha256: _SHA256
    evidence_span_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=5)]
    source_trust: TrustLabel
    source_sensitivity: SensitivityLabel
    derived_trust: TrustLabel
    derived_sensitivity: SensitivityLabel
    proposed_capability: Capability
    policy_rule_id: PolicyRuleId
    policy_request_sha256: _SHA256
    policy_sha256: _SHA256
    registry_sha256: _SHA256
    status: Literal["PREVIEW_ONLY"] = "PREVIEW_ONLY"
    disclaimer: Literal[
        "Possible review only; not an actual task assignment; not an accepted task, "
        "persisted proposal, approval, or grant."
    ] = (
        "Possible review only; not an actual task assignment; not an accepted task, "
        "persisted proposal, approval, or grant."
    )
    executable: Literal[False] = False

    @model_validator(mode="after")
    def enforce_closed_preview_contract(self) -> SyntheticProposalPreview:
        if (
            self.provider_item_id != f"example-owner/fixture-project#{self.issue_number}"
            or self.proposal_title != f"Review synthetic GitHub issue #{self.issue_number}"
            or self.source_trust is not TrustLabel.T4_EXTERNAL
            or self.source_sensitivity is not SensitivityLabel.PUBLIC
            or self.derived_trust is not TrustLabel.T3_DERIVED
            or self.derived_sensitivity is not SensitivityLabel.PUBLIC
            or self.proposed_capability is not Capability.C2_WRITE_LOCAL_PROPOSAL
            or self.policy_rule_id is not PolicyRuleId.P06
            or self.executable is not False
            or len(self.evidence_span_ids) != len(set(self.evidence_span_ids))
        ):
            raise ValueError("preview does not match the fixed synthetic review contract")
        return self


def _mark_verified_preview(preview: SyntheticProposalPreview) -> SyntheticProposalPreview:
    """Seal only the result assembled after local P06 evaluation."""
    if type(preview) is not SyntheticProposalPreview:
        raise TypeError("verified preview requires the registered preview type")
    preview._verification_seal = _PREVIEW_VERIFICATION_SEAL
    return preview


def _is_verified_preview(value: object) -> bool:
    return (
        type(value) is SyntheticProposalPreview
        and value._verification_seal is _PREVIEW_VERIFICATION_SEAL
    )


__all__ = ["SyntheticProposalPreview"]
